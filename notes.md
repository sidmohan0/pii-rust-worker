
A lean design that fits
Keep the Worker in Rust.
Rust → wasm32-unknown-unknown compiles to a few hundred KB, leaving almost the whole 128 MB for request buffers.

Use deterministic regex + dictionaries.
For e-mail, phone, SSN, credit cards, ICD-10 codes—whatever you care about—you can pre-compile patterns once with lazy_static! and reuse them on every request.

Expose one POST endpoint

json
Copy
Edit
{
  "text": "...",
  "fields": ["EMAIL","PHONE"],
  "priv_policy": "REDACT" | "ANONYMIZE" | "HASH"
}
Transform in place.

REDACT → replace span with the same number of █

ANONYMIZE → replace with <EMAIL_1>, <PHONE_2> … (count per type)

HASH → sha2 of the raw span, keep first 8 hex chars

Working back-to-front through the matches avoids shifting offsets.

Return the rewritten string and a parallel map of original→replacement so downstream systems can reason about it.

here is some pseudocode: 




use worker::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use once_cell::sync::Lazy;

static EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)[\w.+-]+@[\w.-]+\.\w{2,}").unwrap());
static PHONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap());
// add more patterns…

#[event(fetch)]
pub async fn main(req: Request, _env: Env, _ctx: worker::Context) -> Result<Response> {
    let Input { text, fields, priv_policy } = req.json().await?;
    let result = detect_and_transform(&text, &fields, priv_policy)?;
    Response::from_json(&result)
}

fn detect_and_transform(src: &str, fields: &[String], policy: Policy) -> Result<Output> {
    let mut spans = Vec::new();
    if fields.contains(&"EMAIL".into()) {
        for m in EMAIL.find_iter(src) { spans.push(("EMAIL", m.start(), m.end())); }
    }
    // …repeat for other patterns

    // sort back-to-front so replacement offsets stay valid
    spans.sort_by_key(|s| std::cmp::Reverse(s.1));

    let mut redacted = src.to_string();
    let mut map = Vec::new();
    for (kind, start, end) in spans {
        let original = &redacted[start..end];
        let replacement = match policy {
            Policy::Redact    => "█".repeat(end - start),
            Policy::Anonymize => format!("<{}_{}>", kind, map.len()+1),
            Policy::Hash      => {
                let mut hasher = Sha256::new();
                hasher.update(original);
                hex::encode(&hasher.finalize())[..8].to_string()
            }
        };
        redacted.replace_range(start..end, &replacement);
        map.push((kind.to_string(), original.to_string(), replacement));
    }
    Ok(Output { redacted, map })
}
