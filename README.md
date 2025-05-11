# PII Checker for Cloudflare Workers

A simple, accurate PII checker for common patterns with three privacy policy operations: redact, anonymize, and hash.

## Features

- **Lightweight and Efficient**: Compiles to WebAssembly with a small footprint
- **Deterministic Regex Patterns**: Pre-compiled patterns for common PII types
- **Privacy Policies**:
  - **REDACT**: Replace PII with the same number of █ characters
  - **ANONYMIZE**: Replace with type indicators like `<EMAIL_1>`, `<PHONE_2>`
  - **HASH**: Replace with SHA-256 hash (first 8 hex characters)
- **Supported PII Types**:
  - Email addresses
  - Phone numbers (US format)
  - Social Security Numbers (SSN)
  - Credit card numbers

## API Usage

Send a POST request to the `/pii` endpoint with the following JSON structure:

```json
{
  "text": "Text containing PII to process",
  "fields": ["EMAIL", "PHONE", "SSN", "CREDIT_CARD"],
  "priv_policy": "REDACT" | "ANONYMIZE" | "HASH"
}
```

Response format:

```json
{
  "redacted": "Processed text with PII handled according to policy",
  "map": [
    ["PII_TYPE", "original_value", "replacement_value"],
    ...
  ]
}
```

## Example

Input:
```json
{
  "text": "Contact John at john@example.com or 555-123-4567",
  "fields": ["EMAIL", "PHONE"],
  "priv_policy": "REDACT"
}
```

Output:
```json
{
  "redacted": "Contact John at ████████████████ or ████████████",
  "map": [
    ["EMAIL", "john@example.com", "████████████████"],
    ["PHONE", "555-123-4567", "████████████"]
  ]
}
```

## Development

1. Make sure you have Rust and wrangler installed.
2. Clone the repository.
3. Run the examples: `cargo run --example test_pii`
4. Deploy to Cloudflare Workers: `wrangler deploy`

## Implementation Details

- Uses lazy_static to compile regex patterns only once
- Processes matches back-to-front to avoid shifting offsets
- Returns both the processed text and a mapping of original-to-replacement values