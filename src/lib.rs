use axum::{
    extract::Json,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use tower_service::Service;
use worker::*;

// Regex patterns for common PII
static EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)[\w.+-]+@[\w.-]+\.\w{2,}").unwrap());
static PHONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap());
static SSN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b").unwrap());
static CREDIT_CARD: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap());

// Models for privacy policy
#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivacyPolicy {
    Redact,
    Anonymize,
    Hash,
}

// Input model for API
#[derive(Debug, Deserialize)]
pub struct PiiRequest {
    pub text: String,
    pub fields: Vec<String>,
    pub priv_policy: PrivacyPolicy,
}

// Output model for API
#[derive(Debug, Serialize)]
pub struct PiiResponse {
    pub redacted: String,
    pub map: Vec<(String, String, String)>,
}

// PII field type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiField {
    Email,
    Phone,
    Ssn,
    CreditCard,
}

// Custom error for PII field conversion
#[derive(Debug, thiserror::Error)]
pub enum PiiError {
    #[error("Invalid PII field type: {0}")]
    InvalidFieldType(String),
    #[error("Processing error: {0}")]
    ProcessingError(String),
}

impl PiiField {
    fn as_str(&self) -> &'static str {
        match self {
            PiiField::Email => "EMAIL",
            PiiField::Phone => "PHONE",
            PiiField::Ssn => "SSN",
            PiiField::CreditCard => "CREDIT_CARD",
        }
    }

    // Safe conversion with Result
    pub fn try_from_str(s: &str) -> std::result::Result<Self, PiiError> {
        match s.to_uppercase().as_str() {
            "EMAIL" => Ok(PiiField::Email),
            "PHONE" => Ok(PiiField::Phone),
            "SSN" => Ok(PiiField::Ssn),
            "CREDIT_CARD" => Ok(PiiField::CreditCard),
            _ => Err(PiiError::InvalidFieldType(s.to_string())),
        }
    }
}

impl From<&str> for PiiField {
    fn from(s: &str) -> Self {
        Self::try_from_str(s).unwrap_or_else(|e| {
            // Log the error but default to Email as a fallback
            // In production you might want different behavior
            console_log!("Warning: {}", e);
            PiiField::Email
        })
    }
}

fn router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/pii", post(process_pii))
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    Ok(router().call(req).await?)
}

pub async fn root() -> &'static str {
    "Hello from PII Processor!"
}

// PII detection and transformation endpoint
pub async fn process_pii(Json(request): Json<PiiRequest>) -> impl IntoResponse {
    match detect_and_transform(&request.text, &request.fields, request.priv_policy) {
        Ok(result) => Json(result),
        Err(e) => {
            // Log the actual error for debugging
            console_log!("Error processing PII: {:?}", e);

            // Return a user-friendly error response
            Json(PiiResponse {
                redacted: "Error processing PII request. Please check your input and try again.".to_string(),
                map: Vec::new(),
            })
        }
    }
}

pub fn detect_and_transform(
    src: &str,
    fields: &[String],
    policy: PrivacyPolicy,
) -> Result<PiiResponse> {
    let mut spans = Vec::new();

    // Find all matches for each requested field type
    for field in fields {
        // Try to convert the field to a PiiField, logging any errors but continuing
        match PiiField::try_from_str(field) {
            Ok(PiiField::Email) => {
                for m in EMAIL.find_iter(src) {
                    spans.push(("EMAIL", m.start(), m.end()));
                }
            }
            Ok(PiiField::Phone) => {
                for m in PHONE.find_iter(src) {
                    spans.push(("PHONE", m.start(), m.end()));
                }
            }
            Ok(PiiField::Ssn) => {
                for m in SSN.find_iter(src) {
                    spans.push(("SSN", m.start(), m.end()));
                }
            }
            Ok(PiiField::CreditCard) => {
                for m in CREDIT_CARD.find_iter(src) {
                    spans.push(("CREDIT_CARD", m.start(), m.end()));
                }
            }
            Err(e) => {
                // Log invalid field types but continue processing valid ones
                console_log!("Warning: {}", e);
            }
        }
    }

    // Sort back-to-front so replacement offsets stay valid
    spans.sort_by_key(|s| Reverse(s.1));

    let mut redacted = src.to_string();
    let mut map = Vec::new();
    
    // Type counters for anonymization
    let mut type_counters: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    
    for (kind, start, end) in spans {
        let original = redacted[start..end].to_string();

        // Get the counter for this type for anonymization
        let counter = match policy {
            PrivacyPolicy::Anonymize => {
                let count = type_counters.entry(kind.to_string()).or_insert(0);
                *count += 1;
                *count
            },
            _ => 0, // Not used for other policies
        };

        let replacement = match policy {
            PrivacyPolicy::Redact => "█".repeat(end - start),
            PrivacyPolicy::Anonymize => format!("<{}_{}>", kind, counter),
            PrivacyPolicy::Hash => {
                let mut hasher = Sha256::new();
                hasher.update(&original);
                hex::encode(&hasher.finalize())[..8].to_string()
            }
        };

        redacted.replace_range(start..end, &replacement);
        map.push((kind.to_string(), original, replacement));
    }
    
    Ok(PiiResponse { redacted, map })
}