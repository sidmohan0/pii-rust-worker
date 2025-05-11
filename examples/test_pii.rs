extern crate gliner_rust_worker;
use gliner_rust_worker::{detect_and_transform, PiiRequest, PrivacyPolicy};

fn main() {
    // Sample text with different types of PII
    let text = "Contact John Doe at john.doe@example.com or call 555-123-4567. 
His SSN is 123-45-6789 and credit card 4111-1111-1111-1111.
Jane Smith can be reached at jane.smith@company.org or (800) 555-1212.";

    println!("Original text:\n{}\n", text);

    // Test each privacy policy
    test_policy(text, PrivacyPolicy::Redact);
    test_policy(text, PrivacyPolicy::Anonymize);
    test_policy(text, PrivacyPolicy::Hash);
}

fn test_policy(text: &str, policy: PrivacyPolicy) {
    let policy_name = match policy {
        PrivacyPolicy::Redact => "REDACT",
        PrivacyPolicy::Anonymize => "ANONYMIZE",
        PrivacyPolicy::Hash => "HASH",
    };
    
    println!("\n============ Testing {} policy ============", policy_name);
    
    // Create a request with all supported PII fields
    let request = PiiRequest {
        text: text.to_string(),
        fields: vec![
            "EMAIL".to_string(),
            "PHONE".to_string(),
            "SSN".to_string(),
            "CREDIT_CARD".to_string(),
        ],
        priv_policy: policy,
    };
    
    // Process the request
    match detect_and_transform(&request.text, &request.fields, policy) {
        Ok(response) => {
            println!("Processed text:\n{}\n", response.redacted);
            println!("Replacement map:");
            for (kind, original, replacement) in response.map {
                println!("{}: '{}' -> '{}'", kind, original, replacement);
            }
        },
        Err(e) => {
            println!("Error processing PII: {:?}", e);
        }
    }
}