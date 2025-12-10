//! Breach data lookup via Have I Been Pwned API
//!
//! Implements password and email breach checks using the HIBP API.

use crate::protocols::http::HttpClient;
use crate::crypto::sha1::sha1;

/// Breach information for an email
#[derive(Debug, Clone)]
pub struct BreachInfo {
    pub name: String,
    pub domain: String,
    pub breach_date: String,
    pub pwn_count: u64,
    pub data_classes: Vec<String>,
}

/// Result of a password check
#[derive(Debug, Clone)]
pub struct PasswordCheckResult {
    pub pwned: bool,
    pub count: u64,
}

/// Result of an email check
#[derive(Debug, Clone)]
pub struct EmailCheckResult {
    pub email: String,
    pub pwned: bool,
    pub breach_count: usize,
    pub breaches: Vec<BreachInfo>,
}

/// HIBP breach client
pub struct BreachClient {
    api_key: Option<String>,
    http: HttpClient,
}

impl BreachClient {
    pub fn new() -> Self {
        Self {
            api_key: None,
            http: HttpClient::new(),
        }
    }

    /// Set HIBP API key (required for email checks) - builder pattern
    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    /// Set HIBP API key (required for email checks) - mutating version
    pub fn set_api_key(&mut self, key: &str) {
        self.api_key = Some(key.to_string());
    }

    /// Check if a password has been exposed in breaches using k-Anonymity
    /// Uses SHA-1 hash prefix to preserve privacy (only first 5 chars sent)
    pub fn check_password(&self, password: &str) -> Result<PasswordCheckResult, String> {
        // Hash the password with SHA-1 and convert to hex
        let hash_bytes = sha1(password.as_bytes());
        let hash: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let hash_upper = hash.to_uppercase();

        // Split into prefix (first 5 chars) and suffix (rest)
        let prefix = &hash_upper[..5];
        let suffix = &hash_upper[5..];

        // Query HIBP API
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        let response = self.http.get(&url)
            .map_err(|e| format!("HIBP API error: {}", e))?;

        // Convert body to string and search for our suffix
        let body_str = String::from_utf8_lossy(&response.body);
        for line in body_str.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let hash_suffix = parts[0].trim();
                if hash_suffix.eq_ignore_ascii_case(suffix) {
                    let count: u64 = parts[1].trim().parse().unwrap_or(0);
                    return Ok(PasswordCheckResult {
                        pwned: true,
                        count,
                    });
                }
            }
        }

        Ok(PasswordCheckResult {
            pwned: false,
            count: 0,
        })
    }

    /// Check if an email has been exposed in breaches (requires API key)
    pub fn check_email(&self, email: &str) -> Result<EmailCheckResult, String> {
        let api_key = self.api_key.as_ref()
            .ok_or("HIBP API key required for email checks")?;

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
            urlencoding(email)
        );

        let response = self.http.get_with_headers(&url, &[
            ("hibp-api-key", api_key.as_str()),
            ("User-Agent", "redblue-security-tool"),
        ]).map_err(|e| format!("HIBP API error: {}", e))?;

        if response.status_code == 404 {
            return Ok(EmailCheckResult {
                email: email.to_string(),
                pwned: false,
                breach_count: 0,
                breaches: vec![],
            });
        }

        if response.status_code != 200 {
            return Err(format!("HIBP API returned status {}", response.status_code));
        }

        // Parse JSON response (simple parser)
        let body_str = String::from_utf8_lossy(&response.body);
        let breaches = self.parse_breaches_json(&body_str)?;

        Ok(EmailCheckResult {
            email: email.to_string(),
            pwned: !breaches.is_empty(),
            breach_count: breaches.len(),
            breaches,
        })
    }

    /// Simple JSON parser for breach data
    fn parse_breaches_json(&self, json: &str) -> Result<Vec<BreachInfo>, String> {
        let mut breaches = Vec::new();

        // Very simple JSON array parser
        if !json.trim().starts_with('[') {
            return Ok(breaches);
        }

        // Split by objects (crude but works for HIBP response)
        for obj in json.split("},") {
            let name = extract_json_string(obj, "Name").unwrap_or_default();
            let domain = extract_json_string(obj, "Domain").unwrap_or_default();
            let breach_date = extract_json_string(obj, "BreachDate").unwrap_or_default();
            let pwn_count = extract_json_number(obj, "PwnCount").unwrap_or(0);

            if !name.is_empty() {
                breaches.push(BreachInfo {
                    name,
                    domain,
                    breach_date,
                    pwn_count,
                    data_classes: vec![], // Skip for now
                });
            }
        }

        Ok(breaches)
    }
}

impl Default for BreachClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple URL encoding
fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

/// Extract string value from JSON
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = json[value_start..].find('"') {
            return Some(json[value_start..value_start + end].to_string());
        }
    }
    None
}

/// Extract number value from JSON
fn extract_json_number(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", key);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        let rest = json[value_start..].trim_start();
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().ok()
    } else {
        None
    }
}
