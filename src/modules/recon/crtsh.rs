/// Certificate Transparency Log Client (crt.sh)
///
/// Replaces: crt.sh manual queries, CT log enumeration from amass/subfinder
///
/// Features:
/// - Query crt.sh database for certificates issued to a domain
/// - Extract subdomains from certificate SANs
/// - Wildcard handling
/// - Deduplication
///
/// NO external dependencies - pure HTTP from scratch
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

/// crt.sh client for Certificate Transparency log queries
pub struct CrtShClient {
    http_client: HttpClient,
}

/// Certificate entry from crt.sh
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub id: u64,
    pub issuer_name: String,
    pub common_name: String,
    pub name_values: Vec<String>,
    pub not_before: String,
    pub not_after: String,
}

impl CrtShClient {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
        }
    }

    /// Query crt.sh for certificates issued to a domain
    /// Returns list of unique subdomains found in certificate SANs
    pub fn query_subdomains(&self, domain: &str) -> Result<Vec<String>, String> {
        // crt.sh JSON API endpoint
        // Format: https://crt.sh/?q=%.domain.com&output=json
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

        let response = self
            .http_client
            .get(&url)
            .map_err(|e| format!("crt.sh request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!("crt.sh returned status {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body);

        // Handle empty response
        if body.trim().is_empty() || body.trim() == "[]" {
            return Ok(Vec::new());
        }

        // Parse JSON response and extract subdomains
        let subdomains = self.parse_json_response(&body, domain)?;

        Ok(subdomains)
    }

    /// Query crt.sh and return full certificate entries
    pub fn query_certificates(&self, domain: &str) -> Result<Vec<CertificateEntry>, String> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

        let response = self
            .http_client
            .get(&url)
            .map_err(|e| format!("crt.sh request failed: {}", e))?;

        if response.status_code != 200 {
            return Err(format!("crt.sh returned status {}", response.status_code));
        }

        let body = String::from_utf8_lossy(&response.body);

        if body.trim().is_empty() || body.trim() == "[]" {
            return Ok(Vec::new());
        }

        self.parse_certificate_entries(&body)
    }

    /// Parse JSON response from crt.sh
    ///
    /// Response format:
    /// ```json
    /// [
    ///   {
    ///     "issuer_ca_id": 183267,
    ///     "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    ///     "common_name": "example.com",
    ///     "name_value": "example.com\nwww.example.com\napi.example.com",
    ///     "id": 12345678,
    ///     "entry_timestamp": "2024-01-01T00:00:00.000",
    ///     "not_before": "2024-01-01T00:00:00",
    ///     "not_after": "2024-04-01T00:00:00",
    ///     "serial_number": "abc123..."
    ///   },
    ///   ...
    /// ]
    /// ```
    fn parse_json_response(&self, json: &str, domain: &str) -> Result<Vec<String>, String> {
        let mut subdomains = HashSet::new();
        let domain_lower = domain.to_lowercase();

        // Simple JSON parsing - extract name_value fields
        // Each entry has "name_value": "sub1.example.com\nsub2.example.com"

        let mut pos = 0;
        let bytes = json.as_bytes();

        while pos < bytes.len() {
            // Find "name_value" key
            if let Some(key_pos) = self.find_json_key(json, pos, "name_value") {
                // Extract the value (string after the colon)
                if let Some(value) = self.extract_json_string_value(json, key_pos) {
                    // name_value contains newline-separated domain names
                    for name in value.split('\n') {
                        let name = name.trim().to_lowercase();

                        // Skip wildcards, empty, and non-matching domains
                        if name.is_empty() {
                            continue;
                        }

                        // Handle wildcard certificates: *.example.com -> example.com
                        let clean_name = if name.starts_with("*.") {
                            &name[2..]
                        } else {
                            &name
                        };

                        // Validate it's a subdomain of our target domain
                        if clean_name.ends_with(&domain_lower) || clean_name == domain_lower {
                            subdomains.insert(clean_name.to_string());
                        }
                    }
                    pos = key_pos + 1;
                } else {
                    pos += 1;
                }
            } else {
                break;
            }
        }

        let mut result: Vec<String> = subdomains.into_iter().collect();
        result.sort();
        Ok(result)
    }

    /// Parse full certificate entries from JSON
    fn parse_certificate_entries(&self, json: &str) -> Result<Vec<CertificateEntry>, String> {
        let mut entries = Vec::new();

        // Find each object in the array
        let mut depth = 0;
        let mut obj_start = None;

        for (i, c) in json.char_indices() {
            match c {
                '[' if depth == 0 => depth = 1,
                '{' if depth >= 1 => {
                    if depth == 1 {
                        obj_start = Some(i);
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 1 {
                        if let Some(start) = obj_start {
                            let obj_json = &json[start..=i];
                            if let Ok(entry) = self.parse_single_entry(obj_json) {
                                entries.push(entry);
                            }
                        }
                        obj_start = None;
                    }
                }
                ']' if depth == 1 => break,
                _ => {}
            }
        }

        Ok(entries)
    }

    /// Parse a single certificate entry object
    fn parse_single_entry(&self, obj_json: &str) -> Result<CertificateEntry, String> {
        let id = self.extract_json_number(obj_json, "id").unwrap_or(0);
        let issuer_name = self
            .extract_json_string(obj_json, "issuer_name")
            .unwrap_or_default();
        let common_name = self
            .extract_json_string(obj_json, "common_name")
            .unwrap_or_default();
        let name_value = self
            .extract_json_string(obj_json, "name_value")
            .unwrap_or_default();
        let not_before = self
            .extract_json_string(obj_json, "not_before")
            .unwrap_or_default();
        let not_after = self
            .extract_json_string(obj_json, "not_after")
            .unwrap_or_default();

        let name_values: Vec<String> = name_value
            .split('\n')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(CertificateEntry {
            id,
            issuer_name,
            common_name,
            name_values,
            not_before,
            not_after,
        })
    }

    /// Find position of a JSON key
    fn find_json_key(&self, json: &str, start: usize, key: &str) -> Option<usize> {
        let search = format!("\"{}\"", key);
        json[start..]
            .find(&search)
            .map(|pos| start + pos + search.len())
    }

    /// Extract string value after a JSON key position
    fn extract_json_string_value(&self, json: &str, key_end: usize) -> Option<String> {
        let rest = &json[key_end..];

        // Skip whitespace and colon
        let mut chars = rest.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c == ':' || c.is_whitespace() {
                chars.next();
            } else {
                break;
            }
        }

        // Find opening quote
        if chars.next() != Some('"') {
            return None;
        }

        // Collect string until closing quote (handle escapes)
        let mut result = String::new();
        let mut escaped = false;

        for c in chars {
            if escaped {
                match c {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    _ => {
                        result.push('\\');
                        result.push(c);
                    }
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                break;
            } else {
                result.push(c);
            }
        }

        Some(result)
    }

    /// Extract a string field from JSON object
    fn extract_json_string(&self, json: &str, key: &str) -> Option<String> {
        let search = format!("\"{}\"", key);
        if let Some(pos) = json.find(&search) {
            self.extract_json_string_value(json, pos + search.len())
        } else {
            None
        }
    }

    /// Extract a number field from JSON object
    fn extract_json_number(&self, json: &str, key: &str) -> Option<u64> {
        let search = format!("\"{}\"", key);
        if let Some(key_pos) = json.find(&search) {
            let rest = &json[key_pos + search.len()..];

            // Skip to colon and whitespace
            let mut start = 0;
            for (i, c) in rest.chars().enumerate() {
                if c.is_ascii_digit() {
                    start = i;
                    break;
                }
            }

            // Collect digits
            let num_str: String = rest[start..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();

            num_str.parse().ok()
        } else {
            None
        }
    }
}

impl Default for CrtShClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_string_extraction() {
        let client = CrtShClient::new();
        let json = r#"{"name_value": "sub1.example.com\nsub2.example.com"}"#;

        if let Some(pos) = client.find_json_key(json, 0, "name_value") {
            let value = client.extract_json_string_value(json, pos);
            assert!(value.is_some());
            let v = value.unwrap();
            assert!(v.contains("sub1.example.com"));
            assert!(v.contains("sub2.example.com"));
        }
    }

    #[test]
    fn test_wildcard_handling() {
        let client = CrtShClient::new();
        let json = r#"[{"name_value": "*.example.com\nwww.example.com"}]"#;

        let result = client.parse_json_response(json, "example.com");
        assert!(result.is_ok());
        let subdomains = result.unwrap();
        assert!(subdomains.contains(&"example.com".to_string()));
        assert!(subdomains.contains(&"www.example.com".to_string()));
    }
}
