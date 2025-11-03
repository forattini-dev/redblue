/// Certificate Transparency (CT) Logs Query
/// Query crt.sh API to discover subdomains from historical certificates
///
/// ✅ ZERO DEPENDENCIES - Pure Rust HTTP client from scratch
///
/// This module provides OSINT capabilities by:
/// 1. Querying Certificate Transparency logs via crt.sh API
/// 2. Extracting Subject Alternative Names (SANs) from certificates
/// 3. Discovering historical subdomains (including deleted ones!)
/// 4. Finding wildcard certificates
/// 5. Detecting infrastructure changes
///
/// **Use Case**: Subdomain enumeration without DNS queries (stealth!)
///
/// CT logs are public append-only ledgers of ALL TLS certificates issued.
/// This is a goldmine for reconnaissance:
/// - Find dev/staging/internal subdomains leaked in certificates
/// - Discover recently deleted subdomains
/// - Track infrastructure changes over time
/// - Find wildcard certificates (*.example.com)
///
/// **NO external binaries** - We implement HTTP client and JSON parsing from scratch!
use std::collections::HashSet;
use std::time::Duration;

/// Certificate Transparency log entry
#[derive(Debug, Clone)]
pub struct CTLogEntry {
    pub issuer_name: String,
    pub common_name: String,
    pub name_value: String, // All SANs (newline-separated)
    pub min_cert_id: u64,
    pub min_entry_timestamp: String,
    pub not_before: String,
    pub not_after: String,
}

/// CT Logs client for querying crt.sh
pub struct CTLogsClient {
    timeout: Duration,
}

impl CTLogsClient {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Query crt.sh for certificates matching a domain
    ///
    /// Returns all unique subdomains found in CT logs
    pub fn query_subdomains(&self, domain: &str) -> Result<Vec<String>, String> {
        let entries = self.query_ct_logs(domain)?;
        let subdomains = self.extract_subdomains(&entries, domain);
        Ok(subdomains)
    }

    /// Query crt.sh API for certificate entries
    ///
    /// API endpoint: https://crt.sh/?q=%.example.com&output=json
    pub fn query_ct_logs(&self, domain: &str) -> Result<Vec<CTLogEntry>, String> {
        // crt.sh API query: %.domain.com finds all subdomains
        let query = format!("%.{}", domain);
        let url = format!("https://crt.sh/?q={}&output=json", query);

        // Make HTTP GET request using our HTTP client
        let response = self.http_get(&url)?;

        // Parse JSON response
        self.parse_ct_response(&response)
    }

    /// Extract unique subdomains from CT log entries
    fn extract_subdomains(&self, entries: &[CTLogEntry], base_domain: &str) -> Vec<String> {
        let mut subdomains = HashSet::new();

        for entry in entries {
            // Parse name_value field (contains SANs separated by newlines)
            for line in entry.name_value.lines() {
                let name = line.trim();

                // Skip wildcards and invalid entries
                if name.starts_with('*') {
                    // Extract wildcard domain (*.dev.example.com -> dev.example.com)
                    if let Some(domain) = name.strip_prefix("*.") {
                        if domain.ends_with(base_domain) && domain != base_domain {
                            subdomains.insert(domain.to_string());
                        }
                    }
                    continue;
                }

                // Only include subdomains of the target domain
                if name.ends_with(base_domain) && name != base_domain {
                    subdomains.insert(name.to_string());
                }
            }

            // Also check common_name
            let cn = entry.common_name.trim();
            if !cn.starts_with('*') && cn.ends_with(base_domain) && cn != base_domain {
                subdomains.insert(cn.to_string());
            }
        }

        let mut result: Vec<String> = subdomains.into_iter().collect();
        result.sort();
        result
    }

    /// Parse crt.sh JSON response
    ///
    /// Example response:
    /// ```json
    /// [
    ///   {
    ///     "issuer_ca_id": 183267,
    ///     "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    ///     "common_name": "example.com",
    ///     "name_value": "example.com\nwww.example.com",
    ///     "id": 9876543210,
    ///     "entry_timestamp": "2024-01-15T10:30:00.000",
    ///     "not_before": "2024-01-15T09:00:00",
    ///     "not_after": "2024-04-15T09:00:00"
    ///   }
    /// ]
    /// ```
    fn parse_ct_response(&self, json: &str) -> Result<Vec<CTLogEntry>, String> {
        // Simple JSON parsing from scratch (we don't use external JSON libraries!)
        let mut entries = Vec::new();

        // Remove leading/trailing whitespace and array brackets
        let json = json.trim();
        if !json.starts_with('[') || !json.ends_with(']') {
            return Err("Invalid JSON response: not an array".to_string());
        }

        let json = &json[1..json.len() - 1]; // Remove [ and ]

        // Split by objects (between { and })
        let mut depth = 0;
        let mut current_obj = String::new();

        for ch in json.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    current_obj.push(ch);
                }
                '}' => {
                    current_obj.push(ch);
                    depth -= 1;
                    if depth == 0 {
                        // Parse this object
                        if let Ok(entry) = self.parse_ct_entry(&current_obj) {
                            entries.push(entry);
                        }
                        current_obj.clear();
                    }
                }
                ',' if depth == 0 => {
                    // Skip comma between objects
                    continue;
                }
                _ => {
                    if depth > 0 {
                        current_obj.push(ch);
                    }
                }
            }
        }

        if entries.is_empty() {
            return Err("No certificates found in CT logs".to_string());
        }

        Ok(entries)
    }

    /// Parse a single CT log entry object
    fn parse_ct_entry(&self, json: &str) -> Result<CTLogEntry, String> {
        let issuer_name = self.extract_json_string(json, "issuer_name")?;
        let common_name = self.extract_json_string(json, "common_name")?;
        let name_value = self.extract_json_string(json, "name_value")?;
        let min_cert_id = self.extract_json_number(json, "id")?;
        let min_entry_timestamp = self.extract_json_string(json, "entry_timestamp")?;
        let not_before = self.extract_json_string(json, "not_before")?;
        let not_after = self.extract_json_string(json, "not_after")?;

        Ok(CTLogEntry {
            issuer_name,
            common_name,
            name_value,
            min_cert_id,
            min_entry_timestamp,
            not_before,
            not_after,
        })
    }

    /// Extract string value from JSON field
    fn extract_json_string(&self, json: &str, field: &str) -> Result<String, String> {
        let pattern = format!("\"{}\":", field);
        if let Some(start) = json.find(&pattern) {
            let value_start = start + pattern.len();
            let remaining = &json[value_start..].trim_start();

            if remaining.starts_with('"') {
                // String value
                let end = remaining[1..]
                    .find('"')
                    .ok_or_else(|| format!("Unterminated string for field {}", field))?;
                let value = &remaining[1..end + 1];
                // Unescape JSON string
                let unescaped = value.replace("\\n", "\n").replace("\\\"", "\"");
                return Ok(unescaped);
            }
        }

        Ok(String::new())
    }

    /// Extract number value from JSON field
    fn extract_json_number(&self, json: &str, field: &str) -> Result<u64, String> {
        let pattern = format!("\"{}\":", field);
        if let Some(start) = json.find(&pattern) {
            let value_start = start + pattern.len();
            let remaining = &json[value_start..].trim_start();

            // Find end of number (comma, brace, or whitespace)
            let mut end = 0;
            for (i, ch) in remaining.chars().enumerate() {
                if ch.is_ascii_digit() {
                    end = i + 1;
                } else {
                    break;
                }
            }

            if end > 0 {
                let num_str = &remaining[..end];
                return num_str
                    .parse()
                    .map_err(|_| format!("Failed to parse number for field {}", field));
            }
        }

        Ok(0)
    }

    /// Make HTTP GET request using our HTTP client
    ///
    /// Uses our pure Rust HTTP implementation (no external dependencies!)
    fn http_get(&self, url: &str) -> Result<String, String> {
        use crate::protocols::http::HttpRequest;
        use crate::protocols::https::HttpsConnection;

        let request = HttpRequest::get(url);
        let connection =
            HttpsConnection::new(request.host(), request.port()).with_timeout(self.timeout);
        let response = connection.request(&request)?;

        String::from_utf8(response.body)
            .map_err(|_| "Invalid UTF-8 in HTTP response body".to_string())
    }
}

impl Default for CTLogsClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_string() {
        let client = CTLogsClient::new();
        let json = r#"{"name":"test value","other":"foo"}"#;

        let value = client.extract_json_string(json, "name").unwrap();
        assert_eq!(value, "test value");
    }

    #[test]
    fn test_extract_json_number() {
        let client = CTLogsClient::new();
        let json = r#"{"id":12345,"other":"foo"}"#;

        let value = client.extract_json_number(json, "id").unwrap();
        assert_eq!(value, 12345);
    }

    #[test]
    fn test_extract_subdomains() {
        let client = CTLogsClient::new();
        let entries = vec![
            CTLogEntry {
                issuer_name: "Let's Encrypt".to_string(),
                common_name: "example.com".to_string(),
                name_value: "example.com\nwww.example.com\napi.example.com".to_string(),
                min_cert_id: 123,
                min_entry_timestamp: "2024-01-01".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2024-04-01".to_string(),
            },
            CTLogEntry {
                issuer_name: "Let's Encrypt".to_string(),
                common_name: "*.dev.example.com".to_string(),
                name_value: "*.dev.example.com\ndev.example.com".to_string(),
                min_cert_id: 124,
                min_entry_timestamp: "2024-01-02".to_string(),
                not_before: "2024-01-02".to_string(),
                not_after: "2024-04-02".to_string(),
            },
        ];

        let subdomains = client.extract_subdomains(&entries, "example.com");

        assert!(subdomains.contains(&"www.example.com".to_string()));
        assert!(subdomains.contains(&"api.example.com".to_string()));
        assert!(subdomains.contains(&"dev.example.com".to_string()));
        assert!(!subdomains.contains(&"example.com".to_string())); // Base domain excluded
    }
}
