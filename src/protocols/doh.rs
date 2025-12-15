/// DNS-over-HTTPS (DoH) Protocol Implementation
/// Uses JSON API format for easy parsing
use crate::protocols::dns::DnsRecordType;
use crate::protocols::http::{HttpClient, HttpRequest};
use std::collections::HashMap;
use std::time::Duration;

/// DoH Provider configuration
#[derive(Debug, Clone)]
pub struct DohProvider {
    pub name: &'static str,
    pub url: &'static str,
}

/// Well-known DoH providers
pub const DOH_PROVIDERS: &[DohProvider] = &[
    DohProvider {
        name: "Google",
        url: "https://dns.google/resolve",
    },
    DohProvider {
        name: "Cloudflare",
        url: "https://cloudflare-dns.com/dns-query",
    },
    DohProvider {
        name: "Quad9",
        url: "https://dns.quad9.net:5053/dns-query",
    },
    DohProvider {
        name: "AdGuard",
        url: "https://dns.adguard.com/dns-query",
    },
];

/// DoH response answer record
#[derive(Debug, Clone)]
pub struct DohAnswer {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: String,
}

/// DoH query response
#[derive(Debug, Clone)]
pub struct DohResponse {
    pub status: u8,
    pub answers: Vec<DohAnswer>,
    pub provider: String,
}

/// DNS-over-HTTPS client
pub struct DohClient {
    http_client: HttpClient,
    timeout: Duration,
}

impl DohClient {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new().with_timeout(Duration::from_secs(10)),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.http_client = HttpClient::new().with_timeout(timeout);
        self
    }

    /// Query a single DoH provider
    pub fn query(
        &self,
        provider: &DohProvider,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Result<DohResponse, String> {
        let type_num = record_type.to_u16();

        // Build URL with query parameters
        let url = format!(
            "{}?name={}&type={}",
            provider.url,
            urlencod(domain),
            type_num
        );

        // Create request with JSON accept header
        let request = HttpRequest::get(&url).with_header("Accept", "application/dns-json");

        let response = self
            .http_client
            .send(&request)
            .map_err(|e| format!("{} query failed: {}", provider.name, e))?;

        if !response.is_success() {
            return Err(format!(
                "{} returned HTTP {}",
                provider.name, response.status_code
            ));
        }

        let body = response.body_as_string();
        self.parse_json_response(&body, provider.name)
    }

    /// Query all providers in parallel for propagation check
    pub fn query_all_providers(
        &self,
        domain: &str,
        record_type: DnsRecordType,
    ) -> Vec<Result<DohResponse, String>> {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for provider in DOH_PROVIDERS {
            let domain = domain.to_string();
            let provider = provider.clone();
            let results = Arc::clone(&results);
            let timeout = self.timeout;

            let handle = thread::spawn(move || {
                let client = DohClient::new().with_timeout(timeout);
                let result = client.query(&provider, &domain, record_type);
                results.lock().unwrap().push((provider.name, result));
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        // Extract results
        let collected = results.lock().unwrap().drain(..).collect::<Vec<_>>();

        collected.into_iter().map(|(_, r)| r).collect()
    }

    /// Parse JSON response from DoH provider
    fn parse_json_response(&self, body: &str, provider_name: &str) -> Result<DohResponse, String> {
        // Simple JSON parser for DoH response
        // Format: {"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,
        //          "Question":[...],"Answer":[{"name":"...","type":1,"TTL":300,"data":"..."}]}

        let status = self.extract_json_number(body, "Status").unwrap_or(0) as u8;

        let mut answers = Vec::new();

        // Find Answer array
        if let Some(answer_start) = body.find("\"Answer\"") {
            if let Some(arr_start) = body[answer_start..].find('[') {
                let arr_start = answer_start + arr_start;
                if let Some(arr_end) = find_matching_bracket(body, arr_start) {
                    let answer_array = &body[arr_start + 1..arr_end];
                    answers = self.parse_answer_array(answer_array);
                }
            }
        }

        Ok(DohResponse {
            status,
            answers,
            provider: provider_name.to_string(),
        })
    }

    /// Parse answer array from JSON
    fn parse_answer_array(&self, array_str: &str) -> Vec<DohAnswer> {
        let mut answers = Vec::new();
        let mut depth = 0;
        let mut obj_start = None;

        for (i, c) in array_str.char_indices() {
            match c {
                '{' => {
                    if depth == 0 {
                        obj_start = Some(i);
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(start) = obj_start {
                            let obj_str = &array_str[start..=i];
                            if let Some(answer) = self.parse_answer_object(obj_str) {
                                answers.push(answer);
                            }
                        }
                        obj_start = None;
                    }
                }
                _ => {}
            }
        }

        answers
    }

    /// Parse a single answer object from JSON
    fn parse_answer_object(&self, obj_str: &str) -> Option<DohAnswer> {
        let name = self.extract_json_string(obj_str, "name")?;
        let record_type = self.extract_json_number(obj_str, "type")? as u16;
        let ttl = self.extract_json_number(obj_str, "TTL").unwrap_or(0) as u32;
        let data = self.extract_json_string(obj_str, "data")?;

        Some(DohAnswer {
            name,
            record_type,
            ttl,
            data,
        })
    }

    /// Extract string value from JSON
    fn extract_json_string(&self, json: &str, key: &str) -> Option<String> {
        let pattern = format!("\"{}\"", key);
        let key_pos = json.find(&pattern)?;
        let after_key = &json[key_pos + pattern.len()..];

        // Find the colon and opening quote
        let colon_pos = after_key.find(':')?;
        let after_colon = after_key[colon_pos + 1..].trim_start();

        if !after_colon.starts_with('"') {
            return None;
        }

        let value_start = 1; // Skip opening quote
        let value_end = after_colon[value_start..].find('"')?;
        let value = &after_colon[value_start..value_start + value_end];

        Some(unescape_json_string(value))
    }

    /// Extract number value from JSON
    fn extract_json_number(&self, json: &str, key: &str) -> Option<i64> {
        let pattern = format!("\"{}\"", key);
        let key_pos = json.find(&pattern)?;
        let after_key = &json[key_pos + pattern.len()..];

        // Find the colon
        let colon_pos = after_key.find(':')?;
        let after_colon = after_key[colon_pos + 1..].trim_start();

        // Parse number
        let mut end = 0;
        for (i, c) in after_colon.char_indices() {
            if c.is_ascii_digit() || c == '-' {
                end = i + 1;
            } else if end > 0 {
                break;
            }
        }

        if end > 0 {
            after_colon[..end].parse().ok()
        } else {
            None
        }
    }
}

impl Default for DohClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Find matching closing bracket
fn find_matching_bracket(s: &str, open_pos: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let open_char = bytes[open_pos];
    let close_char = match open_char {
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };

    let mut depth = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, &c) in bytes[open_pos..].iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match c {
            b'\\' if in_string => escape_next = true,
            b'"' => in_string = !in_string,
            _ if in_string => {}
            c if c == open_char => depth += 1,
            c if c == close_char => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_pos + i);
                }
            }
            _ => {}
        }
    }

    None
}

/// URL encode a string (minimal implementation)
fn urlencod(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
    }
    result
}

/// Unescape JSON string
fn unescape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('/') => result.push('/'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Check DNS propagation across multiple providers
pub struct PropagationResult {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub results: Vec<ProviderResult>,
    pub is_propagated: bool,
    pub consensus_values: Vec<String>,
}

#[derive(Clone)]
pub struct ProviderResult {
    pub provider: String,
    pub status: PropagationStatus,
    pub values: Vec<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PropagationStatus {
    Success,
    NoRecords,
    Error,
}

impl DohClient {
    /// Check DNS propagation across all providers
    pub fn check_propagation(&self, domain: &str, record_type: DnsRecordType) -> PropagationResult {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for provider in DOH_PROVIDERS {
            let domain = domain.to_string();
            let provider = provider.clone();
            let results = Arc::clone(&results);
            let timeout = self.timeout;

            let handle = thread::spawn(move || {
                let client = DohClient::new().with_timeout(timeout);
                let result = client.query(&provider, &domain, record_type);

                let provider_result = match result {
                    Ok(response) => {
                        if response.answers.is_empty() {
                            ProviderResult {
                                provider: provider.name.to_string(),
                                status: PropagationStatus::NoRecords,
                                values: Vec::new(),
                                ttl: None,
                            }
                        } else {
                            let values: Vec<String> =
                                response.answers.iter().map(|a| a.data.clone()).collect();
                            let ttl = response.answers.first().map(|a| a.ttl);
                            ProviderResult {
                                provider: provider.name.to_string(),
                                status: PropagationStatus::Success,
                                values,
                                ttl,
                            }
                        }
                    }
                    Err(_) => ProviderResult {
                        provider: provider.name.to_string(),
                        status: PropagationStatus::Error,
                        values: Vec::new(),
                        ttl: None,
                    },
                };

                results.lock().unwrap().push(provider_result);
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        let provider_results = results.lock().unwrap().drain(..).collect::<Vec<_>>();

        // Calculate consensus
        let mut value_counts: HashMap<String, usize> = HashMap::new();
        let successful_count = provider_results
            .iter()
            .filter(|r| r.status == PropagationStatus::Success)
            .count();

        for result in &provider_results {
            for value in &result.values {
                *value_counts.entry(value.clone()).or_insert(0) += 1;
            }
        }

        // Find values that appear in majority of successful responses
        let threshold = (successful_count + 1) / 2; // Majority
        let consensus_values: Vec<String> = value_counts
            .into_iter()
            .filter(|(_, count)| *count >= threshold.max(1))
            .map(|(value, _)| value)
            .collect();

        // Propagation is complete if all successful providers agree
        let is_propagated = successful_count >= DOH_PROVIDERS.len() - 1 // Allow 1 failure
            && provider_results
                .iter()
                .filter(|r| r.status == PropagationStatus::Success)
                .all(|r| {
                    r.values.iter().all(|v| consensus_values.contains(v))
                        || consensus_values.iter().all(|v| r.values.contains(v))
                });

        PropagationResult {
            domain: domain.to_string(),
            record_type,
            results: provider_results,
            is_propagated,
            consensus_values,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencod() {
        assert_eq!(urlencod("example.com"), "example.com");
        assert_eq!(urlencod("test domain"), "test%20domain");
    }

    #[test]
    fn test_unescape_json_string() {
        assert_eq!(unescape_json_string("hello"), "hello");
        assert_eq!(unescape_json_string("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_json_string("test\\\"quote"), "test\"quote");
    }

    #[test]
    fn test_find_matching_bracket() {
        assert_eq!(find_matching_bracket("[1,2,3]", 0), Some(6));
        assert_eq!(find_matching_bracket("{\"key\":\"value\"}", 0), Some(14));
        assert_eq!(find_matching_bracket("[[1],[2]]", 0), Some(8));
    }
}
