/// DNSDumpster DNS Intelligence Module
///
/// Web scraping client for dnsdumpster.com to gather DNS intelligence:
/// - DNS records (A, MX, NS, TXT)
/// - Subdomains with IP addresses
/// - Related domains
/// - Network topology hints
///
/// NO external dependencies - pure Rust std implementation
use crate::protocols::http::HttpClient;
use std::collections::HashSet;

/// DNS record discovered from DNSDumpster
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub host: String,
    pub record_type: String,
    pub value: String,
    pub ip: Option<String>,
    pub reverse_dns: Option<String>,
    pub asn: Option<String>,
    pub country: Option<String>,
}

/// DNSDumpster scan result
#[derive(Debug, Clone)]
pub struct DnsDumpsterResult {
    pub domain: String,
    pub dns_records: Vec<DnsRecord>,
    pub subdomains: Vec<DnsRecord>,
    pub mx_records: Vec<DnsRecord>,
    pub txt_records: Vec<String>,
    pub host_records: Vec<DnsRecord>,
    pub errors: Vec<String>,
}

impl DnsDumpsterResult {
    fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            dns_records: Vec::new(),
            subdomains: Vec::new(),
            mx_records: Vec::new(),
            txt_records: Vec::new(),
            host_records: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Get all unique subdomains
    pub fn unique_subdomains(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        for record in &self.subdomains {
            if seen.insert(record.host.clone()) {
                result.push(record.host.clone());
            }
        }

        for record in &self.host_records {
            if seen.insert(record.host.clone()) {
                result.push(record.host.clone());
            }
        }

        result.sort();
        result
    }

    /// Get total record count
    pub fn total_records(&self) -> usize {
        self.dns_records.len()
            + self.subdomains.len()
            + self.mx_records.len()
            + self.txt_records.len()
            + self.host_records.len()
    }
}

/// DNSDumpster web scraping client
pub struct DnsDumpsterClient {
    client: HttpClient,
    user_agent: String,
}

impl DnsDumpsterClient {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
        }
    }

    /// Query DNSDumpster for domain intelligence
    pub fn query(&self, domain: &str) -> Result<DnsDumpsterResult, String> {
        let mut result = DnsDumpsterResult::new(domain);

        // Step 1: Get CSRF token from the main page
        let csrf_token = self.get_csrf_token()?;

        // Step 2: Submit the domain query with CSRF token
        let html = self.submit_query(domain, &csrf_token)?;

        // Step 3: Parse the HTML response
        self.parse_response(&html, &mut result);

        Ok(result)
    }

    /// Get CSRF token from DNSDumpster main page
    fn get_csrf_token(&self) -> Result<String, String> {
        let response = self
            .client
            .get_with_headers(
                "https://dnsdumpster.com/",
                &[("User-Agent", &self.user_agent)],
            )
            .map_err(|e| format!("Failed to fetch DNSDumpster: {}", e))?;

        if response.status_code != 200 {
            return Err(format!(
                "DNSDumpster returned status {}",
                response.status_code
            ));
        }

        let body = String::from_utf8_lossy(&response.body);

        // Extract CSRF token from: <input type="hidden" name="csrfmiddlewaretoken" value="TOKEN">
        self.extract_csrf_token(&body)
            .ok_or_else(|| "Could not find CSRF token in DNSDumpster response".to_string())
    }

    /// Extract CSRF token from HTML
    fn extract_csrf_token(&self, html: &str) -> Option<String> {
        // Look for csrfmiddlewaretoken input
        let csrf_pattern = "name=\"csrfmiddlewaretoken\" value=\"";

        if let Some(start) = html.find(csrf_pattern) {
            let after = &html[start + csrf_pattern.len()..];
            if let Some(end) = after.find('"') {
                return Some(after[..end].to_string());
            }
        }

        // Alternative: look in cookies (csrftoken=...)
        None
    }

    /// Submit domain query with CSRF token
    fn submit_query(&self, domain: &str, csrf_token: &str) -> Result<String, String> {
        let body = format!(
            "csrfmiddlewaretoken={}&targetip={}&user=free",
            csrf_token,
            urlencoded(domain)
        );

        let response = self
            .client
            .post_with_headers(
                "https://dnsdumpster.com/",
                body.into_bytes(),
                &[
                    ("User-Agent", &self.user_agent),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Referer", "https://dnsdumpster.com/"),
                    ("Origin", "https://dnsdumpster.com"),
                ],
            )
            .map_err(|e| format!("Failed to query DNSDumpster: {}", e))?;

        // DNSDumpster may return 200 or 302 (redirect)
        if response.status_code != 200 && response.status_code != 302 {
            return Err(format!(
                "DNSDumpster query returned status {}",
                response.status_code
            ));
        }

        Ok(String::from_utf8_lossy(&response.body).to_string())
    }

    /// Parse DNSDumpster HTML response
    fn parse_response(&self, html: &str, result: &mut DnsDumpsterResult) {
        // Parse DNS servers table
        self.parse_dns_table(html, "DNS Servers", &mut result.dns_records);

        // Parse MX records table
        self.parse_dns_table(html, "MX Records", &mut result.mx_records);

        // Parse TXT records
        self.parse_txt_records(html, &mut result.txt_records);

        // Parse Host Records (A)
        self.parse_host_table(html, &mut result.host_records);

        // Also extract subdomains from all tables
        self.extract_subdomains_from_tables(html, &result.domain, &mut result.subdomains);
    }

    /// Parse a DNS table section
    fn parse_dns_table(&self, html: &str, table_header: &str, records: &mut Vec<DnsRecord>) {
        // Find table section by header
        let header_pattern = format!("<th>{}", table_header);
        if let Some(start) = html.find(&header_pattern) {
            // Find the table body
            if let Some(tbody_start) = html[start..].find("<tbody>") {
                let table_start = start + tbody_start;
                if let Some(tbody_end) = html[table_start..].find("</tbody>") {
                    let table_html = &html[table_start..table_start + tbody_end];
                    self.parse_table_rows(table_html, records);
                }
            }
        }
    }

    /// Parse table rows into DNS records
    fn parse_table_rows(&self, table_html: &str, records: &mut Vec<DnsRecord>) {
        let mut pos = 0;

        while let Some(row_start) = table_html[pos..].find("<tr") {
            let row_pos = pos + row_start;

            if let Some(row_end) = table_html[row_pos..].find("</tr>") {
                let row_html = &table_html[row_pos..row_pos + row_end];

                if let Some(record) = self.parse_row(row_html) {
                    records.push(record);
                }

                pos = row_pos + row_end + 5;
            } else {
                break;
            }
        }
    }

    /// Parse a single table row
    fn parse_row(&self, row_html: &str) -> Option<DnsRecord> {
        let cells = self.extract_cells(row_html);

        if cells.is_empty() {
            return None;
        }

        // Extract data from cells
        let host = cells.first().cloned().unwrap_or_default();

        if host.is_empty() {
            return None;
        }

        let value = cells.get(1).cloned().unwrap_or_default();
        let ip = self.extract_ip_from_text(&host).or_else(|| self.extract_ip_from_text(&value));
        let reverse_dns = cells.get(2).cloned();
        let asn_info = cells.get(3).cloned();

        // Parse ASN and country from combined field
        let (asn, country) = asn_info
            .as_ref()
            .map(|s| self.parse_asn_country(s))
            .unwrap_or((None, None));

        Some(DnsRecord {
            host: self.clean_html(&host),
            record_type: self.detect_record_type(&host, &value),
            value: self.clean_html(&value),
            ip,
            reverse_dns: reverse_dns.map(|s| self.clean_html(&s)),
            asn,
            country,
        })
    }

    /// Extract table cells from a row
    fn extract_cells(&self, row_html: &str) -> Vec<String> {
        let mut cells = Vec::new();
        let mut pos = 0;

        while let Some(td_start) = row_html[pos..].find("<td") {
            let td_pos = pos + td_start;

            // Find the actual content start (after >)
            if let Some(content_start) = row_html[td_pos..].find('>') {
                let content_pos = td_pos + content_start + 1;

                // Find closing </td>
                if let Some(td_end) = row_html[content_pos..].find("</td>") {
                    let cell_content = &row_html[content_pos..content_pos + td_end];
                    cells.push(cell_content.to_string());
                    pos = content_pos + td_end + 5;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        cells
    }

    /// Parse TXT records section
    fn parse_txt_records(&self, html: &str, records: &mut Vec<String>) {
        // Find TXT records section
        let txt_pattern = "<th>TXT Records</th>";
        if let Some(start) = html.find(txt_pattern) {
            // Look for pre or code blocks with TXT content
            if let Some(tbody_start) = html[start..].find("<tbody>") {
                let table_start = start + tbody_start;
                if let Some(tbody_end) = html[table_start..].find("</tbody>") {
                    let table_html = &html[table_start..table_start + tbody_end];

                    // Extract text content from each row
                    let mut pos = 0;
                    while let Some(td_start) = table_html[pos..].find("<td") {
                        let td_pos = pos + td_start;
                        if let Some(content_start) = table_html[td_pos..].find('>') {
                            let content_pos = td_pos + content_start + 1;
                            if let Some(td_end) = table_html[content_pos..].find("</td>") {
                                let content = &table_html[content_pos..content_pos + td_end];
                                let cleaned = self.clean_html(content).trim().to_string();
                                if !cleaned.is_empty() {
                                    records.push(cleaned);
                                }
                                pos = content_pos + td_end + 5;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Parse Host Records table (A records)
    fn parse_host_table(&self, html: &str, records: &mut Vec<DnsRecord>) {
        // Host records are typically in a table with "Host" header
        self.parse_dns_table(html, "Host Records", records);

        // Also try parsing the main results table
        let patterns = ["class=\"table table-condensed\"", "id=\"results\""];

        for pattern in patterns {
            if let Some(start) = html.find(pattern) {
                if let Some(tbody_start) = html[start..].find("<tbody>") {
                    let table_start = start + tbody_start;
                    if let Some(tbody_end) = html[table_start..].find("</tbody>") {
                        let table_html = &html[table_start..table_start + tbody_end];
                        self.parse_table_rows(table_html, records);
                    }
                }
            }
        }
    }

    /// Extract subdomains from all table content
    fn extract_subdomains_from_tables(
        &self,
        html: &str,
        base_domain: &str,
        subdomains: &mut Vec<DnsRecord>,
    ) {
        // Find all hostnames that match the base domain pattern
        let domain_pattern = format!(".{}", base_domain);
        let mut seen = HashSet::new();

        // Simple regex-like extraction for subdomains
        let mut pos = 0;
        while pos < html.len() {
            // Look for potential subdomain patterns
            if let Some(idx) = html[pos..].find(&domain_pattern) {
                let match_pos = pos + idx;

                // Walk backwards to find the start of the hostname
                let mut start = match_pos;
                while start > 0 {
                    let ch = html.chars().nth(start - 1).unwrap_or(' ');
                    if ch.is_alphanumeric() || ch == '-' || ch == '.' || ch == '_' {
                        start -= 1;
                    } else {
                        break;
                    }
                }

                // Walk forward to find the end
                let mut end = match_pos + domain_pattern.len();
                while end < html.len() {
                    let ch = html.chars().nth(end).unwrap_or(' ');
                    if ch.is_alphanumeric() || ch == '-' || ch == '.' {
                        end += 1;
                    } else {
                        break;
                    }
                }

                let hostname = &html[start..end];
                let cleaned = self.clean_html(hostname).trim().to_string();

                // Validate it looks like a subdomain
                if cleaned.ends_with(base_domain)
                    && cleaned.len() > base_domain.len()
                    && self.is_valid_hostname(&cleaned)
                    && seen.insert(cleaned.clone())
                {
                    // Try to extract IP from nearby context
                    let context_start = if match_pos > 100 { match_pos - 100 } else { 0 };
                    let context_end = (end + 100).min(html.len());
                    let context = &html[context_start..context_end];
                    let ip = self.extract_ip_from_text(context);

                    subdomains.push(DnsRecord {
                        host: cleaned,
                        record_type: "A".to_string(),
                        value: ip.clone().unwrap_or_default(),
                        ip,
                        reverse_dns: None,
                        asn: None,
                        country: None,
                    });
                }

                pos = end;
            } else {
                break;
            }
        }
    }

    /// Extract IP address from text
    fn extract_ip_from_text(&self, text: &str) -> Option<String> {
        // Simple IPv4 pattern matching
        let mut current = String::new();
        let mut octets = 0;
        let mut dots = 0;

        for ch in text.chars() {
            if ch.is_ascii_digit() {
                current.push(ch);
            } else if ch == '.' && !current.is_empty() && octets < 3 {
                // Validate octet
                if let Ok(num) = current.parse::<u32>() {
                    if num <= 255 {
                        if octets == 0 {
                            current.push('.');
                        }
                        dots += 1;
                        octets += 1;
                    } else {
                        current.clear();
                        octets = 0;
                        dots = 0;
                    }
                } else {
                    current.clear();
                    octets = 0;
                    dots = 0;
                }
            } else if !current.is_empty() {
                if dots == 3 {
                    // We might have a complete IP
                    // Validate the last octet
                    let parts: Vec<&str> = current.split('.').collect();
                    if parts.len() == 4 {
                        let valid = parts.iter().all(|p| {
                            p.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
                        });
                        if valid {
                            return Some(current);
                        }
                    }
                }
                current.clear();
                octets = 0;
                dots = 0;
            }
        }

        // Check if we ended with a valid IP
        if dots == 3 {
            let parts: Vec<&str> = current.split('.').collect();
            if parts.len() == 4 {
                let valid = parts.iter().all(|p| {
                    p.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
                });
                if valid {
                    return Some(current);
                }
            }
        }

        None
    }

    /// Parse ASN and country from combined text
    fn parse_asn_country(&self, text: &str) -> (Option<String>, Option<String>) {
        let mut asn = None;
        let mut country = None;

        // Look for AS number (AS12345)
        if let Some(as_pos) = text.find("AS") {
            let after_as = &text[as_pos + 2..];
            let mut num = String::new();
            for ch in after_as.chars() {
                if ch.is_ascii_digit() {
                    num.push(ch);
                } else {
                    break;
                }
            }
            if !num.is_empty() {
                asn = Some(format!("AS{}", num));
            }
        }

        // Look for country codes (two uppercase letters at the end or in parentheses)
        let cleaned = self.clean_html(text);
        let words: Vec<&str> = cleaned.split_whitespace().collect();

        for word in words.iter().rev() {
            let trimmed = word.trim_matches(|c: char| !c.is_alphabetic());
            if trimmed.len() == 2 && trimmed.chars().all(|c| c.is_ascii_uppercase()) {
                country = Some(trimmed.to_string());
                break;
            }
        }

        (asn, country)
    }

    /// Detect record type from content
    fn detect_record_type(&self, host: &str, value: &str) -> String {
        if host.contains("mail") || value.contains("mail") || value.contains("smtp") {
            "MX".to_string()
        } else if host.contains("ns") || value.contains("dns") {
            "NS".to_string()
        } else if self.extract_ip_from_text(value).is_some() {
            "A".to_string()
        } else {
            "CNAME".to_string()
        }
    }

    /// Clean HTML tags and entities from text
    fn clean_html(&self, html: &str) -> String {
        let mut result = String::new();
        let mut in_tag = false;
        let mut entity = String::new();
        let mut in_entity = false;

        for ch in html.chars() {
            if ch == '<' {
                in_tag = true;
            } else if ch == '>' {
                in_tag = false;
            } else if ch == '&' {
                in_entity = true;
                entity.clear();
            } else if in_entity {
                if ch == ';' {
                    // Decode entity
                    let decoded = match entity.as_str() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        "nbsp" => " ",
                        _ => "",
                    };
                    result.push_str(decoded);
                    in_entity = false;
                } else {
                    entity.push(ch);
                }
            } else if !in_tag {
                result.push(ch);
            }
        }

        result.trim().to_string()
    }

    /// Validate hostname format
    fn is_valid_hostname(&self, hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }

        // Must not start or end with dot or hyphen
        if hostname.starts_with('.')
            || hostname.ends_with('.')
            || hostname.starts_with('-')
            || hostname.ends_with('-')
        {
            return false;
        }

        // All characters must be valid
        hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    }
}

impl Default for DnsDumpsterClient {
    fn default() -> Self {
        Self::new()
    }
}

/// URL encode a string
fn urlencoded(s: &str) -> String {
    let mut result = String::new();

    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == '~' {
            result.push(ch);
        } else {
            // Percent-encode
            for byte in ch.to_string().as_bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencoded() {
        assert_eq!(urlencoded("example.com"), "example.com");
        assert_eq!(urlencoded("test domain"), "test%20domain");
        assert_eq!(urlencoded("a@b.com"), "a%40b.com");
    }

    #[test]
    fn test_clean_html() {
        let client = DnsDumpsterClient::new();
        assert_eq!(client.clean_html("<b>test</b>"), "test");
        assert_eq!(client.clean_html("a &amp; b"), "a & b");
        assert_eq!(client.clean_html("<a href=\"#\">link</a>"), "link");
    }

    #[test]
    fn test_extract_ip() {
        let client = DnsDumpsterClient::new();
        assert_eq!(
            client.extract_ip_from_text("IP: 192.168.1.1 here"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            client.extract_ip_from_text("8.8.8.8"),
            Some("8.8.8.8".to_string())
        );
        assert_eq!(client.extract_ip_from_text("no ip here"), None);
        assert_eq!(client.extract_ip_from_text("999.999.999.999"), None);
    }

    #[test]
    fn test_is_valid_hostname() {
        let client = DnsDumpsterClient::new();
        assert!(client.is_valid_hostname("www.example.com"));
        assert!(client.is_valid_hostname("sub-domain.example.com"));
        assert!(!client.is_valid_hostname(".example.com"));
        assert!(!client.is_valid_hostname("example.com."));
        assert!(!client.is_valid_hostname("-example.com"));
    }

    #[test]
    fn test_parse_asn_country() {
        let client = DnsDumpsterClient::new();

        let (asn, country) = client.parse_asn_country("AS15169 Google US");
        assert_eq!(asn, Some("AS15169".to_string()));
        assert_eq!(country, Some("US".to_string()));

        let (asn2, _) = client.parse_asn_country("Cloudflare AS13335");
        assert_eq!(asn2, Some("AS13335".to_string()));
    }
}
