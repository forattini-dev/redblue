/// RDAP (Registration Data Access Protocol) Implementation
/// Modern replacement for WHOIS - RFC 7480-7484
use crate::protocols::http::{HttpClient, HttpRequest};
use std::time::Duration;

/// IANA Bootstrap registry URLs
const BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
const BOOTSTRAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";

/// Fallback RDAP servers for common TLDs
const FALLBACK_SERVERS: &[(&str, &str)] = &[
    ("com", "https://rdap.verisign.com/com/v1"),
    ("net", "https://rdap.verisign.com/net/v1"),
    ("org", "https://rdap.publicinterestregistry.org/rdap"),
    ("io", "https://rdap.nic.io"),
    ("dev", "https://rdap.nic.google"),
    ("app", "https://rdap.nic.google"),
    ("xyz", "https://rdap.centralnic.com/xyz"),
    ("info", "https://rdap.afilias.net/rdap/info"),
    ("biz", "https://rdap.nic.biz"),
    ("me", "https://rdap.nic.me"),
    ("co", "https://rdap.nic.co"),
    ("uk", "https://rdap.nominet.uk/uk"),
    ("de", "https://rdap.denic.de"),
    ("br", "https://rdap.registro.br"),
    ("au", "https://rdap.auda.org.au"),
];

/// RDAP Response for domain lookups
#[derive(Debug, Clone)]
pub struct RdapDomainResponse {
    pub domain: String,
    pub status: Vec<String>,
    pub registrar: Option<String>,
    pub registrant: Option<RdapEntity>,
    pub nameservers: Vec<String>,
    pub events: Vec<RdapEvent>,
    pub links: Vec<String>,
    pub raw_json: String,
}

/// RDAP Entity (registrant, admin, tech contacts)
#[derive(Debug, Clone)]
pub struct RdapEntity {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub organization: Option<String>,
    pub address: Option<String>,
    pub roles: Vec<String>,
}

/// RDAP Event (registration, expiration, etc.)
#[derive(Debug, Clone)]
pub struct RdapEvent {
    pub action: String,
    pub date: String,
}

/// RDAP Response for IP lookups
#[derive(Debug, Clone)]
pub struct RdapIpResponse {
    pub handle: String,
    pub start_address: String,
    pub end_address: String,
    pub ip_version: String,
    pub name: Option<String>,
    pub country: Option<String>,
    pub status: Vec<String>,
    pub entities: Vec<RdapEntity>,
    pub events: Vec<RdapEvent>,
    pub raw_json: String,
}

/// RDAP Client
pub struct RdapClient {
    http_client: HttpClient,
    timeout: Duration,
    bootstrap_cache: Option<BootstrapCache>,
}

/// Cached bootstrap data
struct BootstrapCache {
    dns_services: Vec<(Vec<String>, String)>,
    ipv4_services: Vec<(String, String)>,
    ipv6_services: Vec<(String, String)>,
}

impl RdapClient {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new().with_timeout(Duration::from_secs(15)),
            timeout: Duration::from_secs(15),
            bootstrap_cache: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.http_client = HttpClient::new().with_timeout(timeout);
        self
    }

    /// Query RDAP for a domain
    pub fn query_domain(&mut self, domain: &str) -> Result<RdapDomainResponse, String> {
        // Get the TLD
        let tld = domain
            .rsplit('.')
            .next()
            .ok_or("Invalid domain format")?
            .to_lowercase();

        // Find RDAP server for this TLD
        let server = self.find_server_for_tld(&tld)?;

        // Query the RDAP server
        let url = format!("{}/domain/{}", server.trim_end_matches('/'), domain);
        let request =
            HttpRequest::get(&url).with_header("Accept", "application/rdap+json, application/json");

        let response = self
            .http_client
            .send(&request)
            .map_err(|e| format!("RDAP query failed: {}", e))?;

        if !response.is_success() {
            return Err(format!(
                "RDAP server returned HTTP {} for {}",
                response.status_code, domain
            ));
        }

        let body = response.body_as_string();
        self.parse_domain_response(&body, domain)
    }

    /// Query RDAP for an IP address
    pub fn query_ip(&mut self, ip: &str) -> Result<RdapIpResponse, String> {
        // Determine IP version
        let is_v6 = ip.contains(':');

        // Find RDAP server for this IP
        let server = self.find_server_for_ip(ip, is_v6)?;

        // Query the RDAP server
        let url = format!("{}/ip/{}", server.trim_end_matches('/'), ip);
        let request =
            HttpRequest::get(&url).with_header("Accept", "application/rdap+json, application/json");

        let response = self
            .http_client
            .send(&request)
            .map_err(|e| format!("RDAP query failed: {}", e))?;

        if !response.is_success() {
            return Err(format!(
                "RDAP server returned HTTP {} for {}",
                response.status_code, ip
            ));
        }

        let body = response.body_as_string();
        self.parse_ip_response(&body, ip)
    }

    /// Find RDAP server for a TLD
    fn find_server_for_tld(&mut self, tld: &str) -> Result<String, String> {
        // Try fallback servers first (faster)
        for (t, server) in FALLBACK_SERVERS {
            if *t == tld {
                return Ok(server.to_string());
            }
        }

        // Try to load bootstrap if not cached
        if self.bootstrap_cache.is_none() {
            self.load_bootstrap();
        }

        // Search bootstrap cache
        if let Some(ref cache) = self.bootstrap_cache {
            for (tlds, server) in &cache.dns_services {
                if tlds.iter().any(|t| t == tld) {
                    return Ok(server.clone());
                }
            }
        }

        // Final fallback - try common registries
        Err(format!(
            "No RDAP server found for TLD: {}. Try: rb recon domain whois <domain> for WHOIS fallback.",
            tld
        ))
    }

    /// Find RDAP server for an IP address
    fn find_server_for_ip(&mut self, _ip: &str, is_v6: bool) -> Result<String, String> {
        // Regional Internet Registries (RIRs)
        let rir_servers = if is_v6 {
            vec![
                ("https://rdap.arin.net/registry", "ARIN (North America)"),
                ("https://rdap.apnic.net", "APNIC (Asia-Pacific)"),
                ("https://rdap.db.ripe.net", "RIPE (Europe)"),
                ("https://rdap.lacnic.net/rdap", "LACNIC (Latin America)"),
                ("https://rdap.afrinic.net/rdap", "AFRINIC (Africa)"),
            ]
        } else {
            vec![
                ("https://rdap.arin.net/registry", "ARIN (North America)"),
                ("https://rdap.apnic.net", "APNIC (Asia-Pacific)"),
                ("https://rdap.db.ripe.net", "RIPE (Europe)"),
                ("https://rdap.lacnic.net/rdap", "LACNIC (Latin America)"),
                ("https://rdap.afrinic.net/rdap", "AFRINIC (Africa)"),
            ]
        };

        // Try bootstrap first
        if self.bootstrap_cache.is_none() {
            self.load_bootstrap();
        }

        // For simplicity, try ARIN first (most common for US)
        // In production, would parse IP range and match to correct RIR
        Ok(rir_servers[0].0.to_string())
    }

    /// Load IANA bootstrap registry
    fn load_bootstrap(&mut self) {
        let mut cache = BootstrapCache {
            dns_services: Vec::new(),
            ipv4_services: Vec::new(),
            ipv6_services: Vec::new(),
        };

        // Try to load DNS bootstrap
        if let Ok(dns_bootstrap) = self.fetch_bootstrap(BOOTSTRAP_DNS) {
            cache.dns_services = self.parse_dns_bootstrap(&dns_bootstrap);
        }

        self.bootstrap_cache = Some(cache);
    }

    /// Fetch bootstrap JSON from IANA
    fn fetch_bootstrap(&self, url: &str) -> Result<String, String> {
        let request = HttpRequest::get(url).with_header("Accept", "application/json");

        let response = self
            .http_client
            .send(&request)
            .map_err(|e| format!("Failed to fetch bootstrap: {}", e))?;

        if response.is_success() {
            Ok(response.body_as_string())
        } else {
            Err(format!("Bootstrap returned HTTP {}", response.status_code))
        }
    }

    /// Parse DNS bootstrap JSON
    fn parse_dns_bootstrap(&self, json: &str) -> Vec<(Vec<String>, String)> {
        let mut services = Vec::new();

        // Find services array
        if let Some(svc_start) = json.find("\"services\"") {
            if let Some(arr_start) = json[svc_start..].find('[') {
                let arr_start = svc_start + arr_start;
                if let Some(arr_end) = find_matching_bracket(json, arr_start) {
                    let services_str = &json[arr_start + 1..arr_end];

                    // Parse each service entry [[tlds...], [urls...]]
                    let mut depth = 0;
                    let mut entry_start = None;

                    for (i, c) in services_str.char_indices() {
                        match c {
                            '[' => {
                                if depth == 0 {
                                    entry_start = Some(i);
                                }
                                depth += 1;
                            }
                            ']' => {
                                depth -= 1;
                                if depth == 0 {
                                    if let Some(start) = entry_start {
                                        let entry = &services_str[start..=i];
                                        if let Some((tlds, url)) = self.parse_service_entry(entry) {
                                            services.push((tlds, url));
                                        }
                                    }
                                    entry_start = None;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        services
    }

    /// Parse a single service entry [[tlds], [urls]]
    fn parse_service_entry(&self, entry: &str) -> Option<(Vec<String>, String)> {
        // Find first array (TLDs)
        let first_arr_start = entry.find('[')?;
        let first_arr_end = find_matching_bracket(entry, first_arr_start)?;
        let tld_str = &entry[first_arr_start + 1..first_arr_end];

        // Find second array (URLs)
        let rest = &entry[first_arr_end + 1..];
        let second_arr_start = rest.find('[')?;
        let second_arr_end = find_matching_bracket(rest, second_arr_start)?;
        let url_str = &rest[second_arr_start + 1..second_arr_end];

        // Extract TLDs
        let tlds: Vec<String> = tld_str
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim().trim_matches('"');
                if !trimmed.is_empty() {
                    Some(trimmed.to_lowercase())
                } else {
                    None
                }
            })
            .collect();

        // Extract first URL
        let url = url_str.split(',').next().and_then(|s| {
            let trimmed = s.trim().trim_matches('"');
            if !trimmed.is_empty() {
                Some(trimmed.to_string())
            } else {
                None
            }
        })?;

        if tlds.is_empty() {
            None
        } else {
            Some((tlds, url))
        }
    }

    /// Parse domain RDAP response
    fn parse_domain_response(
        &self,
        json: &str,
        domain: &str,
    ) -> Result<RdapDomainResponse, String> {
        let mut response = RdapDomainResponse {
            domain: domain.to_string(),
            status: Vec::new(),
            registrar: None,
            registrant: None,
            nameservers: Vec::new(),
            events: Vec::new(),
            links: Vec::new(),
            raw_json: json.to_string(),
        };

        // Parse status array
        response.status = self.extract_string_array(json, "status");

        // Parse nameservers
        response.nameservers = self.extract_nameservers(json);

        // Parse events
        response.events = self.extract_events(json);

        // Parse entities (registrar, registrant, etc.)
        let entities = self.extract_entities(json);
        for entity in entities {
            if entity.roles.iter().any(|r| r == "registrar") {
                response.registrar = entity.name.clone().or(entity.organization.clone());
            }
            if entity.roles.iter().any(|r| r == "registrant") {
                response.registrant = Some(entity);
            }
        }

        // Parse links
        if let Some(link_start) = json.find("\"links\"") {
            if let Some(arr_start) = json[link_start..].find('[') {
                let arr_start = link_start + arr_start;
                if let Some(arr_end) = find_matching_bracket(json, arr_start) {
                    let links_str = &json[arr_start + 1..arr_end];
                    // Extract href values
                    let mut pos = 0;
                    while let Some(href_pos) = links_str[pos..].find("\"href\"") {
                        let abs_pos = pos + href_pos;
                        if let Some(href) = self.extract_string_value(&links_str[abs_pos..]) {
                            response.links.push(href);
                        }
                        pos = abs_pos + 6;
                    }
                }
            }
        }

        Ok(response)
    }

    /// Parse IP RDAP response
    fn parse_ip_response(&self, json: &str, ip: &str) -> Result<RdapIpResponse, String> {
        let handle = self
            .extract_string_value_for_key(json, "handle")
            .unwrap_or_else(|| "N/A".to_string());
        let start_address = self
            .extract_string_value_for_key(json, "startAddress")
            .unwrap_or_else(|| ip.to_string());
        let end_address = self
            .extract_string_value_for_key(json, "endAddress")
            .unwrap_or_else(|| ip.to_string());
        let ip_version = self
            .extract_string_value_for_key(json, "ipVersion")
            .unwrap_or_else(|| {
                if ip.contains(':') {
                    "v6".to_string()
                } else {
                    "v4".to_string()
                }
            });
        let name = self.extract_string_value_for_key(json, "name");
        let country = self.extract_string_value_for_key(json, "country");

        Ok(RdapIpResponse {
            handle,
            start_address,
            end_address,
            ip_version,
            name,
            country,
            status: self.extract_string_array(json, "status"),
            entities: self.extract_entities(json),
            events: self.extract_events(json),
            raw_json: json.to_string(),
        })
    }

    /// Extract nameservers from RDAP response
    fn extract_nameservers(&self, json: &str) -> Vec<String> {
        let mut nameservers = Vec::new();

        if let Some(ns_start) = json.find("\"nameservers\"") {
            if let Some(arr_start) = json[ns_start..].find('[') {
                let arr_start = ns_start + arr_start;
                if let Some(arr_end) = find_matching_bracket(json, arr_start) {
                    let ns_str = &json[arr_start + 1..arr_end];

                    // Find each ldhName value
                    let mut pos = 0;
                    while let Some(name_pos) = ns_str[pos..].find("\"ldhName\"") {
                        let abs_pos = pos + name_pos;
                        if let Some(name) = self.extract_string_value(&ns_str[abs_pos..]) {
                            nameservers.push(name.to_lowercase());
                        }
                        pos = abs_pos + 9;
                    }
                }
            }
        }

        nameservers
    }

    /// Extract events from RDAP response
    fn extract_events(&self, json: &str) -> Vec<RdapEvent> {
        let mut events = Vec::new();

        if let Some(ev_start) = json.find("\"events\"") {
            if let Some(arr_start) = json[ev_start..].find('[') {
                let arr_start = ev_start + arr_start;
                if let Some(arr_end) = find_matching_bracket(json, arr_start) {
                    let ev_str = &json[arr_start + 1..arr_end];

                    // Parse each event object
                    let mut depth = 0;
                    let mut obj_start = None;

                    for (i, c) in ev_str.char_indices() {
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
                                        let obj = &ev_str[start..=i];
                                        if let (Some(action), Some(date)) = (
                                            self.extract_string_value_for_key(obj, "eventAction"),
                                            self.extract_string_value_for_key(obj, "eventDate"),
                                        ) {
                                            events.push(RdapEvent { action, date });
                                        }
                                    }
                                    obj_start = None;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        events
    }

    /// Extract entities from RDAP response
    fn extract_entities(&self, json: &str) -> Vec<RdapEntity> {
        let mut entities = Vec::new();

        if let Some(ent_start) = json.find("\"entities\"") {
            if let Some(arr_start) = json[ent_start..].find('[') {
                let arr_start = ent_start + arr_start;
                if let Some(arr_end) = find_matching_bracket(json, arr_start) {
                    let ent_str = &json[arr_start + 1..arr_end];

                    // Parse each entity object
                    let mut depth = 0;
                    let mut obj_start = None;

                    for (i, c) in ent_str.char_indices() {
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
                                        let obj = &ent_str[start..=i];
                                        entities.push(self.parse_entity(obj));
                                    }
                                    obj_start = None;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        entities
    }

    /// Parse a single entity object
    fn parse_entity(&self, json: &str) -> RdapEntity {
        RdapEntity {
            handle: self.extract_string_value_for_key(json, "handle"),
            name: self.extract_string_value_for_key(json, "fn"),
            email: None, // Would parse from vcard
            phone: None, // Would parse from vcard
            organization: self.extract_string_value_for_key(json, "fn"),
            address: None, // Would parse from vcard
            roles: self.extract_string_array(json, "roles"),
        }
    }

    /// Extract string array from JSON
    fn extract_string_array(&self, json: &str, key: &str) -> Vec<String> {
        let pattern = format!("\"{}\"", key);
        let mut values = Vec::new();

        if let Some(key_pos) = json.find(&pattern) {
            let after_key = &json[key_pos + pattern.len()..];
            if let Some(arr_start) = after_key.find('[') {
                if let Some(arr_end) = find_matching_bracket(after_key, arr_start) {
                    let arr_str = &after_key[arr_start + 1..arr_end];
                    for item in arr_str.split(',') {
                        let trimmed = item.trim().trim_matches('"');
                        if !trimmed.is_empty() {
                            values.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        values
    }

    /// Extract string value after a key pattern
    fn extract_string_value(&self, json: &str) -> Option<String> {
        let colon_pos = json.find(':')?;
        let after_colon = json[colon_pos + 1..].trim_start();

        if !after_colon.starts_with('"') {
            return None;
        }

        let value_start = 1;
        let value_end = after_colon[value_start..].find('"')?;
        let value = &after_colon[value_start..value_start + value_end];

        Some(unescape_json_string(value))
    }

    /// Extract string value for a specific key
    fn extract_string_value_for_key(&self, json: &str, key: &str) -> Option<String> {
        let pattern = format!("\"{}\"", key);
        let key_pos = json.find(&pattern)?;
        self.extract_string_value(&json[key_pos + pattern.len()..])
    }
}

impl Default for RdapClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Find matching closing bracket
fn find_matching_bracket(s: &str, open_pos: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if open_pos >= bytes.len() {
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_matching_bracket() {
        assert_eq!(find_matching_bracket("[1,2,3]", 0), Some(6));
        assert_eq!(find_matching_bracket("{\"key\":\"value\"}", 0), Some(14));
        assert_eq!(find_matching_bracket("[[1],[2]]", 0), Some(8));
    }

    #[test]
    fn test_unescape_json_string() {
        assert_eq!(unescape_json_string("hello"), "hello");
        assert_eq!(unescape_json_string("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_json_string("test\\\"quote"), "test\"quote");
    }
}
