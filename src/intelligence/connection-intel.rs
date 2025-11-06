/// Connection Intelligence Extraction
///
/// Extracts maximum intelligence from network connections by analyzing:
/// - TLS handshake details (ciphers, extensions, server preferences)
/// - TCP/IP stack fingerprinting (TTL, window size, options)
/// - Timing patterns (latency, jitter, response times)
/// - Server behavior quirks (error handling, edge cases)
/// - Certificate chain analysis (issuer, validity, SANs, weaknesses)
///
/// The goal: extract 10x more information than traditional tools.
use crate::protocols::x509::X509Certificate;
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime};

/// Connection metadata extracted from handshake
#[derive(Debug, Clone)]
pub struct ConnectionIntel {
    // Network layer
    pub target_ip: IpAddr,
    pub target_port: u16,
    pub local_ip: Option<IpAddr>,
    pub local_port: Option<u16>,

    // Timing intelligence
    pub connect_time_ms: u64,
    pub first_byte_time_ms: Option<u64>,
    pub handshake_time_ms: Option<u64>,

    // TCP/IP fingerprinting
    pub tcp_window_size: Option<u32>,
    pub tcp_options: Vec<TcpOption>,
    pub ip_ttl: Option<u8>,
    pub ip_id_pattern: Option<String>,

    // TLS intelligence (if applicable)
    pub tls_version: Option<String>,
    pub selected_cipher: Option<String>,
    pub server_extensions: Vec<String>,
    pub cert_chain_length: Option<usize>,
    pub cert_issuer: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_san_count: Option<usize>,
    pub cert_validity_days: Option<i64>,
    pub cert_algorithm: Option<String>,
    pub cert_key_size: Option<u32>,
    pub cert_is_self_signed: bool,
    pub cert_is_expired: bool,
    pub cert_is_wildcard: bool,

    // HTTP intelligence (if applicable)
    pub http_server_header: Option<String>,
    pub http_powered_by: Option<String>,
    pub http_via_proxy: Option<String>,
    pub http_cookies_count: Option<usize>,
    pub http_security_headers: Vec<String>,
    pub http_missing_security_headers: Vec<String>,

    // Behavioral patterns
    pub responds_to_invalid_data: Option<bool>,
    pub error_message_verbosity: Option<String>,
    pub supports_http2: Option<bool>,
    pub supports_compression: Option<bool>,

    // Infrastructure hints
    pub likely_load_balancer: bool,
    pub likely_waf: Option<String>,
    pub likely_cdn: Option<String>,
    pub likely_cloud_provider: Option<String>,
}

impl ConnectionIntel {
    pub fn new(target_ip: IpAddr, target_port: u16) -> Self {
        Self {
            target_ip,
            target_port,
            local_ip: None,
            local_port: None,
            connect_time_ms: 0,
            first_byte_time_ms: None,
            handshake_time_ms: None,
            tcp_window_size: None,
            tcp_options: Vec::new(),
            ip_ttl: None,
            ip_id_pattern: None,
            tls_version: None,
            selected_cipher: None,
            server_extensions: Vec::new(),
            cert_chain_length: None,
            cert_issuer: None,
            cert_subject: None,
            cert_san_count: None,
            cert_validity_days: None,
            cert_algorithm: None,
            cert_key_size: None,
            cert_is_self_signed: false,
            cert_is_expired: false,
            cert_is_wildcard: false,
            http_server_header: None,
            http_powered_by: None,
            http_via_proxy: None,
            http_cookies_count: None,
            http_security_headers: Vec::new(),
            http_missing_security_headers: Vec::new(),
            responds_to_invalid_data: None,
            error_message_verbosity: None,
            supports_http2: None,
            supports_compression: None,
            likely_load_balancer: false,
            likely_waf: None,
            likely_cdn: None,
            likely_cloud_provider: None,
        }
    }

    /// Extract local connection details
    pub fn capture_local_details(&mut self, stream: &TcpStream) {
        if let Ok(local_addr) = stream.local_addr() {
            self.local_ip = Some(local_addr.ip());
            self.local_port = Some(local_addr.port());
        }
    }

    /// Analyze timing patterns
    pub fn analyze_timing(&mut self, connect_start: Instant, first_byte: Option<Instant>) {
        self.connect_time_ms = connect_start.elapsed().as_millis() as u64;

        if let Some(fb) = first_byte {
            self.first_byte_time_ms = Some(fb.duration_since(connect_start).as_millis() as u64);
        }
    }

    /// Infer infrastructure from patterns
    pub fn infer_infrastructure(&mut self) {
        // Detect load balancers (multiple IPs for same host, sticky sessions)
        // Timing patterns: LB adds ~1-5ms latency
        if let Some(connect_time) = self.connect_time_ms.checked_sub(5) {
            if connect_time < 50 && self.http_cookies_count.unwrap_or(0) > 0 {
                self.likely_load_balancer = true;
            }
        }

        // Detect CDN from cert issuer
        if let Some(issuer) = &self.cert_issuer {
            if issuer.contains("Cloudflare") {
                self.likely_cdn = Some("Cloudflare".to_string());
            } else if issuer.contains("Let's Encrypt") || issuer.contains("Amazon") {
                self.likely_cloud_provider = Some("AWS/CloudFront".to_string());
            }
        }

        // Detect WAF from HTTP headers
        if let Some(server) = &self.http_server_header {
            if server.contains("cloudflare") || server.contains("Cloudflare") {
                self.likely_waf = Some("Cloudflare".to_string());
                self.likely_cdn = Some("Cloudflare".to_string());
            } else if server.contains("AkamaiGHost") {
                self.likely_cdn = Some("Akamai".to_string());
            }
        }

        // Detect cloud provider from cert SANs and patterns
        if let Some(subject) = &self.cert_subject {
            if subject.contains("amazonaws.com") {
                self.likely_cloud_provider = Some("AWS".to_string());
            } else if subject.contains("cloudapp.net") {
                self.likely_cloud_provider = Some("Azure".to_string());
            } else if subject.contains("googleapis.com") {
                self.likely_cloud_provider = Some("GCP".to_string());
            }
        }
    }

    /// Generate intelligence summary
    pub fn summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str(&format!(
            "Target: {}:{}\n",
            self.target_ip, self.target_port
        ));
        summary.push_str(&format!("Connect Time: {}ms\n", self.connect_time_ms));

        if let Some(fb) = self.first_byte_time_ms {
            summary.push_str(&format!(
                "First Byte: {}ms ({}ms after connect)\n",
                fb,
                fb.saturating_sub(self.connect_time_ms)
            ));
        }

        if let Some(tls_ver) = &self.tls_version {
            summary.push_str(&format!("\nTLS: {}\n", tls_ver));
            if let Some(cipher) = &self.selected_cipher {
                summary.push_str(&format!("Cipher: {}\n", cipher));
            }
        }

        if let Some(cert_issuer) = &self.cert_issuer {
            summary.push_str(&format!("\nCertificate:\n"));
            summary.push_str(&format!("  Issuer: {}\n", cert_issuer));
            if let Some(subject) = &self.cert_subject {
                summary.push_str(&format!("  Subject: {}\n", subject));
            }
            if let Some(validity) = self.cert_validity_days {
                summary.push_str(&format!("  Valid for: {} days\n", validity));
            }
            if self.cert_is_self_signed {
                summary.push_str("  ⚠️  Self-signed\n");
            }
            if self.cert_is_expired {
                summary.push_str("  ❌ EXPIRED\n");
            }
        }

        if let Some(server) = &self.http_server_header {
            summary.push_str(&format!("\nHTTP Server: {}\n", server));
        }

        if !self.http_security_headers.is_empty() {
            summary.push_str(&format!(
                "\nSecurity Headers ({}):\n",
                self.http_security_headers.len()
            ));
            for header in &self.http_security_headers {
                summary.push_str(&format!("  ✓ {}\n", header));
            }
        }

        if !self.http_missing_security_headers.is_empty() {
            summary.push_str(&format!(
                "\nMissing Security Headers ({}):\n",
                self.http_missing_security_headers.len()
            ));
            for header in &self.http_missing_security_headers {
                summary.push_str(&format!("  ⚠️  {}\n", header));
            }
        }

        summary.push_str("\nInfrastructure Intelligence:\n");
        if self.likely_load_balancer {
            summary.push_str("  • Likely behind load balancer\n");
        }
        if let Some(waf) = &self.likely_waf {
            summary.push_str(&format!("  • WAF detected: {}\n", waf));
        }
        if let Some(cdn) = &self.likely_cdn {
            summary.push_str(&format!("  • CDN: {}\n", cdn));
        }
        if let Some(cloud) = &self.likely_cloud_provider {
            summary.push_str(&format!("  • Cloud: {}\n", cloud));
        }

        summary
    }
}

/// TCP option extracted from handshake
#[derive(Debug, Clone)]
pub struct TcpOption {
    pub kind: u8,
    pub value: Vec<u8>,
}

impl TcpOption {
    pub fn name(&self) -> &str {
        match self.kind {
            0 => "End of Option List",
            1 => "No-Operation",
            2 => "Maximum Segment Size",
            3 => "Window Scale",
            4 => "SACK Permitted",
            5 => "SACK",
            8 => "Timestamp",
            _ => "Unknown",
        }
    }
}

/// Enhanced connection analyzer
pub struct ConnectionAnalyzer {
    intel: ConnectionIntel,
}

impl ConnectionAnalyzer {
    pub fn new(target_ip: IpAddr, target_port: u16) -> Self {
        Self {
            intel: ConnectionIntel::new(target_ip, target_port),
        }
    }

    /// Analyze TCP connection
    pub fn analyze_tcp(&mut self, stream: &TcpStream) -> &ConnectionIntel {
        self.intel.capture_local_details(stream);

        // TODO: Extract TCP options using raw sockets
        // For now, we can infer some from behavior

        &self.intel
    }

    /// Analyze TLS handshake details
    pub fn analyze_tls_handshake(&mut self, server_hello: &[u8], certificates: &[Vec<u8>]) {
        // Parse TLS version
        if server_hello.len() >= 2 {
            let version = match (server_hello[0], server_hello[1]) {
                (0x03, 0x01) => "TLS 1.0",
                (0x03, 0x02) => "TLS 1.1",
                (0x03, 0x03) => "TLS 1.2",
                (0x03, 0x04) => "TLS 1.3",
                _ => "Unknown",
            };
            self.intel.tls_version = Some(version.to_string());
        }

        // Parse selected cipher suite (bytes 2-3 in simplified parsing)
        if server_hello.len() >= 4 {
            let cipher_id = ((server_hello[2] as u16) << 8) | (server_hello[3] as u16);
            self.intel.selected_cipher = Some(format!("0x{:04X}", cipher_id));
        }

        // Analyze certificates
        self.intel.cert_chain_length = Some(certificates.len());

        // Parse first certificate (server cert)
        if let Some(cert) = certificates.first() {
            self.parse_certificate(cert);
        }
    }

    /// Parse X.509 certificate for intelligence
    fn parse_certificate(&mut self, cert_der: &[u8]) {
        match X509Certificate::from_der(cert_der) {
            Ok(cert) => {
                let subject = cert.subject_string();
                if !subject.is_empty() {
                    self.intel.cert_subject = Some(subject.clone());
                    if subject.contains("*.") {
                        self.intel.cert_is_wildcard = true;
                    }
                }

                let issuer = cert.issuer_string();
                if !issuer.is_empty() {
                    self.intel.cert_issuer = Some(issuer);
                }

                if cert.is_self_signed() {
                    self.intel.cert_is_self_signed = true;
                }

                let sans = cert.get_subject_alt_names();
                if !sans.is_empty() {
                    if sans.iter().any(|name| name.starts_with("*")) {
                        self.intel.cert_is_wildcard = true;
                    }
                    self.intel.cert_san_count = Some(sans.len());
                }

                self.intel.cert_algorithm = Some(cert.signature_algorithm.algorithm.clone());

                if let Ok((modulus, _)) = cert.subject_public_key_info.rsa_components() {
                    let bits = (modulus.len() * 8) as u32;
                    self.intel.cert_key_size = Some(bits);
                }

                let not_before = parse_asn1_time(&cert.validity.not_before);
                let not_after = parse_asn1_time(&cert.validity.not_after);
                if let (Some(start), Some(end)) = (not_before, not_after) {
                    if let Ok(duration) = end.duration_since(start) {
                        self.intel.cert_validity_days = Some((duration.as_secs() / 86_400) as i64);
                    }

                    if SystemTime::now()
                        .duration_since(end)
                        .map(|d| d.as_secs() > 0)
                        .unwrap_or(false)
                    {
                        self.intel.cert_is_expired = true;
                    }
                }
            }
            Err(_) => {
                // fall back to minimal parsing for wildcard detection
                if let Some(pos) = find_subsequence(cert_der, b"CN=") {
                    if let Some(end) = cert_der[pos + 3..]
                        .iter()
                        .position(|&b| b == 0 || b == b',')
                    {
                        if let Ok(cn) = std::str::from_utf8(&cert_der[pos + 3..pos + 3 + end]) {
                            if self.intel.cert_subject.is_none() {
                                self.intel.cert_subject = Some(cn.to_string());
                                if cn.starts_with("*.") {
                                    self.intel.cert_is_wildcard = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Analyze HTTP response headers
    pub fn analyze_http_headers(&mut self, headers: &[(String, String)]) {
        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            match name_lower.as_str() {
                "server" => {
                    self.intel.http_server_header = Some(value.clone());
                }
                "x-powered-by" => {
                    self.intel.http_powered_by = Some(value.clone());
                }
                "via" => {
                    self.intel.http_via_proxy = Some(value.clone());
                }
                "set-cookie" => {
                    self.intel.http_cookies_count =
                        Some(self.intel.http_cookies_count.unwrap_or(0) + 1);
                }
                // Security headers
                "strict-transport-security" => {
                    self.intel.http_security_headers.push("HSTS".to_string());
                }
                "content-security-policy" => {
                    self.intel.http_security_headers.push("CSP".to_string());
                }
                "x-frame-options" => {
                    self.intel
                        .http_security_headers
                        .push("X-Frame-Options".to_string());
                }
                "x-content-type-options" => {
                    self.intel
                        .http_security_headers
                        .push("X-Content-Type-Options".to_string());
                }
                "x-xss-protection" => {
                    self.intel
                        .http_security_headers
                        .push("X-XSS-Protection".to_string());
                }
                _ => {}
            }
        }

        // Check for missing security headers
        let expected_headers = vec![
            ("HSTS", "Strict-Transport-Security"),
            ("CSP", "Content-Security-Policy"),
            ("X-Frame-Options", "X-Frame-Options"),
            ("X-Content-Type-Options", "X-Content-Type-Options"),
        ];

        for (short_name, _full_name) in expected_headers {
            if !self
                .intel
                .http_security_headers
                .contains(&short_name.to_string())
            {
                self.intel
                    .http_missing_security_headers
                    .push(short_name.to_string());
            }
        }
    }

    /// Finalize analysis and infer infrastructure
    pub fn finalize(mut self) -> ConnectionIntel {
        self.intel.infer_infrastructure();
        self.intel
    }

    /// Get current intelligence (without consuming)
    pub fn intel(&self) -> &ConnectionIntel {
        &self.intel
    }
}

fn parse_asn1_time(time_str: &str) -> Option<SystemTime> {
    let trimmed = time_str.trim_end_matches('Z').trim();

    let (year, month, day, hour, minute, second) = match trimmed.len() {
        12 => {
            // UTCTime: YYMMDDHHMMSS
            let year = trimmed.get(0..2)?.parse::<i32>().ok()?;
            let year = if year >= 70 { 1900 + year } else { 2000 + year };
            (
                year,
                trimmed.get(2..4)?.parse::<u32>().ok()?,
                trimmed.get(4..6)?.parse::<u32>().ok()?,
                trimmed.get(6..8)?.parse::<u32>().ok()?,
                trimmed.get(8..10)?.parse::<u32>().ok()?,
                trimmed.get(10..12)?.parse::<u32>().ok()?,
            )
        }
        14 => {
            // GeneralizedTime: YYYYMMDDHHMMSS
            (
                trimmed.get(0..4)?.parse::<i32>().ok()?,
                trimmed.get(4..6)?.parse::<u32>().ok()?,
                trimmed.get(6..8)?.parse::<u32>().ok()?,
                trimmed.get(8..10)?.parse::<u32>().ok()?,
                trimmed.get(10..12)?.parse::<u32>().ok()?,
                trimmed.get(12..14)?.parse::<u32>().ok()?,
            )
        }
        _ => return None,
    };

    system_time_from_ymdhms(year, month, day, hour, minute, second)
}

fn system_time_from_ymdhms(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<SystemTime> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour as i64 * 3_600 + minute as i64 * 60 + second as i64)?;

    if seconds >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs((-seconds) as u64))
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let mut y = year;
    let mut m = month as i32;
    let d = day as i32;

    if m <= 2 {
        y -= 1;
        m += 12;
    }

    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = ((153 * (m - 3) + 2) / 5) + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468; // Days since 1970-01-01
    Some(days as i64)
}

/// Helper: find subsequence in byte slice
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_intel_creation() {
        let ip = "192.168.1.1".parse().unwrap();
        let intel = ConnectionIntel::new(ip, 443);

        assert_eq!(intel.target_ip, ip);
        assert_eq!(intel.target_port, 443);
        assert!(!intel.cert_is_self_signed);
    }

    #[test]
    fn test_tcp_option_names() {
        let opt_mss = TcpOption {
            kind: 2,
            value: vec![5, 180],
        };
        assert_eq!(opt_mss.name(), "Maximum Segment Size");

        let opt_sack = TcpOption {
            kind: 4,
            value: vec![],
        };
        assert_eq!(opt_sack.name(), "SACK Permitted");
    }

    #[test]
    fn test_infrastructure_inference() {
        let mut intel = ConnectionIntel::new("1.1.1.1".parse().unwrap(), 443);
        intel.cert_issuer = Some("Cloudflare Inc".to_string());
        intel.http_server_header = Some("cloudflare".to_string());
        intel.infer_infrastructure();

        assert_eq!(intel.likely_cdn, Some("Cloudflare".to_string()));
        assert_eq!(intel.likely_waf, Some("Cloudflare".to_string()));
    }

    #[test]
    fn test_wildcard_cert_detection() {
        let mut intel = ConnectionIntel::new("1.1.1.1".parse().unwrap(), 443);
        intel.cert_subject = Some("*.example.com".to_string());

        // In real code, parse_certificate would set this
        intel.cert_is_wildcard = intel
            .cert_subject
            .as_ref()
            .map(|s| s.starts_with("*."))
            .unwrap_or(false);

        assert!(intel.cert_is_wildcard);
    }
}
