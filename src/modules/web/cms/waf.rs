/// WAF Evasion Module
///
/// Techniques to bypass Web Application Firewalls during CMS scanning

use std::time::Duration;
use std::thread;

/// WAF evasion handler
pub struct WafEvasion {
    enabled: bool,
    techniques: Vec<EvasionTechnique>,
    current_technique: usize,
    detected_waf: Option<WafType>,
}

/// Known WAF types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafType {
    Cloudflare,
    Akamai,
    AWS,
    Imperva,
    ModSecurity,
    Sucuri,
    Wordfence,
    F5BigIP,
    Barracuda,
    Fortinet,
    Palo,
    Unknown,
}

impl WafType {
    pub fn name(&self) -> &str {
        match self {
            Self::Cloudflare => "Cloudflare",
            Self::Akamai => "Akamai",
            Self::AWS => "AWS WAF",
            Self::Imperva => "Imperva/Incapsula",
            Self::ModSecurity => "ModSecurity",
            Self::Sucuri => "Sucuri",
            Self::Wordfence => "Wordfence",
            Self::F5BigIP => "F5 BIG-IP",
            Self::Barracuda => "Barracuda",
            Self::Fortinet => "FortiWeb",
            Self::Palo => "Palo Alto",
            Self::Unknown => "Unknown WAF",
        }
    }
}

/// Evasion techniques
#[derive(Debug, Clone)]
pub enum EvasionTechnique {
    /// Random delay between requests
    RandomDelay { min_ms: u64, max_ms: u64 },
    /// User-Agent rotation
    UserAgentRotation(Vec<String>),
    /// IP rotation via headers
    IpRotation,
    /// Case variation in paths
    CaseVariation,
    /// URL encoding variations
    UrlEncoding,
    /// HTTP method override
    MethodOverride,
    /// Path normalization bypass
    PathNormalization,
    /// Header obfuscation
    HeaderObfuscation,
}

impl WafEvasion {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            techniques: if enabled { Self::default_techniques() } else { vec![] },
            current_technique: 0,
            detected_waf: None,
        }
    }

    /// Get default evasion techniques
    fn default_techniques() -> Vec<EvasionTechnique> {
        vec![
            EvasionTechnique::RandomDelay { min_ms: 100, max_ms: 500 },
            EvasionTechnique::UserAgentRotation(Self::user_agents()),
            EvasionTechnique::IpRotation,
            EvasionTechnique::CaseVariation,
            EvasionTechnique::UrlEncoding,
            EvasionTechnique::PathNormalization,
            EvasionTechnique::HeaderObfuscation,
        ]
    }

    /// Get list of user agents to rotate
    fn user_agents() -> Vec<String> {
        vec![
            // Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            // Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
            "Mozilla/5.0 (X11; Linux i686; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
            // Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".to_string(),
            // Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".to_string(),
            // Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".to_string(),
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36".to_string(),
            // Bots (sometimes WAFs whitelist these)
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".to_string(),
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)".to_string(),
        ]
    }

    /// Detect WAF from response headers
    pub fn detect_waf(&mut self, headers: &[(String, String)], body: &str) -> Option<WafType> {
        // Check headers for WAF signatures
        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            let value_lower = value.to_lowercase();

            // Cloudflare
            if name_lower == "cf-ray" || name_lower == "cf-cache-status" {
                self.detected_waf = Some(WafType::Cloudflare);
                return self.detected_waf;
            }
            if name_lower == "server" && value_lower.contains("cloudflare") {
                self.detected_waf = Some(WafType::Cloudflare);
                return self.detected_waf;
            }

            // Akamai
            if name_lower.starts_with("x-akamai") {
                self.detected_waf = Some(WafType::Akamai);
                return self.detected_waf;
            }

            // AWS
            if name_lower == "x-amz-cf-id" || name_lower == "x-amzn-waf" {
                self.detected_waf = Some(WafType::AWS);
                return self.detected_waf;
            }

            // Imperva/Incapsula
            if name_lower == "x-iinfo" || value_lower.contains("incapsula") {
                self.detected_waf = Some(WafType::Imperva);
                return self.detected_waf;
            }

            // Sucuri
            if name_lower == "x-sucuri-id" || name_lower == "x-sucuri-cache" {
                self.detected_waf = Some(WafType::Sucuri);
                return self.detected_waf;
            }

            // F5 BIG-IP
            if name_lower == "x-wa-info" || value_lower.contains("bigip") {
                self.detected_waf = Some(WafType::F5BigIP);
                return self.detected_waf;
            }

            // ModSecurity
            if name_lower == "server" && value_lower.contains("mod_security") {
                self.detected_waf = Some(WafType::ModSecurity);
                return self.detected_waf;
            }

            // Barracuda
            if name_lower == "barra_counter_session" {
                self.detected_waf = Some(WafType::Barracuda);
                return self.detected_waf;
            }

            // FortiWeb
            if name_lower == "fortiwafsid" {
                self.detected_waf = Some(WafType::Fortinet);
                return self.detected_waf;
            }
        }

        // Check body for WAF signatures
        let body_lower = body.to_lowercase();

        if body_lower.contains("attention required! | cloudflare") {
            self.detected_waf = Some(WafType::Cloudflare);
            return self.detected_waf;
        }

        if body_lower.contains("access denied") && body_lower.contains("incapsula") {
            self.detected_waf = Some(WafType::Imperva);
            return self.detected_waf;
        }

        if body_lower.contains("wordfence") {
            self.detected_waf = Some(WafType::Wordfence);
            return self.detected_waf;
        }

        if body_lower.contains("sucuri") && body_lower.contains("blocked") {
            self.detected_waf = Some(WafType::Sucuri);
            return self.detected_waf;
        }

        None
    }

    /// Apply random delay evasion
    pub fn apply_delay(&self) {
        if !self.enabled {
            return;
        }

        for technique in &self.techniques {
            if let EvasionTechnique::RandomDelay { min_ms, max_ms } = technique {
                let delay = *min_ms + (random_u64() % (*max_ms - *min_ms + 1));
                thread::sleep(Duration::from_millis(delay));
                return;
            }
        }
    }

    /// Get next user agent
    pub fn get_user_agent(&mut self) -> String {
        if !self.enabled {
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string();
        }

        for technique in &self.techniques {
            if let EvasionTechnique::UserAgentRotation(agents) = technique {
                if !agents.is_empty() {
                    let idx = (random_u64() as usize) % agents.len();
                    return agents[idx].clone();
                }
            }
        }

        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()
    }

    /// Get evasion headers
    pub fn get_evasion_headers(&self) -> Vec<(String, String)> {
        if !self.enabled {
            return vec![];
        }

        let mut headers = Vec::new();

        // IP rotation headers (fake source IP)
        if self.techniques.iter().any(|t| matches!(t, EvasionTechnique::IpRotation)) {
            let fake_ip = generate_fake_ip();
            headers.push(("X-Forwarded-For".to_string(), fake_ip.clone()));
            headers.push(("X-Real-IP".to_string(), fake_ip.clone()));
            headers.push(("X-Client-IP".to_string(), fake_ip.clone()));
            headers.push(("X-Originating-IP".to_string(), fake_ip));
        }

        // Header obfuscation
        if self.techniques.iter().any(|t| matches!(t, EvasionTechnique::HeaderObfuscation)) {
            // Add benign-looking headers
            headers.push(("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()));
            headers.push(("Accept-Encoding".to_string(), "gzip, deflate".to_string()));
            headers.push(("DNT".to_string(), "1".to_string()));
            headers.push(("Upgrade-Insecure-Requests".to_string(), "1".to_string()));
        }

        headers
    }

    /// Transform URL path for evasion
    pub fn transform_path(&self, path: &str) -> String {
        if !self.enabled {
            return path.to_string();
        }

        let mut result = path.to_string();

        // Case variation
        if self.techniques.iter().any(|t| matches!(t, EvasionTechnique::CaseVariation)) {
            // Randomly uppercase some characters in path segments
            // Most servers are case-insensitive on Windows
        }

        // URL encoding variations
        if self.techniques.iter().any(|t| matches!(t, EvasionTechnique::UrlEncoding)) {
            // Double-encode some characters
            result = result.replace("/", "/%2f");
            result = result.replace("/", "/"); // Restore first slash
        }

        // Path normalization bypass
        if self.techniques.iter().any(|t| matches!(t, EvasionTechnique::PathNormalization)) {
            // Add harmless path segments
            result = result.replace("/", "/./");
            // Or add null bytes (careful - may break some servers)
        }

        result
    }

    /// Get WAF-specific bypass techniques
    pub fn get_bypass_for_waf(&self, waf: WafType) -> Vec<&'static str> {
        match waf {
            WafType::Cloudflare => vec![
                "Use slower request rate",
                "Rotate User-Agents",
                "Add realistic headers",
                "Consider residential proxies",
            ],
            WafType::ModSecurity => vec![
                "URL encode payloads",
                "Case variation",
                "Comment injection in SQL",
                "Use alternative syntax",
            ],
            WafType::Wordfence => vec![
                "Slow down requests significantly",
                "Use legitimate-looking paths",
                "Avoid common scanning patterns",
            ],
            WafType::Sucuri => vec![
                "Increase delays between requests",
                "Randomize request patterns",
                "Use cache-busting parameters",
            ],
            WafType::AWS => vec![
                "Vary request patterns",
                "Use legitimate referers",
                "Distribute requests over time",
            ],
            _ => vec![
                "Use random delays",
                "Rotate User-Agents",
                "Add realistic headers",
            ],
        }
    }

    /// Check if request was blocked
    pub fn is_blocked(&self, status_code: u16, body: &str) -> bool {
        // Common block status codes
        if status_code == 403 || status_code == 429 || status_code == 503 {
            return true;
        }

        // Check body for block indicators
        let body_lower = body.to_lowercase();
        let block_indicators = [
            "access denied",
            "blocked",
            "forbidden",
            "rate limit",
            "too many requests",
            "captcha",
            "challenge",
            "security check",
            "suspicious activity",
            "automated request",
            "bot detected",
        ];

        block_indicators.iter().any(|indicator| body_lower.contains(indicator))
    }

    /// Get detected WAF
    pub fn get_detected_waf(&self) -> Option<WafType> {
        self.detected_waf
    }
}

impl Default for WafEvasion {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Generate fake IP for X-Forwarded-For
fn generate_fake_ip() -> String {
    // Generate random private IP
    let ranges = [
        (10, 0, 0, 0, 255, 255, 255),      // 10.0.0.0/8
        (172, 16, 0, 0, 31, 255, 255),     // 172.16.0.0/12
        (192, 168, 0, 0, 0, 255, 255),     // 192.168.0.0/16
    ];

    let range_idx = (random_u64() as usize) % ranges.len();
    let (a, b_min, c_min, d_min, b_max, c_max, d_max) = ranges[range_idx];

    let b = b_min + ((random_u64() as u8) % (b_max - b_min + 1));
    let c = c_min + ((random_u64() as u8) % (c_max - c_min + 1));
    let d = d_min + ((random_u64() as u8) % (d_max - d_min + 1));

    format!("{}.{}.{}.{}", a, b, c, d)
}

/// Simple random number generator using system time
fn random_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Simple xorshift
    let mut x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cloudflare() {
        let mut waf = WafEvasion::new(true);
        let headers = vec![
            ("CF-Ray".to_string(), "abc123-IAD".to_string()),
        ];

        let detected = waf.detect_waf(&headers, "");
        assert_eq!(detected, Some(WafType::Cloudflare));
    }

    #[test]
    fn test_is_blocked() {
        let waf = WafEvasion::new(true);

        assert!(waf.is_blocked(403, ""));
        assert!(waf.is_blocked(429, ""));
        assert!(waf.is_blocked(200, "Access Denied"));
        assert!(!waf.is_blocked(200, "OK"));
    }

    #[test]
    fn test_get_user_agent() {
        let mut waf = WafEvasion::new(true);
        let ua = waf.get_user_agent();

        assert!(ua.contains("Mozilla"));
    }
}
