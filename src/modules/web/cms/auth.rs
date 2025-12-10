/// Authentication Testing Module
///
/// Tests CMS authentication mechanisms for weaknesses

use super::{CmsType, CmsScanConfig, Finding, FindingType, VulnSeverity, HttpResponse};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use std::thread;

/// Authentication tester
pub struct AuthTester {
    config: CmsScanConfig,
    cms_type: CmsType,
}

/// Authentication test result
#[derive(Debug, Clone)]
pub struct AuthTestResult {
    /// Findings from authentication testing
    pub findings: Vec<Finding>,
    /// Login endpoint found
    pub login_url: Option<String>,
    /// Is rate limiting enabled?
    pub rate_limited: bool,
    /// Lockout policy detected?
    pub lockout_policy: bool,
    /// CAPTCHA present?
    pub captcha_present: bool,
    /// 2FA available?
    pub two_factor_available: bool,
    /// Weak password policy?
    pub weak_password_policy: bool,
    /// Username enumeration possible?
    pub username_enumerable: bool,
    /// Default credentials found
    pub default_creds_found: Vec<(String, String)>,
}

impl AuthTester {
    pub fn new(config: CmsScanConfig, cms_type: CmsType) -> Self {
        Self { config, cms_type }
    }

    /// Run all authentication tests
    pub fn test(&self) -> AuthTestResult {
        let mut result = AuthTestResult {
            findings: Vec::new(),
            login_url: None,
            rate_limited: false,
            lockout_policy: false,
            captcha_present: false,
            two_factor_available: false,
            weak_password_policy: false,
            username_enumerable: false,
            default_creds_found: Vec::new(),
        };

        // Find login endpoint
        result.login_url = self.find_login_endpoint();

        if result.login_url.is_none() {
            return result;
        }

        let login_url = result.login_url.as_ref().unwrap().clone();

        // Test username enumeration
        result.username_enumerable = self.test_username_enumeration(&login_url);
        if result.username_enumerable {
            result.findings.push(Finding {
                finding_type: FindingType::InformationLeak,
                title: "Username Enumeration Possible".to_string(),
                description: "Login error messages reveal whether usernames exist".to_string(),
                url: Some(login_url.clone()),
                evidence: None,
                severity: VulnSeverity::Low,
                confidence: 85,
            });
        }

        // Test rate limiting
        result.rate_limited = self.test_rate_limiting(&login_url);
        if !result.rate_limited {
            result.findings.push(Finding {
                finding_type: FindingType::WeakPasswordPolicy,
                title: "No Rate Limiting Detected".to_string(),
                description: "Login endpoint does not appear to rate limit failed attempts".to_string(),
                url: Some(login_url.clone()),
                evidence: None,
                severity: VulnSeverity::Medium,
                confidence: 70,
            });
        }

        // Test CAPTCHA
        result.captcha_present = self.test_captcha(&login_url);
        if !result.captcha_present {
            result.findings.push(Finding {
                finding_type: FindingType::WeakPasswordPolicy,
                title: "No CAPTCHA on Login".to_string(),
                description: "Login form does not include CAPTCHA protection".to_string(),
                url: Some(login_url.clone()),
                evidence: None,
                severity: VulnSeverity::Low,
                confidence: 90,
            });
        }

        // Test password policy (if registration is available)
        result.weak_password_policy = self.test_password_policy();

        // Test default credentials (if aggressive mode)
        if self.config.aggressive {
            result.default_creds_found = self.test_default_credentials(&login_url);
            if !result.default_creds_found.is_empty() {
                result.findings.push(Finding {
                    finding_type: FindingType::DefaultCredentials,
                    title: "Default Credentials Found".to_string(),
                    description: format!(
                        "Found {} working default credential(s)",
                        result.default_creds_found.len()
                    ),
                    url: Some(login_url.clone()),
                    evidence: Some(
                        result.default_creds_found
                            .iter()
                            .map(|(u, _)| u.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    severity: VulnSeverity::Critical,
                    confidence: 100,
                });
            }
        }

        result
    }

    /// Find login endpoint based on CMS type
    fn find_login_endpoint(&self) -> Option<String> {
        let endpoints = match self.cms_type {
            CmsType::WordPress => vec![
                "/wp-login.php",
                "/wp-admin/",
            ],
            CmsType::Drupal => vec![
                "/user/login",
                "/user",
            ],
            CmsType::Joomla => vec![
                "/administrator/",
                "/administrator/index.php",
            ],
            CmsType::Magento => vec![
                "/admin/",
                "/admin/index/index/",
            ],
            CmsType::TYPO3 => vec![
                "/typo3/",
            ],
            CmsType::Ghost => vec![
                "/ghost/",
            ],
            _ => vec![
                "/admin/",
                "/login/",
                "/admin/login/",
            ],
        };

        for endpoint in endpoints {
            let url = format!("{}{}", self.config.target.trim_end_matches('/'), endpoint);
            if let Some(response) = self.fetch(&url) {
                // Check for login form indicators
                if response.status_code == 200 || response.status_code == 302 {
                    if self.is_login_page(&response.body) {
                        return Some(url);
                    }
                }
            }
        }

        None
    }

    /// Check if page is a login page
    fn is_login_page(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        let indicators = [
            "type=\"password\"",
            "name=\"pass\"",
            "name=\"pwd\"",
            "name=\"password\"",
            "id=\"user_pass\"",
            "login",
            "sign in",
            "authenticate",
        ];

        indicators.iter().any(|i| body_lower.contains(i))
    }

    /// Test for username enumeration
    fn test_username_enumeration(&self, login_url: &str) -> bool {
        // Test with known-bad username
        let bad_response = self.attempt_login(login_url, "definitely_not_a_user_12345", "wrongpass");

        // Test with likely username
        let likely_response = self.attempt_login(login_url, "admin", "wrongpass");

        if let (Some(bad), Some(likely)) = (bad_response, likely_response) {
            // Compare responses
            // Different response length or content indicates enumeration possible
            let bad_len = bad.body.len();
            let likely_len = likely.body.len();

            // Significant difference in response size
            if (bad_len as i64 - likely_len as i64).abs() > 50 {
                return true;
            }

            // Different error messages
            let bad_lower = bad.body.to_lowercase();
            let likely_lower = likely.body.to_lowercase();

            if bad_lower.contains("invalid username") && !likely_lower.contains("invalid username") {
                return true;
            }

            if !bad_lower.contains("password") && likely_lower.contains("password") {
                return true;
            }
        }

        false
    }

    /// Test for rate limiting
    fn test_rate_limiting(&self, login_url: &str) -> bool {
        let attempts = 5;
        let mut blocked = false;

        for i in 0..attempts {
            let response = self.attempt_login(login_url, "test_user", &format!("wrong_pass_{}", i));

            if let Some(resp) = response {
                // Check for rate limit indicators
                if resp.status_code == 429 {
                    blocked = true;
                    break;
                }

                let body_lower = resp.body.to_lowercase();
                if body_lower.contains("too many")
                    || body_lower.contains("rate limit")
                    || body_lower.contains("slow down")
                    || body_lower.contains("locked")
                {
                    blocked = true;
                    break;
                }
            }

            // Small delay between attempts
            thread::sleep(Duration::from_millis(100));
        }

        blocked
    }

    /// Test for CAPTCHA presence
    fn test_captcha(&self, login_url: &str) -> bool {
        if let Some(response) = self.fetch(login_url) {
            let body_lower = response.body.to_lowercase();

            let captcha_indicators = [
                "captcha",
                "recaptcha",
                "g-recaptcha",
                "hcaptcha",
                "cf-turnstile",
                "areyouahuman",
                "funcaptcha",
            ];

            return captcha_indicators.iter().any(|i| body_lower.contains(i));
        }

        false
    }

    /// Test password policy
    fn test_password_policy(&self) -> bool {
        // Find registration page
        let reg_endpoints = match self.cms_type {
            CmsType::WordPress => vec!["/wp-login.php?action=register"],
            CmsType::Drupal => vec!["/user/register"],
            CmsType::Joomla => vec!["/index.php?option=com_users&view=registration"],
            _ => vec!["/register", "/signup"],
        };

        for endpoint in reg_endpoints {
            let url = format!("{}{}", self.config.target.trim_end_matches('/'), endpoint);
            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    // Check for password requirements
                    let strong_policy_indicators = [
                        "8 characters",
                        "password strength",
                        "uppercase",
                        "lowercase",
                        "number",
                        "special character",
                        "complexity",
                    ];

                    let has_strong_policy = strong_policy_indicators
                        .iter()
                        .any(|i| body_lower.contains(i));

                    return !has_strong_policy;
                }
            }
        }

        false
    }

    /// Test default credentials
    fn test_default_credentials(&self, login_url: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();

        let default_creds = self.get_default_credentials();

        for (username, password) in default_creds {
            // Respect rate limiting
            if let Some(rate) = self.config.rate_limit {
                let delay = Duration::from_secs_f64(1.0 / rate);
                thread::sleep(delay);
            }

            if self.try_login(login_url, &username, &password) {
                found.push((username, password));
            }
        }

        found
    }

    /// Get default credentials for CMS
    fn get_default_credentials(&self) -> Vec<(String, String)> {
        let mut creds = vec![
            ("admin".to_string(), "admin".to_string()),
            ("admin".to_string(), "password".to_string()),
            ("admin".to_string(), "123456".to_string()),
            ("administrator".to_string(), "administrator".to_string()),
            ("root".to_string(), "root".to_string()),
            ("root".to_string(), "toor".to_string()),
            ("test".to_string(), "test".to_string()),
            ("user".to_string(), "user".to_string()),
        ];

        // Add CMS-specific defaults
        match self.cms_type {
            CmsType::WordPress => {
                creds.push(("admin".to_string(), "wordpress".to_string()));
                creds.push(("wp".to_string(), "wp".to_string()));
            }
            CmsType::Drupal => {
                creds.push(("admin".to_string(), "drupal".to_string()));
                creds.push(("drupal".to_string(), "drupal".to_string()));
            }
            CmsType::Joomla => {
                creds.push(("admin".to_string(), "joomla".to_string()));
                creds.push(("joomla".to_string(), "joomla".to_string()));
            }
            CmsType::Magento => {
                creds.push(("admin".to_string(), "magento".to_string()));
                creds.push(("admin".to_string(), "123123qa".to_string()));
            }
            _ => {}
        }

        creds
    }

    /// Try to login with credentials
    fn try_login(&self, login_url: &str, username: &str, password: &str) -> bool {
        let response = self.attempt_login(login_url, username, password);

        if let Some(resp) = response {
            // Check for successful login indicators
            // This varies by CMS

            // Check for redirect to admin area
            if resp.status_code == 302 || resp.status_code == 303 {
                if let Some(location) = resp.get_header("Location") {
                    let loc_lower = location.to_lowercase();
                    if loc_lower.contains("admin")
                        || loc_lower.contains("dashboard")
                        || loc_lower.contains("wp-admin")
                    {
                        return true;
                    }
                }
            }

            // Check body for success indicators
            let body_lower = resp.body.to_lowercase();
            if body_lower.contains("welcome")
                || body_lower.contains("dashboard")
                || body_lower.contains("logout")
            {
                // But make sure it's not an error
                if !body_lower.contains("error")
                    && !body_lower.contains("invalid")
                    && !body_lower.contains("incorrect")
                {
                    return true;
                }
            }
        }

        false
    }

    /// Attempt login and return response
    fn attempt_login(&self, login_url: &str, username: &str, password: &str) -> Option<HttpResponse> {
        let body = self.build_login_body(username, password);
        self.post(login_url, &body)
    }

    /// Build login POST body
    fn build_login_body(&self, username: &str, password: &str) -> String {
        match self.cms_type {
            CmsType::WordPress => {
                format!(
                    "log={}&pwd={}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
                    url_encode(username),
                    url_encode(password)
                )
            }
            CmsType::Drupal => {
                format!(
                    "name={}&pass={}&form_id=user_login_form&op=Log+in",
                    url_encode(username),
                    url_encode(password)
                )
            }
            CmsType::Joomla => {
                format!(
                    "username={}&passwd={}&option=com_login&task=login&return=aW5kZXgucGhw",
                    url_encode(username),
                    url_encode(password)
                )
            }
            _ => {
                format!(
                    "username={}&password={}",
                    url_encode(username),
                    url_encode(password)
                )
            }
        }
    }

    /// Fetch URL
    fn fetch(&self, url: &str) -> Option<HttpResponse> {
        fetch_url(url, &self.config.user_agent, self.config.timeout)
    }

    /// POST request
    fn post(&self, url: &str, body: &str) -> Option<HttpResponse> {
        post_url(url, body, &self.config.user_agent, self.config.timeout)
    }
}

/// URL encode string
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            ' ' => result.push('+'),
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}

/// Fetch URL helper
fn fetch_url(url: &str, user_agent: &str, timeout: Duration) -> Option<HttpResponse> {
    let (host, port, path, use_tls) = parse_url(url)?;

    if use_tls {
        return None;
    }

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Connection: close\r\n\
         \r\n",
        path, host, user_agent
    );

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    parse_response(&response, url)
}

/// POST URL helper
fn post_url(url: &str, body: &str, user_agent: &str, timeout: Duration) -> Option<HttpResponse> {
    let (host, port, path, use_tls) = parse_url(url)?;

    if use_tls {
        return None;
    }

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path, host, user_agent, body.len(), body
    );

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    parse_response(&response, url)
}

/// Parse URL
fn parse_url(url: &str) -> Option<(String, u16, String, bool)> {
    let (scheme, rest) = if url.starts_with("https://") {
        ("https", &url[8..])
    } else if url.starts_with("http://") {
        ("http", &url[7..])
    } else {
        ("http", url)
    };

    let use_tls = scheme == "https";
    let default_port = if use_tls { 443 } else { 80 };

    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(pos) => (&host_port[..pos], host_port[pos + 1..].parse().ok()?),
        None => (host_port, default_port),
    };

    Some((host.to_string(), port, path.to_string(), use_tls))
}

/// Parse HTTP response
fn parse_response(data: &[u8], url: &str) -> Option<HttpResponse> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();

    let status_line = lines.next()?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let status_code: u16 = parts[1].parse().ok()?;

    let mut headers = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        if let Some(pos) = line.find(':') {
            headers.push((line[..pos].trim().to_string(), line[pos + 1..].trim().to_string()));
        }
    }

    let body_start = text.find("\r\n\r\n").map(|p| p + 4)
        .or_else(|| text.find("\n\n").map(|p| p + 2))
        .unwrap_or(text.len());
    let body = text[body_start..].to_string();

    Some(HttpResponse { status_code, headers, body, url: url.to_string() })
}
