/// HTTP Fingerprinting
///
/// Extract server, framework, and technology information from HTTP responses.
///
/// Techniques:
/// - Server header analysis
/// - Header order fingerprinting
/// - Cookie-based framework detection
/// - Error page analysis
/// - Response timing patterns
use std::collections::HashMap;

/// HTTP Server types detected from headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerType {
    Apache,
    Nginx,
    IIS,
    LiteSpeed,
    Caddy,
    Cloudflare,
    AmazonS3,
    AmazonCloudFront,
    GoogleCloudStorage,
    Unknown,
}

/// Web framework detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framework {
    PHP,
    AspNet,
    AspNetCore,
    Java,
    Django,
    Flask,
    Rails,
    Laravel,
    WordPress,
    Drupal,
    Joomla,
    NodeExpress,
    Unknown,
}

/// WAF (Web Application Firewall) detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Waf {
    Cloudflare,
    Akamai,
    Sucuri,
    ModSecurity,
    Imperva,
    F5BigIP,
    Barracuda,
    FortiWeb,
    Unknown,
}

/// CDN detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cdn {
    Cloudflare,
    Fastly,
    Akamai,
    CloudFront,
    MaxCDN,
    KeyCDN,
    Bunny,
    Unknown,
}

/// Cloud provider detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    AWS,
    Azure,
    GCP,
    DigitalOcean,
    Linode,
    Vultr,
    Heroku,
    Vercel,
    Netlify,
    Unknown,
}

/// Server intelligence extracted from HTTP response
#[derive(Debug, Clone)]
pub struct ServerIntelligence {
    pub server_type: ServerType,
    pub server_version: Option<String>,
    pub os_hint: Option<String>,
    pub framework: Option<Framework>,
    pub waf: Option<Waf>,
    pub cdn: Option<Cdn>,
    pub cloud_provider: Option<CloudProvider>,
}

/// HTTP Response Fingerprint
#[derive(Debug, Clone)]
pub struct HttpFingerprint {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub header_order: Vec<String>,
    pub cookies: HashMap<String, String>,
    pub body_snippet: String, // First 1KB for error page analysis
}

impl HttpFingerprint {
    pub fn new() -> Self {
        Self {
            status_code: 0,
            headers: HashMap::new(),
            header_order: Vec::new(),
            cookies: HashMap::new(),
            body_snippet: String::new(),
        }
    }

    /// Analyze Server header
    pub fn analyze_server_header(&self) -> ServerIntelligence {
        let server = self
            .headers
            .get("Server")
            .or_else(|| self.headers.get("server"))
            .cloned()
            .unwrap_or_default();

        let server_lower = server.to_lowercase();

        // Apache detection
        if server_lower.contains("apache") {
            let version = Self::extract_version(&server);
            let os_hint = Self::extract_os_from_apache(&server);

            return ServerIntelligence {
                server_type: ServerType::Apache,
                server_version: version,
                os_hint,
                framework: None,
                waf: None,
                cdn: None,
                cloud_provider: None,
            };
        }

        // nginx detection
        if server_lower.contains("nginx") {
            return ServerIntelligence {
                server_type: ServerType::Nginx,
                server_version: Self::extract_version(&server),
                os_hint: None, // nginx doesn't leak OS
                framework: None,
                waf: None,
                cdn: None,
                cloud_provider: None,
            };
        }

        // IIS detection
        if server_lower.contains("microsoft-iis") || server_lower.contains("iis") {
            let version = Self::extract_version(&server);
            let windows_version = Self::iis_to_windows_version(&version);

            return ServerIntelligence {
                server_type: ServerType::IIS,
                server_version: version,
                os_hint: windows_version,
                framework: None,
                waf: None,
                cdn: None,
                cloud_provider: None,
            };
        }

        // Cloudflare
        if server_lower.contains("cloudflare") {
            return ServerIntelligence {
                server_type: ServerType::Cloudflare,
                server_version: None,
                os_hint: None,
                framework: None,
                waf: Some(Waf::Cloudflare),
                cdn: Some(Cdn::Cloudflare),
                cloud_provider: None,
            };
        }

        // Amazon S3
        if server_lower.contains("amazons3") {
            return ServerIntelligence {
                server_type: ServerType::AmazonS3,
                server_version: None,
                os_hint: None,
                framework: None,
                waf: None,
                cdn: None,
                cloud_provider: Some(CloudProvider::AWS),
            };
        }

        ServerIntelligence {
            server_type: ServerType::Unknown,
            server_version: None,
            os_hint: None,
            framework: None,
            waf: None,
            cdn: None,
            cloud_provider: None,
        }
    }

    /// Extract version from server string
    fn extract_version(server: &str) -> Option<String> {
        // Pattern: Apache/2.4.41 or nginx/1.18.0
        if let Some(slash_pos) = server.find('/') {
            let after_slash = &server[slash_pos + 1..];
            if let Some(space_pos) = after_slash.find(' ') {
                return Some(after_slash[..space_pos].to_string());
            } else {
                return Some(after_slash.to_string());
            }
        }
        None
    }

    /// Extract OS from Apache banner
    /// Example: Apache/2.4.41 (Ubuntu) → Ubuntu
    fn extract_os_from_apache(server: &str) -> Option<String> {
        if let Some(open_paren) = server.find('(') {
            if let Some(close_paren) = server.find(')') {
                return Some(server[open_paren + 1..close_paren].to_string());
            }
        }
        None
    }

    /// Map IIS version to Windows version
    fn iis_to_windows_version(iis_version: &Option<String>) -> Option<String> {
        match iis_version.as_deref() {
            Some("10.0") => Some("Windows Server 2016/2019".to_string()),
            Some("8.5") => Some("Windows Server 2012 R2".to_string()),
            Some("8.0") => Some("Windows Server 2012".to_string()),
            Some("7.5") => Some("Windows Server 2008 R2".to_string()),
            Some("7.0") => Some("Windows Server 2008".to_string()),
            _ => None,
        }
    }

    /// Detect framework from cookies
    pub fn detect_framework_from_cookies(&self) -> Vec<Framework> {
        let mut frameworks = Vec::new();

        if self.cookies.contains_key("PHPSESSID") {
            frameworks.push(Framework::PHP);
        }

        if self.cookies.contains_key("JSESSIONID") {
            frameworks.push(Framework::Java);
        }

        if self.cookies.contains_key("ASP.NET_SessionId")
            || self.cookies.contains_key("ASPSESSIONID")
        {
            frameworks.push(Framework::AspNet);
        }

        if self.cookies.contains_key(".AspNetCore.Session") {
            frameworks.push(Framework::AspNetCore);
        }

        if self.cookies.contains_key("csrftoken") || self.cookies.contains_key("sessionid") {
            frameworks.push(Framework::Django);
        }

        if self.cookies.contains_key("session") {
            frameworks.push(Framework::Flask);
        }

        if self
            .cookies
            .keys()
            .any(|k| k.starts_with("wordpress_") || k.starts_with("wp-"))
        {
            frameworks.push(Framework::WordPress);
        }

        frameworks
    }

    /// Detect WAF from headers
    pub fn detect_waf(&self) -> Option<Waf> {
        // Cloudflare
        if self.headers.contains_key("cf-ray")
            || self.headers.contains_key("CF-Ray")
            || self.cookies.contains_key("__cfduid")
        {
            return Some(Waf::Cloudflare);
        }

        // Sucuri
        if self.headers.contains_key("x-sucuri-id") || self.headers.contains_key("X-Sucuri-ID") {
            return Some(Waf::Sucuri);
        }

        // Akamai
        if self.headers.contains_key("x-akamai-transformed")
            || self.headers.contains_key("X-Akamai-Transformed")
        {
            return Some(Waf::Akamai);
        }

        // Imperva/Incapsula
        if self.headers.contains_key("x-cdn")
            && self
                .headers
                .get("x-cdn")
                .map(|v| v.contains("Incapsula"))
                .unwrap_or(false)
        {
            return Some(Waf::Imperva);
        }

        // F5 BIG-IP
        if self.cookies.keys().any(|k| k.starts_with("BIGip")) {
            return Some(Waf::F5BigIP);
        }

        None
    }

    /// Detect CDN from headers
    pub fn detect_cdn(&self) -> Option<Cdn> {
        // Cloudflare
        if self.headers.contains_key("cf-ray") || self.headers.contains_key("CF-Ray") {
            return Some(Cdn::Cloudflare);
        }

        // Fastly
        if self.headers.contains_key("fastly-debug-digest")
            || self.headers.contains_key("x-fastly-request-id")
        {
            return Some(Cdn::Fastly);
        }

        // Akamai
        if self.headers.contains_key("x-akamai-transformed") {
            return Some(Cdn::Akamai);
        }

        // CloudFront
        if self.headers.contains_key("x-amz-cf-id")
            || self.headers.contains_key("via")
                && self
                    .headers
                    .get("via")
                    .map(|v| v.contains("CloudFront"))
                    .unwrap_or(false)
        {
            return Some(Cdn::CloudFront);
        }

        None
    }

    /// Detect cloud provider from headers
    pub fn detect_cloud_provider(&self) -> Option<CloudProvider> {
        // AWS
        if self.headers.contains_key("x-amz-request-id")
            || self.headers.contains_key("x-amz-id-2")
            || self.headers.contains_key("x-amz-cf-id")
        {
            return Some(CloudProvider::AWS);
        }

        // Azure
        if self.headers.contains_key("x-ms-request-id") || self.headers.contains_key("x-ms-version")
        {
            return Some(CloudProvider::Azure);
        }

        // GCP
        if self.headers.contains_key("x-goog-generation")
            || self.headers.contains_key("x-goog-metageneration")
        {
            return Some(CloudProvider::GCP);
        }

        // Heroku
        if self
            .headers
            .get("Via")
            .or_else(|| self.headers.get("via"))
            .map(|v| v.contains("heroku"))
            .unwrap_or(false)
        {
            return Some(CloudProvider::Heroku);
        }

        // Vercel
        if self.headers.contains_key("x-vercel-id") || self.headers.contains_key("x-vercel-cache") {
            return Some(CloudProvider::Vercel);
        }

        // Netlify
        if self.headers.contains_key("x-nf-request-id") {
            return Some(CloudProvider::Netlify);
        }

        None
    }

    /// Fingerprint server by header order
    ///
    /// Different web servers send headers in different orders
    /// This is a strong fingerprint even when Server header is removed
    pub fn fingerprint_by_header_order(&self) -> ServerType {
        let order_sig = self.header_order.join("|");

        // Apache: Date|Server|Last-Modified|ETag|Accept-Ranges|Content-Length|Content-Type
        if order_sig.starts_with("Date|Server|Last-Modified") {
            return ServerType::Apache;
        }

        // nginx: Server|Date|Content-Type|Content-Length|Connection
        if order_sig.starts_with("Server|Date|Content-Type") {
            return ServerType::Nginx;
        }

        // IIS: Content-Length|Content-Type|Server|X-Powered-By|Date
        if order_sig.starts_with("Content-Length|Content-Type|Server") {
            return ServerType::IIS;
        }

        ServerType::Unknown
    }

    /// Detect technology from error pages
    pub fn detect_from_error_page(&self) -> Vec<Framework> {
        let mut frameworks = Vec::new();

        if self.status_code == 404 || self.status_code == 500 {
            let body_lower = self.body_snippet.to_lowercase();

            if body_lower.contains("django") {
                frameworks.push(Framework::Django);
            }

            if body_lower.contains("laravel") {
                frameworks.push(Framework::Laravel);
            }

            if body_lower.contains("wordpress") {
                frameworks.push(Framework::WordPress);
            }

            if body_lower.contains("drupal") {
                frameworks.push(Framework::Drupal);
            }

            if body_lower.contains("flask") {
                frameworks.push(Framework::Flask);
            }

            if body_lower.contains("express") {
                frameworks.push(Framework::NodeExpress);
            }
        }

        frameworks
    }

    /// Get comprehensive intelligence
    pub fn get_comprehensive_intelligence(&self) -> ServerIntelligence {
        let mut intel = self.analyze_server_header();

        // Add framework detection
        let frameworks = self.detect_framework_from_cookies();
        if !frameworks.is_empty() {
            intel.framework = Some(frameworks[0].clone());
        }

        // Add WAF detection
        if intel.waf.is_none() {
            intel.waf = self.detect_waf();
        }

        // Add CDN detection
        if intel.cdn.is_none() {
            intel.cdn = self.detect_cdn();
        }

        // Add cloud provider
        if intel.cloud_provider.is_none() {
            intel.cloud_provider = self.detect_cloud_provider();
        }

        // If server type unknown, try header order
        if intel.server_type == ServerType::Unknown {
            intel.server_type = self.fingerprint_by_header_order();
        }

        intel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apache_detection() {
        let mut fp = HttpFingerprint::new();
        fp.headers
            .insert("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());

        let intel = fp.analyze_server_header();
        assert_eq!(intel.server_type, ServerType::Apache);
        assert_eq!(intel.server_version, Some("2.4.41".to_string()));
        assert_eq!(intel.os_hint, Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_nginx_detection() {
        let mut fp = HttpFingerprint::new();
        fp.headers
            .insert("Server".to_string(), "nginx/1.18.0".to_string());

        let intel = fp.analyze_server_header();
        assert_eq!(intel.server_type, ServerType::Nginx);
        assert_eq!(intel.server_version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_framework_from_cookies() {
        let mut fp = HttpFingerprint::new();
        fp.cookies
            .insert("PHPSESSID".to_string(), "abc123".to_string());

        let frameworks = fp.detect_framework_from_cookies();
        assert!(frameworks.contains(&Framework::PHP));
    }

    #[test]
    fn test_cloudflare_detection() {
        let mut fp = HttpFingerprint::new();
        fp.headers
            .insert("cf-ray".to_string(), "12345-SJC".to_string());

        assert_eq!(fp.detect_waf(), Some(Waf::Cloudflare));
        assert_eq!(fp.detect_cdn(), Some(Cdn::Cloudflare));
    }

    #[test]
    fn test_aws_detection() {
        let mut fp = HttpFingerprint::new();
        fp.headers
            .insert("x-amz-request-id".to_string(), "abc123".to_string());

        assert_eq!(fp.detect_cloud_provider(), Some(CloudProvider::AWS));
    }
}
