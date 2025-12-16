/// HTTP Fingerprinting & Technology Detection
///
/// Extract intelligence from HTTP responses:
/// - Web server detection (nginx, Apache, IIS, etc.)
/// - WAF/CDN detection (Cloudflare, AWS, Akamai, etc.)
/// - Technology stack (PHP, ASP.NET, Node.js, etc.)
/// - CMS detection (WordPress, Drupal, Joomla, etc.)
/// - Framework detection (Laravel, Django, Rails, etc.)
use crate::protocols::http::HttpClient;
use std::collections::HashMap;

#[derive(Debug)]
pub struct HTTPFingerprint {
    pub url: String,
    pub server: Option<WebServer>,
    pub waf: Option<WAFProvider>,
    pub technologies: Vec<Technology>,
    pub cms: Option<CMS>,
    pub framework: Option<Framework>,
    pub headers_analyzed: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebServer {
    Nginx(Option<String>), // version if detected
    Apache(Option<String>),
    IIS(Option<String>),
    Cloudflare,
    LiteSpeed(Option<String>),
    Caddy(Option<String>),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum WAFProvider {
    Cloudflare,
    AWS,
    Akamai,
    Sucuri,
    Imperva,
    ModSecurity,
    F5BigIP,
    Barracuda,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Technology {
    PHP(Option<String>),
    ASPNET(Option<String>),
    NodeJS,
    Java,
    Python,
    Ruby,
    Go,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CMS {
    WordPress(Option<String>),
    Drupal(Option<String>),
    Joomla(Option<String>),
    Magento(Option<String>),
    Shopify,
    Wix,
    Squarespace,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Framework {
    Laravel,
    Django,
    Rails,
    Express,
    Spring,
    Flask,
    NextJS,
    Unknown(String),
}

impl HTTPFingerprint {
    /// Fingerprint a web server by analyzing HTTP response
    pub fn analyze(url: &str) -> Result<Self, String> {
        let client = HttpClient::new();

        // Send GET request
        let response = client.get(url)?;

        // Get headers and body
        let headers = &response.headers;
        let body = String::from_utf8_lossy(&response.body).to_string();

        // Detect web server
        let server = Self::detect_web_server(headers);

        // Detect WAF/CDN
        let waf = Self::detect_waf(headers);

        // Detect technologies
        let technologies = Self::detect_technologies(headers, &body);

        // Detect CMS
        let cms = Self::detect_cms(headers, &body);

        // Detect framework
        let framework = Self::detect_framework(headers, &body);

        Ok(HTTPFingerprint {
            url: url.to_string(),
            server,
            waf,
            technologies,
            cms,
            framework,
            headers_analyzed: headers.len(),
        })
    }

    /// Detect web server from headers
    fn detect_web_server(headers: &HashMap<String, String>) -> Option<WebServer> {
        if let Some(server_header) = headers.get("server") {
            let lower = server_header.to_lowercase();

            if lower.contains("nginx") {
                let version = Self::extract_version(&lower, "nginx/");
                return Some(WebServer::Nginx(version));
            }

            if lower.contains("apache") {
                let version = Self::extract_version(&lower, "apache/");
                return Some(WebServer::Apache(version));
            }

            if lower.contains("microsoft-iis") {
                let version = Self::extract_version(&lower, "microsoft-iis/");
                return Some(WebServer::IIS(version));
            }

            if lower.contains("cloudflare") {
                return Some(WebServer::Cloudflare);
            }

            if lower.contains("litespeed") {
                let version = Self::extract_version(&lower, "litespeed/");
                return Some(WebServer::LiteSpeed(version));
            }

            if lower.contains("caddy") {
                let version = Self::extract_version(&lower, "caddy/");
                return Some(WebServer::Caddy(version));
            }

            return Some(WebServer::Unknown(server_header.clone()));
        }

        // Even without Server header, try to infer from other headers
        if headers.contains_key("cf-ray") {
            return Some(WebServer::Cloudflare);
        }

        None
    }

    /// Detect WAF/CDN from headers
    fn detect_waf(headers: &HashMap<String, String>) -> Option<WAFProvider> {
        // Cloudflare
        if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
            return Some(WAFProvider::Cloudflare);
        }

        // AWS WAF
        if headers.contains_key("x-amz-cf-id") || headers.contains_key("x-amz-cf-pop") {
            return Some(WAFProvider::AWS);
        }

        // Akamai
        if headers.contains_key("x-akamai-transformed")
            || headers.contains_key("x-akamai-request-id")
        {
            return Some(WAFProvider::Akamai);
        }

        // Sucuri
        if headers.contains_key("x-sucuri-id") || headers.contains_key("x-sucuri-cache") {
            return Some(WAFProvider::Sucuri);
        }

        // Imperva (Incapsula)
        if headers.contains_key("x-iinfo") || headers.contains_key("x-cdn") {
            if let Some(x_cdn) = headers.get("x-cdn") {
                if x_cdn.to_lowercase().contains("incapsula") {
                    return Some(WAFProvider::Imperva);
                }
            }
        }

        None
    }

    /// Detect technology stack from headers and response body
    fn detect_technologies(headers: &HashMap<String, String>, response: &str) -> Vec<Technology> {
        let mut techs = Vec::new();

        // Check X-Powered-By header
        if let Some(powered_by) = headers.get("x-powered-by") {
            let lower = powered_by.to_lowercase();

            if lower.contains("php") {
                let version = Self::extract_version(&lower, "php/");
                techs.push(Technology::PHP(version));
            }

            if lower.contains("asp.net") {
                let version = Self::extract_version(&lower, "asp.net/");
                techs.push(Technology::ASPNET(version));
            }

            if lower.contains("express") {
                techs.push(Technology::NodeJS);
            }
        }

        // Check cookie patterns
        if response.contains("PHPSESSID") && !techs.iter().any(|t| matches!(t, Technology::PHP(_)))
        {
            techs.push(Technology::PHP(None));
        }

        if response.contains("JSESSIONID") {
            techs.push(Technology::Java);
        }

        if (response.contains("ASP.NET_SessionId") || response.contains("X-AspNet-Version"))
            && !techs.iter().any(|t| matches!(t, Technology::ASPNET(_)))
        {
            techs.push(Technology::ASPNET(None));
        }

        techs
    }

    /// Detect CMS from headers and response body
    fn detect_cms(headers: &HashMap<String, String>, response: &str) -> Option<CMS> {
        let response_lower = response.to_lowercase();

        // WordPress
        if response_lower.contains("/wp-content/")
            || response_lower.contains("/wp-includes/")
            || response_lower.contains("wp-json")
        {
            return Some(CMS::WordPress(None));
        }

        // Drupal
        if let Some(generator) = headers.get("x-generator") {
            if generator.to_lowercase().contains("drupal") {
                return Some(CMS::Drupal(None));
            }
        }

        if response_lower.contains("/sites/default/") || response_lower.contains("drupal.js") {
            return Some(CMS::Drupal(None));
        }

        // Joomla
        if response_lower.contains("/components/com_") || response_lower.contains("joomla") {
            return Some(CMS::Joomla(None));
        }

        // Magento
        if response_lower.contains("/skin/frontend/") || headers.contains_key("x-magento-tags") {
            return Some(CMS::Magento(None));
        }

        // Shopify
        if response_lower.contains("cdn.shopify.com") || response_lower.contains("shopify") {
            return Some(CMS::Shopify);
        }

        None
    }

    /// Detect framework from cookies and headers
    fn detect_framework(headers: &HashMap<String, String>, response: &str) -> Option<Framework> {
        let response_lower = response.to_lowercase();

        // Laravel
        if response_lower.contains("laravel_session") || response_lower.contains("x-csrf-token") {
            return Some(Framework::Laravel);
        }

        // Django
        if response_lower.contains("csrftoken") && response_lower.contains("sessionid") {
            return Some(Framework::Django);
        }

        // Express
        if headers
            .get("x-powered-by")
            .map_or(false, |v| v.contains("Express"))
        {
            return Some(Framework::Express);
        }

        // Next.js
        if response_lower.contains("__next") || response_lower.contains("_next/static") {
            return Some(Framework::NextJS);
        }

        None
    }

    /// Extract version from a string like "nginx/1.18.0"
    fn extract_version(text: &str, prefix: &str) -> Option<String> {
        if let Some(pos) = text.find(prefix) {
            let version_start = pos + prefix.len();
            let version_end = text[version_start..]
                .find(|c: char| !c.is_numeric() && c != '.')
                .map(|i| version_start + i)
                .unwrap_or(text.len());

            Some(text[version_start..version_end].to_string())
        } else {
            None
        }
    }

    /// Generate human-readable fingerprint report
    pub fn report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("URL: {}\n\n", self.url));

        if let Some(ref server) = self.server {
            report.push_str(&format!("Web Server: {:?}\n", server));
        }

        if let Some(ref waf) = self.waf {
            report.push_str(&format!("WAF/CDN: {:?}\n", waf));
        }

        if !self.technologies.is_empty() {
            report.push_str("\nTechnologies:\n");
            for tech in &self.technologies {
                report.push_str(&format!("  - {:?}\n", tech));
            }
        }

        if let Some(ref cms) = self.cms {
            report.push_str(&format!("\nCMS: {:?}\n", cms));
        }

        if let Some(ref framework) = self.framework {
            report.push_str(&format!("Framework: {:?}\n", framework));
        }

        report.push_str(&format!("\nHeaders analyzed: {}\n", self.headers_analyzed));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version() {
        assert_eq!(
            HTTPFingerprint::extract_version("nginx/1.18.0", "nginx/"),
            Some("1.18.0".to_string())
        );
        assert_eq!(
            HTTPFingerprint::extract_version("Apache/2.4.41 (Ubuntu)", "apache/"),
            Some("2.4.41".to_string())
        );
    }
}
