/// CMS Detection Module
///
/// Multi-method CMS detection with confidence scoring

use super::{CmsScanConfig, CmsType, DetectionResult, HttpResponse};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Duration;

/// CMS Detector with multiple detection methods
pub struct CmsDetector {
    signatures: Vec<CmsSignature>,
}

/// CMS detection signature
struct CmsSignature {
    cms: CmsType,
    method: DetectionMethod,
    pattern: &'static str,
    confidence: u8,
    description: &'static str,
}

/// Detection method types
#[derive(Debug, Clone, Copy)]
enum DetectionMethod {
    /// Check HTML body for pattern
    HtmlBody,
    /// Check HTTP headers
    Header(&'static str),
    /// Check specific path exists
    PathExists,
    /// Check generator meta tag
    MetaGenerator,
    /// Check cookie names
    Cookie,
    /// Check JavaScript files
    JavaScript,
    /// Check CSS files
    Css,
    /// Check robots.txt
    RobotsTxt,
    /// Check specific file content
    FileContent(&'static str),
}

impl CmsDetector {
    pub fn new() -> Self {
        Self {
            signatures: Self::build_signatures(),
        }
    }

    /// Build all CMS signatures
    fn build_signatures() -> Vec<CmsSignature> {
        vec![
            // WordPress signatures
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::HtmlBody,
                pattern: "/wp-content/",
                confidence: 95,
                description: "wp-content directory in HTML",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::HtmlBody,
                pattern: "/wp-includes/",
                confidence: 95,
                description: "wp-includes directory in HTML",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::MetaGenerator,
                pattern: "WordPress",
                confidence: 100,
                description: "WordPress meta generator",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::PathExists,
                pattern: "/wp-login.php",
                confidence: 90,
                description: "wp-login.php exists",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::PathExists,
                pattern: "/xmlrpc.php",
                confidence: 70,
                description: "xmlrpc.php exists",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::Cookie,
                pattern: "wordpress_",
                confidence: 85,
                description: "WordPress cookie prefix",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::RobotsTxt,
                pattern: "wp-admin",
                confidence: 80,
                description: "wp-admin in robots.txt",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::Header("X-Powered-By"),
                pattern: "WordPress",
                confidence: 90,
                description: "WordPress in X-Powered-By",
            },
            CmsSignature {
                cms: CmsType::WordPress,
                method: DetectionMethod::PathExists,
                pattern: "/wp-json/",
                confidence: 85,
                description: "WP REST API endpoint",
            },

            // Drupal signatures
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::HtmlBody,
                pattern: "/sites/default/files",
                confidence: 95,
                description: "Drupal sites/default/files",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::HtmlBody,
                pattern: "/sites/all/",
                confidence: 90,
                description: "Drupal sites/all directory",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::MetaGenerator,
                pattern: "Drupal",
                confidence: 100,
                description: "Drupal meta generator",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::Header("X-Drupal-Cache"),
                pattern: "",
                confidence: 100,
                description: "X-Drupal-Cache header",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::Header("X-Generator"),
                pattern: "Drupal",
                confidence: 100,
                description: "Drupal in X-Generator",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::PathExists,
                pattern: "/core/misc/drupal.js",
                confidence: 95,
                description: "Drupal core JS file",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::FileContent("/CHANGELOG.txt"),
                pattern: "Drupal",
                confidence: 95,
                description: "Drupal changelog",
            },
            CmsSignature {
                cms: CmsType::Drupal,
                method: DetectionMethod::Cookie,
                pattern: "SSESS",
                confidence: 80,
                description: "Drupal session cookie",
            },

            // Joomla signatures
            CmsSignature {
                cms: CmsType::Joomla,
                method: DetectionMethod::HtmlBody,
                pattern: "/media/jui/",
                confidence: 95,
                description: "Joomla media/jui directory",
            },
            CmsSignature {
                cms: CmsType::Joomla,
                method: DetectionMethod::HtmlBody,
                pattern: "/components/com_",
                confidence: 90,
                description: "Joomla components directory",
            },
            CmsSignature {
                cms: CmsType::Joomla,
                method: DetectionMethod::MetaGenerator,
                pattern: "Joomla",
                confidence: 100,
                description: "Joomla meta generator",
            },
            CmsSignature {
                cms: CmsType::Joomla,
                method: DetectionMethod::PathExists,
                pattern: "/administrator/",
                confidence: 70,
                description: "Joomla administrator path",
            },
            CmsSignature {
                cms: CmsType::Joomla,
                method: DetectionMethod::FileContent("/administrator/manifests/files/joomla.xml"),
                pattern: "<version>",
                confidence: 95,
                description: "Joomla manifest file",
            },
            CmsSignature {
                cms: CmsType::Joomla,
                method: DetectionMethod::HtmlBody,
                pattern: "Joomla!",
                confidence: 85,
                description: "Joomla! in HTML",
            },

            // Magento signatures
            CmsSignature {
                cms: CmsType::Magento,
                method: DetectionMethod::HtmlBody,
                pattern: "/skin/frontend/",
                confidence: 95,
                description: "Magento skin directory",
            },
            CmsSignature {
                cms: CmsType::Magento,
                method: DetectionMethod::HtmlBody,
                pattern: "Mage.Cookies",
                confidence: 95,
                description: "Magento Mage.Cookies JS",
            },
            CmsSignature {
                cms: CmsType::Magento,
                method: DetectionMethod::Cookie,
                pattern: "frontend=",
                confidence: 70,
                description: "Magento frontend cookie",
            },
            CmsSignature {
                cms: CmsType::Magento,
                method: DetectionMethod::PathExists,
                pattern: "/admin/",
                confidence: 50,
                description: "Magento admin path",
            },

            // Shopify signatures
            CmsSignature {
                cms: CmsType::Shopify,
                method: DetectionMethod::HtmlBody,
                pattern: "cdn.shopify.com",
                confidence: 100,
                description: "Shopify CDN",
            },
            CmsSignature {
                cms: CmsType::Shopify,
                method: DetectionMethod::HtmlBody,
                pattern: "Shopify.theme",
                confidence: 95,
                description: "Shopify.theme JS object",
            },
            CmsSignature {
                cms: CmsType::Shopify,
                method: DetectionMethod::Header("X-ShopId"),
                pattern: "",
                confidence: 100,
                description: "X-ShopId header",
            },

            // Ghost signatures
            CmsSignature {
                cms: CmsType::Ghost,
                method: DetectionMethod::MetaGenerator,
                pattern: "Ghost",
                confidence: 100,
                description: "Ghost meta generator",
            },
            CmsSignature {
                cms: CmsType::Ghost,
                method: DetectionMethod::HtmlBody,
                pattern: "/ghost/api/",
                confidence: 95,
                description: "Ghost API path",
            },
            CmsSignature {
                cms: CmsType::Ghost,
                method: DetectionMethod::PathExists,
                pattern: "/ghost/",
                confidence: 85,
                description: "Ghost admin path",
            },

            // TYPO3 signatures
            CmsSignature {
                cms: CmsType::TYPO3,
                method: DetectionMethod::HtmlBody,
                pattern: "typo3temp/",
                confidence: 95,
                description: "TYPO3 temp directory",
            },
            CmsSignature {
                cms: CmsType::TYPO3,
                method: DetectionMethod::MetaGenerator,
                pattern: "TYPO3",
                confidence: 100,
                description: "TYPO3 meta generator",
            },
            CmsSignature {
                cms: CmsType::TYPO3,
                method: DetectionMethod::PathExists,
                pattern: "/typo3/",
                confidence: 90,
                description: "TYPO3 backend path",
            },

            // Static site generators
            CmsSignature {
                cms: CmsType::Hugo,
                method: DetectionMethod::MetaGenerator,
                pattern: "Hugo",
                confidence: 100,
                description: "Hugo meta generator",
            },
            CmsSignature {
                cms: CmsType::Jekyll,
                method: DetectionMethod::MetaGenerator,
                pattern: "Jekyll",
                confidence: 100,
                description: "Jekyll meta generator",
            },
            CmsSignature {
                cms: CmsType::Gatsby,
                method: DetectionMethod::HtmlBody,
                pattern: "___gatsby",
                confidence: 95,
                description: "Gatsby ID in HTML",
            },
            CmsSignature {
                cms: CmsType::NextJS,
                method: DetectionMethod::HtmlBody,
                pattern: "__NEXT_DATA__",
                confidence: 95,
                description: "Next.js data object",
            },

            // Hosted platforms
            CmsSignature {
                cms: CmsType::Squarespace,
                method: DetectionMethod::HtmlBody,
                pattern: "squarespace.com",
                confidence: 95,
                description: "Squarespace in HTML",
            },
            CmsSignature {
                cms: CmsType::Wix,
                method: DetectionMethod::HtmlBody,
                pattern: "wix.com",
                confidence: 95,
                description: "Wix in HTML",
            },
            CmsSignature {
                cms: CmsType::Webflow,
                method: DetectionMethod::HtmlBody,
                pattern: "webflow.com",
                confidence: 95,
                description: "Webflow in HTML",
            },
        ]
    }

    /// Detect CMS type
    pub fn detect(&self, url: &str, config: &CmsScanConfig) -> DetectionResult {
        let mut result = DetectionResult::unknown();
        let mut scores: std::collections::HashMap<CmsType, u16> = std::collections::HashMap::new();
        let mut methods: std::collections::HashMap<CmsType, Vec<String>> = std::collections::HashMap::new();

        // Fetch main page
        let main_response = match self.fetch(url, config) {
            Some(r) => r,
            None => return result,
        };

        // Check all signatures against main page
        for sig in &self.signatures {
            let matched = match sig.method {
                DetectionMethod::HtmlBody => main_response.contains(sig.pattern),
                DetectionMethod::Header(header_name) => {
                    if let Some(value) = main_response.get_header(header_name) {
                        sig.pattern.is_empty() || value.contains(sig.pattern)
                    } else {
                        false
                    }
                }
                DetectionMethod::MetaGenerator => {
                    self.check_meta_generator(&main_response.body, sig.pattern)
                }
                DetectionMethod::Cookie => {
                    if let Some(cookie) = main_response.get_header("Set-Cookie") {
                        cookie.contains(sig.pattern)
                    } else {
                        false
                    }
                }
                DetectionMethod::PathExists => {
                    let check_url = format!("{}{}", url.trim_end_matches('/'), sig.pattern);
                    self.check_path_exists(&check_url, config)
                }
                DetectionMethod::RobotsTxt => {
                    let robots_url = format!("{}/robots.txt", url.trim_end_matches('/'));
                    if let Some(robots) = self.fetch(&robots_url, config) {
                        robots.contains(sig.pattern)
                    } else {
                        false
                    }
                }
                DetectionMethod::FileContent(path) => {
                    let file_url = format!("{}{}", url.trim_end_matches('/'), path);
                    if let Some(content) = self.fetch(&file_url, config) {
                        content.contains(sig.pattern)
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if matched {
                *scores.entry(sig.cms).or_insert(0) += sig.confidence as u16;
                methods.entry(sig.cms).or_default().push(sig.description.to_string());
            }
        }

        // Find CMS with highest score
        if let Some((cms, score)) = scores.iter().max_by_key(|(_, s)| *s) {
            result.cms_type = *cms;
            result.confidence = ((*score).min(100) as u8);
            result.methods = methods.get(cms).cloned().unwrap_or_default();

            // Try to detect version
            result.version = self.detect_version(*cms, url, &main_response, config);
        }

        result
    }

    /// Check meta generator tag
    fn check_meta_generator(&self, html: &str, pattern: &str) -> bool {
        // Look for <meta name="generator" content="...">
        let html_lower = html.to_lowercase();
        if let Some(start) = html_lower.find("name=\"generator\"") {
            // Find content attribute
            let search_area = &html[start.saturating_sub(100)..html.len().min(start + 200)];
            if let Some(content_start) = search_area.to_lowercase().find("content=\"") {
                let content_area = &search_area[content_start + 9..];
                if let Some(end) = content_area.find('"') {
                    let content = &content_area[..end];
                    return content.to_lowercase().contains(&pattern.to_lowercase());
                }
            }
        }
        false
    }

    /// Check if path exists (returns 200 OK)
    fn check_path_exists(&self, url: &str, config: &CmsScanConfig) -> bool {
        if let Some(response) = self.fetch(url, config) {
            response.status_code == 200
        } else {
            false
        }
    }

    /// Detect CMS version
    fn detect_version(&self, cms: CmsType, url: &str, main_response: &HttpResponse, config: &CmsScanConfig) -> Option<String> {
        match cms {
            CmsType::WordPress => self.detect_wordpress_version(url, main_response, config),
            CmsType::Drupal => self.detect_drupal_version(url, config),
            CmsType::Joomla => self.detect_joomla_version(url, config),
            _ => None,
        }
    }

    /// Detect WordPress version
    fn detect_wordpress_version(&self, url: &str, main_response: &HttpResponse, config: &CmsScanConfig) -> Option<String> {
        // Method 1: Meta generator
        if let Some(version) = self.extract_meta_generator_version(&main_response.body, "WordPress") {
            return Some(version);
        }

        // Method 2: readme.html
        let readme_url = format!("{}/readme.html", url.trim_end_matches('/'));
        if let Some(readme) = self.fetch(&readme_url, config) {
            if let Some(version) = self.extract_version_from_html(&readme.body, r"Version (\d+\.\d+(?:\.\d+)?)") {
                return Some(version);
            }
        }

        // Method 3: feed
        let feed_url = format!("{}/feed/", url.trim_end_matches('/'));
        if let Some(feed) = self.fetch(&feed_url, config) {
            if let Some(version) = self.extract_meta_generator_version(&feed.body, "WordPress") {
                return Some(version);
            }
        }

        // Method 4: wp-includes/version.php hash matching (aggressive)
        if config.aggressive {
            // Could implement hash-based version detection here
        }

        None
    }

    /// Detect Drupal version
    fn detect_drupal_version(&self, url: &str, config: &CmsScanConfig) -> Option<String> {
        // Method 1: CHANGELOG.txt
        let changelog_url = format!("{}/CHANGELOG.txt", url.trim_end_matches('/'));
        if let Some(changelog) = self.fetch(&changelog_url, config) {
            // Look for "Drupal X.Y.Z"
            for line in changelog.body.lines().take(10) {
                if line.contains("Drupal ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if *part == "Drupal" && i + 1 < parts.len() {
                            let version = parts[i + 1].trim_end_matches(',');
                            if version.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                                return Some(version.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Method 2: core/modules/system/system.info.yml (Drupal 8+)
        let system_url = format!("{}/core/modules/system/system.info.yml", url.trim_end_matches('/'));
        if let Some(system) = self.fetch(&system_url, config) {
            if let Some(version) = self.extract_yaml_version(&system.body) {
                return Some(version);
            }
        }

        None
    }

    /// Detect Joomla version
    fn detect_joomla_version(&self, url: &str, config: &CmsScanConfig) -> Option<String> {
        // Method 1: administrator/manifests/files/joomla.xml
        let manifest_url = format!("{}/administrator/manifests/files/joomla.xml", url.trim_end_matches('/'));
        if let Some(manifest) = self.fetch(&manifest_url, config) {
            if let Some(version) = self.extract_xml_version(&manifest.body) {
                return Some(version);
            }
        }

        // Method 2: language/en-GB/en-GB.xml
        let lang_url = format!("{}/language/en-GB/en-GB.xml", url.trim_end_matches('/'));
        if let Some(lang) = self.fetch(&lang_url, config) {
            if let Some(version) = self.extract_xml_version(&lang.body) {
                return Some(version);
            }
        }

        None
    }

    /// Extract version from meta generator tag
    fn extract_meta_generator_version(&self, html: &str, cms_name: &str) -> Option<String> {
        let html_lower = html.to_lowercase();
        let cms_lower = cms_name.to_lowercase();

        // Find generator content
        if let Some(gen_pos) = html_lower.find("name=\"generator\"") {
            let search_area = &html[gen_pos.saturating_sub(100)..html.len().min(gen_pos + 200)];
            if let Some(content_start) = search_area.to_lowercase().find("content=\"") {
                let content_area = &search_area[content_start + 9..];
                if let Some(end) = content_area.find('"') {
                    let content = &content_area[..end];
                    if content.to_lowercase().contains(&cms_lower) {
                        // Extract version number
                        let parts: Vec<&str> = content.split_whitespace().collect();
                        for part in parts.iter().skip(1) {
                            if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                                return Some(part.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract version using simple pattern
    fn extract_version_from_html(&self, html: &str, _pattern: &str) -> Option<String> {
        // Simple version extraction
        for line in html.lines() {
            if line.contains("Version") {
                let words: Vec<&str> = line.split_whitespace().collect();
                for (i, word) in words.iter().enumerate() {
                    if *word == "Version" && i + 1 < words.len() {
                        let version = words[i + 1].trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract version from YAML
    fn extract_yaml_version(&self, content: &str) -> Option<String> {
        for line in content.lines() {
            if line.starts_with("version:") {
                let value = line.trim_start_matches("version:").trim().trim_matches('\'').trim_matches('"');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    /// Extract version from XML
    fn extract_xml_version(&self, content: &str) -> Option<String> {
        // Look for <version>X.Y.Z</version>
        if let Some(start) = content.find("<version>") {
            let after = &content[start + 9..];
            if let Some(end) = after.find("</version>") {
                let version = &after[..end];
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
        None
    }

    /// Fetch URL and return response
    fn fetch(&self, url: &str, config: &CmsScanConfig) -> Option<HttpResponse> {
        // Parse URL
        let (host, port, path, use_tls) = self.parse_url(url)?;

        // Build request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Connection: close\r\n\
             \r\n",
            path, host, config.user_agent
        );

        // Connect
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().ok()?,
            config.timeout
        ).ok()?;

        stream.set_read_timeout(Some(config.timeout)).ok()?;
        stream.set_write_timeout(Some(config.timeout)).ok()?;

        if use_tls {
            // For TLS, we'd need our TLS implementation
            // For now, return None for HTTPS
            return None;
        }

        // Send request
        stream.write_all(request.as_bytes()).ok()?;

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        // Parse response
        self.parse_response(&response, url)
    }

    /// Parse URL into components
    fn parse_url(&self, url: &str) -> Option<(String, u16, String, bool)> {
        let url = url.trim();
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
            Some(pos) => {
                let h = &host_port[..pos];
                let p = host_port[pos + 1..].parse().ok()?;
                (h, p)
            }
            None => (host_port, default_port),
        };

        Some((host.to_string(), port, path.to_string(), use_tls))
    }

    /// Parse HTTP response
    fn parse_response(&self, data: &[u8], url: &str) -> Option<HttpResponse> {
        let text = String::from_utf8_lossy(data);
        let mut lines = text.lines();

        // Parse status line
        let status_line = lines.next()?;
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        let status_code: u16 = parts[1].parse().ok()?;

        // Parse headers
        let mut headers = Vec::new();
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some(pos) = line.find(':') {
                let name = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                headers.push((name, value));
            }
        }

        // Rest is body
        let body_start = text.find("\r\n\r\n").map(|p| p + 4)
            .or_else(|| text.find("\n\n").map(|p| p + 2))
            .unwrap_or(text.len());
        let body = text[body_start..].to_string();

        Some(HttpResponse {
            status_code,
            headers,
            body,
            url: url.to_string(),
        })
    }
}

impl Default for CmsDetector {
    fn default() -> Self {
        Self::new()
    }
}
