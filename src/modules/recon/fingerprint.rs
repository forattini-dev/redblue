//! Technology Fingerprinting Engine
//!
//! Extract technology fingerprints from HTTP headers, TLS certificates, and service banners.
//! Maps detected technologies to CPE identifiers for vulnerability correlation.
//!
//! ## Data Sources
//!
//! - **HTTP Headers**: Server, X-Powered-By, X-AspNet-Version, X-Generator
//! - **TLS Certificates**: CN, issuer patterns, SAN entries
//! - **Service Banners**: SSH, SMTP, FTP banners
//! - **HTML Content**: Meta generator tags, framework indicators

use crate::modules::recon::vuln::{generate_cpe, DetectedTech, TechCategory};
use std::collections::HashMap;

/// Fingerprint extraction engine
pub struct FingerprintEngine {
    /// Detection results
    results: Vec<DetectedTech>,
}

impl FingerprintEngine {
    /// Create a new fingerprint engine
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Extract fingerprints from HTTP headers
    pub fn extract_from_http_headers(&mut self, headers: &HashMap<String, String>) {
        // Server header - most common source
        if let Some(server) = headers.get("server").or(headers.get("Server")) {
            self.parse_server_header(server);
        }

        // X-Powered-By header - runtime/framework info
        if let Some(powered_by) = headers.get("x-powered-by").or(headers.get("X-Powered-By")) {
            self.parse_powered_by_header(powered_by);
        }

        // X-AspNet-Version - .NET specific
        if let Some(aspnet) = headers
            .get("x-aspnet-version")
            .or(headers.get("X-AspNet-Version"))
        {
            self.add_detection(
                "asp.net",
                Some(aspnet),
                TechCategory::Runtime,
                0.9,
                "http_header",
            );
        }

        // X-AspNetMvc-Version - ASP.NET MVC
        if let Some(mvc) = headers
            .get("x-aspnetmvc-version")
            .or(headers.get("X-AspNetMvc-Version"))
        {
            self.add_detection(
                "asp.net_mvc",
                Some(mvc),
                TechCategory::Framework,
                0.9,
                "http_header",
            );
        }

        // X-Generator - CMS/Framework
        if let Some(generator) = headers.get("x-generator").or(headers.get("X-Generator")) {
            self.parse_generator_header(generator);
        }

        // X-Drupal-Cache or X-Drupal-Dynamic-Cache
        if headers.contains_key("x-drupal-cache")
            || headers.contains_key("X-Drupal-Cache")
            || headers.contains_key("x-drupal-dynamic-cache")
            || headers.contains_key("X-Drupal-Dynamic-Cache")
        {
            self.add_detection("drupal", None, TechCategory::Cms, 0.85, "http_header");
        }

        // X-Varnish - Varnish cache
        if headers.contains_key("x-varnish") || headers.contains_key("X-Varnish") {
            self.add_detection("varnish", None, TechCategory::Proxy, 0.9, "http_header");
        }

        // X-Cache - Generic cache indicator
        if let Some(cache) = headers.get("x-cache").or(headers.get("X-Cache")) {
            if cache.to_lowercase().contains("cloudflare") {
                self.add_detection("cloudflare", None, TechCategory::Cdn, 0.9, "http_header");
            } else if cache.to_lowercase().contains("varnish") {
                self.add_detection("varnish", None, TechCategory::Proxy, 0.8, "http_header");
            }
        }

        // CF-Ray - Cloudflare specific
        if headers.contains_key("cf-ray") || headers.contains_key("CF-Ray") {
            self.add_detection("cloudflare", None, TechCategory::Cdn, 0.95, "http_header");
        }

        // X-Amz-* - AWS headers
        for key in headers.keys() {
            if key.to_lowercase().starts_with("x-amz-") {
                self.add_detection("aws", None, TechCategory::Cdn, 0.8, "http_header");
                break;
            }
        }

        // Via header - proxy info
        if let Some(via) = headers.get("via").or(headers.get("Via")) {
            self.parse_via_header(via);
        }
    }

    /// Parse Server header value
    fn parse_server_header(&mut self, value: &str) {
        let lower = value.to_lowercase();

        // nginx/1.18.0
        if let Some(version) = self.extract_version(&lower, "nginx") {
            self.add_detection(
                "nginx",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.95,
                "http_header",
            );
        } else if lower.contains("nginx") {
            self.add_detection("nginx", None, TechCategory::WebServer, 0.9, "http_header");
        }

        // Apache/2.4.41 (Ubuntu)
        if let Some(version) = self.extract_version(&lower, "apache") {
            self.add_detection(
                "apache",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.95,
                "http_header",
            );
            // Try to extract OS from parentheses
            if let Some(os) = self.extract_parentheses_content(value) {
                let os_lower = os.to_lowercase();
                if os_lower.contains("ubuntu") {
                    self.add_detection(
                        "ubuntu",
                        None,
                        TechCategory::OperatingSystem,
                        0.7,
                        "http_header",
                    );
                } else if os_lower.contains("debian") {
                    self.add_detection(
                        "debian",
                        None,
                        TechCategory::OperatingSystem,
                        0.7,
                        "http_header",
                    );
                } else if os_lower.contains("centos") {
                    self.add_detection(
                        "centos",
                        None,
                        TechCategory::OperatingSystem,
                        0.7,
                        "http_header",
                    );
                } else if os_lower.contains("win") || os_lower.contains("windows") {
                    self.add_detection(
                        "windows_server",
                        None,
                        TechCategory::OperatingSystem,
                        0.7,
                        "http_header",
                    );
                }
            }
        } else if lower.contains("apache") {
            self.add_detection("apache", None, TechCategory::WebServer, 0.9, "http_header");
        }

        // Microsoft-IIS/10.0
        if let Some(version) = self.extract_version(&lower, "microsoft-iis") {
            self.add_detection(
                "iis",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.95,
                "http_header",
            );
        } else if lower.contains("iis") || lower.contains("microsoft-iis") {
            self.add_detection("iis", None, TechCategory::WebServer, 0.9, "http_header");
        }

        // LiteSpeed
        if let Some(version) = self.extract_version(&lower, "litespeed") {
            self.add_detection(
                "litespeed",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.95,
                "http_header",
            );
        } else if lower.contains("litespeed") {
            self.add_detection(
                "litespeed",
                None,
                TechCategory::WebServer,
                0.9,
                "http_header",
            );
        }

        // Caddy
        if lower.contains("caddy") {
            self.add_detection("caddy", None, TechCategory::WebServer, 0.9, "http_header");
        }

        // OpenResty (nginx-based)
        if let Some(version) = self.extract_version(&lower, "openresty") {
            self.add_detection(
                "nginx",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.9,
                "http_header",
            );
        } else if lower.contains("openresty") {
            self.add_detection("nginx", None, TechCategory::WebServer, 0.85, "http_header");
        }

        // gunicorn/20.0.4
        if let Some(version) = self.extract_version(&lower, "gunicorn") {
            self.add_detection(
                "gunicorn",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.95,
                "http_header",
            );
        } else if lower.contains("gunicorn") {
            self.add_detection(
                "gunicorn",
                None,
                TechCategory::WebServer,
                0.9,
                "http_header",
            );
        }

        // uvicorn
        if lower.contains("uvicorn") {
            self.add_detection("uvicorn", None, TechCategory::WebServer, 0.9, "http_header");
        }

        // Tomcat
        if lower.contains("tomcat") {
            let version = self.extract_version(&lower, "tomcat");
            self.add_detection(
                "tomcat",
                version.as_deref(),
                TechCategory::WebServer,
                0.9,
                "http_header",
            );
        }

        // Jetty
        if let Some(version) = self.extract_version(&lower, "jetty") {
            self.add_detection(
                "jetty",
                Some(version.as_str()),
                TechCategory::WebServer,
                0.95,
                "http_header",
            );
        } else if lower.contains("jetty") {
            self.add_detection("jetty", None, TechCategory::WebServer, 0.9, "http_header");
        }

        // cloudflare
        if lower.contains("cloudflare") {
            self.add_detection("cloudflare", None, TechCategory::Cdn, 0.95, "http_header");
        }

        // AmazonS3
        if lower.contains("amazons3") || lower.contains("amazon s3") {
            self.add_detection("aws_s3", None, TechCategory::Cdn, 0.95, "http_header");
        }
    }

    /// Parse X-Powered-By header
    fn parse_powered_by_header(&mut self, value: &str) {
        let lower = value.to_lowercase();

        // PHP/7.4.3
        if let Some(version) = self.extract_version(&lower, "php") {
            self.add_detection(
                "php",
                Some(version.as_str()),
                TechCategory::Runtime,
                0.95,
                "http_header",
            );
        } else if lower.contains("php") {
            self.add_detection("php", None, TechCategory::Runtime, 0.9, "http_header");
        }

        // ASP.NET
        if lower.contains("asp.net") {
            self.add_detection("asp.net", None, TechCategory::Runtime, 0.9, "http_header");
        }

        // Express
        if lower.contains("express") {
            self.add_detection("express", None, TechCategory::Framework, 0.9, "http_header");
            self.add_detection("nodejs", None, TechCategory::Runtime, 0.7, "http_header");
        }

        // Django
        if lower.contains("django") {
            self.add_detection("django", None, TechCategory::Framework, 0.9, "http_header");
            self.add_detection("python", None, TechCategory::Runtime, 0.7, "http_header");
        }

        // Flask
        if lower.contains("flask") {
            self.add_detection("flask", None, TechCategory::Framework, 0.9, "http_header");
            self.add_detection("python", None, TechCategory::Runtime, 0.7, "http_header");
        }

        // Ruby on Rails
        if lower.contains("phusion passenger") || lower.contains("mod_rack") {
            self.add_detection(
                "ruby_on_rails",
                None,
                TechCategory::Framework,
                0.8,
                "http_header",
            );
        }

        // Servlet
        if lower.contains("servlet") {
            self.add_detection("java", None, TechCategory::Runtime, 0.7, "http_header");
        }

        // Next.js
        if lower.contains("next.js") {
            self.add_detection("nextjs", None, TechCategory::Framework, 0.9, "http_header");
        }

        // Nuxt
        if lower.contains("nuxt") {
            self.add_detection("nuxt", None, TechCategory::Framework, 0.9, "http_header");
        }

        // PleskLin / PleskWin
        if lower.contains("plesk") {
            self.add_detection("plesk", None, TechCategory::Other, 0.9, "http_header");
        }
    }

    /// Parse X-Generator header
    fn parse_generator_header(&mut self, value: &str) {
        let lower = value.to_lowercase();

        // WordPress
        if lower.contains("wordpress") {
            let version = self.extract_version(&lower, "wordpress");
            self.add_detection(
                "wordpress",
                version.as_deref(),
                TechCategory::Cms,
                0.95,
                "http_header",
            );
        }

        // Drupal
        if lower.contains("drupal") {
            let version = self.extract_version(&lower, "drupal");
            self.add_detection(
                "drupal",
                version.as_deref(),
                TechCategory::Cms,
                0.95,
                "http_header",
            );
        }

        // Joomla
        if lower.contains("joomla") {
            let version = self.extract_version(&lower, "joomla");
            self.add_detection(
                "joomla",
                version.as_deref(),
                TechCategory::Cms,
                0.95,
                "http_header",
            );
        }
    }

    /// Parse Via header for proxy info
    fn parse_via_header(&mut self, value: &str) {
        let lower = value.to_lowercase();

        if lower.contains("varnish") {
            self.add_detection("varnish", None, TechCategory::Proxy, 0.8, "http_header");
        }
        if lower.contains("squid") {
            self.add_detection("squid", None, TechCategory::Proxy, 0.8, "http_header");
        }
        if lower.contains("cloudfront") {
            self.add_detection(
                "aws_cloudfront",
                None,
                TechCategory::Cdn,
                0.9,
                "http_header",
            );
        }
    }

    /// Extract fingerprints from TLS certificate information
    pub fn extract_from_tls(
        &mut self,
        _subject: Option<&str>,
        issuer: Option<&str>,
        san: &[String],
    ) {
        if let Some(issuer_str) = issuer {
            let lower = issuer_str.to_lowercase();

            // Let's Encrypt
            if lower.contains("let's encrypt") || lower.contains("letsencrypt") {
                // Using Let's Encrypt often indicates modern, automated setup
            }

            // Cloudflare
            if lower.contains("cloudflare") {
                self.add_detection("cloudflare", None, TechCategory::Cdn, 0.9, "tls_cert");
            }

            // AWS
            if lower.contains("amazon") {
                self.add_detection("aws", None, TechCategory::Cdn, 0.7, "tls_cert");
            }

            // DigiCert
            if lower.contains("digicert") {
                // Enterprise-level cert, indicates larger organization
            }
        }

        // Check SANs for cloud service patterns
        for name in san {
            let lower = name.to_lowercase();
            if lower.ends_with(".cloudflare.com") {
                self.add_detection("cloudflare", None, TechCategory::Cdn, 0.95, "tls_san");
            }
            if lower.ends_with(".amazonaws.com") || lower.ends_with(".aws.amazon.com") {
                self.add_detection("aws", None, TechCategory::Cdn, 0.95, "tls_san");
            }
            if lower.ends_with(".azurewebsites.net") || lower.ends_with(".azure.com") {
                self.add_detection("azure", None, TechCategory::Cdn, 0.95, "tls_san");
            }
            if lower.ends_with(".appspot.com") || lower.ends_with(".googleapis.com") {
                self.add_detection("gcp", None, TechCategory::Cdn, 0.95, "tls_san");
            }
            if lower.ends_with(".herokuapp.com") {
                self.add_detection("heroku", None, TechCategory::Cdn, 0.95, "tls_san");
            }
        }
    }

    /// Extract fingerprints from service banner
    pub fn extract_from_banner(&mut self, port: u16, banner: &str) {
        let lower = banner.to_lowercase();

        match port {
            // SSH banners
            22 => {
                // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
                if lower.contains("openssh") {
                    let version = self.extract_version(&lower, "openssh");
                    self.add_detection(
                        "openssh",
                        version.as_deref(),
                        TechCategory::Other,
                        0.95,
                        "banner",
                    );

                    // Extract OS from SSH banner
                    if lower.contains("ubuntu") {
                        self.add_detection(
                            "ubuntu",
                            None,
                            TechCategory::OperatingSystem,
                            0.8,
                            "banner",
                        );
                    } else if lower.contains("debian") {
                        self.add_detection(
                            "debian",
                            None,
                            TechCategory::OperatingSystem,
                            0.8,
                            "banner",
                        );
                    } else if lower.contains("centos")
                        || lower.contains("el7")
                        || lower.contains("el8")
                    {
                        self.add_detection(
                            "centos",
                            None,
                            TechCategory::OperatingSystem,
                            0.8,
                            "banner",
                        );
                    }
                }
                if lower.contains("dropbear") {
                    let version = self.extract_version(&lower, "dropbear");
                    self.add_detection(
                        "dropbear",
                        version.as_deref(),
                        TechCategory::Other,
                        0.95,
                        "banner",
                    );
                }
            }

            // SMTP banners
            25 | 465 | 587 => {
                if lower.contains("postfix") {
                    self.add_detection("postfix", None, TechCategory::Other, 0.9, "banner");
                }
                if lower.contains("exim") {
                    let version = self.extract_version(&lower, "exim");
                    self.add_detection(
                        "exim",
                        version.as_deref(),
                        TechCategory::Other,
                        0.9,
                        "banner",
                    );
                }
                if lower.contains("sendmail") {
                    self.add_detection("sendmail", None, TechCategory::Other, 0.9, "banner");
                }
                if lower.contains("microsoft esmtp") || lower.contains("exchange") {
                    self.add_detection("exchange", None, TechCategory::Other, 0.9, "banner");
                }
            }

            // FTP banners
            21 => {
                if lower.contains("vsftpd") {
                    let version = self.extract_version(&lower, "vsftpd");
                    self.add_detection(
                        "vsftpd",
                        version.as_deref(),
                        TechCategory::Other,
                        0.95,
                        "banner",
                    );
                }
                if lower.contains("proftpd") {
                    let version = self.extract_version(&lower, "proftpd");
                    self.add_detection(
                        "proftpd",
                        version.as_deref(),
                        TechCategory::Other,
                        0.95,
                        "banner",
                    );
                }
                if lower.contains("pure-ftpd") {
                    self.add_detection("pureftpd", None, TechCategory::Other, 0.95, "banner");
                }
                if lower.contains("microsoft ftp") || lower.contains("iis") {
                    self.add_detection("iis", None, TechCategory::WebServer, 0.7, "banner");
                }
            }

            // MySQL/MariaDB
            3306 => {
                if lower.contains("mysql") {
                    let version = self.extract_version(&lower, "mysql");
                    self.add_detection(
                        "mysql",
                        version.as_deref(),
                        TechCategory::Database,
                        0.95,
                        "banner",
                    );
                }
                if lower.contains("mariadb") {
                    let version = self.extract_version(&lower, "mariadb");
                    self.add_detection(
                        "mariadb",
                        version.as_deref(),
                        TechCategory::Database,
                        0.95,
                        "banner",
                    );
                }
            }

            // PostgreSQL
            5432 => {
                // PostgreSQL typically doesn't expose version in initial banner
                if lower.contains("postgresql") || lower.contains("postgres") {
                    self.add_detection("postgresql", None, TechCategory::Database, 0.85, "banner");
                }
            }

            // Redis
            6379 => {
                if lower.contains("redis") {
                    let version = self.extract_version(&lower, "redis");
                    self.add_detection(
                        "redis",
                        version.as_deref(),
                        TechCategory::Database,
                        0.95,
                        "banner",
                    );
                }
            }

            // MongoDB
            27017 => {
                if lower.contains("mongodb") {
                    self.add_detection("mongodb", None, TechCategory::Database, 0.85, "banner");
                }
            }

            // Elasticsearch
            9200 | 9300 => {
                if lower.contains("elasticsearch") || lower.contains("elastic") {
                    let version = self.extract_version(&lower, "elasticsearch");
                    self.add_detection(
                        "elasticsearch",
                        version.as_deref(),
                        TechCategory::Database,
                        0.9,
                        "banner",
                    );
                }
            }

            _ => {}
        }
    }

    /// Extract fingerprints from HTML content (meta tags, etc.)
    pub fn extract_from_html(&mut self, html: &str) {
        let lower = html.to_lowercase();

        // Meta generator tag
        // <meta name="generator" content="WordPress 5.8">
        if let Some(start) = lower.find("name=\"generator\"") {
            if let Some(content_start) = lower[start..].find("content=\"") {
                let content_start = start + content_start + 9;
                if let Some(content_end) = lower[content_start..].find('"') {
                    let generator = &html[content_start..content_start + content_end];
                    self.parse_meta_generator(generator);
                }
            }
        }

        // WordPress indicators
        if lower.contains("/wp-content/") || lower.contains("/wp-includes/") {
            self.add_detection("wordpress", None, TechCategory::Cms, 0.9, "html");
        }

        // Drupal indicators
        if lower.contains("drupal.js") || lower.contains("drupal.settings") {
            self.add_detection("drupal", None, TechCategory::Cms, 0.9, "html");
        }

        // Joomla indicators
        if lower.contains("/media/jui/") || lower.contains("/components/com_") {
            self.add_detection("joomla", None, TechCategory::Cms, 0.9, "html");
        }

        // React
        if lower.contains("react-root")
            || lower.contains("data-reactroot")
            || lower.contains("__next")
        {
            self.add_detection("react", None, TechCategory::JsLibrary, 0.8, "html");
        }

        // Vue.js
        if lower.contains("__vue__") || lower.contains("v-if") || lower.contains("v-for") {
            self.add_detection("vuejs", None, TechCategory::JsLibrary, 0.8, "html");
        }

        // Angular
        if lower.contains("ng-app")
            || lower.contains("ng-controller")
            || lower.contains("_ngcontent")
        {
            self.add_detection("angular", None, TechCategory::JsLibrary, 0.8, "html");
        }

        // jQuery
        if lower.contains("jquery") {
            let version = self.extract_jquery_version(html);
            self.add_detection(
                "jquery",
                version.as_deref(),
                TechCategory::JsLibrary,
                0.7,
                "html",
            );
        }

        // Bootstrap
        if lower.contains("bootstrap") {
            self.add_detection("bootstrap", None, TechCategory::JsLibrary, 0.7, "html");
        }
    }

    /// Parse meta generator content
    fn parse_meta_generator(&mut self, generator: &str) {
        let lower = generator.to_lowercase();

        if lower.contains("wordpress") {
            let version = self.extract_version(&lower, "wordpress");
            self.add_detection(
                "wordpress",
                version.as_deref(),
                TechCategory::Cms,
                0.95,
                "meta_generator",
            );
        } else if lower.contains("drupal") {
            let version = self.extract_version(&lower, "drupal");
            self.add_detection(
                "drupal",
                version.as_deref(),
                TechCategory::Cms,
                0.95,
                "meta_generator",
            );
        } else if lower.contains("joomla") {
            let version = self.extract_version(&lower, "joomla");
            self.add_detection(
                "joomla",
                version.as_deref(),
                TechCategory::Cms,
                0.95,
                "meta_generator",
            );
        } else if lower.contains("typo3") {
            self.add_detection("typo3", None, TechCategory::Cms, 0.95, "meta_generator");
        } else if lower.contains("magento") {
            self.add_detection("magento", None, TechCategory::Cms, 0.95, "meta_generator");
        } else if lower.contains("shopify") {
            self.add_detection("shopify", None, TechCategory::Cms, 0.95, "meta_generator");
        } else if lower.contains("wix") {
            self.add_detection("wix", None, TechCategory::Cms, 0.95, "meta_generator");
        } else if lower.contains("squarespace") {
            self.add_detection(
                "squarespace",
                None,
                TechCategory::Cms,
                0.95,
                "meta_generator",
            );
        }
    }

    /// Try to extract jQuery version from script tags
    fn extract_jquery_version(&self, html: &str) -> Option<String> {
        // jquery-3.6.0.min.js or jquery.min.js?ver=3.6.0
        let lower = html.to_lowercase();

        // Try jquery-X.Y.Z pattern
        if let Some(idx) = lower.find("jquery-") {
            let rest = &lower[idx + 7..];
            if let Some(end) = rest.find(|c: char| !c.is_ascii_digit() && c != '.') {
                let version = &rest[..end];
                if !version.is_empty() && version.contains('.') {
                    return Some(version.to_string());
                }
            }
        }

        // Try ver= pattern
        if let Some(idx) = lower.find("jquery") {
            if let Some(ver_idx) = lower[idx..].find("ver=") {
                let rest = &lower[idx + ver_idx + 4..];
                if let Some(end) = rest.find(|c: char| !c.is_ascii_digit() && c != '.') {
                    let version = &rest[..end];
                    if !version.is_empty() && version.contains('.') {
                        return Some(version.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract version number from a string (e.g., "nginx/1.18.0" -> Some("1.18.0"))
    fn extract_version(&self, text: &str, product: &str) -> Option<String> {
        // Try product/version pattern
        if let Some(idx) = text.find(product) {
            let rest = &text[idx + product.len()..];
            // Skip slash or space
            let rest = rest.trim_start_matches('/').trim_start_matches(' ');
            // Extract version (digits and dots)
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() && version.contains('.') {
                return Some(version);
            }
        }

        // Try product version or product-version pattern
        let patterns = [
            format!("{} ", product),
            format!("{}-", product),
            format!("{}:", product),
            format!("{}_", product), // OpenSSH_8.2p1 pattern
        ];

        for pattern in patterns {
            if let Some(idx) = text.find(&pattern) {
                let rest = &text[idx + pattern.len()..];
                let version: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !version.is_empty() && version.contains('.') {
                    return Some(version);
                }
            }
        }

        None
    }

    /// Extract content from parentheses
    fn extract_parentheses_content(&self, text: &str) -> Option<String> {
        if let Some(start) = text.find('(') {
            if let Some(end) = text[start..].find(')') {
                return Some(text[start + 1..start + end].to_string());
            }
        }
        None
    }

    /// Add a detection to results
    fn add_detection(
        &mut self,
        tech_name: &str,
        version: Option<&str>,
        category: TechCategory,
        confidence: f32,
        source: &str,
    ) {
        // Check for duplicate (same tech + version)
        let existing = self.results.iter().position(|t| {
            t.name.to_lowercase() == tech_name.to_lowercase() && t.version.as_deref() == version
        });

        if let Some(idx) = existing {
            // Update confidence if higher
            if confidence > self.results[idx].confidence {
                self.results[idx].confidence = confidence;
            }
            return;
        }

        // Look up CPE
        let cpe = generate_cpe(tech_name, version);

        let tech = DetectedTech::new(tech_name, version)
            .with_cpe(cpe)
            .with_confidence(confidence)
            .with_source(source)
            .with_category(category);

        self.results.push(tech);
    }

    /// Get all detected technologies
    pub fn results(&self) -> &[DetectedTech] {
        &self.results
    }

    /// Take ownership of results
    pub fn into_results(self) -> Vec<DetectedTech> {
        self.results
    }

    /// Get results sorted by confidence (highest first)
    pub fn results_sorted(&self) -> Vec<&DetectedTech> {
        let mut sorted: Vec<_> = self.results.iter().collect();
        sorted.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        sorted
    }

    /// Get technologies with CPE mappings (for vuln lookup)
    pub fn results_with_cpe(&self) -> Vec<&DetectedTech> {
        self.results.iter().filter(|t| t.cpe.is_some()).collect()
    }

    /// Clear all results
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

impl Default for FingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_server_nginx() {
        let mut engine = FingerprintEngine::new();
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "nginx/1.18.0".to_string());

        engine.extract_from_http_headers(&headers);

        let results = engine.results();
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .any(|t| t.name == "nginx" && t.version == Some("1.18.0".to_string())));
    }

    #[test]
    fn test_extract_server_apache_with_os() {
        let mut engine = FingerprintEngine::new();
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.4.41 (Ubuntu)".to_string());

        engine.extract_from_http_headers(&headers);

        let results = engine.results();
        assert!(results
            .iter()
            .any(|t| t.name == "apache" && t.version == Some("2.4.41".to_string())));
        assert!(results.iter().any(|t| t.name == "ubuntu"));
    }

    #[test]
    fn test_extract_powered_by_php() {
        let mut engine = FingerprintEngine::new();
        let mut headers = HashMap::new();
        headers.insert("X-Powered-By".to_string(), "PHP/7.4.3".to_string());

        engine.extract_from_http_headers(&headers);

        let results = engine.results();
        assert!(results
            .iter()
            .any(|t| t.name == "php" && t.version == Some("7.4.3".to_string())));
    }

    #[test]
    fn test_extract_cloudflare() {
        let mut engine = FingerprintEngine::new();
        let mut headers = HashMap::new();
        headers.insert("CF-Ray".to_string(), "12345-IAD".to_string());

        engine.extract_from_http_headers(&headers);

        let results = engine.results();
        assert!(results.iter().any(|t| t.name == "cloudflare"));
    }

    #[test]
    fn test_extract_ssh_banner() {
        let mut engine = FingerprintEngine::new();
        engine.extract_from_banner(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1");

        let results = engine.results();
        assert!(results
            .iter()
            .any(|t| t.name == "openssh" && t.version == Some("8.2".to_string())));
        assert!(results.iter().any(|t| t.name == "ubuntu"));
    }

    #[test]
    fn test_extract_wordpress_html() {
        let mut engine = FingerprintEngine::new();
        let html = r#"<html><head><meta name="generator" content="WordPress 5.8"></head></html>"#;

        engine.extract_from_html(html);

        let results = engine.results();
        assert!(results
            .iter()
            .any(|t| t.name == "wordpress" && t.version == Some("5.8".to_string())));
    }

    #[test]
    fn test_cpe_generation() {
        let mut engine = FingerprintEngine::new();
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "nginx/1.18.0".to_string());

        engine.extract_from_http_headers(&headers);

        let results = engine.results_with_cpe();
        assert!(!results.is_empty());

        let nginx = results.iter().find(|t| t.name == "nginx").unwrap();
        assert_eq!(
            nginx.cpe,
            Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*".to_string())
        );
    }

    #[test]
    fn test_confidence_update() {
        let mut engine = FingerprintEngine::new();

        // Add detection with low confidence
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "nginx".to_string());
        engine.extract_from_http_headers(&headers);

        // Add detection with high confidence
        let mut headers2 = HashMap::new();
        headers2.insert("Server".to_string(), "nginx/1.18.0".to_string());
        engine.extract_from_http_headers(&headers2);

        // Should have two nginx entries (one without version, one with)
        let results = engine.results();
        let nginx_with_version = results
            .iter()
            .find(|t| t.name == "nginx" && t.version.is_some());
        assert!(nginx_with_version.is_some());
        assert!(nginx_with_version.unwrap().confidence >= 0.9);
    }
}
