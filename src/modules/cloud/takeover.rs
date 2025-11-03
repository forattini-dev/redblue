#![allow(dead_code)]

/// Subdomain Takeover Checker
///
/// Replaces tools like subjack, tko-subs, can-i-take-over-xyz
/// Features:
/// - CNAME resolution and validation
/// - Vulnerable service detection (Azure, AWS, GitHub, Heroku, etc.)
/// - Fingerprint matching for takeover confirmation
/// - Dead DNS detection
///
/// NO external dependencies - pure Rust std implementation
use crate::protocols::dns::DnsClient;
use crate::protocols::http::HttpClient;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TakeoverResult {
    pub domain: String,
    pub cname: Option<String>,
    pub vulnerable: bool,
    pub service: Option<String>,
    pub confidence: Confidence,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Confidence {
    High,   // CNAME points to known vulnerable service + fingerprint match
    Medium, // CNAME points to known vulnerable service
    Low,    // Dead CNAME (NXDOMAIN)
    None,   // Not vulnerable
}

#[derive(Debug, Clone)]
struct ServiceFingerprint {
    name: &'static str,
    cname_patterns: Vec<&'static str>,
    error_signatures: Vec<&'static str>,
    description: &'static str,
}

pub struct TakeoverChecker {
    dns_client: DnsClient,
    http_client: HttpClient,
    fingerprints: Vec<ServiceFingerprint>,
}

impl TakeoverChecker {
    pub fn new() -> Self {
        Self {
            dns_client: DnsClient::new("8.8.8.8"),
            http_client: HttpClient::new(),
            fingerprints: Self::load_fingerprints(),
        }
    }

    /// Check a single domain for subdomain takeover vulnerability
    pub fn check(&self, domain: &str) -> Result<TakeoverResult, String> {
        // Resolve CNAME
        let cname_result = self.dns_client.lookup_cname(domain);

        match cname_result {
            Ok(cname) => {
                // Check if CNAME points to vulnerable service
                if let Some(service) = self.match_vulnerable_service(&cname) {
                    // Try to confirm vulnerability with HTTP fingerprint
                    let fingerprint_match = self.check_http_fingerprint(domain, service);

                    let confidence = if fingerprint_match {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };

                    Ok(TakeoverResult {
                        domain: domain.to_string(),
                        cname: Some(cname.clone()),
                        vulnerable: true,
                        service: Some(service.name.to_string()),
                        confidence,
                        message: format!(
                            "Potentially vulnerable to takeover via {} (CNAME: {})",
                            service.name, cname
                        ),
                    })
                } else {
                    // CNAME exists but not known vulnerable service
                    Ok(TakeoverResult {
                        domain: domain.to_string(),
                        cname: Some(cname.clone()),
                        vulnerable: false,
                        service: None,
                        confidence: Confidence::None,
                        message: format!("CNAME points to: {}", cname),
                    })
                }
            }
            Err(e) => {
                // Check if it's NXDOMAIN (dead DNS)
                if e.contains("NXDOMAIN") || e.contains("not found") {
                    Ok(TakeoverResult {
                        domain: domain.to_string(),
                        cname: None,
                        vulnerable: true,
                        service: Some("Dead DNS".to_string()),
                        confidence: Confidence::Low,
                        message: "Dead DNS record (NXDOMAIN) - potential takeover".to_string(),
                    })
                } else {
                    // Other DNS error
                    Ok(TakeoverResult {
                        domain: domain.to_string(),
                        cname: None,
                        vulnerable: false,
                        service: None,
                        confidence: Confidence::None,
                        message: format!("DNS lookup failed: {}", e),
                    })
                }
            }
        }
    }

    /// Check multiple domains for takeover vulnerabilities
    pub fn check_bulk(&self, domains: &[String]) -> Vec<TakeoverResult> {
        let mut results = Vec::new();

        for domain in domains {
            if let Ok(result) = self.check(domain) {
                results.push(result);
            }
        }

        results
    }

    /// Match CNAME against vulnerable service fingerprints
    fn match_vulnerable_service(&self, cname: &str) -> Option<&ServiceFingerprint> {
        let cname_lower = cname.to_lowercase();

        for fingerprint in &self.fingerprints {
            for pattern in &fingerprint.cname_patterns {
                if cname_lower.contains(pattern) {
                    return Some(fingerprint);
                }
            }
        }

        None
    }

    /// Check HTTP response for takeover error signatures
    fn check_http_fingerprint(&self, domain: &str, service: &ServiceFingerprint) -> bool {
        let url = format!("http://{}", domain);

        match self.http_client.get(&url) {
            Ok(response) => {
                let body = String::from_utf8_lossy(&response.body).to_lowercase();

                // Check for error signatures
                for signature in &service.error_signatures {
                    if body.contains(&signature.to_lowercase()) {
                        return true;
                    }
                }

                false
            }
            Err(_) => false,
        }
    }

    /// Load known vulnerable service fingerprints
    fn load_fingerprints() -> Vec<ServiceFingerprint> {
        vec![
            // GitHub Pages
            ServiceFingerprint {
                name: "GitHub Pages",
                cname_patterns: vec!["github.io", "githubusercontent.com"],
                error_signatures: vec![
                    "There isn't a GitHub Pages site here",
                    "For root URLs (like http://example.com/) you must provide an index.html file",
                ],
                description: "GitHub Pages subdomain takeover",
            },
            // Heroku
            ServiceFingerprint {
                name: "Heroku",
                cname_patterns: vec!["herokuapp.com", "herokussl.com"],
                error_signatures: vec![
                    "No such app",
                    "There's nothing here, yet",
                    "herokucdn.com/error-pages/no-such-app.html",
                ],
                description: "Heroku app takeover",
            },
            // AWS S3
            ServiceFingerprint {
                name: "AWS S3",
                cname_patterns: vec![".s3.amazonaws.com", ".s3-website"],
                error_signatures: vec!["NoSuchBucket", "The specified bucket does not exist"],
                description: "AWS S3 bucket takeover",
            },
            // Azure
            ServiceFingerprint {
                name: "Azure",
                cname_patterns: vec![
                    ".azurewebsites.net",
                    ".cloudapp.azure.com",
                    ".cloudapp.net",
                    ".trafficmanager.net",
                    ".blob.core.windows.net",
                ],
                error_signatures: vec!["404 Web Site not found", "Error 404 - Web app not found"],
                description: "Microsoft Azure service takeover",
            },
            // Amazon CloudFront
            ServiceFingerprint {
                name: "CloudFront",
                cname_patterns: vec!["cloudfront.net"],
                error_signatures: vec!["Bad request", "ERROR: The request could not be satisfied"],
                description: "Amazon CloudFront distribution takeover",
            },
            // Bitbucket
            ServiceFingerprint {
                name: "Bitbucket",
                cname_patterns: vec!["bitbucket.io"],
                error_signatures: vec!["Repository not found"],
                description: "Bitbucket repository takeover",
            },
            // Shopify
            ServiceFingerprint {
                name: "Shopify",
                cname_patterns: vec!["myshopify.com"],
                error_signatures: vec![
                    "Sorry, this shop is currently unavailable",
                    "Only one step left",
                ],
                description: "Shopify store takeover",
            },
            // AWS Elastic Beanstalk
            ServiceFingerprint {
                name: "Elastic Beanstalk",
                cname_patterns: vec!["elasticbeanstalk.com"],
                error_signatures: vec!["404 Not Found"],
                description: "AWS Elastic Beanstalk takeover",
            },
            // Tumblr
            ServiceFingerprint {
                name: "Tumblr",
                cname_patterns: vec!["tumblr.com"],
                error_signatures: vec![
                    "Whatever you were looking for doesn't currently exist at this address",
                    "There's nothing here",
                ],
                description: "Tumblr blog takeover",
            },
            // WordPress.com
            ServiceFingerprint {
                name: "WordPress.com",
                cname_patterns: vec!["wordpress.com"],
                error_signatures: vec!["Do you want to register"],
                description: "WordPress.com site takeover",
            },
            // Fastly
            ServiceFingerprint {
                name: "Fastly",
                cname_patterns: vec!["fastly.net"],
                error_signatures: vec!["Fastly error: unknown domain"],
                description: "Fastly CDN takeover",
            },
            // Pantheon
            ServiceFingerprint {
                name: "Pantheon",
                cname_patterns: vec!["pantheonsite.io"],
                error_signatures: vec!["404 error unknown site"],
                description: "Pantheon hosting takeover",
            },
            // Zendesk
            ServiceFingerprint {
                name: "Zendesk",
                cname_patterns: vec!["zendesk.com"],
                error_signatures: vec!["Help Center Closed"],
                description: "Zendesk help center takeover",
            },
            // Cargo Collective
            ServiceFingerprint {
                name: "Cargo",
                cname_patterns: vec!["cargocollective.com"],
                error_signatures: vec!["404 Not Found"],
                description: "Cargo Collective site takeover",
            },
            // StatusPage
            ServiceFingerprint {
                name: "StatusPage",
                cname_patterns: vec!["statuspage.io"],
                error_signatures: vec!["You are being redirected"],
                description: "StatusPage.io takeover",
            },
            // UserVoice
            ServiceFingerprint {
                name: "UserVoice",
                cname_patterns: vec!["uservoice.com"],
                error_signatures: vec!["This UserVoice subdomain is currently available"],
                description: "UserVoice portal takeover",
            },
            // Surge.sh
            ServiceFingerprint {
                name: "Surge.sh",
                cname_patterns: vec!["surge.sh"],
                error_signatures: vec!["project not found"],
                description: "Surge.sh deployment takeover",
            },
            // Readme.io
            ServiceFingerprint {
                name: "Readme.io",
                cname_patterns: vec!["readme.io"],
                error_signatures: vec!["Project doesnt exist"],
                description: "Readme.io documentation takeover",
            },
        ]
    }

    /// Get statistics about vulnerable services
    pub fn get_stats(results: &[TakeoverResult]) -> HashMap<String, usize> {
        let mut stats = HashMap::new();

        stats.insert("total".to_string(), results.len());
        stats.insert(
            "vulnerable".to_string(),
            results.iter().filter(|r| r.vulnerable).count(),
        );
        stats.insert(
            "high_confidence".to_string(),
            results
                .iter()
                .filter(|r| r.confidence == Confidence::High)
                .count(),
        );
        stats.insert(
            "medium_confidence".to_string(),
            results
                .iter()
                .filter(|r| r.confidence == Confidence::Medium)
                .count(),
        );
        stats.insert(
            "low_confidence".to_string(),
            results
                .iter()
                .filter(|r| r.confidence == Confidence::Low)
                .count(),
        );

        stats
    }

    /// List all supported vulnerable services
    pub fn list_services(&self) -> Vec<&str> {
        self.fingerprints.iter().map(|f| f.name).collect()
    }
}

impl Default for TakeoverChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_fingerprints() {
        let checker = TakeoverChecker::new();
        assert!(checker.fingerprints.len() > 15);

        // Check GitHub Pages fingerprint
        let github = checker.match_vulnerable_service("example.github.io");
        assert!(github.is_some());
        assert_eq!(github.unwrap().name, "GitHub Pages");

        // Check Heroku fingerprint
        let heroku = checker.match_vulnerable_service("myapp.herokuapp.com");
        assert!(heroku.is_some());
        assert_eq!(heroku.unwrap().name, "Heroku");

        // Check S3 fingerprint
        let s3 = checker.match_vulnerable_service("bucket.s3.amazonaws.com");
        assert!(s3.is_some());
        assert_eq!(s3.unwrap().name, "AWS S3");
    }

    #[test]
    fn test_list_services() {
        let checker = TakeoverChecker::new();
        let services = checker.list_services();
        assert!(services.contains(&"GitHub Pages"));
        assert!(services.contains(&"Heroku"));
        assert!(services.contains(&"AWS S3"));
        assert!(services.contains(&"Azure"));
    }

    #[test]
    fn test_confidence_levels() {
        assert_ne!(Confidence::High, Confidence::Medium);
        assert_ne!(Confidence::Medium, Confidence::Low);
        assert_ne!(Confidence::Low, Confidence::None);
    }
}
