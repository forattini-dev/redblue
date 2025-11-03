/// Web technology fingerprinting module (COMPLETELY REWRITTEN)
///
/// Replaces: whatweb, wappalyzer
///
/// NEW APPROACH:
/// - Deduplication of technology detections
/// - Confidence merging (keep highest confidence and most detailed version)
/// - Better detection patterns for modern SPAs
/// - Header analysis
/// - Meta tag inspection
/// - Script/link tag parsing
/// - CDN pattern matching
/// - DOM structure fingerprinting
///
/// NO external dependencies - pure Rust implementation
use crate::protocols::http::HttpClient;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub url: String,
    pub technologies: Vec<Technology>,
    pub cms: Option<String>,
    pub web_server: Option<String>,
    pub programming_language: Option<String>,
    pub frameworks: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Technology {
    pub name: String,
    pub category: TechCategory,
    pub version: Option<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TechCategory {
    CMS,
    Framework,
    WebServer,
    Language,
    Library,
    CDN,
    Analytics,
    Database,
    Other,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum Confidence {
    Low,    // <50% certain
    Medium, // 50-90% certain
    High,   // 90%+ certain
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "HIGH"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::Low => write!(f, "LOW"),
        }
    }
}

pub struct WebFingerprinter {
    client: HttpClient,
}

impl WebFingerprinter {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
        }
    }

    /// Run fingerprinting on a URL with deduplication
    pub fn fingerprint(&self, url: &str) -> Result<FingerprintResult, String> {
        // Fetch the page
        let response = self.client.get(url)?;

        let mut candidates: HashMap<String, Technology> = HashMap::new();

        // Analyze in order of reliability (most reliable first)
        let body_str = String::from_utf8_lossy(&response.body);

        // 1. Headers (highest confidence)
        self.merge_technologies(&mut candidates, self.detect_from_headers(&response.headers));

        // 2. Meta tags (high confidence)
        self.merge_technologies(&mut candidates, self.detect_from_meta_tags(&body_str));

        // 3. Script/link tags with versions (high confidence)
        self.merge_technologies(&mut candidates, self.detect_from_scripts(&body_str));

        // 4. Body content patterns (medium confidence)
        self.merge_technologies(&mut candidates, self.detect_from_body(&body_str));

        // 5. DOM structure patterns (low to medium confidence)
        self.merge_technologies(&mut candidates, self.detect_from_dom(&body_str));

        // 6. Enhanced CMS version detection
        self.enhance_cms_versions(url, &body_str, &mut candidates);

        // Convert to Vec and sort by confidence
        let mut technologies: Vec<Technology> = candidates.into_values().collect();
        technologies.sort_by(|a, b| {
            // Sort by confidence desc, then by name
            match b.confidence.partial_cmp(&a.confidence) {
                Some(std::cmp::Ordering::Equal) => a.name.cmp(&b.name),
                other => other.unwrap_or(std::cmp::Ordering::Equal),
            }
        });

        // Categorize findings
        let cms = technologies
            .iter()
            .find(|t| t.category == TechCategory::CMS)
            .map(|t| t.name.clone());

        let web_server = technologies
            .iter()
            .find(|t| t.category == TechCategory::WebServer)
            .map(|t| t.name.clone());

        let programming_language = technologies
            .iter()
            .find(|t| t.category == TechCategory::Language)
            .map(|t| t.name.clone());

        let frameworks = technologies
            .iter()
            .filter(|t| t.category == TechCategory::Framework)
            .map(|t| t.name.clone())
            .collect();

        Ok(FingerprintResult {
            url: url.to_string(),
            technologies,
            cms,
            web_server,
            programming_language,
            frameworks,
        })
    }

    /// Merge new technologies into existing map, keeping highest confidence and best version
    fn merge_technologies(
        &self,
        map: &mut HashMap<String, Technology>,
        new_techs: Vec<Technology>,
    ) {
        for tech in new_techs {
            let key = tech.name.clone();

            match map.get_mut(&key) {
                Some(existing) => {
                    // Technology already detected - merge information

                    // Keep highest confidence
                    if tech.confidence > existing.confidence {
                        existing.confidence = tech.confidence;
                    }

                    // Keep most detailed version (prefer specific over None)
                    match (&tech.version, &existing.version) {
                        (Some(new_v), None) => {
                            existing.version = Some(new_v.clone());
                        }
                        (Some(new_v), Some(old_v)) => {
                            // Keep longer/more detailed version
                            if new_v.len() > old_v.len() {
                                existing.version = Some(new_v.clone());
                            }
                        }
                        _ => {} // Keep existing version
                    }
                }
                None => {
                    // New technology - add it
                    map.insert(key, tech);
                }
            }
        }
    }

    /// Detect technologies from HTTP headers
    fn detect_from_headers(&self, headers: &HashMap<String, String>) -> Vec<Technology> {
        let mut techs = Vec::new();

        // Server header
        if let Some(server) = headers.get("Server") {
            let server_lower = server.to_lowercase();

            if server_lower.contains("nginx") {
                let version = self.extract_version(&server_lower, "nginx/");
                techs.push(Technology {
                    name: "Nginx".to_string(),
                    category: TechCategory::WebServer,
                    version,
                    confidence: Confidence::High,
                });
            } else if server_lower.contains("apache") {
                let version = self.extract_version(&server_lower, "apache/");
                techs.push(Technology {
                    name: "Apache".to_string(),
                    category: TechCategory::WebServer,
                    version,
                    confidence: Confidence::High,
                });
            } else if server_lower.contains("iis") {
                let version = self.extract_version(&server_lower, "iis/");
                techs.push(Technology {
                    name: "Microsoft IIS".to_string(),
                    category: TechCategory::WebServer,
                    version,
                    confidence: Confidence::High,
                });
            } else if server_lower.contains("cloudflare") {
                techs.push(Technology {
                    name: "Cloudflare".to_string(),
                    category: TechCategory::CDN,
                    version: None,
                    confidence: Confidence::High,
                });
            }
        }

        // CF-RAY header (Cloudflare)
        if headers.contains_key("CF-RAY") || headers.contains_key("cf-ray") {
            techs.push(Technology {
                name: "Cloudflare".to_string(),
                category: TechCategory::CDN,
                version: None,
                confidence: Confidence::High,
            });
        }

        // X-Powered-By header
        if let Some(powered_by) = headers.get("X-Powered-By") {
            let powered_lower = powered_by.to_lowercase();

            if powered_lower.contains("strapi") {
                let version = self.extract_version(&powered_lower, "strapi/");
                techs.push(Technology {
                    name: "Strapi".to_string(),
                    category: TechCategory::CMS,
                    version,
                    confidence: Confidence::High,
                });
            } else if powered_lower.contains("ghost") {
                let version = self.extract_version(&powered_lower, "ghost/");
                techs.push(Technology {
                    name: "Ghost".to_string(),
                    category: TechCategory::CMS,
                    version,
                    confidence: Confidence::High,
                });
            } else if powered_lower.contains("directus") {
                let version = self.extract_version(&powered_lower, "directus/");
                techs.push(Technology {
                    name: "Directus".to_string(),
                    category: TechCategory::CMS,
                    version,
                    confidence: Confidence::High,
                });
            } else if powered_lower.contains("php") {
                let version = self.extract_version(&powered_lower, "php/");
                techs.push(Technology {
                    name: "PHP".to_string(),
                    category: TechCategory::Language,
                    version,
                    confidence: Confidence::High,
                });
            } else if powered_lower.contains("asp.net") {
                techs.push(Technology {
                    name: "ASP.NET".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                });
            } else if powered_lower.contains("express") {
                techs.push(Technology {
                    name: "Express".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::High,
                });
            }
        }

        // X-Generator header
        if let Some(generator) = headers.get("X-Generator") {
            techs.push(Technology {
                name: generator.clone(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::High,
            });
        }

        // === MODERN CMS SPECIFIC HEADERS ===

        // Strapi specific headers
        if headers.get("X-Strapi-Response-Time").is_some() {
            techs.push(Technology {
                name: "Strapi".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Discourse specific headers
        if headers.contains_key("X-Discourse-Route") || headers.contains_key("Discourse-Present") {
            techs.push(Technology {
                name: "Discourse".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::High,
            });
        }

        // Magento specific headers
        if headers.contains_key("X-Magento-Cache-Control") || headers.contains_key("X-Magento-Tags")
        {
            techs.push(Technology {
                name: "Magento".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::High,
            });
        }

        // PrestaShop cookie detection
        if let Some(cookie) = headers.get("Set-Cookie") {
            let cookie_lower = cookie.to_lowercase();
            if cookie_lower.contains("prestashop-") {
                techs.push(Technology {
                    name: "PrestaShop".to_string(),
                    category: TechCategory::CMS,
                    version: None,
                    confidence: Confidence::High,
                });
            } else if cookie_lower.contains("laravel_session")
                || cookie_lower.contains("xsrf-token")
            {
                techs.push(Technology {
                    name: "Laravel".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::Medium,
                });
            } else if cookie_lower.contains("csrftoken") || cookie_lower.contains("sessionid") {
                techs.push(Technology {
                    name: "Django".to_string(),
                    category: TechCategory::Framework,
                    version: None,
                    confidence: Confidence::Medium,
                });
            }
        }

        techs
    }

    /// Detect technologies from meta tags
    fn detect_from_meta_tags(&self, body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();

        // Look for <meta name="generator" content="...">
        if let Some(start) = body.to_lowercase().find("<meta name=\"generator\"") {
            if let Some(content_start) = body[start..].find("content=\"") {
                let content_pos = start + content_start + 9;
                if let Some(content_end) = body[content_pos..].find('"') {
                    let generator = &body[content_pos..content_pos + content_end];
                    let gen_lower = generator.to_lowercase();

                    if gen_lower.contains("wordpress") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "WordPress".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("drupal") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "Drupal".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("joomla") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "Joomla".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("ghost") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "Ghost".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("prestashop") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "PrestaShop".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("mediawiki") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "MediaWiki".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("magento") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "Magento".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    } else if gen_lower.contains("discourse") {
                        let version = self.extract_version_number(generator);
                        techs.push(Technology {
                            name: "Discourse".to_string(),
                            category: TechCategory::CMS,
                            version,
                            confidence: Confidence::High,
                        });
                    }
                }
            }
        }

        techs
    }

    /// Detect from script and link tags (HIGH confidence when version found)
    fn detect_from_scripts(&self, body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();

        for line in body.lines() {
            let line_lower = line.to_lowercase();

            // React from CDN
            if (line_lower.contains("<script") || line_lower.contains("src="))
                && (line_lower.contains("react") || line_lower.contains("react-dom"))
            {
                if let Some(version) = self.extract_from_cdn_url(line, "react") {
                    techs.push(Technology {
                        name: "React".to_string(),
                        category: TechCategory::Framework,
                        version: Some(version),
                        confidence: Confidence::High,
                    });
                }
            }

            // Vue.js from CDN
            if (line_lower.contains("<script") || line_lower.contains("src="))
                && line_lower.contains("vue")
            {
                if let Some(version) = self.extract_from_cdn_url(line, "vue") {
                    techs.push(Technology {
                        name: "Vue.js".to_string(),
                        category: TechCategory::Framework,
                        version: Some(version),
                        confidence: Confidence::High,
                    });
                }
            }

            // Angular from CDN
            if (line_lower.contains("<script") || line_lower.contains("src="))
                && (line_lower.contains("angular") || line_lower.contains("@angular"))
            {
                if let Some(version) = self.extract_from_cdn_url(line, "angular") {
                    techs.push(Technology {
                        name: "Angular".to_string(),
                        category: TechCategory::Framework,
                        version: Some(version),
                        confidence: Confidence::High,
                    });
                }
            }

            // jQuery from CDN
            if (line_lower.contains("<script") || line_lower.contains("src="))
                && line_lower.contains("jquery")
            {
                if let Some(version) = self.extract_from_cdn_url(line, "jquery") {
                    techs.push(Technology {
                        name: "jQuery".to_string(),
                        category: TechCategory::Library,
                        version: Some(version),
                        confidence: Confidence::High,
                    });
                }
            }

            // Bootstrap from CDN
            if (line_lower.contains("<link") || line_lower.contains("<script"))
                && line_lower.contains("bootstrap")
            {
                if let Some(version) = self.extract_from_cdn_url(line, "bootstrap") {
                    techs.push(Technology {
                        name: "Bootstrap".to_string(),
                        category: TechCategory::Library,
                        version: Some(version),
                        confidence: Confidence::High,
                    });
                }
            }
        }

        techs
    }

    /// Detect from body content (MEDIUM confidence - fallback for non-CDN)
    fn detect_from_body(&self, body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();
        let body_lower = body.to_lowercase();

        // WordPress detection (only if not already detected from meta)
        if body_lower.contains("wp-content") || body_lower.contains("/wp-includes/") {
            techs.push(Technology {
                name: "WordPress".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Joomla detection
        if body_lower.contains("/components/com_") || body_lower.contains("joomla") {
            techs.push(Technology {
                name: "Joomla".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Drupal detection
        if body_lower.contains("/sites/default/files") || body_lower.contains("drupal") {
            techs.push(Technology {
                name: "Drupal".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // === MODERN HEADLESS CMS ===

        // Strapi detection
        if body_lower.contains("strapi")
            || body_lower.contains("/admin/init")
            || body_lower.contains("@strapi/plugin")
            || body_lower.contains("window.strapi_telemetry")
        {
            techs.push(Technology {
                name: "Strapi".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Ghost detection
        if body_lower.contains("/ghost/assets/")
            || body_lower.contains("/public/ghost-sdk.js")
            || body_lower.contains("window.ghost")
            || body_lower.contains("ghost-")
        {
            techs.push(Technology {
                name: "Ghost".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Directus detection
        if body_lower.contains("directus")
            || body_lower.contains("/.directus/")
            || body_lower.contains("window.directus")
        {
            techs.push(Technology {
                name: "Directus".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Payload CMS detection
        if body_lower.contains("payload")
            || body_lower.contains("/admin/api/")
            || body_lower.contains("window.__payload")
        {
            techs.push(Technology {
                name: "Payload CMS".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // === E-COMMERCE ===

        // PrestaShop detection
        if body_lower.contains("prestashop")
            || body_lower.contains("/modules/ps_")
            || body_lower.contains("/themes/classic/")
        {
            techs.push(Technology {
                name: "PrestaShop".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Magento detection
        if body_lower.contains("mage.cookies")
            || body_lower.contains("/static/version")
            || body_lower.contains("magento")
        {
            techs.push(Technology {
                name: "Magento".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // OpenCart detection
        if body_lower.contains("opencart")
            || body_lower.contains("catalog/view/theme/")
            || body_lower.contains("route=common/home")
        {
            techs.push(Technology {
                name: "OpenCart".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // === WIKI / DOCUMENTATION ===

        // MediaWiki detection
        if body_lower.contains("wgserver")
            || body_lower.contains("wgarticlepath")
            || body_lower.contains("/skins/vector/")
        {
            techs.push(Technology {
                name: "MediaWiki".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // DokuWiki detection
        if body_lower.contains("dokuwiki") || body_lower.contains("doku.php") {
            techs.push(Technology {
                name: "DokuWiki".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // BookStack detection
        if body_lower.contains("bookstack") || body_lower.contains("/books/") {
            techs.push(Technology {
                name: "BookStack".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // === FORUM / COMMUNITY ===

        // Discourse detection
        if body_lower.contains("discourse.environment")
            || body_lower.contains("/assets/discourse-")
            || body_lower.contains("data-discourse-setup")
        {
            techs.push(Technology {
                name: "Discourse".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // phpBB detection
        if body_lower.contains("phpbb") || body_lower.contains("/styles/prosilver/") {
            techs.push(Technology {
                name: "phpBB".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // MyBB detection
        if body_lower.contains("mybb") || body_lower.contains("var MyBB") {
            techs.push(Technology {
                name: "MyBB".to_string(),
                category: TechCategory::CMS,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // === FRAMEWORKS ===

        // Laravel detection (additional patterns)
        if body_lower.contains("laravel")
            || body_lower.contains("csrf-token")
            || body_lower.contains("laravel_session")
        {
            techs.push(Technology {
                name: "Laravel".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Django detection
        if body_lower.contains("csrfmiddlewaretoken") || body_lower.contains("/static/admin/") {
            techs.push(Technology {
                name: "Django".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Ruby on Rails detection
        if body_lower.contains("csrf-param")
            || body_lower.contains("csrf-token")
            || body_lower.contains("_rails_")
        {
            techs.push(Technology {
                name: "Ruby on Rails".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Express.js detection
        if body_lower.contains("x-powered-by: express") || body_lower.contains("connect.sid") {
            techs.push(Technology {
                name: "Express.js".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Google Analytics
        if body_lower.contains("google-analytics")
            || body_lower.contains("gtag")
            || body_lower.contains("ga.js")
        {
            techs.push(Technology {
                name: "Google Analytics".to_string(),
                category: TechCategory::Analytics,
                version: None,
                confidence: Confidence::High,
            });
        }

        techs
    }

    /// Detect from DOM structure patterns (LOW to MEDIUM confidence)
    fn detect_from_dom(&self, body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();
        let body_lower = body.to_lowercase();

        // React patterns (LOW confidence without CDN)
        if body_lower.contains("data-reactroot")
            || body_lower.contains("data-react-helmet")
            || body.contains("__REACT")
        {
            techs.push(Technology {
                name: "React".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Vue.js patterns
        if body_lower.contains("v-if")
            || body_lower.contains("v-for")
            || body_lower.contains("v-bind")
            || body.contains("__VUE__")
        {
            techs.push(Technology {
                name: "Vue.js".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Angular patterns
        if body_lower.contains("ng-app")
            || body_lower.contains("ng-controller")
            || body_lower.contains("[ng-")
        {
            techs.push(Technology {
                name: "Angular".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Low,
            });
        }

        // Next.js patterns
        if body.contains("__NEXT_DATA__") || body_lower.contains("/_next/") {
            techs.push(Technology {
                name: "Next.js".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        // Nuxt.js patterns
        if body.contains("__NUXT__") || body_lower.contains("/_nuxt/") {
            techs.push(Technology {
                name: "Nuxt.js".to_string(),
                category: TechCategory::Framework,
                version: None,
                confidence: Confidence::Medium,
            });
        }

        techs
    }

    /// Enhanced CMS version detection
    fn enhance_cms_versions(
        &self,
        base_url: &str,
        body: &str,
        candidates: &mut HashMap<String, Technology>,
    ) {
        // WordPress version enhancement
        if let Some(wp_tech) = candidates.get_mut("WordPress") {
            if wp_tech.version.is_none() {
                if let Some(version) = self.detect_wordpress_version(base_url, body) {
                    wp_tech.version = Some(version);
                    wp_tech.confidence = Confidence::High;
                }
            }
        }

        // Drupal version enhancement
        if let Some(drupal_tech) = candidates.get_mut("Drupal") {
            if drupal_tech.version.is_none() {
                if let Some(version) = self.detect_drupal_version(base_url, body) {
                    drupal_tech.version = Some(version);
                    drupal_tech.confidence = Confidence::High;
                }
            }
        }

        // Joomla version enhancement
        if let Some(joomla_tech) = candidates.get_mut("Joomla") {
            if joomla_tech.version.is_none() {
                if let Some(version) = self.detect_joomla_version(base_url, body) {
                    joomla_tech.version = Some(version);
                    joomla_tech.confidence = Confidence::High;
                }
            }
        }
    }

    /// Detect WordPress version
    fn detect_wordpress_version(&self, base_url: &str, body: &str) -> Option<String> {
        // Method 1: RSS feed generator tag
        let feed_url = format!("{}/feed/", base_url.trim_end_matches('/'));
        if let Ok(response) = self.client.get(&feed_url) {
            let feed_body = String::from_utf8_lossy(&response.body);
            if let Some(start) = feed_body.find("<generator>") {
                let gen_start = start + 11;
                if let Some(end) = feed_body[gen_start..].find("</generator>") {
                    let generator = &feed_body[gen_start..gen_start + end];
                    if let Some(v_pos) = generator.find("?v=") {
                        let version = &generator[v_pos + 3..];
                        if !version.is_empty() {
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }

        // Method 2: readme.html
        let readme_url = format!("{}/readme.html", base_url.trim_end_matches('/'));
        if let Ok(response) = self.client.get(&readme_url) {
            let readme_body = String::from_utf8_lossy(&response.body);
            for line in readme_body.lines() {
                if line.to_lowercase().contains("version")
                    || line.to_lowercase().contains("stable tag")
                {
                    if let Some(v) = self.extract_version_number(line) {
                        return Some(v);
                    }
                }
            }
        }

        // Method 3: Body meta tag
        if let Some(v) = self.extract_version_number(body) {
            return Some(v);
        }

        None
    }

    /// Detect Drupal version
    fn detect_drupal_version(&self, base_url: &str, _body: &str) -> Option<String> {
        // Try /CHANGELOG.txt
        let changelog_url = format!("{}/CHANGELOG.txt", base_url.trim_end_matches('/'));
        if let Ok(response) = self.client.get(&changelog_url) {
            let changelog_body = String::from_utf8_lossy(&response.body);
            if let Some(first_line) = changelog_body.lines().next() {
                if let Some(v) = self.extract_version_number(first_line) {
                    return Some(v);
                }
            }
        }

        None
    }

    /// Detect Joomla version
    fn detect_joomla_version(&self, base_url: &str, _body: &str) -> Option<String> {
        // Try /administrator/manifests/files/joomla.xml
        let manifest_url = format!(
            "{}/administrator/manifests/files/joomla.xml",
            base_url.trim_end_matches('/')
        );
        if let Ok(response) = self.client.get(&manifest_url) {
            let manifest_body = String::from_utf8_lossy(&response.body);
            if let Some(start) = manifest_body.find("<version>") {
                let version_start = start + 9;
                if let Some(end) = manifest_body[version_start..].find("</version>") {
                    let version = &manifest_body[version_start..version_start + end];
                    return Some(version.trim().to_string());
                }
            }
        }

        None
    }

    /// Extract version number from text (X.Y.Z pattern)
    fn extract_version_number(&self, text: &str) -> Option<String> {
        let chars: Vec<char> = text.chars().collect();
        for i in 0..chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                let mut end = i;

                // Collect version string (digits and dots)
                while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                    end += 1;
                }

                let version = &text[start..end];
                // Must have at least one dot (X.Y)
                if version.contains('.') && version.len() >= 3 {
                    return Some(version.trim_end_matches('.').to_string());
                }
            }
        }
        None
    }

    /// Extract version from CDN URL patterns
    fn extract_from_cdn_url(&self, line: &str, lib_name: &str) -> Option<String> {
        let line_lower = line.to_lowercase();

        // Pattern 1: lib@version (e.g., react@18.2.0)
        let pattern1 = format!("{}@", lib_name);
        if let Some(pos) = line_lower.find(&pattern1) {
            let start = pos + pattern1.len();
            let remaining = &line[start..];
            let end = remaining
                .find(|c: char| c == '/' || c == '"' || c == '\'' || c.is_whitespace())
                .unwrap_or(remaining.len());
            let version = &remaining[..end];
            if !version.is_empty() && version.chars().next().unwrap().is_ascii_digit() {
                return Some(version.to_string());
            }
        }

        // Pattern 2: lib-version (e.g., jquery-3.6.0.min.js)
        let pattern2 = format!("{}-", lib_name);
        if let Some(pos) = line_lower.find(&pattern2) {
            let start = pos + pattern2.len();
            if let Some(version) = self.extract_version_number(&line[start..]) {
                return Some(version);
            }
        }

        // Pattern 3: lib.version (e.g., vue.3.3.4.js)
        let pattern3 = format!("{}.", lib_name);
        if let Some(pos) = line_lower.find(&pattern3) {
            let start = pos + pattern3.len();
            if let Some(version) = self.extract_version_number(&line[start..]) {
                return Some(version);
            }
        }

        // Pattern 4: lib/version/ (e.g., /react/18.2.0/)
        let pattern4 = format!("{}/", lib_name);
        if let Some(pos) = line_lower.find(&pattern4) {
            let start = pos + pattern4.len();
            if let Some(version) = self.extract_version_number(&line[start..]) {
                return Some(version);
            }
        }

        None
    }

    /// Extract version from string like "nginx/1.18.0"
    fn extract_version(&self, text: &str, prefix: &str) -> Option<String> {
        if let Some(start) = text.find(prefix) {
            let version_start = start + prefix.len();
            let remaining = &text[version_start..];

            let version_end = remaining
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(remaining.len());

            let version = &remaining[..version_end];
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
        None
    }
}

impl Default for WebFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        let fp = WebFingerprinter::new();
        assert_eq!(
            fp.extract_version("nginx/1.18.0 ubuntu", "nginx/"),
            Some("1.18.0".to_string())
        );
        assert_eq!(
            fp.extract_version("apache/2.4.41", "apache/"),
            Some("2.4.41".to_string())
        );
    }

    #[test]
    fn test_confidence_display() {
        assert_eq!(format!("{}", Confidence::High), "HIGH");
        assert_eq!(format!("{}", Confidence::Medium), "MEDIUM");
        assert_eq!(format!("{}", Confidence::Low), "LOW");
    }

    #[test]
    fn test_deduplication() {
        let fp = WebFingerprinter::new();
        let mut map = HashMap::new();

        // First detection: React with MEDIUM confidence, no version
        let tech1 = Technology {
            name: "React".to_string(),
            category: TechCategory::Framework,
            version: None,
            confidence: Confidence::Medium,
        };

        // Second detection: React with HIGH confidence and version
        let tech2 = Technology {
            name: "React".to_string(),
            category: TechCategory::Framework,
            version: Some("18.2.0".to_string()),
            confidence: Confidence::High,
        };

        fp.merge_technologies(&mut map, vec![tech1]);
        fp.merge_technologies(&mut map, vec![tech2]);

        assert_eq!(map.len(), 1); // Should have only 1 React entry
        let react = map.get("React").unwrap();
        assert_eq!(react.confidence, Confidence::High);
        assert_eq!(react.version, Some("18.2.0".to_string()));
    }
}
