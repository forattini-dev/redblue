/// Joomla security scanner
///
/// Replaces: droopescan (Joomla plugin for CMSmap), joomscan
///
/// Features:
/// - Joomla detection (multiple methods)
/// - Version detection
/// - Extension enumeration (components, modules, plugins)
/// - Template enumeration
/// - User enumeration
/// - Common vulnerabilities check
/// - Configuration file exposure
///
/// NO external dependencies - pure Rust implementation
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct JoomlaScanResult {
    pub is_joomla: bool,
    pub version: Option<String>,
    pub extensions: Vec<JoomlaExtension>,
    pub templates: Vec<JoomlaTemplate>,
    pub users: Vec<String>,
    pub vulnerabilities: Vec<JoomlaVulnerability>,
    pub config_exposure: Vec<ConfigFile>,
}

#[derive(Debug, Clone)]
pub struct JoomlaExtension {
    pub name: String,
    pub ext_type: ExtensionType,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub enum ExtensionType {
    Component,
    Module,
    Plugin,
}

impl std::fmt::Display for ExtensionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionType::Component => write!(f, "Component"),
            ExtensionType::Module => write!(f, "Module"),
            ExtensionType::Plugin => write!(f, "Plugin"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JoomlaTemplate {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct JoomlaVulnerability {
    pub title: String,
    pub severity: VulnSeverity,
    pub description: String,
    pub affected_versions: String,
    pub cve: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnSeverity::Critical => write!(f, "CRITICAL"),
            VulnSeverity::High => write!(f, "HIGH"),
            VulnSeverity::Medium => write!(f, "MEDIUM"),
            VulnSeverity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigFile {
    pub path: String,
    pub status: u16,
    pub risk: String,
}

pub struct JoomlaScanner {
    client: HttpClient,
    aggressive: bool,
}

impl JoomlaScanner {
    pub fn new() -> Self {
        Self {
            client: HttpClient::new(),
            aggressive: false,
        }
    }

    pub fn with_aggressive(mut self, aggressive: bool) -> Self {
        self.aggressive = aggressive;
        self
    }

    /// Main scan entry point
    pub fn scan(&self, url: &str) -> Result<JoomlaScanResult, String> {
        self.scan_with_progress(url, None)
    }

    pub fn scan_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<JoomlaScanResult, String> {
        const TOTAL_PHASES: usize = 6;
        fn advance_progress(
            progress: &Option<Arc<dyn ScanProgress>>,
            completed: &mut usize,
            count: usize,
        ) {
            if count == 0 {
                return;
            }
            if let Some(p) = progress.as_ref() {
                p.inc(count);
            }
            *completed += count;
        }
        let mut completed = 0usize;

        let base_url = url.trim_end_matches('/');

        // 1. Detect if it's Joomla
        let (is_joomla, version) = self.detect_joomla(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        if !is_joomla {
            let remaining = TOTAL_PHASES.saturating_sub(completed);
            if remaining > 0 {
                advance_progress(&progress, &mut completed, remaining);
            }
            return Ok(JoomlaScanResult {
                is_joomla: false,
                version: None,
                extensions: vec![],
                templates: vec![],
                users: vec![],
                vulnerabilities: vec![],
                config_exposure: vec![],
            });
        }

        // 2. Enumerate extensions (components, modules, plugins)
        let extensions = self.enumerate_extensions(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        // 3. Enumerate templates
        let templates = self.enumerate_templates(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        // 4. Enumerate users (if aggressive)
        let users = if self.aggressive {
            let users = self.enumerate_users(base_url)?;
            advance_progress(&progress, &mut completed, 1);
            users
        } else {
            advance_progress(&progress, &mut completed, 1);
            vec![]
        };

        // 5. Check for config file exposure
        let config_exposure = self.check_config_files(base_url)?;
        advance_progress(&progress, &mut completed, 1);

        // 6. Check for known vulnerabilities based on version
        let vulnerabilities = if let Some(ref ver) = version {
            self.check_vulnerabilities(ver)
        } else {
            vec![]
        };
        advance_progress(&progress, &mut completed, 1);

        Ok(JoomlaScanResult {
            is_joomla: true,
            version,
            extensions,
            templates,
            users,
            vulnerabilities,
            config_exposure,
        })
    }

    /// Detect Joomla using multiple methods
    fn detect_joomla(&self, base_url: &str) -> Result<(bool, Option<String>), String> {
        // Method 1: Check main page for Joomla signatures
        if let Ok(response) = self.client.get(base_url) {
            let body = String::from_utf8_lossy(&response.body);
            let body_lower = body.to_lowercase();

            // Look for Joomla-specific patterns
            if body_lower.contains("/components/com_")
                || body_lower.contains("/media/jui/")
                || body_lower.contains("joomla!")
                || body.contains("Joomla.JText")
                || body_lower.contains("/templates/system/")
            {
                let version = self.detect_version(base_url, &body);
                return Ok((true, version));
            }

            // Check meta generator
            if let Some(start) = body_lower.find("<meta name=\"generator\"") {
                if let Some(content_start) = body[start..].find("content=\"") {
                    let content_pos = start + content_start + 9;
                    if let Some(content_end) = body[content_pos..].find('"') {
                        let generator = &body[content_pos..content_pos + content_end];
                        if generator.to_lowercase().contains("joomla") {
                            let version = self.extract_version_from_text(generator);
                            return Ok((true, version));
                        }
                    }
                }
            }
        }

        // Method 2: Try administrator/manifests/files/joomla.xml
        let manifest_url = format!("{}/administrator/manifests/files/joomla.xml", base_url);
        if let Ok(response) = self.client.get(&manifest_url) {
            if response.status_code == 200 {
                let manifest = String::from_utf8_lossy(&response.body);
                if manifest.to_lowercase().contains("joomla") {
                    let version = self.extract_version_from_xml(&manifest, "version");
                    return Ok((true, version));
                }
            }
        }

        // Method 3: Try language/en-GB/en-GB.xml
        let lang_url = format!("{}/language/en-GB/en-GB.xml", base_url);
        if let Ok(response) = self.client.get(&lang_url) {
            if response.status_code == 200 {
                let lang_xml = String::from_utf8_lossy(&response.body);
                if lang_xml.to_lowercase().contains("joomla") {
                    let version = self.extract_version_from_xml(&lang_xml, "version");
                    return Ok((true, version));
                }
            }
        }

        Ok((false, None))
    }

    /// Detect Joomla version
    fn detect_version(&self, base_url: &str, body: &str) -> Option<String> {
        // Try administrator/manifests/files/joomla.xml first
        let manifest_url = format!("{}/administrator/manifests/files/joomla.xml", base_url);
        if let Ok(response) = self.client.get(&manifest_url) {
            if response.status_code == 200 {
                let manifest = String::from_utf8_lossy(&response.body);
                if let Some(version) = self.extract_version_from_xml(&manifest, "version") {
                    return Some(version);
                }
            }
        }

        // Try language/en-GB/en-GB.xml
        let lang_url = format!("{}/language/en-GB/en-GB.xml", base_url);
        if let Ok(response) = self.client.get(&lang_url) {
            if response.status_code == 200 {
                let lang_xml = String::from_utf8_lossy(&response.body);
                if let Some(version) = self.extract_version_from_xml(&lang_xml, "version") {
                    return Some(version);
                }
            }
        }

        // Try extracting from body meta tags
        self.extract_version_from_text(body)
    }

    /// Extract version from XML
    fn extract_version_from_xml(&self, xml: &str, tag: &str) -> Option<String> {
        let open_tag = format!("<{}>", tag);
        let close_tag = format!("</{}>", tag);

        if let Some(start) = xml.find(&open_tag) {
            let version_start = start + open_tag.len();
            if let Some(end) = xml[version_start..].find(&close_tag) {
                let version = &xml[version_start..version_start + end];
                return Some(version.trim().to_string());
            }
        }
        None
    }

    /// Extract version number from text
    fn extract_version_from_text(&self, text: &str) -> Option<String> {
        let chars: Vec<char> = text.chars().collect();
        for i in 0..chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                let mut end = i;

                while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                    end += 1;
                }

                let version = &text[start..end];
                if version.contains('.') && version.len() >= 3 {
                    return Some(version.trim_end_matches('.').to_string());
                }
            }
        }
        None
    }

    /// Enumerate installed extensions (components, modules, plugins)
    fn enumerate_extensions(&self, base_url: &str) -> Result<Vec<JoomlaExtension>, String> {
        let mut extensions = Vec::new();
        let mut found = HashSet::new();

        // Popular components
        let popular_components = vec![
            "com_content",
            "com_users",
            "com_contact",
            "com_search",
            "com_weblinks",
            "com_newsfeeds",
            "com_banners",
            "com_media",
            "com_mailto",
            "com_wrapper",
            "com_admin",
            "com_ajax",
            "com_config",
            "com_finder",
            "com_joomlaupdate",
            "com_languages",
            "com_login",
            "com_modules",
            "com_plugins",
            "com_redirect",
            "com_tags",
            "com_templates",
        ];

        for component in popular_components {
            let component_url = format!("{}/components/{}/", base_url, component);

            if let Ok(response) = self.client.get(&component_url) {
                if (200..400).contains(&response.status_code) && !found.contains(component) {
                    // Try to get manifest
                    let manifest_url =
                        format!("{}/components/{}/{}.xml", base_url, component, component);
                    let version = if let Ok(manifest_resp) = self.client.get(&manifest_url) {
                        if manifest_resp.status_code == 200 {
                            let manifest = String::from_utf8_lossy(&manifest_resp.body);
                            self.extract_version_from_xml(&manifest, "version")
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    extensions.push(JoomlaExtension {
                        name: component.to_string(),
                        ext_type: ExtensionType::Component,
                        version,
                        path: format!("/components/{}", component),
                    });

                    found.insert(component);
                }
            }
        }

        // Popular modules
        let popular_modules = vec![
            "mod_articles_archive",
            "mod_articles_categories",
            "mod_articles_category",
            "mod_articles_latest",
            "mod_articles_news",
            "mod_articles_popular",
            "mod_banners",
            "mod_breadcrumbs",
            "mod_custom",
            "mod_feed",
            "mod_finder",
            "mod_footer",
            "mod_languages",
            "mod_login",
            "mod_menu",
            "mod_random_image",
            "mod_related_items",
            "mod_search",
            "mod_stats",
            "mod_syndicate",
            "mod_tags_popular",
            "mod_tags_similar",
            "mod_users_latest",
            "mod_weblinks",
            "mod_whosonline",
            "mod_wrapper",
        ];

        for module in popular_modules {
            let module_url = format!("{}/modules/{}/{}.xml", base_url, module, module);

            if let Ok(response) = self.client.get(&module_url) {
                if response.status_code == 200 {
                    let manifest = String::from_utf8_lossy(&response.body);
                    let version = self.extract_version_from_xml(&manifest, "version");

                    extensions.push(JoomlaExtension {
                        name: module.to_string(),
                        ext_type: ExtensionType::Module,
                        version,
                        path: format!("/modules/{}", module),
                    });
                }
            }
        }

        Ok(extensions)
    }

    /// Enumerate installed templates
    fn enumerate_templates(&self, base_url: &str) -> Result<Vec<JoomlaTemplate>, String> {
        let mut templates = Vec::new();
        let mut found_templates = HashSet::new();

        // Popular Joomla templates
        let popular_templates = vec![
            "protostar",
            "beez3",
            "atomic",
            "system",
            "isis",       // Administrator template
            "hathor",     // Old admin template
            "cassiopeia", // Joomla 4+
            "atum",       // Joomla 4+ admin
        ];

        for template_name in popular_templates {
            let template_url = format!(
                "{}/templates/{}/templateDetails.xml",
                base_url, template_name
            );

            if let Ok(response) = self.client.get(&template_url) {
                if response.status_code == 200 && !found_templates.contains(template_name) {
                    let details = String::from_utf8_lossy(&response.body);
                    let version = self.extract_version_from_xml(&details, "version");

                    templates.push(JoomlaTemplate {
                        name: template_name.to_string(),
                        version,
                        path: format!("/templates/{}", template_name),
                    });

                    found_templates.insert(template_name);
                }
            }
        }

        Ok(templates)
    }

    /// Enumerate users (aggressive mode)
    fn enumerate_users(&self, base_url: &str) -> Result<Vec<String>, String> {
        let mut users = Vec::new();

        // Try common user IDs (1-10)
        for uid in 1..=10 {
            // Joomla user profiles are usually at /index.php?option=com_users&view=user&id=X
            let user_url = format!(
                "{}/index.php?option=com_users&view=user&id={}",
                base_url, uid
            );

            if let Ok(response) = self.client.get(&user_url) {
                if response.status_code == 200 {
                    let body = String::from_utf8_lossy(&response.body);

                    // Try to extract username from page title or content
                    if let Some(title_start) = body.find("<title>") {
                        let title_pos = title_start + 7;
                        if let Some(title_end) = body[title_pos..].find("</title>") {
                            let title = &body[title_pos..title_pos + title_end];
                            let username = title.split('-').next().unwrap_or(title).trim();
                            if !username.is_empty() && username != "User" {
                                users.push(username.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(users)
    }

    /// Check for exposed configuration files
    fn check_config_files(&self, base_url: &str) -> Result<Vec<ConfigFile>, String> {
        let mut exposed = Vec::new();

        let sensitive_files = vec![
            (
                "/configuration.php",
                "Main configuration file (database credentials)",
                "CRITICAL",
            ),
            (
                "/configuration.php~",
                "Configuration backup file",
                "CRITICAL",
            ),
            (
                "/configuration.php.bak",
                "Configuration backup file",
                "CRITICAL",
            ),
            ("/.htaccess", "Apache configuration", "MEDIUM"),
            ("/web.config", "IIS configuration", "MEDIUM"),
            ("/README.txt", "Readme file with version info", "LOW"),
            ("/LICENSE.txt", "License file", "LOW"),
            ("/robots.txt", "Robots exclusion file", "LOW"),
        ];

        for (path, risk, _severity) in sensitive_files {
            let url = format!("{}{}", base_url, path);

            if let Ok(response) = self.client.get(&url) {
                if response.status_code == 200 {
                    exposed.push(ConfigFile {
                        path: path.to_string(),
                        status: response.status_code,
                        risk: risk.to_string(),
                    });
                }
            }
        }

        Ok(exposed)
    }

    /// Check for known vulnerabilities based on version
    fn check_vulnerabilities(&self, version: &str) -> Vec<JoomlaVulnerability> {
        let mut vulns = Vec::new();

        // Parse version (e.g., "3.9.28" -> (3, 9, 28))
        let parts: Vec<&str> = version.split('.').collect();
        if parts.is_empty() {
            return vulns;
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = if parts.len() > 1 {
            parts[1].parse().unwrap_or(0)
        } else {
            0
        };
        let patch: u32 = if parts.len() > 2 {
            parts[2].parse().unwrap_or(0)
        } else {
            0
        };

        // Joomla 3.x EOL (End of Life August 2023)
        if major == 3 {
            vulns.push(JoomlaVulnerability {
                title: "Joomla 3.x End of Life".to_string(),
                severity: VulnSeverity::High,
                description:
                    "Joomla 3.x reached end of life in August 2023. No more security updates."
                        .to_string(),
                affected_versions: "3.x".to_string(),
                cve: None,
            });
        }

        // Object Injection - CVE-2023-23752
        if major == 4 && minor == 2 && patch < 8 {
            vulns.push(JoomlaVulnerability {
                title: "Object Injection Vulnerability".to_string(),
                severity: VulnSeverity::Critical,
                description:
                    "Improper access check allows unauthorized access to webservice endpoints."
                        .to_string(),
                affected_versions: "4.0.0 - 4.2.7".to_string(),
                cve: Some("CVE-2023-23752".to_string()),
            });
        }

        // XSS in com_fields - CVE-2018-6376
        if major == 3 && minor < 8 {
            vulns.push(JoomlaVulnerability {
                title: "XSS in com_fields Component".to_string(),
                severity: VulnSeverity::Medium,
                description: "Cross-site scripting vulnerability in custom fields component."
                    .to_string(),
                affected_versions: "3.7.0 - 3.8.3".to_string(),
                cve: Some("CVE-2018-6376".to_string()),
            });
        }

        // SQL Injection - CVE-2015-8562
        if major == 3 && minor < 5 {
            vulns.push(JoomlaVulnerability {
                title: "SQL Injection in Session Handling".to_string(),
                severity: VulnSeverity::Critical,
                description:
                    "SQL injection vulnerability in session handling allows remote code execution."
                        .to_string(),
                affected_versions: "3.2.0 - 3.4.6".to_string(),
                cve: Some("CVE-2015-8562".to_string()),
            });
        }

        vulns
    }
}

impl Default for JoomlaScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        let scanner = JoomlaScanner::new();
        assert_eq!(
            scanner.extract_version_from_text("Joomla! 3.9.28"),
            Some("3.9.28".to_string())
        );
        assert_eq!(
            scanner.extract_version_from_text("Version 4.2.7"),
            Some("4.2.7".to_string())
        );
    }

    #[test]
    fn test_xml_version_extraction() {
        let scanner = JoomlaScanner::new();
        let xml = "<manifest><version>3.9.28</version></manifest>";
        assert_eq!(
            scanner.extract_version_from_xml(xml, "version"),
            Some("3.9.28".to_string())
        );
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", VulnSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", VulnSeverity::High), "HIGH");
        assert_eq!(format!("{}", VulnSeverity::Medium), "MEDIUM");
        assert_eq!(format!("{}", VulnSeverity::Low), "LOW");
    }
}
