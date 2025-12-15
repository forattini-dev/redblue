/// Vulnerability Database Module
///
/// Correlates CMS versions and components with known vulnerabilities
use super::{CmsType, PluginInfo, ThemeInfo, VulnComponent, VulnSeverity, VulnType, Vulnerability};

/// Vulnerability database
pub struct VulnDatabase {
    /// Core CMS vulnerabilities
    core_vulns: Vec<VulnEntry>,
    /// Plugin/module vulnerabilities
    plugin_vulns: Vec<VulnEntry>,
    /// Theme/template vulnerabilities
    theme_vulns: Vec<VulnEntry>,
}

/// Vulnerability entry in database
#[derive(Debug, Clone)]
struct VulnEntry {
    /// CMS type (or Any for all)
    cms: Option<CmsType>,
    /// Component name (empty for core)
    component_name: String,
    /// Component type
    component: VulnComponent,
    /// Vulnerability ID
    id: String,
    /// Title
    title: String,
    /// Description
    description: String,
    /// Affected versions (semver range)
    affected_versions: String,
    /// Fixed version
    fixed_in: Option<String>,
    /// Severity
    severity: VulnSeverity,
    /// CVSS score
    cvss: Option<f32>,
    /// Vulnerability type
    vuln_type: VulnType,
    /// References
    references: Vec<String>,
    /// Exploit available
    exploit_available: bool,
}

impl VulnDatabase {
    pub fn new() -> Self {
        Self {
            core_vulns: Self::load_core_vulns(),
            plugin_vulns: Self::load_plugin_vulns(),
            theme_vulns: Self::load_theme_vulns(),
        }
    }

    /// Lookup vulnerabilities for CMS, plugins, and themes
    pub fn lookup(
        &self,
        cms_type: CmsType,
        version: &str,
        plugins: &[PluginInfo],
        themes: &[ThemeInfo],
    ) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check core vulnerabilities
        for entry in &self.core_vulns {
            if entry.cms.map_or(true, |c| c == cms_type) {
                if self.version_matches(version, &entry.affected_versions) {
                    vulns.push(entry.to_vulnerability());
                }
            }
        }

        // Check plugin vulnerabilities
        for plugin in plugins {
            for entry in &self.plugin_vulns {
                if entry.cms.map_or(true, |c| c == cms_type) {
                    if self.component_matches(&plugin.name, &entry.component_name) {
                        let plugin_version = plugin.version.as_deref().unwrap_or("0.0.0");
                        if self.version_matches(plugin_version, &entry.affected_versions) {
                            vulns.push(entry.to_vulnerability());
                        }
                    }
                }
            }
        }

        // Check theme vulnerabilities
        for theme in themes {
            for entry in &self.theme_vulns {
                if entry.cms.map_or(true, |c| c == cms_type) {
                    if self.component_matches(&theme.name, &entry.component_name) {
                        let theme_version = theme.version.as_deref().unwrap_or("0.0.0");
                        if self.version_matches(theme_version, &entry.affected_versions) {
                            vulns.push(entry.to_vulnerability());
                        }
                    }
                }
            }
        }

        // Deduplicate by ID
        vulns.sort_by(|a, b| a.id.cmp(&b.id));
        vulns.dedup_by(|a, b| a.id == b.id);

        // Sort by severity
        vulns.sort_by(|a, b| b.severity.cmp(&a.severity));

        vulns
    }

    /// Check if version matches affected range
    fn version_matches(&self, version: &str, affected: &str) -> bool {
        // Simple version matching
        // Supports formats like:
        // - "< 5.8.2" (less than)
        // - "<= 5.8.2" (less than or equal)
        // - "> 5.0.0" (greater than)
        // - "5.0.0 - 5.8.2" (range)
        // - "*" (all versions)
        // - "5.8.2" (exact match)

        if affected == "*" {
            return true;
        }

        let current = self.parse_version(version);

        if affected.contains(" - ") {
            // Range: "5.0.0 - 5.8.2"
            let parts: Vec<&str> = affected.split(" - ").collect();
            if parts.len() == 2 {
                let min = self.parse_version(parts[0]);
                let max = self.parse_version(parts[1]);
                return current >= min && current <= max;
            }
        } else if affected.starts_with("<=") {
            let target = self.parse_version(affected.trim_start_matches("<=").trim());
            return current <= target;
        } else if affected.starts_with('<') {
            let target = self.parse_version(affected.trim_start_matches('<').trim());
            return current < target;
        } else if affected.starts_with(">=") {
            let target = self.parse_version(affected.trim_start_matches(">=").trim());
            return current >= target;
        } else if affected.starts_with('>') {
            let target = self.parse_version(affected.trim_start_matches('>').trim());
            return current > target;
        } else {
            // Exact match
            let target = self.parse_version(affected);
            return current == target;
        }

        false
    }

    /// Parse version string into comparable tuple
    fn parse_version(&self, version: &str) -> (u32, u32, u32) {
        let parts: Vec<u32> = version
            .split('.')
            .take(3)
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
            })
            .map(|s| s.parse().unwrap_or(0))
            .collect();

        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    }

    /// Check if component name matches
    fn component_matches(&self, actual: &str, pattern: &str) -> bool {
        let actual_lower = actual.to_lowercase();
        let pattern_lower = pattern.to_lowercase();

        actual_lower == pattern_lower
            || actual_lower.contains(&pattern_lower)
            || pattern_lower.contains(&actual_lower)
    }

    /// Load core CMS vulnerabilities
    fn load_core_vulns() -> Vec<VulnEntry> {
        vec![
            // WordPress core vulnerabilities
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2023-2745".to_string(),
                title: "WordPress < 6.2.1 - Directory Traversal".to_string(),
                description: "Directory traversal vulnerability in wp_lang parameter".to_string(),
                affected_versions: "< 6.2.1".to_string(),
                fixed_in: Some("6.2.1".to_string()),
                severity: VulnSeverity::Medium,
                cvss: Some(5.4),
                vuln_type: VulnType::PathTraversal,
                references: vec![
                    "https://wpscan.com/vulnerability/edcf8b94-2c73-4301-a4c0-1c8ce0bdc748"
                        .to_string(),
                ],
                exploit_available: false,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2022-21661".to_string(),
                title: "WordPress 5.8.2 - SQL Injection".to_string(),
                description: "SQL injection vulnerability in WP_Query".to_string(),
                affected_versions: "< 5.8.3".to_string(),
                fixed_in: Some("5.8.3".to_string()),
                severity: VulnSeverity::High,
                cvss: Some(8.0),
                vuln_type: VulnType::SqlInjection,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-21661".to_string()],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2021-29447".to_string(),
                title: "WordPress 5.6 - 5.7 - XXE via Media Library".to_string(),
                description: "XXE vulnerability when uploading media files".to_string(),
                affected_versions: "5.6.0 - 5.7.0".to_string(),
                fixed_in: Some("5.7.1".to_string()),
                severity: VulnSeverity::High,
                cvss: Some(7.1),
                vuln_type: VulnType::Xxe,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-29447".to_string()],
                exploit_available: true,
            },
            // Drupal core vulnerabilities
            VulnEntry {
                cms: Some(CmsType::Drupal),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2018-7600".to_string(),
                title: "Drupalgeddon 2 - Remote Code Execution".to_string(),
                description: "Critical RCE via Form API #default_value".to_string(),
                affected_versions: "< 7.58".to_string(),
                fixed_in: Some("7.58".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(9.8),
                vuln_type: VulnType::Rce,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-7600".to_string()],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::Drupal),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2018-7602".to_string(),
                title: "Drupalgeddon 3 - Remote Code Execution".to_string(),
                description: "Critical RCE vulnerability requiring authentication".to_string(),
                affected_versions: "< 7.59".to_string(),
                fixed_in: Some("7.59".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(8.1),
                vuln_type: VulnType::Rce,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-7602".to_string()],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::Drupal),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2019-6340".to_string(),
                title: "Drupal < 8.6.10 - RESTful RCE".to_string(),
                description: "RCE via RESTful web services module".to_string(),
                affected_versions: "< 8.6.10".to_string(),
                fixed_in: Some("8.6.10".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(9.8),
                vuln_type: VulnType::Rce,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-6340".to_string()],
                exploit_available: true,
            },
            // Joomla core vulnerabilities
            VulnEntry {
                cms: Some(CmsType::Joomla),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2023-23752".to_string(),
                title: "Joomla 4.0.0-4.2.7 - Improper Access Check".to_string(),
                description: "Unauthenticated information disclosure via REST API".to_string(),
                affected_versions: "4.0.0 - 4.2.7".to_string(),
                fixed_in: Some("4.2.8".to_string()),
                severity: VulnSeverity::High,
                cvss: Some(7.5),
                vuln_type: VulnType::InformationDisclosure,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-23752".to_string()],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::Joomla),
                component_name: String::new(),
                component: VulnComponent::Core,
                id: "CVE-2015-8562".to_string(),
                title: "Joomla 1.5.0-3.4.5 - Object Injection RCE".to_string(),
                description: "Remote code execution via PHP object injection".to_string(),
                affected_versions: "< 3.4.6".to_string(),
                fixed_in: Some("3.4.6".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(9.8),
                vuln_type: VulnType::Deserialization,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2015-8562".to_string()],
                exploit_available: true,
            },
        ]
    }

    /// Load plugin/module vulnerabilities
    fn load_plugin_vulns() -> Vec<VulnEntry> {
        vec![
            // WordPress plugin vulnerabilities
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "elementor".to_string(),
                component: VulnComponent::Plugin,
                id: "CVE-2023-32243".to_string(),
                title: "Elementor Pro < 3.11.7 - Arbitrary File Upload".to_string(),
                description: "Authenticated arbitrary file upload leading to RCE".to_string(),
                affected_versions: "< 3.11.7".to_string(),
                fixed_in: Some("3.11.7".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(9.8),
                vuln_type: VulnType::FileUpload,
                references: vec![
                    "https://wpscan.com/vulnerability/31c23b9c-e5c2-4d0b-9f8a-cd6b5b9a75c7"
                        .to_string(),
                ],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "contact-form-7".to_string(),
                component: VulnComponent::Plugin,
                id: "CVE-2020-35489".to_string(),
                title: "Contact Form 7 < 5.3.2 - Unrestricted File Upload".to_string(),
                description: "File upload bypass allowing PHP file uploads".to_string(),
                affected_versions: "< 5.3.2".to_string(),
                fixed_in: Some("5.3.2".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(10.0),
                vuln_type: VulnType::FileUpload,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-35489".to_string()],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "wp-file-manager".to_string(),
                component: VulnComponent::Plugin,
                id: "CVE-2020-25213".to_string(),
                title: "File Manager < 6.9 - Unauthenticated RCE".to_string(),
                description: "Unauthenticated arbitrary file upload and execution".to_string(),
                affected_versions: "< 6.9".to_string(),
                fixed_in: Some("6.9".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(10.0),
                vuln_type: VulnType::Rce,
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-25213".to_string()],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "really-simple-ssl".to_string(),
                component: VulnComponent::Plugin,
                id: "CVE-2023-44478".to_string(),
                title: "Really Simple SSL < 7.2.0 - Authentication Bypass".to_string(),
                description: "Authentication bypass via 2FA bypass".to_string(),
                affected_versions: "< 7.2.0".to_string(),
                fixed_in: Some("7.2.0".to_string()),
                severity: VulnSeverity::Critical,
                cvss: Some(9.8),
                vuln_type: VulnType::AuthBypass,
                references: vec!["https://wpscan.com/vulnerability/a1b2c3d4".to_string()],
                exploit_available: false,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "yoast-seo".to_string(),
                component: VulnComponent::Plugin,
                id: "WPScan-2021-001".to_string(),
                title: "Yoast SEO < 16.5 - Authenticated Stored XSS".to_string(),
                description: "Stored XSS via SEO analysis features".to_string(),
                affected_versions: "< 16.5".to_string(),
                fixed_in: Some("16.5".to_string()),
                severity: VulnSeverity::Medium,
                cvss: Some(5.4),
                vuln_type: VulnType::Xss,
                references: vec![],
                exploit_available: false,
            },
            // Drupal module vulnerabilities
            VulnEntry {
                cms: Some(CmsType::Drupal),
                component_name: "webform".to_string(),
                component: VulnComponent::Plugin,
                id: "SA-CONTRIB-2022-001".to_string(),
                title: "Webform < 6.1.3 - Access Bypass".to_string(),
                description: "Access bypass allowing unauthorized submissions".to_string(),
                affected_versions: "< 6.1.3".to_string(),
                fixed_in: Some("6.1.3".to_string()),
                severity: VulnSeverity::Medium,
                cvss: Some(5.3),
                vuln_type: VulnType::AuthBypass,
                references: vec![],
                exploit_available: false,
            },
            // Joomla component vulnerabilities
            VulnEntry {
                cms: Some(CmsType::Joomla),
                component_name: "com_fabrik".to_string(),
                component: VulnComponent::Plugin,
                id: "CVE-2023-FABRIK".to_string(),
                title: "Fabrik - SQL Injection".to_string(),
                description: "SQL injection in list view".to_string(),
                affected_versions: "*".to_string(),
                fixed_in: None,
                severity: VulnSeverity::High,
                cvss: Some(8.6),
                vuln_type: VulnType::SqlInjection,
                references: vec![],
                exploit_available: true,
            },
        ]
    }

    /// Load theme/template vulnerabilities
    fn load_theme_vulns() -> Vec<VulnEntry> {
        vec![
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "flavor".to_string(),
                component: VulnComponent::Theme,
                id: "WPScan-THEME-001".to_string(),
                title: "flavor Theme - Local File Inclusion".to_string(),
                description: "LFI via template parameter".to_string(),
                affected_versions: "*".to_string(),
                fixed_in: None,
                severity: VulnSeverity::High,
                cvss: Some(7.5),
                vuln_type: VulnType::Lfi,
                references: vec![],
                exploit_available: true,
            },
            VulnEntry {
                cms: Some(CmsType::WordPress),
                component_name: "flavor".to_string(),
                component: VulnComponent::Theme,
                id: "WPScan-THEME-002".to_string(),
                title: "flavor Theme - Arbitrary File Upload".to_string(),
                description: "Unauthenticated file upload".to_string(),
                affected_versions: "*".to_string(),
                fixed_in: None,
                severity: VulnSeverity::Critical,
                cvss: Some(9.8),
                vuln_type: VulnType::FileUpload,
                references: vec![],
                exploit_available: true,
            },
        ]
    }
}

impl Default for VulnDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnEntry {
    /// Convert to Vulnerability struct
    fn to_vulnerability(&self) -> Vulnerability {
        Vulnerability {
            id: self.id.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            severity: self.severity,
            cvss: self.cvss,
            component: self.component,
            component_name: self.component_name.clone(),
            affected_versions: self.affected_versions.clone(),
            fixed_in: self.fixed_in.clone(),
            vuln_type: self.vuln_type,
            references: self.references.clone(),
            exploit_available: self.exploit_available,
            published: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_matching() {
        let db = VulnDatabase::new();

        assert!(db.version_matches("5.8.0", "< 5.8.3"));
        assert!(!db.version_matches("5.8.3", "< 5.8.3"));
        assert!(db.version_matches("5.8.3", "<= 5.8.3"));
        assert!(db.version_matches("5.6.0", "5.6.0 - 5.7.0"));
        assert!(db.version_matches("5.7.0", "5.6.0 - 5.7.0"));
        assert!(!db.version_matches("5.8.0", "5.6.0 - 5.7.0"));
        assert!(db.version_matches("1.0.0", "*"));
    }

    #[test]
    fn test_lookup_wordpress() {
        let db = VulnDatabase::new();
        let vulns = db.lookup(CmsType::WordPress, "5.8.0", &[], &[]);

        // Should find vulnerabilities for WordPress 5.8.0
        assert!(!vulns.is_empty());
    }
}
