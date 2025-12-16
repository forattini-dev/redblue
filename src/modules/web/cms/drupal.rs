/// Drupal Security Scanner
///
/// Replaces: droopescan (Drupal features)
///
/// Features:
/// - Module enumeration
/// - Theme enumeration
/// - User enumeration
/// - Version detection
/// - Vulnerability correlation
use super::{
    CmsScanConfig, DetectionResult, Finding, FindingType, HttpResponse, PluginDetectionMethod,
    PluginInfo, ThemeInfo, UserDetectionMethod, UserInfo, VulnSeverity,
};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;

/// Drupal scan result
pub struct DrupalScanResult {
    pub modules: Vec<PluginInfo>,
    pub themes: Vec<ThemeInfo>,
    pub users: Vec<UserInfo>,
    pub findings: Vec<Finding>,
}

/// Scan Drupal site
pub fn scan(config: &CmsScanConfig, _detection: &DetectionResult) -> DrupalScanResult {
    let mut result = DrupalScanResult {
        modules: Vec::new(),
        themes: Vec::new(),
        users: Vec::new(),
        findings: Vec::new(),
    };

    let scanner = DrupalScanner::new(config.clone());

    // Enumerate modules
    if config.enumerate_plugins {
        result.modules = scanner.enumerate_modules();
    }

    // Enumerate themes
    if config.enumerate_themes {
        result.themes = scanner.enumerate_themes();
    }

    // Enumerate users
    if config.enumerate_users {
        result.users = scanner.enumerate_users();
    }

    // Check for interesting findings
    result.findings = scanner.check_findings();

    result
}

/// Drupal scanner
struct DrupalScanner {
    config: CmsScanConfig,
}

impl DrupalScanner {
    fn new(config: CmsScanConfig) -> Self {
        Self { config }
    }

    /// Enumerate Drupal modules
    fn enumerate_modules(&self) -> Vec<PluginInfo> {
        let mut modules = Vec::new();

        // Method 1: Passive - Check HTML source
        modules.extend(self.enumerate_modules_passive());

        // Method 2: Active - Probe known module paths
        if self.config.aggressive {
            modules.extend(self.enumerate_modules_aggressive());
        }

        // Deduplicate
        modules.sort_by(|a, b| a.name.cmp(&b.name));
        modules.dedup_by(|a, b| a.name == b.name);

        modules
    }

    /// Passive module enumeration
    fn enumerate_modules_passive(&self) -> Vec<PluginInfo> {
        let mut modules = Vec::new();

        if let Some(response) = self.fetch(&self.config.target) {
            // Drupal 7: /sites/all/modules/MODULE_NAME
            // Drupal 8+: /modules/contrib/MODULE_NAME or /modules/custom/MODULE_NAME
            let patterns = [
                "/sites/all/modules/",
                "/sites/default/modules/",
                "/modules/contrib/",
                "/modules/custom/",
            ];

            for pattern in patterns {
                let mut pos = 0;
                while let Some(start) = response.body[pos..].find(pattern) {
                    let abs_start = pos + start + pattern.len();
                    if let Some(end) = response.body[abs_start..]
                        .find(|c: char| matches!(c, '/' | '"' | '\'' | '?'))
                    {
                        let module_name = &response.body[abs_start..abs_start + end];
                        if !module_name.is_empty() && self.is_valid_slug(module_name) {
                            let mut module = PluginInfo::new(module_name);
                            module.detection_method = PluginDetectionMethod::HtmlSource;
                            module.confidence = 80;
                            modules.push(module);
                        }
                    }
                    pos = abs_start;
                }
            }
        }

        modules
    }

    /// Aggressive module enumeration
    fn enumerate_modules_aggressive(&self) -> Vec<PluginInfo> {
        let modules = Arc::new(Mutex::new(Vec::new()));
        let wordlist = self.get_module_wordlist();
        let queue = Arc::new(Mutex::new(VecDeque::from(wordlist)));

        let mut handles = Vec::new();
        let num_threads = self.config.threads.min(queue.lock().unwrap().len().max(1));

        for _ in 0..num_threads {
            let queue = Arc::clone(&queue);
            let modules = Arc::clone(&modules);
            let target = self.config.target.clone();
            let timeout = self.config.timeout;
            let user_agent = self.config.user_agent.clone();

            let handle = thread::spawn(move || {
                loop {
                    let module_slug = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };

                    match module_slug {
                        Some(slug) => {
                            // Try Drupal 8+ path first
                            let paths = [
                                format!(
                                    "{}/modules/contrib/{}/{}.info.yml",
                                    target.trim_end_matches('/'),
                                    slug,
                                    slug
                                ),
                                format!(
                                    "{}/sites/all/modules/{}/{}.info",
                                    target.trim_end_matches('/'),
                                    slug,
                                    slug
                                ),
                            ];

                            for path in paths {
                                if let Some(response) = fetch_url(&path, &user_agent, timeout) {
                                    if response.status_code == 200 {
                                        let mut module = PluginInfo::new(&slug);
                                        module.detection_method =
                                            PluginDetectionMethod::DirectAccess;
                                        module.confidence = 95;

                                        // Extract version
                                        if let Some(version) =
                                            extract_drupal_version(&response.body)
                                        {
                                            module.version = Some(version);
                                        }

                                        modules.lock().unwrap().push(module);
                                        break;
                                    }
                                }
                            }
                        }
                        None => break,
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        Arc::try_unwrap(modules)
            .unwrap_or_else(|_| panic!("Failed to unwrap modules"))
            .into_inner()
            .unwrap()
    }

    /// Enumerate Drupal themes
    fn enumerate_themes(&self) -> Vec<ThemeInfo> {
        let mut themes = Vec::new();

        if let Some(response) = self.fetch(&self.config.target) {
            // Drupal 7: /sites/all/themes/THEME_NAME
            // Drupal 8+: /themes/contrib/THEME_NAME
            let patterns = [
                "/sites/all/themes/",
                "/sites/default/themes/",
                "/themes/contrib/",
                "/themes/custom/",
            ];

            for pattern in patterns {
                let mut pos = 0;
                while let Some(start) = response.body[pos..].find(pattern) {
                    let abs_start = pos + start + pattern.len();
                    if let Some(end) = response.body[abs_start..]
                        .find(|c: char| matches!(c, '/' | '"' | '\'' | '?'))
                    {
                        let theme_name = &response.body[abs_start..abs_start + end];
                        if !theme_name.is_empty() && self.is_valid_slug(theme_name) {
                            let mut theme = ThemeInfo::new(theme_name);
                            theme.detection_method = PluginDetectionMethod::HtmlSource;
                            theme.is_active = true;
                            themes.push(theme);
                        }
                    }
                    pos = abs_start;
                }
            }
        }

        themes
    }

    /// Enumerate Drupal users
    fn enumerate_users(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        // Method 1: User profile pages (/user/N)
        for id in 0..=20 {
            let url = format!("{}/user/{}", self.config.target.trim_end_matches('/'), id);

            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200 {
                    // Extract username from page title or content
                    if let Some(username) = extract_drupal_username(&response.body) {
                        let mut user = UserInfo::new(&username);
                        user.id = Some(id as u64);
                        user.detection_method = UserDetectionMethod::AuthorArchive;
                        user.profile_url = Some(url);
                        users.push(user);
                    }
                }
            }
        }

        // Method 2: JSONAPI (Drupal 8+)
        let jsonapi_url = format!(
            "{}/jsonapi/user/user",
            self.config.target.trim_end_matches('/')
        );
        if let Some(response) = self.fetch(&jsonapi_url) {
            if response.status_code == 200 {
                users.extend(parse_drupal_jsonapi_users(&response.body));
            }
        }

        // Deduplicate
        users.sort_by(|a, b| a.username.cmp(&b.username));
        users.dedup_by(|a, b| a.username == b.username);

        users
    }

    /// Check for interesting findings
    fn check_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check CHANGELOG.txt (version disclosure)
        let changelog_url = format!("{}/CHANGELOG.txt", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&changelog_url) {
            if response.status_code == 200 && response.contains("Drupal") {
                findings.push(Finding {
                    finding_type: FindingType::VersionDisclosure,
                    title: "CHANGELOG.txt Accessible".to_string(),
                    description:
                        "Drupal CHANGELOG.txt is publicly accessible, exposing version information"
                            .to_string(),
                    url: Some(changelog_url),
                    evidence: None,
                    severity: VulnSeverity::Low,
                    confidence: 100,
                });
            }
        }

        // Check INSTALL.txt
        let install_url = format!("{}/INSTALL.txt", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&install_url) {
            if response.status_code == 200 {
                findings.push(Finding {
                    finding_type: FindingType::SensitiveFile,
                    title: "INSTALL.txt Accessible".to_string(),
                    description: "Drupal installation instructions are publicly accessible"
                        .to_string(),
                    url: Some(install_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 100,
                });
            }
        }

        // Check update.php
        let update_url = format!("{}/update.php", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&update_url) {
            if response.status_code == 200 && !response.contains("Access denied") {
                findings.push(Finding {
                    finding_type: FindingType::SensitiveFile,
                    title: "update.php Accessible".to_string(),
                    description: "Drupal update.php may be accessible without authentication"
                        .to_string(),
                    url: Some(update_url),
                    evidence: None,
                    severity: VulnSeverity::High,
                    confidence: 70,
                });
            }
        }

        // Check user registration
        let register_url = format!("{}/user/register", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&register_url) {
            if response.status_code == 200 && response.contains("Create new account") {
                findings.push(Finding {
                    finding_type: FindingType::RegistrationEnabled,
                    title: "User Registration Enabled".to_string(),
                    description: "User registration is enabled on this Drupal site".to_string(),
                    url: Some(register_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 90,
                });
            }
        }

        // Check private files exposure
        let private_url = format!(
            "{}/sites/default/files/private",
            self.config.target.trim_end_matches('/')
        );
        if let Some(response) = self.fetch(&private_url) {
            if response.status_code == 200 || response.status_code == 403 {
                // Even 403 indicates the path exists
                if response.contains("Index of") {
                    findings.push(Finding {
                        finding_type: FindingType::DirectoryListing,
                        title: "Private Files Directory Listing".to_string(),
                        description:
                            "Private files directory is accessible with directory listing enabled"
                                .to_string(),
                        url: Some(private_url),
                        evidence: None,
                        severity: VulnSeverity::High,
                        confidence: 100,
                    });
                }
            }
        }

        // Check for backup files
        let backup_files = [
            "/sites/default/settings.php.bak",
            "/sites/default/settings.php.old",
            "/sites/default/settings.php~",
            "/sites/default/default.settings.php",
        ];

        for backup in backup_files {
            let url = format!("{}{}", self.config.target.trim_end_matches('/'), backup);
            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200 && response.contains("database") {
                    findings.push(Finding {
                        finding_type: FindingType::BackupFile,
                        title: "Configuration Backup Exposed".to_string(),
                        description: format!("Drupal configuration backup found at {}", backup),
                        url: Some(url),
                        evidence: None,
                        severity: VulnSeverity::Critical,
                        confidence: 100,
                    });
                }
            }
        }

        findings
    }

    /// Check if string is valid module/theme slug
    fn is_valid_slug(&self, s: &str) -> bool {
        !s.is_empty() && s.len() < 100 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Get module wordlist
    fn get_module_wordlist(&self) -> Vec<String> {
        // Top Drupal modules
        vec![
            "admin_toolbar",
            "pathauto",
            "ctools",
            "token",
            "metatag",
            "redirect",
            "webform",
            "google_analytics",
            "xmlsitemap",
            "captcha",
            "views_slideshow",
            "backup_migrate",
            "media",
            "colorbox",
            "entity",
            "field_group",
            "link",
            "libraries",
            "date",
            "imce",
            "rules",
            "features",
            "views_bulk_operations",
            "module_filter",
            "devel",
            "admin_menu",
            "wysiwyg",
            "entity_reference",
            "ckeditor",
            "entityqueue",
            "paragraphs",
            "layout_builder",
            "twig_tweak",
            "config_split",
            "simple_sitemap",
            "recaptcha",
            "honeypot",
            "seckit",
            "security_review",
            "password_policy",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    /// Fetch URL
    fn fetch(&self, url: &str) -> Option<HttpResponse> {
        fetch_url(url, &self.config.user_agent, self.config.timeout)
    }
}

/// Fetch URL helper
fn fetch_url(url: &str, user_agent: &str, timeout: std::time::Duration) -> Option<HttpResponse> {
    let (host, port, path, use_tls) = parse_url(url)?;

    if use_tls {
        return None;
    }

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Accept: */*\r\n\
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

/// Parse URL
fn parse_url(url: &str) -> Option<(String, u16, String, bool)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
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
            headers.push((
                line[..pos].trim().to_string(),
                line[pos + 1..].trim().to_string(),
            ));
        }
    }

    let body_start = text
        .find("\r\n\r\n")
        .map(|p| p + 4)
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

/// Extract version from Drupal .info or .info.yml
fn extract_drupal_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("version") {
            // Handle both .info and .info.yml formats
            let parts: Vec<&str> = line.splitn(2, |c| matches!(c, '=' | ':')).collect();
            if parts.len() == 2 {
                let version = parts[1].trim().trim_matches('"').trim_matches('\'');
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
    }
    None
}

/// Extract username from Drupal user page
fn extract_drupal_username(html: &str) -> Option<String> {
    // Look for <title>USERNAME | Site Name</title>
    if let Some(start) = html.find("<title>") {
        let after = &html[start + 7..];
        if let Some(end) = after.find("</title>") {
            let title = &after[..end];
            // Username is usually before | or -
            if let Some(sep) = title.find('|').or_else(|| title.find('-')) {
                let username = title[..sep].trim();
                if !username.is_empty() && username != "Anonymous" {
                    return Some(username.to_string());
                }
            }
        }
    }

    // Look for class="username"
    if let Some(start) = html.find("class=\"username\"") {
        let after = &html[start..];
        if let Some(tag_end) = after.find('>') {
            let content_start = tag_end + 1;
            if let Some(end) = after[content_start..].find('<') {
                let username = &after[content_start..content_start + end];
                if !username.is_empty() {
                    return Some(username.to_string());
                }
            }
        }
    }

    None
}

/// Parse Drupal JSONAPI users response
fn parse_drupal_jsonapi_users(json: &str) -> Vec<UserInfo> {
    let mut users = Vec::new();

    // Look for "name": patterns in data array
    let json = json.trim();

    // Simple parsing for user objects in JSONAPI format
    let mut pos = 0;
    while let Some(name_pos) = json[pos..].find("\"name\":") {
        let abs_pos = pos + name_pos + 7;
        let after = json[abs_pos..].trim_start();

        if after.starts_with('"') {
            let value_start = 1;
            if let Some(end) = after[value_start..].find('"') {
                let username = &after[value_start..value_start + end];
                if !username.is_empty() && username != "Anonymous" {
                    let mut user = UserInfo::new(username);
                    user.detection_method = UserDetectionMethod::RestApi;
                    users.push(user);
                }
            }
        }

        pos = abs_pos;
    }

    users
}
