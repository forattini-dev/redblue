/// Joomla Security Scanner
///
/// Replaces: joomscan
///
/// Features:
/// - Extension enumeration
/// - Template enumeration
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

/// Joomla scan result
pub struct JoomlaScanResult {
    pub extensions: Vec<PluginInfo>,
    pub templates: Vec<ThemeInfo>,
    pub users: Vec<UserInfo>,
    pub findings: Vec<Finding>,
}

/// Scan Joomla site
pub fn scan(config: &CmsScanConfig, _detection: &DetectionResult) -> JoomlaScanResult {
    let mut result = JoomlaScanResult {
        extensions: Vec::new(),
        templates: Vec::new(),
        users: Vec::new(),
        findings: Vec::new(),
    };

    let scanner = JoomlaScanner::new(config.clone());

    // Enumerate extensions
    if config.enumerate_plugins {
        result.extensions = scanner.enumerate_extensions();
    }

    // Enumerate templates
    if config.enumerate_themes {
        result.templates = scanner.enumerate_templates();
    }

    // Enumerate users
    if config.enumerate_users {
        result.users = scanner.enumerate_users();
    }

    // Check for interesting findings
    result.findings = scanner.check_findings();

    result
}

/// Joomla scanner
struct JoomlaScanner {
    config: CmsScanConfig,
}

impl JoomlaScanner {
    fn new(config: CmsScanConfig) -> Self {
        Self { config }
    }

    /// Enumerate Joomla extensions (components, modules, plugins)
    fn enumerate_extensions(&self) -> Vec<PluginInfo> {
        let mut extensions = Vec::new();

        // Method 1: Passive - Check HTML source
        extensions.extend(self.enumerate_extensions_passive());

        // Method 2: Active - Probe known extension paths
        if self.config.aggressive {
            extensions.extend(self.enumerate_extensions_aggressive());
        }

        // Deduplicate
        extensions.sort_by(|a, b| a.name.cmp(&b.name));
        extensions.dedup_by(|a, b| a.name == b.name);

        extensions
    }

    /// Passive extension enumeration
    fn enumerate_extensions_passive(&self) -> Vec<PluginInfo> {
        let mut extensions = Vec::new();

        if let Some(response) = self.fetch(&self.config.target) {
            // Components: /components/com_NAME/
            // Modules: /modules/mod_NAME/
            // Plugins: /plugins/TYPE/PLUGIN_NAME/
            let patterns = [
                ("/components/com_", "component"),
                ("/modules/mod_", "module"),
                ("/plugins/", "plugin"),
            ];

            for (pattern, ext_type) in patterns {
                let mut pos = 0;
                while let Some(start) = response.body[pos..].find(pattern) {
                    let abs_start = pos + start + pattern.len();
                    if let Some(end) = response.body[abs_start..]
                        .find(|c: char| c == '/' || c == '"' || c == '\'' || c == '?')
                    {
                        let ext_name = &response.body[abs_start..abs_start + end];
                        if !ext_name.is_empty() && self.is_valid_slug(ext_name) {
                            let full_name = if ext_type == "component" {
                                format!("com_{}", ext_name)
                            } else if ext_type == "module" {
                                format!("mod_{}", ext_name)
                            } else {
                                ext_name.to_string()
                            };

                            let mut extension = PluginInfo::new(&full_name);
                            extension.detection_method = PluginDetectionMethod::HtmlSource;
                            extension.confidence = 80;
                            extensions.push(extension);
                        }
                    }
                    pos = abs_start;
                }
            }
        }

        extensions
    }

    /// Aggressive extension enumeration
    fn enumerate_extensions_aggressive(&self) -> Vec<PluginInfo> {
        let extensions = Arc::new(Mutex::new(Vec::new()));
        let wordlist = self.get_extension_wordlist();
        let queue = Arc::new(Mutex::new(VecDeque::from(wordlist)));

        let mut handles = Vec::new();
        let num_threads = self.config.threads.min(queue.lock().unwrap().len().max(1));

        for _ in 0..num_threads {
            let queue = Arc::clone(&queue);
            let extensions = Arc::clone(&extensions);
            let target = self.config.target.clone();
            let timeout = self.config.timeout;
            let user_agent = self.config.user_agent.clone();

            let handle = thread::spawn(move || {
                loop {
                    let ext_name = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };

                    match ext_name {
                        Some(name) => {
                            // Check component manifest
                            let manifest_url = format!(
                                "{}/administrator/components/{}/{}.xml",
                                target.trim_end_matches('/'),
                                name,
                                name.trim_start_matches("com_")
                            );

                            if let Some(response) = fetch_url(&manifest_url, &user_agent, timeout) {
                                if response.status_code == 200 && response.contains("<extension") {
                                    let mut extension = PluginInfo::new(&name);
                                    extension.detection_method =
                                        PluginDetectionMethod::DirectAccess;
                                    extension.confidence = 95;

                                    // Extract version
                                    if let Some(version) = extract_joomla_version(&response.body) {
                                        extension.version = Some(version);
                                    }

                                    extensions.lock().unwrap().push(extension);
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

        Arc::try_unwrap(extensions)
            .unwrap_or_else(|_| panic!("Failed to unwrap extensions"))
            .into_inner()
            .unwrap()
    }

    /// Enumerate Joomla templates
    fn enumerate_templates(&self) -> Vec<ThemeInfo> {
        let mut templates = Vec::new();

        if let Some(response) = self.fetch(&self.config.target) {
            // Look for /templates/TEMPLATE_NAME/
            let pattern = "/templates/";
            let mut pos = 0;
            while let Some(start) = response.body[pos..].find(pattern) {
                let abs_start = pos + start + pattern.len();
                if let Some(end) = response.body[abs_start..]
                    .find(|c: char| c == '/' || c == '"' || c == '\'' || c == '?')
                {
                    let template_name = &response.body[abs_start..abs_start + end];
                    if !template_name.is_empty()
                        && self.is_valid_slug(template_name)
                        && template_name != "system"
                    {
                        let mut template = ThemeInfo::new(template_name);
                        template.detection_method = PluginDetectionMethod::HtmlSource;
                        template.is_active = true;

                        // Try to get version from templateDetails.xml
                        let manifest_url = format!(
                            "{}/templates/{}/templateDetails.xml",
                            self.config.target.trim_end_matches('/'),
                            template_name
                        );

                        if let Some(manifest) = self.fetch(&manifest_url) {
                            if manifest.status_code == 200 {
                                if let Some(version) = extract_joomla_version(&manifest.body) {
                                    template.version = Some(version);
                                }
                            }
                        }

                        templates.push(template);
                    }
                }
                pos = abs_start;
            }
        }

        // Deduplicate
        templates.sort_by(|a, b| a.name.cmp(&b.name));
        templates.dedup_by(|a, b| a.name == b.name);

        templates
    }

    /// Enumerate Joomla users
    fn enumerate_users(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        // Method 1: Check author pages
        // Joomla doesn't have standard user enumeration like WordPress
        // But we can try some common paths

        // Method 2: Registration page for info
        let register_url = format!(
            "{}/index.php?option=com_users&view=registration",
            self.config.target.trim_end_matches('/')
        );

        if let Some(response) = self.fetch(&register_url) {
            if response.status_code == 200 && response.contains("registration") {
                // Registration is enabled, note this in findings
            }
        }

        // Method 3: Contact form users
        let contact_url = format!(
            "{}/index.php?option=com_contact&view=contacts",
            self.config.target.trim_end_matches('/')
        );

        if let Some(response) = self.fetch(&contact_url) {
            if response.status_code == 200 {
                // Parse contact names from the page
                users.extend(parse_joomla_contacts(&response.body));
            }
        }

        // Method 4: Author articles
        for id in 1..=10 {
            let url = format!(
                "{}/index.php?option=com_content&view=articles&author={}",
                self.config.target.trim_end_matches('/'),
                id
            );

            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200 {
                    if let Some(author) = extract_joomla_author(&response.body) {
                        let mut user = UserInfo::new(&author);
                        user.id = Some(id as u64);
                        user.detection_method = UserDetectionMethod::AuthorArchive;
                        users.push(user);
                    }
                }
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

        // Check configuration.php backup
        let backup_files = [
            "/configuration.php.bak",
            "/configuration.php.old",
            "/configuration.php~",
            "/configuration.bak",
            "/configuration.txt",
            "/.configuration.php.swp",
        ];

        for backup in backup_files {
            let url = format!("{}{}", self.config.target.trim_end_matches('/'), backup);
            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200 && response.contains("JConfig") {
                    findings.push(Finding {
                        finding_type: FindingType::BackupFile,
                        title: "Configuration Backup Exposed".to_string(),
                        description: format!("Joomla configuration backup found at {}", backup),
                        url: Some(url),
                        evidence: None,
                        severity: VulnSeverity::Critical,
                        confidence: 100,
                    });
                }
            }
        }

        // Check README.txt
        let readme_url = format!("{}/README.txt", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&readme_url) {
            if response.status_code == 200 && response.contains("Joomla") {
                findings.push(Finding {
                    finding_type: FindingType::VersionDisclosure,
                    title: "README.txt Accessible".to_string(),
                    description: "Joomla README.txt is publicly accessible".to_string(),
                    url: Some(readme_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 100,
                });
            }
        }

        // Check htaccess.txt
        let htaccess_url = format!("{}/htaccess.txt", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&htaccess_url) {
            if response.status_code == 200 {
                findings.push(Finding {
                    finding_type: FindingType::ConfigFile,
                    title: "htaccess.txt Accessible".to_string(),
                    description: "Joomla htaccess.txt template is publicly accessible".to_string(),
                    url: Some(htaccess_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 100,
                });
            }
        }

        // Check web.config.txt
        let webconfig_url = format!(
            "{}/web.config.txt",
            self.config.target.trim_end_matches('/')
        );
        if let Some(response) = self.fetch(&webconfig_url) {
            if response.status_code == 200 {
                findings.push(Finding {
                    finding_type: FindingType::ConfigFile,
                    title: "web.config.txt Accessible".to_string(),
                    description: "Joomla web.config.txt template is publicly accessible"
                        .to_string(),
                    url: Some(webconfig_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 100,
                });
            }
        }

        // Check directory listing in key directories
        let dirs = [
            "/administrator/components/",
            "/administrator/modules/",
            "/administrator/templates/",
            "/components/",
            "/modules/",
            "/plugins/",
            "/images/",
            "/media/",
            "/tmp/",
        ];

        for dir in dirs {
            let url = format!("{}{}", self.config.target.trim_end_matches('/'), dir);
            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200
                    && (response.contains("Index of") || response.contains("Parent Directory"))
                {
                    findings.push(Finding {
                        finding_type: FindingType::DirectoryListing,
                        title: "Directory Listing Enabled".to_string(),
                        description: format!("Directory listing enabled at {}", dir),
                        url: Some(url),
                        evidence: None,
                        severity: VulnSeverity::Low,
                        confidence: 100,
                    });
                }
            }
        }

        // Check for debug mode
        if let Some(response) = self.fetch(&self.config.target) {
            if response.contains("JDEBUG") || response.contains("Joomla! Debug Console") {
                findings.push(Finding {
                    finding_type: FindingType::DebugMode,
                    title: "Debug Mode Enabled".to_string(),
                    description: "Joomla debug mode appears to be enabled".to_string(),
                    url: Some(self.config.target.clone()),
                    evidence: None,
                    severity: VulnSeverity::Medium,
                    confidence: 80,
                });
            }
        }

        // Check user registration
        let register_url = format!(
            "{}/index.php?option=com_users&view=registration",
            self.config.target.trim_end_matches('/')
        );
        if let Some(response) = self.fetch(&register_url) {
            if response.status_code == 200
                && (response.contains("Register") || response.contains("registration"))
            {
                findings.push(Finding {
                    finding_type: FindingType::RegistrationEnabled,
                    title: "User Registration Enabled".to_string(),
                    description: "User registration is enabled on this Joomla site".to_string(),
                    url: Some(register_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 90,
                });
            }
        }

        findings
    }

    /// Check if string is valid extension slug
    fn is_valid_slug(&self, s: &str) -> bool {
        !s.is_empty()
            && s.len() < 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }

    /// Get extension wordlist
    fn get_extension_wordlist(&self) -> Vec<String> {
        // Top Joomla components
        vec![
            "com_content",
            "com_users",
            "com_contact",
            "com_banners",
            "com_newsfeeds",
            "com_weblinks",
            "com_search",
            "com_finder",
            "com_tags",
            "com_redirect",
            "com_akeeba",
            "com_sh404sef",
            "com_k2",
            "com_virtuemart",
            "com_hikashop",
            "com_kunena",
            "com_easyblog",
            "com_zoo",
            "com_jce",
            "com_acymailing",
            "com_rsform",
            "com_phocagallery",
            "com_fabrik",
            "com_jevents",
            "com_docman",
            "com_jdownloads",
            "com_jomsocial",
            "com_community",
            "com_comprofiler",
            "com_easydiscuss",
            "com_roksprocket",
            "com_widgetkit",
            "com_yootheme",
            "com_gantry5",
            "com_sp_pagebuilder",
            "com_quix",
            "com_jch_optimize",
            "com_admintools",
            "com_jsecure",
            "com_jomdefender",
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

/// Extract version from Joomla XML manifest
fn extract_joomla_version(xml: &str) -> Option<String> {
    // Look for <version>X.Y.Z</version>
    if let Some(start) = xml.find("<version>") {
        let after = &xml[start + 9..];
        if let Some(end) = after.find("</version>") {
            let version = &after[..end];
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
    }
    None
}

/// Parse contacts from Joomla contacts page
fn parse_joomla_contacts(html: &str) -> Vec<UserInfo> {
    let mut users = Vec::new();

    // Look for contact names in typical Joomla contact list HTML
    // Usually in format: <span class="contact-name">Name</span>
    let patterns = [
        ("class=\"contact-name\"", "</span>"),
        ("class=\"contact_name\"", "</span>"),
        ("itemprop=\"name\"", "</span>"),
    ];

    for (start_pattern, end_tag) in patterns {
        let mut pos = 0;
        while let Some(start) = html[pos..].find(start_pattern) {
            let abs_start = pos + start;
            let after = &html[abs_start..];

            // Find the end of the opening tag
            if let Some(tag_end) = after.find('>') {
                let content_start = tag_end + 1;
                if let Some(end) = after[content_start..].find(end_tag) {
                    let name = after[content_start..content_start + end].trim();
                    // Remove HTML entities
                    let clean_name = name
                        .replace("&amp;", "&")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&quot;", "\"");

                    if !clean_name.is_empty() {
                        let mut user = UserInfo::new(&clean_name);
                        user.detection_method = UserDetectionMethod::AuthorArchive;
                        users.push(user);
                    }
                }
            }

            pos = abs_start + start_pattern.len();
        }
    }

    users
}

/// Extract author from Joomla article page
fn extract_joomla_author(html: &str) -> Option<String> {
    // Look for author in article metadata
    let patterns = [
        ("class=\"createdby\"", "</span>"),
        ("class=\"created-by\"", "</span>"),
        ("itemprop=\"author\"", "</span>"),
    ];

    for (start_pattern, end_tag) in patterns {
        if let Some(start) = html.find(start_pattern) {
            let after = &html[start..];
            if let Some(tag_end) = after.find('>') {
                let content_start = tag_end + 1;
                if let Some(end) = after[content_start..].find(end_tag) {
                    let author = after[content_start..content_start + end].trim();
                    // Clean up - remove "Written by:" prefix if present
                    let clean = author
                        .trim_start_matches("Written by:")
                        .trim_start_matches("By:")
                        .trim();

                    if !clean.is_empty() {
                        return Some(clean.to_string());
                    }
                }
            }
        }
    }

    None
}
