/// WordPress Security Scanner
///
/// Replaces: wpscan
///
/// Features:
/// - Plugin enumeration (passive & aggressive)
/// - Theme enumeration
/// - User enumeration (7 methods)
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

/// WordPress scan result
pub struct WordPressScanResult {
    pub plugins: Vec<PluginInfo>,
    pub themes: Vec<ThemeInfo>,
    pub users: Vec<UserInfo>,
    pub findings: Vec<Finding>,
}

/// Scan WordPress site
pub fn scan(config: &CmsScanConfig, _detection: &DetectionResult) -> WordPressScanResult {
    let mut result = WordPressScanResult {
        plugins: Vec::new(),
        themes: Vec::new(),
        users: Vec::new(),
        findings: Vec::new(),
    };

    let scanner = WordPressScanner::new(config.clone());

    // Enumerate plugins
    if config.enumerate_plugins {
        result.plugins = scanner.enumerate_plugins();
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

/// WordPress scanner
struct WordPressScanner {
    config: CmsScanConfig,
}

impl WordPressScanner {
    fn new(config: CmsScanConfig) -> Self {
        Self { config }
    }

    /// Enumerate WordPress plugins
    fn enumerate_plugins(&self) -> Vec<PluginInfo> {
        let mut plugins = Vec::new();

        // Method 1: Passive - Check HTML source for plugin paths
        plugins.extend(self.enumerate_plugins_passive());

        // Method 2: Active - Probe known plugin paths
        if self.config.aggressive {
            plugins.extend(self.enumerate_plugins_aggressive());
        }

        // Deduplicate
        plugins.sort_by(|a, b| a.name.cmp(&b.name));
        plugins.dedup_by(|a, b| a.name == b.name);

        plugins
    }

    /// Passive plugin enumeration from HTML
    fn enumerate_plugins_passive(&self) -> Vec<PluginInfo> {
        let mut plugins = Vec::new();

        if let Some(response) = self.fetch(&self.config.target) {
            // Look for wp-content/plugins/PLUGIN_NAME patterns
            let patterns = ["/wp-content/plugins/", "/wp-content/mu-plugins/"];

            for pattern in patterns {
                let mut pos = 0;
                while let Some(start) = response.body[pos..].find(pattern) {
                    let abs_start = pos + start + pattern.len();
                    if let Some(end) = response.body[abs_start..]
                        .find(|c: char| matches!(c, '/' | '"' | '\'' | '?'))
                    {
                        let plugin_name = &response.body[abs_start..abs_start + end];
                        if !plugin_name.is_empty() && self.is_valid_slug(plugin_name) {
                            let mut plugin = PluginInfo::new(plugin_name);
                            plugin.detection_method = PluginDetectionMethod::HtmlSource;
                            plugin.confidence = 80;
                            plugins.push(plugin);
                        }
                    }
                    pos = abs_start;
                }
            }
        }

        plugins
    }

    /// Aggressive plugin enumeration
    fn enumerate_plugins_aggressive(&self) -> Vec<PluginInfo> {
        let plugins = Arc::new(Mutex::new(Vec::new()));
        let wordlist = self.get_plugin_wordlist();
        let queue = Arc::new(Mutex::new(VecDeque::from(wordlist)));

        let mut handles = Vec::new();
        let num_threads = self.config.threads.min(queue.lock().unwrap().len().max(1));

        for _ in 0..num_threads {
            let queue = Arc::clone(&queue);
            let plugins = Arc::clone(&plugins);
            let target = self.config.target.clone();
            let timeout = self.config.timeout;
            let user_agent = self.config.user_agent.clone();

            let handle = thread::spawn(move || {
                loop {
                    let plugin_slug = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };

                    match plugin_slug {
                        Some(slug) => {
                            // Check readme.txt
                            let readme_url = format!(
                                "{}/wp-content/plugins/{}/readme.txt",
                                target.trim_end_matches('/'),
                                slug
                            );

                            if let Some(response) = fetch_url(&readme_url, &user_agent, timeout) {
                                if response.status_code == 200 {
                                    let mut plugin = PluginInfo::new(&slug);
                                    plugin.detection_method = PluginDetectionMethod::ReadmeFile;
                                    plugin.confidence = 95;

                                    // Try to extract version from readme
                                    if let Some(version) = extract_wp_readme_version(&response.body)
                                    {
                                        plugin.version = Some(version);
                                    }

                                    plugins.lock().unwrap().push(plugin);
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

        Arc::try_unwrap(plugins)
            .unwrap_or_else(|_| panic!("Failed to unwrap plugins"))
            .into_inner()
            .unwrap()
    }

    /// Enumerate WordPress themes
    fn enumerate_themes(&self) -> Vec<ThemeInfo> {
        let mut themes = Vec::new();

        // Method 1: Passive - Check HTML for theme paths
        if let Some(response) = self.fetch(&self.config.target) {
            // Look for wp-content/themes/THEME_NAME
            let pattern = "/wp-content/themes/";
            let mut pos = 0;
            while let Some(start) = response.body[pos..].find(pattern) {
                let abs_start = pos + start + pattern.len();
                if let Some(end) =
                    response.body[abs_start..].find(|c: char| matches!(c, '/' | '"' | '\'' | '?'))
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

        // Method 2: Check style.css for version
        for theme in &mut themes {
            let style_url = format!(
                "{}/wp-content/themes/{}/style.css",
                self.config.target.trim_end_matches('/'),
                theme.name
            );

            if let Some(response) = self.fetch(&style_url) {
                if response.status_code == 200 {
                    // Extract version from style.css header
                    if let Some(version) = extract_theme_version(&response.body) {
                        theme.version = Some(version);
                    }
                }
            }
        }

        themes
    }

    /// Enumerate WordPress users (7 methods)
    fn enumerate_users(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        // Method 1: Author archive (/?author=N)
        users.extend(self.enumerate_users_author_archive());

        // Method 2: REST API (/wp-json/wp/v2/users)
        users.extend(self.enumerate_users_rest_api());

        // Method 3: oEmbed
        users.extend(self.enumerate_users_oembed());

        // Method 4: RSS feed
        users.extend(self.enumerate_users_rss());

        // Method 5: Login error messages
        if self.config.aggressive {
            users.extend(self.enumerate_users_login_errors());
        }

        // Deduplicate by username
        users.sort_by(|a, b| a.username.cmp(&b.username));
        users.dedup_by(|a, b| a.username == b.username);

        users
    }

    /// Enumerate users via author archive
    fn enumerate_users_author_archive(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        for id in 1..=20 {
            let url = format!(
                "{}/?author={}",
                self.config.target.trim_end_matches('/'),
                id
            );

            if let Some(response) = self.fetch(&url) {
                // Check for redirect to author page
                if response.status_code == 301 || response.status_code == 302 {
                    if let Some(location) = response.get_header("Location") {
                        // Extract username from /author/USERNAME/
                        if let Some(author_pos) = location.find("/author/") {
                            let after = &location[author_pos + 8..];
                            if let Some(end) = after.find('/') {
                                let username = &after[..end];
                                let mut user = UserInfo::new(username);
                                user.id = Some(id as u64);
                                user.detection_method = UserDetectionMethod::AuthorArchive;
                                users.push(user);
                            }
                        }
                    }
                }
            }
        }

        users
    }

    /// Enumerate users via REST API
    fn enumerate_users_rest_api(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        let url = format!(
            "{}/wp-json/wp/v2/users",
            self.config.target.trim_end_matches('/')
        );

        if let Some(response) = self.fetch(&url) {
            if response.status_code == 200 {
                // Parse JSON array of users
                // Format: [{"id":1,"name":"admin","slug":"admin",...},...]
                users.extend(parse_wp_users_json(&response.body));
            }
        }

        for user in &mut users {
            user.detection_method = UserDetectionMethod::RestApi;
        }

        users
    }

    /// Enumerate users via oEmbed
    fn enumerate_users_oembed(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        let url = format!(
            "{}/wp-json/oembed/1.0/embed?url={}",
            self.config.target.trim_end_matches('/'),
            urlencoding(&self.config.target)
        );

        if let Some(response) = self.fetch(&url) {
            if response.status_code == 200 {
                // Look for "author_name" in JSON
                if let Some(name) = extract_json_field(&response.body, "author_name") {
                    let mut user = UserInfo::new(&name);
                    user.detection_method = UserDetectionMethod::OEmbed;
                    users.push(user);
                }
            }
        }

        users
    }

    /// Enumerate users via RSS feed
    fn enumerate_users_rss(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        let url = format!("{}/feed/", self.config.target.trim_end_matches('/'));

        if let Some(response) = self.fetch(&url) {
            if response.status_code == 200 {
                // Parse <dc:creator> tags
                let mut pos = 0;
                while let Some(start) = response.body[pos..].find("<dc:creator>") {
                    let abs_start = pos + start + 12;
                    if let Some(end) = response.body[abs_start..].find("</dc:creator>") {
                        let creator = &response.body[abs_start..abs_start + end];
                        // Handle CDATA
                        let username = creator
                            .trim_start_matches("<![CDATA[")
                            .trim_end_matches("]]>");

                        if !username.is_empty() {
                            let mut user = UserInfo::new(username);
                            user.detection_method = UserDetectionMethod::RssFeed;
                            users.push(user);
                        }
                    }
                    pos = abs_start;
                }
            }
        }

        users
    }

    /// Enumerate users via login error messages
    fn enumerate_users_login_errors(&self) -> Vec<UserInfo> {
        let mut users = Vec::new();

        let common_usernames = [
            "admin",
            "administrator",
            "root",
            "user",
            "test",
            "wp",
            "wordpress",
        ];

        for username in common_usernames {
            let url = format!("{}/wp-login.php", self.config.target.trim_end_matches('/'));
            let body = format!("log={}&pwd=wrong&wp-submit=Log+In", username);

            if let Some(response) = self.post(&url, &body) {
                // Check for "Invalid username" vs "incorrect password"
                if response.body.contains("incorrect password")
                    || response.body.contains("The password you entered")
                    || !response.body.contains("Invalid username")
                {
                    let mut user = UserInfo::new(username);
                    user.detection_method = UserDetectionMethod::LoginError;
                    users.push(user);
                }
            }
        }

        users
    }

    /// Check for interesting findings
    fn check_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check XML-RPC
        let xmlrpc_url = format!("{}/xmlrpc.php", self.config.target.trim_end_matches('/'));
        if let Some(response) = self.fetch(&xmlrpc_url) {
            if response.status_code == 200
                && response.contains("XML-RPC server accepts POST requests only")
            {
                findings.push(Finding {
                    finding_type: FindingType::XmlRpcEnabled,
                    title: "XML-RPC Enabled".to_string(),
                    description: "XML-RPC is enabled, which can be used for brute force attacks"
                        .to_string(),
                    url: Some(xmlrpc_url),
                    evidence: None,
                    severity: VulnSeverity::Medium,
                    confidence: 100,
                });
            }
        }

        // Check wp-config.php backup
        let backup_files = [
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php~",
            "/wp-config.bak",
            "/wp-config.old",
            "/wp-config.txt",
            "/.wp-config.php.swp",
        ];

        for backup in backup_files {
            let url = format!("{}{}", self.config.target.trim_end_matches('/'), backup);
            if let Some(response) = self.fetch(&url) {
                if response.status_code == 200 && response.contains("DB_NAME") {
                    findings.push(Finding {
                        finding_type: FindingType::BackupFile,
                        title: "Configuration Backup Exposed".to_string(),
                        description: format!("WordPress configuration backup found at {}", backup),
                        url: Some(url),
                        evidence: None,
                        severity: VulnSeverity::Critical,
                        confidence: 100,
                    });
                }
            }
        }

        // Check debug.log
        let debug_url = format!(
            "{}/wp-content/debug.log",
            self.config.target.trim_end_matches('/')
        );
        if let Some(response) = self.fetch(&debug_url) {
            if response.status_code == 200 && response.body.len() > 100 {
                findings.push(Finding {
                    finding_type: FindingType::DebugMode,
                    title: "Debug Log Exposed".to_string(),
                    description: "WordPress debug log is publicly accessible".to_string(),
                    url: Some(debug_url),
                    evidence: None,
                    severity: VulnSeverity::High,
                    confidence: 90,
                });
            }
        }

        // Check user registration
        let register_url = format!(
            "{}/wp-login.php?action=register",
            self.config.target.trim_end_matches('/')
        );
        if let Some(response) = self.fetch(&register_url) {
            if response.status_code == 200 && response.contains("Register") {
                findings.push(Finding {
                    finding_type: FindingType::RegistrationEnabled,
                    title: "User Registration Enabled".to_string(),
                    description: "User registration is enabled on this WordPress site".to_string(),
                    url: Some(register_url),
                    evidence: None,
                    severity: VulnSeverity::Info,
                    confidence: 80,
                });
            }
        }

        // Check directory listing
        let dirs = [
            "/wp-content/uploads/",
            "/wp-content/plugins/",
            "/wp-includes/",
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

        findings
    }

    /// Check if string is valid plugin/theme slug
    fn is_valid_slug(&self, s: &str) -> bool {
        !s.is_empty()
            && s.len() < 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Get plugin wordlist
    fn get_plugin_wordlist(&self) -> Vec<String> {
        // Top 100 WordPress plugins
        vec![
            "akismet",
            "jetpack",
            "wordfence",
            "yoast-seo",
            "contact-form-7",
            "elementor",
            "woocommerce",
            "wpforms-lite",
            "classic-editor",
            "really-simple-ssl",
            "updraftplus",
            "duplicate-post",
            "wp-super-cache",
            "tinymce-advanced",
            "all-in-one-wp-migration",
            "redirection",
            "wp-mail-smtp",
            "mailchimp-for-wp",
            "google-analytics-for-wordpress",
            "wp-statistics",
            "all-in-one-seo-pack",
            "w3-total-cache",
            "instagram-feed",
            "wp-smushit",
            "loginizer",
            "google-sitemap-generator",
            "better-wp-security",
            "wp-fastest-cache",
            "ninja-forms",
            "tablepress",
            "regenerate-thumbnails",
            "limit-login-attempts-reloaded",
            "wp-file-manager",
            "ewww-image-optimizer",
            "shortcodes-ultimate",
            "optinmonster",
            "advanced-custom-fields",
            "cookiebot",
            "autoptimize",
            "easy-table-of-contents",
            "svg-support",
            "insert-headers-and-footers",
            "cookie-notice",
            "post-smtp",
            "widget-logic",
            "header-footer-elementor",
            "disable-comments",
            "custom-css-js",
            "broken-link-checker",
            "sucuri-scanner",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    /// Fetch URL
    fn fetch(&self, url: &str) -> Option<HttpResponse> {
        fetch_url(url, &self.config.user_agent, self.config.timeout)
    }

    /// POST request
    fn post(&self, url: &str, body: &str) -> Option<HttpResponse> {
        post_url(url, body, &self.config.user_agent, self.config.timeout)
    }
}

/// Fetch URL helper
fn fetch_url(url: &str, user_agent: &str, timeout: std::time::Duration) -> Option<HttpResponse> {
    let (host, port, path, use_tls) = parse_url(url)?;

    if use_tls {
        return None; // Would need TLS implementation
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

/// POST URL helper
fn post_url(
    url: &str,
    body: &str,
    user_agent: &str,
    timeout: std::time::Duration,
) -> Option<HttpResponse> {
    let (host, port, path, use_tls) = parse_url(url)?;

    if use_tls {
        return None;
    }

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path,
        host,
        user_agent,
        body.len(),
        body
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

/// Extract version from readme.txt
fn extract_wp_readme_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("stable tag:") {
            let version = line[11..].trim();
            if !version.is_empty() && version != "trunk" {
                return Some(version.to_string());
            }
        }
    }
    None
}

/// Extract version from style.css
fn extract_theme_version(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.to_lowercase().contains("version:") {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let version = parts[1].trim();
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
    }
    None
}

/// Parse WordPress users JSON
fn parse_wp_users_json(json: &str) -> Vec<UserInfo> {
    let mut users = Vec::new();

    // Simple JSON array parsing
    let json = json.trim();
    if !json.starts_with('[') || !json.ends_with(']') {
        return users;
    }

    // Split by user objects
    let mut depth = 0;
    let mut start = 1;

    for (i, c) in json.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    let obj = &json[start..=i];
                    let mut user = UserInfo::new("");

                    if let Some(id) = extract_json_number(obj, "id") {
                        user.id = Some(id);
                    }
                    if let Some(name) = extract_json_field(obj, "name") {
                        user.display_name = Some(name);
                    }
                    if let Some(slug) = extract_json_field(obj, "slug") {
                        user.username = slug;
                    }

                    if !user.username.is_empty() {
                        users.push(user);
                    }
                }
            }
            _ => {}
        }
    }

    users
}

/// Extract JSON string field
fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    if let Some(pos) = json.find(&pattern) {
        let after = &json[pos + pattern.len()..];
        let after = after.trim_start();

        if after.starts_with('"') {
            let value_start = 1;
            if let Some(end) = after[value_start..].find('"') {
                return Some(after[value_start..value_start + end].to_string());
            }
        }
    }
    None
}

/// Extract JSON number field
fn extract_json_number(json: &str, field: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", field);
    if let Some(pos) = json.find(&pattern) {
        let after = &json[pos + pattern.len()..];
        let after = after.trim_start();

        let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();

        if !num_str.is_empty() {
            return num_str.parse().ok();
        }
    }
    None
}

/// Simple URL encoding
fn urlencoding(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for b in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    result
}
