//! Google Dorks reconnaissance
//!
//! Search engine dorking using DuckDuckGo (more permissive than Google).
//! Discovers:
//! - GitHub repositories and code leaks
//! - Pastebin leaks
//! - LinkedIn employees
//! - Exposed documents (PDF, DOC, XLS)
//! - Subdomains via search
//! - Login/admin pages
//! - Config files
//! - Error pages revealing info

use crate::protocols::http::HttpClient;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;

/// Result from a single dork query
#[derive(Debug, Clone)]
pub struct DorkResult {
    pub query: String,
    pub category: String,
    pub urls: Vec<String>,
}

/// Result from all dork searches
#[derive(Debug, Clone)]
pub struct DorksSearchResult {
    pub domain: String,
    pub company_name: String,
    pub categories: DorkCategories,
    pub summary: DorksSummary,
}

#[derive(Debug, Clone, Default)]
pub struct DorkCategories {
    pub github: Vec<DorkResult>,
    pub pastebin: Vec<DorkResult>,
    pub linkedin: Vec<DorkResult>,
    pub documents: Vec<DorkResult>,
    pub subdomains: Vec<String>,
    pub login_pages: Vec<DorkResult>,
    pub configs: Vec<DorkResult>,
    pub errors: Vec<DorkResult>,
}

#[derive(Debug, Clone, Default)]
pub struct DorksSummary {
    pub total_results: usize,
    pub github_count: usize,
    pub pastebin_count: usize,
    pub linkedin_count: usize,
    pub documents_count: usize,
    pub subdomains_count: usize,
    pub login_pages_count: usize,
    pub configs_count: usize,
    pub errors_count: usize,
}

/// Google Dorks searcher
pub struct DorksSearcher {
    http: HttpClient,
    delay_ms: u64,
    max_results_per_query: usize,
}

impl DorksSearcher {
    pub fn new() -> Self {
        Self {
            http: HttpClient::new().with_timeout(Duration::from_secs(15)),
            delay_ms: 2000, // Rate limiting
            max_results_per_query: 10,
        }
    }

    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = delay_ms;
        self
    }

    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results_per_query = max;
        self
    }

    /// Run all dork searches for a domain
    pub fn search(&self, domain: &str) -> DorksSearchResult {
        let base_domain = Self::extract_base_domain(domain);
        let company_name = Self::extract_company_name(&base_domain);

        let mut categories = DorkCategories::default();

        // GitHub search
        categories.github = self.search_github(&base_domain, &company_name);
        self.rate_limit();

        // Pastebin search
        categories.pastebin = self.search_pastebin(&base_domain, &company_name);
        self.rate_limit();

        // LinkedIn search
        categories.linkedin = self.search_linkedin(&company_name);
        self.rate_limit();

        // Document search
        categories.documents = self.search_documents(&base_domain);
        self.rate_limit();

        // Subdomain search
        categories.subdomains = self.search_subdomains(&base_domain);
        self.rate_limit();

        // Login pages search
        categories.login_pages = self.search_login_pages(&base_domain);
        self.rate_limit();

        // Config files search
        categories.configs = self.search_configs(&base_domain);
        self.rate_limit();

        // Error pages search
        categories.errors = self.search_errors(&base_domain);

        // Calculate summary
        let summary = DorksSummary {
            github_count: categories.github.iter().map(|r| r.urls.len()).sum(),
            pastebin_count: categories.pastebin.iter().map(|r| r.urls.len()).sum(),
            linkedin_count: categories.linkedin.iter().map(|r| r.urls.len()).sum(),
            documents_count: categories.documents.iter().map(|r| r.urls.len()).sum(),
            subdomains_count: categories.subdomains.len(),
            login_pages_count: categories.login_pages.iter().map(|r| r.urls.len()).sum(),
            configs_count: categories.configs.iter().map(|r| r.urls.len()).sum(),
            errors_count: categories.errors.iter().map(|r| r.urls.len()).sum(),
            total_results: 0, // Will be calculated below
        };

        let total = summary.github_count
            + summary.pastebin_count
            + summary.linkedin_count
            + summary.documents_count
            + summary.subdomains_count
            + summary.login_pages_count
            + summary.configs_count
            + summary.errors_count;

        DorksSearchResult {
            domain: base_domain,
            company_name,
            categories,
            summary: DorksSummary {
                total_results: total,
                ..summary
            },
        }
    }

    /// Search GitHub for company repos/code
    fn search_github(&self, domain: &str, company_name: &str) -> Vec<DorkResult> {
        let queries = vec![
            format!("site:github.com \"{}\"", company_name),
            format!("site:github.com \"{}\"", domain),
            format!("site:github.com \"api\" \"{}\"", domain),
            format!("site:github.com \"config\" \"{}\"", domain),
            format!("site:github.com \"password\" \"{}\"", domain),
            format!("site:github.com \"secret\" \"{}\"", domain),
        ];

        self.execute_queries(&queries, "github")
    }

    /// Search Pastebin for leaks
    fn search_pastebin(&self, domain: &str, company_name: &str) -> Vec<DorkResult> {
        let queries = vec![
            format!("site:pastebin.com \"{}\"", domain),
            format!("site:pastebin.com \"{}\"", company_name),
            format!("site:paste2.org \"{}\"", domain),
            format!("site:ghostbin.com \"{}\"", domain),
        ];

        self.execute_queries(&queries, "pastebin")
    }

    /// Search LinkedIn for employees
    fn search_linkedin(&self, company_name: &str) -> Vec<DorkResult> {
        let slug = company_name.to_lowercase().replace(' ', "-");
        let queries = vec![
            format!("site:linkedin.com/in \"{}\"", company_name),
            format!("site:linkedin.com/company/{}", slug),
        ];

        self.execute_queries(&queries, "linkedin")
    }

    /// Search for exposed documents
    fn search_documents(&self, domain: &str) -> Vec<DorkResult> {
        let filetypes = [
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
        ];
        let queries: Vec<String> = filetypes
            .iter()
            .map(|ft| format!("site:{} filetype:{}", domain, ft))
            .collect();

        self.execute_queries(&queries, "documents")
    }

    /// Search for subdomains via search engine
    fn search_subdomains(&self, domain: &str) -> Vec<String> {
        let query = format!("site:*.{}", domain);
        let urls = self.perform_search(&query);

        let mut subdomains = HashSet::new();
        for url in urls {
            if let Some(host) = Self::extract_host(&url) {
                if host.ends_with(domain) && host != domain {
                    subdomains.insert(host);
                }
            }
        }

        subdomains.into_iter().collect()
    }

    /// Search for login/admin pages
    fn search_login_pages(&self, domain: &str) -> Vec<DorkResult> {
        let queries = vec![
            format!("site:{} inurl:login", domain),
            format!("site:{} inurl:admin", domain),
            format!("site:{} inurl:dashboard", domain),
            format!("site:{} inurl:portal", domain),
            format!("site:{} intitle:\"login\" OR intitle:\"sign in\"", domain),
            format!("site:{} inurl:wp-admin", domain),
            format!("site:{} inurl:wp-login", domain),
        ];

        self.execute_queries(&queries, "login_pages")
    }

    /// Search for config files
    fn search_configs(&self, domain: &str) -> Vec<DorkResult> {
        let queries = vec![
            format!("site:{} ext:env", domain),
            format!("site:{} ext:config", domain),
            format!("site:{} ext:ini", domain),
            format!("site:{} ext:yml", domain),
            format!("site:{} ext:yaml", domain),
            format!("site:{} ext:json inurl:config", domain),
            format!("site:{} inurl:config", domain),
            format!("site:{} intitle:\"index of\" \"config\"", domain),
            format!("site:{} intitle:\"index of\" \".env\"", domain),
        ];

        self.execute_queries(&queries, "configs")
    }

    /// Search for error pages
    fn search_errors(&self, domain: &str) -> Vec<DorkResult> {
        let queries = vec![
            format!("site:{} intext:\"error\" OR intext:\"exception\"", domain),
            format!("site:{} intext:\"stack trace\"", domain),
            format!("site:{} intext:\"warning\" intitle:\"error\"", domain),
            format!("site:{} intext:\"mysql\" intext:\"error\"", domain),
            format!("site:{} intext:\"fatal error\"", domain),
            format!("site:{} intext:\"syntax error\"", domain),
        ];

        self.execute_queries(&queries, "errors")
    }

    /// Search for emails associated with a domain
    pub fn search_emails_for_domain(&self, domain: &str) -> Result<Vec<String>, String> {
        let queries = vec![
            format!("\"@{}\"", domain),
            format!("site:{} \"email\" OR \"contact\"", domain),
            format!("site:linkedin.com \"@{}\"", domain),
            format!("site:github.com \"@{}\"", domain),
            format!("site:pastebin.com \"@{}\"", domain),
        ];

        let mut emails = HashSet::new();
        let email_pattern = format!("@{}", domain);

        for query in queries {
            let urls = self.perform_search(&query);
            // For each URL, try to fetch and extract emails
            // For performance, just extract emails from the search results snippets
            self.rate_limit();
        }

        // Also try direct email pattern search from snippets
        let query = format!("\"@{}\" intext:email", domain);
        let results = self.perform_search(&query);

        // Extract emails from URLs (some contain email addresses)
        for url in &results {
            if let Some(email) = Self::extract_email_from_text(url, domain) {
                emails.insert(email);
            }
        }

        Ok(emails.into_iter().collect())
    }

    /// Extract email from text that matches the domain
    fn extract_email_from_text(text: &str, domain: &str) -> Option<String> {
        // Simple email extraction - look for @domain patterns
        let pattern = format!("@{}", domain);
        if let Some(at_pos) = text.find(&pattern) {
            // Find the start of the email (word boundary before @)
            let before = &text[..at_pos];
            let start = before
                .rfind(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-')
                .map(|p| p + 1)
                .unwrap_or(0);
            let local_part = &text[start..at_pos];

            if !local_part.is_empty()
                && local_part
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-')
            {
                return Some(format!("{}@{}", local_part, domain));
            }
        }
        None
    }

    /// Execute multiple queries and collect results
    fn execute_queries(&self, queries: &[String], category: &str) -> Vec<DorkResult> {
        let mut results = Vec::new();

        for query in queries {
            let urls = self.perform_search(query);
            if !urls.is_empty() {
                results.push(DorkResult {
                    query: query.clone(),
                    category: category.to_string(),
                    urls,
                });
            }
            self.rate_limit();
        }

        results
    }

    /// Perform actual search using DuckDuckGo HTML
    fn perform_search(&self, query: &str) -> Vec<String> {
        let encoded_query = Self::url_encode(query);
        let url = format!("https://html.duckduckgo.com/html/?q={}", encoded_query);

        let response = match self.http.get_with_headers(
            &url,
            &[
                (
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ),
                ("Accept", "text/html,application/xhtml+xml"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ],
        ) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        if response.status_code != 200 {
            return Vec::new();
        }

        let html = String::from_utf8_lossy(&response.body);
        self.parse_duckduckgo_results(&html)
    }

    /// Parse DuckDuckGo HTML results
    fn parse_duckduckgo_results(&self, html: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // DuckDuckGo result URLs are in href attributes with uddg parameter
        // Pattern: href="//duckduckgo.com/l/?uddg=ENCODED_URL&amp;rut=..."
        // Or: class="result__url" href="..."

        // Method 1: Extract from result__url class
        for line in html.lines() {
            if line.contains("result__url") {
                // Extract URL from the line
                if let Some(start) = line.find("href=\"") {
                    let rest = &line[start + 6..];
                    if let Some(end) = rest.find('"') {
                        let url = &rest[..end];
                        if url.starts_with("http") {
                            urls.push(url.to_string());
                        } else if url.starts_with("//") {
                            urls.push(format!("https:{}", url));
                        }
                    }
                }
            }
        }

        // Method 2: Extract from uddg parameter
        let uddg_pattern = "uddg=";
        let mut search_pos = 0;
        while let Some(pos) = html[search_pos..].find(uddg_pattern) {
            let start = search_pos + pos + uddg_pattern.len();
            if let Some(end) = html[start..].find('&') {
                let encoded = &html[start..start + end];
                if let Some(decoded) = Self::url_decode(encoded) {
                    if decoded.starts_with("http") && !urls.contains(&decoded) {
                        urls.push(decoded);
                    }
                }
            }
            search_pos = start;

            if urls.len() >= self.max_results_per_query {
                break;
            }
        }

        // Method 3: Extract displayed URLs from result__snippet
        for line in html.lines() {
            if line.contains("result__snippet") || line.contains("result__a") {
                // Try to find HTTP URLs in the text
                let mut pos = 0;
                while let Some(start) = line[pos..].find("http") {
                    let actual_start = pos + start;
                    let rest = &line[actual_start..];
                    let end = rest
                        .find(|c: char| c.is_whitespace() || c == '"' || c == '<' || c == '>')
                        .unwrap_or(rest.len());
                    let url = &rest[..end];
                    if url.len() > 10 && !urls.contains(&url.to_string()) {
                        urls.push(url.to_string());
                    }
                    pos = actual_start + 1;

                    if urls.len() >= self.max_results_per_query {
                        break;
                    }
                }
            }
        }

        // Deduplicate and limit
        let mut seen = HashSet::new();
        urls.into_iter()
            .filter(|url| seen.insert(url.clone()))
            .take(self.max_results_per_query)
            .collect()
    }

    fn rate_limit(&self) {
        thread::sleep(Duration::from_millis(self.delay_ms));
    }

    fn extract_base_domain(host: &str) -> String {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() > 2 {
            let special_tlds = [
                "co.uk", "com.br", "co.jp", "co.za", "com.mx", "com.ar", "com.au",
            ];
            let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            if special_tlds.contains(&last_two.as_str()) && parts.len() > 3 {
                return parts[parts.len() - 3..].join(".");
            }
            return parts[parts.len() - 2..].join(".");
        }
        host.to_string()
    }

    fn extract_company_name(domain: &str) -> String {
        domain.split('.').next().unwrap_or(domain).to_string()
    }

    fn extract_host(url: &str) -> Option<String> {
        let url = url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        url.split('/').next().map(|s| s.to_string())
    }

    fn url_encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 3);
        for c in s.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                    result.push(c);
                }
                ' ' => result.push('+'),
                _ => {
                    for byte in c.to_string().bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }

    fn url_decode(s: &str) -> Option<String> {
        let mut result = Vec::new();
        let bytes = s.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(hex) =
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?, 16)
                {
                    result.push(hex);
                    i += 3;
                    continue;
                }
            } else if bytes[i] == b'+' {
                result.push(b' ');
                i += 1;
                continue;
            }
            result.push(bytes[i]);
            i += 1;
        }

        String::from_utf8(result).ok()
    }
}

impl Default for DorksSearcher {
    fn default() -> Self {
        Self::new()
    }
}
