/// Username Enumeration Module
///
/// Replaces: sherlock, maigret, socialscan
///
/// Multi-threaded username lookup across 70+ platforms with:
/// - Parallel HTTP requests
/// - Detection method support (status code, response body, redirect)
/// - Rate limiting
/// - Metadata extraction
use super::{
    platforms::{get_all_platforms, DetectionMethod, Platform, PlatformCategory},
    EnumerationSummary, OsintConfig, ProfileMetadata, ProfileResult,
};
use crate::protocols::http::HttpClient;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Username Enumerator - checks username existence across platforms
pub struct UsernameEnumerator {
    config: OsintConfig,
    http: HttpClient,
    platforms: Vec<Platform>,
}

impl UsernameEnumerator {
    pub fn new(config: OsintConfig) -> Self {
        let mut platforms: Vec<Platform> = get_all_platforms()
            .into_iter()
            .filter(|p| {
                // Filter by category
                config.categories.contains(&p.category)
            })
            .filter(|p| {
                // Filter out skipped platforms
                !config
                    .skip_platforms
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(p.name))
            })
            .collect();

        // Sort by category for organized output
        platforms.sort_by(|a, b| {
            a.category
                .to_string()
                .cmp(&b.category.to_string())
                .then(a.name.cmp(b.name))
        });

        let mut http = HttpClient::new();
        http.set_timeout(config.timeout);
        http.set_user_agent(&config.user_agent);

        Self {
            config,
            http,
            platforms,
        }
    }

    /// Enumerate username across all configured platforms
    pub fn enumerate(&self, username: &str) -> EnumerationSummary {
        let start = Instant::now();
        let results = Arc::new(Mutex::new(EnumerationSummary::new()));
        let work_queue = Arc::new(Mutex::new(
            self.platforms
                .iter()
                .filter(|p| p.is_valid_username(username))
                .cloned()
                .collect::<VecDeque<Platform>>(),
        ));

        // Spawn worker threads
        let mut handles = Vec::new();
        let num_threads = self.config.threads.min(self.platforms.len());

        for _ in 0..num_threads {
            let queue = Arc::clone(&work_queue);
            let results = Arc::clone(&results);
            let username = username.to_string();
            let config = self.config.clone();

            let handle = thread::spawn(move || {
                let mut http = HttpClient::new();
                http.set_timeout(config.timeout);
                http.set_user_agent(&config.user_agent);

                loop {
                    // Get next platform from queue
                    let platform = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };

                    match platform {
                        Some(platform) => {
                            let result = Self::check_platform(&http, &platform, &username, &config);

                            // Add result to summary
                            let mut r = results.lock().unwrap();
                            r.add_result(result);

                            // Rate limiting
                            if config.delay > Duration::ZERO {
                                thread::sleep(config.delay);
                            }
                        }
                        None => break,
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            let _ = handle.join();
        }

        // Set total duration
        let mut summary = Arc::try_unwrap(results)
            .unwrap_or_else(|_| panic!("Failed to unwrap results"))
            .into_inner()
            .unwrap();
        summary.duration = start.elapsed();

        summary
    }

    /// Check a single platform for username existence
    fn check_platform(
        http: &HttpClient,
        platform: &Platform,
        username: &str,
        config: &OsintConfig,
    ) -> ProfileResult {
        let start = Instant::now();
        let url = platform.url_for(username);

        // Perform HTTP request
        let response = match platform.method {
            "GET" => http.get(&url),
            "HEAD" => http.head(&url),
            _ => http.get(&url),
        };

        let duration = start.elapsed();

        match response {
            Ok(resp) => {
                // Check based on detection method
                let exists = match &platform.detection {
                    DetectionMethod::StatusCode {
                        found,
                        not_found: _,
                    } => resp.status_code == *found,
                    DetectionMethod::ResponseContains {
                        found,
                        not_found: _,
                    } => {
                        let body = String::from_utf8_lossy(&resp.body);
                        body.contains(found)
                    }
                    DetectionMethod::ResponseNotContains { text } => {
                        let body = String::from_utf8_lossy(&resp.body);
                        !body.contains(text)
                    }
                    DetectionMethod::RedirectTo { pattern } => resp
                        .headers
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("location") && v.contains(pattern)),
                    DetectionMethod::JsonField { path, expected } => {
                        let body = String::from_utf8_lossy(&resp.body);
                        // Simplified JSON check
                        body.contains(&format!("\"{}\":", path)) && body.contains(expected)
                    }
                    DetectionMethod::Regex { pattern } => {
                        // Simplified regex check (no regex crate)
                        let body = String::from_utf8_lossy(&resp.body);
                        body.contains(pattern)
                    }
                };

                if exists {
                    let mut result = ProfileResult::found(platform.name, platform.category, &url)
                        .with_duration(duration);

                    // Extract metadata if enabled
                    if config.extract_metadata {
                        let metadata = Self::extract_metadata(&resp.body, platform);
                        result = result.with_metadata(metadata);
                    }

                    result
                } else {
                    ProfileResult::not_found(platform.name, platform.category)
                        .with_duration(duration)
                }
            }
            Err(e) => {
                ProfileResult::error(platform.name, platform.category, &e).with_duration(duration)
            }
        }
    }

    /// Extract metadata from response body
    fn extract_metadata(body: &[u8], platform: &Platform) -> ProfileMetadata {
        let body_str = String::from_utf8_lossy(body);
        let mut metadata = ProfileMetadata::default();

        // Platform-specific metadata extraction
        match platform.name {
            "GitHub" => {
                // Extract from meta tags or JSON
                if let Some(name) = Self::extract_meta_content(&body_str, "property", "og:title") {
                    metadata.display_name = Some(name);
                }
                if let Some(bio) =
                    Self::extract_meta_content(&body_str, "property", "og:description")
                {
                    metadata.bio = Some(bio);
                }
                if let Some(img) = Self::extract_meta_content(&body_str, "property", "og:image") {
                    metadata.avatar_url = Some(img);
                }
            }
            "Twitter/X" => {
                if let Some(name) = Self::extract_meta_content(&body_str, "property", "og:title") {
                    metadata.display_name = Some(name);
                }
                if let Some(bio) =
                    Self::extract_meta_content(&body_str, "property", "og:description")
                {
                    metadata.bio = Some(bio);
                }
            }
            "Instagram" => {
                if let Some(bio) =
                    Self::extract_meta_content(&body_str, "property", "og:description")
                {
                    metadata.bio = Some(bio);
                }
            }
            _ => {
                // Generic extraction from OpenGraph tags
                if let Some(name) = Self::extract_meta_content(&body_str, "property", "og:title") {
                    metadata.display_name = Some(name);
                }
                if let Some(bio) =
                    Self::extract_meta_content(&body_str, "property", "og:description")
                {
                    metadata.bio = Some(bio);
                }
                if let Some(img) = Self::extract_meta_content(&body_str, "property", "og:image") {
                    metadata.avatar_url = Some(img);
                }
            }
        }

        metadata
    }

    /// Extract content from meta tags
    fn extract_meta_content(html: &str, attr_type: &str, attr_value: &str) -> Option<String> {
        // Find meta tag with given attribute
        let search = format!("{}=\"{}\"", attr_type, attr_value);
        if let Some(pos) = html.find(&search) {
            // Find content attribute
            let after = &html[pos..];
            if let Some(content_start) = after.find("content=\"") {
                let content_begin = content_start + 9;
                if let Some(content_end) = after[content_begin..].find('"') {
                    let content = &after[content_begin..content_begin + content_end];
                    return Some(html_decode(content));
                }
            }
        }
        None
    }

    /// Get total number of platforms
    pub fn platform_count(&self) -> usize {
        self.platforms.len()
    }

    /// Get platforms by category
    pub fn platforms_by_category(&self) -> std::collections::HashMap<PlatformCategory, usize> {
        let mut counts = std::collections::HashMap::new();
        for p in &self.platforms {
            *counts.entry(p.category).or_insert(0) += 1;
        }
        counts
    }
}

impl Default for UsernameEnumerator {
    fn default() -> Self {
        Self::new(OsintConfig::default())
    }
}

/// Simple HTML entity decoder
fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Quick check of a single platform
pub fn check_single_platform(platform_name: &str, username: &str) -> Option<ProfileResult> {
    let platform = super::platforms::get_platform_by_name(platform_name)?;

    let config = OsintConfig::default();
    let mut http = HttpClient::new();
    http.set_timeout(config.timeout);
    http.set_user_agent(&config.user_agent);

    Some(UsernameEnumerator::check_platform(
        &http, &platform, username, &config,
    ))
}

/// List all available platforms
pub fn list_platforms() -> Vec<(&'static str, PlatformCategory)> {
    get_all_platforms()
        .into_iter()
        .map(|p| (p.name, p.category))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_url_generation() {
        let platforms = get_all_platforms();
        let github = platforms.iter().find(|p| p.name == "GitHub").unwrap();
        assert_eq!(github.url_for("octocat"), "https://github.com/octocat");
    }

    #[test]
    fn test_username_validation() {
        let platforms = get_all_platforms();
        let github = platforms.iter().find(|p| p.name == "GitHub").unwrap();

        assert!(github.is_valid_username("octocat"));
        assert!(github.is_valid_username("test-user"));
        assert!(!github.is_valid_username("")); // Too short
    }

    #[test]
    fn test_html_decode() {
        assert_eq!(html_decode("test &amp; test"), "test & test");
        assert_eq!(html_decode("&lt;script&gt;"), "<script>");
    }
}
