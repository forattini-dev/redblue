//! Social Media Mapping
//! 
//! Maps company/brand social media presence across platforms.
//! Discovers official accounts on:
//! - Twitter/X
//! - LinkedIn
//! - Facebook
//! - Instagram
//! - GitHub
//! - YouTube
//! - TikTok
//! - Discord
//! - Telegram

use crate::protocols::http::HttpClient;
use std::collections::{HashMap, HashSet, VecDeque}; // Added VecDeque and HashSet for BFS
use std::time::Duration;

/// Social media platform info
#[derive(Debug, Clone)]
pub struct SocialProfile {
    pub platform: String,
    pub url: String,
    pub found: bool,
    pub username: Option<String>,
    pub followers: Option<String>,
    pub bio: Option<String>,
    pub verified: Option<bool>,
    pub location: Option<String>, // Added location field
    pub activity: Option<String>, // Added activity field
}

/// Result of social media mapping
#[derive(Debug, Clone)]
pub struct SocialMappingResult {
    pub domain: String,
    pub company_name: String,
    pub profiles: HashMap<String, SocialProfile>,
    pub found_count: usize,
    pub total_checked: usize,
}

/// Social media mapper
pub struct SocialMapper {
    http: HttpClient,
}

impl SocialMapper {
    pub fn new() -> Self {
        Self {
            http: HttpClient::new().with_timeout(Duration::from_secs(10)),
        }
    }

    /// Map social media presence for a domain/company
    pub fn map(&self, domain: &str) -> SocialMappingResult {
        let base_domain = Self::extract_base_domain(domain);
        let company_name = Self::extract_company_name(&base_domain);

        let mut profiles = HashMap::new();

        // Generate variations to try
        let variations = self.generate_variations(&company_name);

        // Check each platform
        let platforms = self.get_platforms();

        for (platform_name, url_template, _check_fn) in platforms { // check_fn is now unused
            let mut best_match: Option<SocialProfile> = None;

            for variation in &variations {
                let url = url_template.replace("{}", variation);
                if let Some(profile) = self.check_platform_helper(&platform_name, &url) {
                    if profile.found {
                        best_match = Some(profile);
                        break; // Found a match, move to next platform
                    }
                }
            }

            profiles.insert(
                platform_name.to_string(),
                best_match.unwrap_or_else(|| SocialProfile {
                    platform: platform_name.to_string(),
                    url: url_template.replace("{}", &company_name),
                    found: false,
                    username: None,
                    followers: None,
                    bio: None,
                    verified: None,
                    location: None, // Added default for new field
                    activity: None, // Added default for new field
                }),
            );
        }

        let found_count = profiles.values().filter(|p| p.found).count();

        SocialMappingResult {
            domain: base_domain,
            company_name,
            profiles,
            found_count,
            total_checked: 10, // Number of platforms
        }
    }

    /// Recursively discover usernames from profiles.
    /// This is a simplified BFS-like approach.
    pub fn discover_recursive(&self, initial_username: &str, max_depth: usize) -> HashSet<String> {
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut visited_usernames: HashSet<String> = HashSet::new();
        let mut discovered_usernames: HashSet<String> = HashSet::new();

        queue.push_back(initial_username.to_string());
        visited_usernames.insert(initial_username.to_string());

        let mut current_depth = 0;

        while let Some(username) = queue.pop_front() {
            if current_depth >= max_depth {
                break;
            }

            // Add the current username to the discovered set
            discovered_usernames.insert(username.clone());

            // Check platforms for this username and extract linked usernames/mentions
            let platforms = self.get_platforms(); // Reuse platforms info

            for (platform_name, url_template, _check_fn) in platforms {
                let url = url_template.replace("{}", &username);
                // Reusing helper to check profile, but need to pass self
                if let Some(profile) = self.check_platform_helper(platform_name, &url) { 
                    if profile.found {
                        // Simulate extracting mentions/linked profiles from the profile's bio/description
                        // In a real scenario, this would involve parsing the profile page HTML.
                        if let Some(bio) = &profile.bio {
                            // Simple heuristic: look for '@' symbols
                            for part in bio.split_whitespace() {
                                if part.starts_with('@') && part.len() > 1 {
                                    let linked_username = part.trim_start_matches('@').to_string();
                                    if !visited_usernames.contains(&linked_username) {
                                        visited_usernames.insert(linked_username.clone());
                                        queue.push_back(linked_username);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            current_depth += 1;
        }
        discovered_usernames
    }

    // Helper function to encapsulate platform checking logic, to be used by both map and discover_recursive
    fn check_platform_helper(
        &self,
        platform: &str,
        url: &str,
    ) -> Option<SocialProfile> {
        let response = match self.http.get(url) {
            Ok(r) => r,
            Err(_) => {
                return None;
            }
        };

        let found = response.status_code == 200;
        let body = String::from_utf8_lossy(&response.body);
        let followers = self.extract_followers(&body);
        let bio = self.extract_bio(&body);
        let verified = self.extract_verified(&body);
        let location = self.extract_location(&body); // Extract location
        let activity = self.extract_activity(&body); // Extract activity

        Some(SocialProfile {
            platform: platform.to_string(),
            url: url.to_string(),
            found,
            username: None,
            followers,
            bio,
            verified,
            location, // Include location
            activity, // Include activity
        })
    }


    /// Check a single platform URL
    fn check_platform(
        &self,
        platform: &str,
        url: &str,
        _check_fn: fn(&str) -> bool, // This parameter is now redundant due to check_platform_helper
    ) -> SocialProfile {
        self.check_platform_helper(platform, url)
            .unwrap_or_else(|| SocialProfile {
                platform: platform.to_string(),
                url: url.to_string(),
                found: false,
                username: None,
                followers: None,
                bio: None,
                verified: None,
                location: None, // Added default for new field
                activity: None, // Added default for new field
            })
    }

    /// Get platform configurations
    fn get_platforms(&self) -> Vec<(&'static str, &'static str, fn(&str) -> bool)> {
        vec![
            ("twitter", "https://x.com/{}", |_| true),
            ("linkedin", "https://www.linkedin.com/company/{}", |_| true),
            ("facebook", "https://www.facebook.com/{}", |_| true),
            ("instagram", "https://www.instagram.com/{}/", |_| true),
            ("github", "https://github.com/{}", |_| true),
            ("youtube", "https://www.youtube.com/@{}", |_| true),
            ("tiktok", "https://www.tiktok.com/@{}", |_| true),
            ("discord", "https://discord.gg/{}", |_| true),
            ("telegram", "https://t.me/{}", |_| true),
            ("medium", "https://medium.com/@{}", |_| true),
            ("reddit", "https://www.reddit.com/user/{}", |_| true),
            ("pinterest", "https://www.pinterest.com/{}/", |_| true),
            ("snapchat", "https://www.snapchat.com/add/{}", |_| true),
            ("tumblr", "https://{}.tumblr.com/", |_| true),
            ("foursquare", "https://foursquare.com/user/{}", |_| true),
            ("vk", "https://vk.com/{}", |_| true),
            ("odnoklassniki", "https://ok.ru/{}", |_| true),
            ("weibo", "https://weibo.com/n/{}", |_| true),
            ("douban", "https://www.douban.com/people/{}/", |_| true),
            ("zhihu", "https://www.zhihu.com/people/{}/", |_| true),
            ("qq", "https://user.qzone.qq.com/{}", |_| true),
            ("periscope", "https://www.pscp.tv/{}/", |_| true),
            ("patreon", "https://www.patreon.com/{}/", |_| true),
            ("etsy", "https://www.etsy.com/shop/{}/", |_| true),
            ("ebay", "https://www.ebay.com/usr/{}/", |_| true),
            ("amazon", "https://www.amazon.com/gp/profile/amzn1.account.{}/", |_| true),
            ("google_plus", "https://plus.google.com/{}", |_| true), // Deprecated
            ("myspace", "https://myspace.com/{}/", |_| true), // Legacy
            ("lastfm", "https://www.last.fm/user/{}", |_| true),
            ("stackoverflow", "https://stackoverflow.com/users/{}", |_| true),
            ("superuser", "https://superuser.com/users/{}", |_| true),
            ("askubuntu", "https://askubuntu.com/users/{}", |_| true),
            ("serverfault", "https://serverfault.com/users/{}", |_| true),
            // Cryptocurrency & Web3
            ("opensea", "https://opensea.io/{}", |_| true),
            ("rarible", "https://rarible.com/{}", |_| true),
            ("foundation", "https://foundation.app/@{}", |_| true),
            ("mirror", "https://mirror.xyz/{}", |_| true),
            // Design Tools
            ("figma", "https://www.figma.com/@{}", |_| true),
            ("dribbble", "https://dribbble.com/{}", |_| true),
            ("behance", "https://www.behance.net/{}", |_| true),
            // Newsletter
            ("substack", "https://{}.substack.com", |_| true),
            ("ghost", "https://{}.ghost.io", |_| true),
            // Coding
            ("leetcode", "https://leetcode.com/{}", |_| true),
            ("hackerrank", "https://www.hackerrank.com/{}", |_| true),
            ("codewars", "https://www.codewars.com/users/{}", |_| true),
            // Education
            ("udemy", "https://www.udemy.com/user/{}", |_| true),
            ("coursera", "https://www.coursera.org/user/{}", |_| true),
            // Security
            ("hackerone", "https://hackerone.com/{}", |_| true),
            ("bugcrowd", "https://bugcrowd.com/{}", |_| true),
            ("tryhackme", "https://tryhackme.com/p/{}", |_| true),
            ("hackthebox", "https://app.hackthebox.com/users/{}", |_| true),
            // Other
            ("strava", "https://www.strava.com/athletes/{}", |_| true),
            ("tripadvisor", "https://www.tripadvisor.com/Profile/{}", |_| true),
            ("yelp", "https://www.yelp.com/user_details?userid={}", |_| true),
            ("poshmark", "https://poshmark.com/closet/{}", |_| true),
            ("instructables", "https://www.instructables.com/member/{}", |_| true),
            ("notion", "https://www.notion.so/{}", |_| true),
            ("vk", "https://vk.com/{}", |_| true),
            ("mercadolibre", "https://www.mercadolibre.com.ar/perfil/{}", |_| true),
            // Podcasting
            ("anchor", "https://anchor.fm/{}", |_| true),
            ("podbean", "https://www.podbean.com/user-{}", |_| true),
            ("soundcloud", "https://soundcloud.com/{}", |_| true),
            ("mixcloud", "https://soundcloud.com/{}", |_| true),
            // 3D & Art
            ("artstation", "https://www.artstation.com/{}", |_| true),
            ("sketchfab", "https://sketchfab.com/{}", |_| true),
            ("deviantart", "https://www.deviantart.com/{}", |_| true),
            ("unsplash", "https://unsplash.com/@{}", |_| true),
            // Open Source & Code
            ("gitlab", "https://gitlab.com/{}", |_| true),
            ("bitbucket", "https://bitbucket.org/{}", |_| true),
            ("sourceforge", "https://sourceforge.net/u/{}/profile", |_| true),
            ("dockerhub", "https://hub.docker.com/u/{}", |_| true),
            ("npm", "https://www.npmjs.com/~{}", |_| true),
            ("pypi", "https://pypi.org/user/{}", |_| true),
            // Regional & Misc
            ("sharechat", "https://sharechat.com/profile/{}", |_| true), // India
            ("ok_ru", "https://ok.ru/{}", |_| true), // Russia
            ("gumroad", "https://www.gumroad.com/{}", |_| true),
            ("keybase", "https://keybase.io/{}", |_| true),
            ("about.me", "https://about.me/{}", |_| true),
            ("gravatar", "https://en.gravatar.com/{}", |_| true),
            ("pastebin", "https://pastebin.com/u/{}", |_| true),
            ("wattpad", "https://www.wattpad.com/user/{}", |_| true),
            ("canva", "https://www.canva.com/p/{}", |_| true),
            ("dailymotion", "https://www.dailymotion.com/{}", |_| true),
            ("vimeo", "https://vimeo.com/{}", |_| true),
            ("flickr", "https://www.flickr.com/people/{}", |_| true),
            ("houzz", "https://www.houzz.com/user/{}", |_| true),
            ("contently", "https://{}.contently.com", |_| true),
            ("hubpages", "https://hubpages.com/@{}", |_| true),
            ("ifttt", "https://ifttt.com/p/{}", |_| true),
            ("trakt", "https://trakt.tv/users/{}", |_| true),
            ("tripit", "https://trakt.tv/users/{}", |_| true),
        ]
    }

    /// Loads additional platforms from a simple CSV file: platform_name,url_template
    pub fn load_platforms_from_file(path: &str) -> Result<Vec<(String, String)>, String> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(path).map_err(|e| format!("Failed to open platforms file: {}", e))?;
        let reader = BufReader::new(file);
        let mut platforms = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line from platforms file: {}", e))?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }

            if let Some((platform_name, url_template)) = trimmed.split_once(',') {
                platforms.push((platform_name.trim().to_string(), url_template.trim().to_string()));
            } else {
                eprintln!("Warning: Invalid line in platforms file: {}", line);
            }
        }
        Ok(platforms)
    }

    /// Generate username variations to try
    fn generate_variations(&self, company_name: &str) -> Vec<String> {
        let base = company_name.to_lowercase();
        let no_spaces = base.replace(' ', "");
        let with_underscore = base.replace(' ', "_");
        let with_dash = base.replace(' ', "-");

        vec![
            no_spaces.clone(),
            with_underscore.clone(),
            with_dash.clone(),
            format!("{}official", no_spaces),
            format!("{}_official", no_spaces),
            format!("{}-official", no_spaces),
            format!("{}hq", no_spaces),
            format!("{}_hq", no_spaces),
            format!("the{}", no_spaces),
            format!("get{}", no_spaces),
        ]
    }

    /// Try to extract follower count from HTML
    fn extract_followers(&self, html: &str) -> Option<String> {
        // Look for common patterns
        let patterns = [
            r#"followers"[^>]*>([0-9,KMB.]+)"#, // e.g. <span class="followers">10K</span>
            r"([0-9,]+)\s*followers",            // e.g. 1,234 followers
            r#"followerCount["\s:]+([0-9,]+)"#,  // e.g. "followerCount":1234
            r#"<meta property="profile:followers" content="([0-9]+)""#, // LinkedIn
        ];

        for pattern in patterns {
            if let Some(caps) = Self::simple_regex_match(html, pattern) {
                return Some(caps);
            }
        }
        None
    }

    /// Try to extract bio/description from HTML
    fn extract_bio(&self, html: &str) -> Option<String> {
        // Look for meta description
        if let Some(start) = html.find("meta name=\"description\" content=\"") {
            let rest = &html[start + 34..];
            if let Some(end) = rest.find('"') {
                let bio = &rest[..end];
                if bio.len() > 10 && bio.len() < 500 { // Increased max length for bio
                    return Some(Self::html_decode(bio));
                }
            }
        }

        // Look for og:description
        if let Some(start) = html.find("og:description\" content=\"") {
            let rest = &html[start + 25..];
            if let Some(end) = rest.find('"') {
                let bio = &rest[..end];
                if bio.len() > 10 && bio.len() < 500 { // Increased max length for bio
                    return Some(Self::html_decode(bio));
                }
            }
        }

        // Look for common div/p with description class
        if let Some(start) = html.find("class=\"profile-bio\"") {
            let rest = &html[start..];
            if let Some(p_start) = rest.find('>') {
                let p_rest = &rest[p_start + 1..];
                if let Some(p_end) = p_rest.find('<') {
                    let bio = p_rest[..p_end].trim();
                     if bio.len() > 10 && bio.len() < 500 {
                        return Some(Self::html_decode(bio));
                    }
                }
            }
        }

        None
    }

    /// Try to extract location from HTML
    fn extract_location(&self, html: &str) -> Option<String> {
        // Look for common patterns for location in profile pages
        let patterns = [
            r#">Location<[^>]*>([A-Za-z\s,]+)<"#, // e.g. <span>Location</span><span>New York, USA</span>
            r#"<meta name=\"geo.placename\" content=\"([^\"]+)\""#,
            r#"([A-Z][a-z]+(?:[\s,-][A-Z][a-z]+)*),\s*([A-Z]{2,3})"# // City, Country Code
        ];

        for pattern in patterns {
            if let Some(caps) = Self::simple_regex_match(html, pattern) {
                return Some(caps);
            }
        }
        None
    }

    /// Try to extract recent activity from HTML (placeholder)
    fn extract_activity(&self, _html: &str) -> Option<String> {
        // This would be highly platform-specific and involve parsing recent posts/commits.
        // For now, it's a placeholder.
        Some("Activity extraction not yet implemented.".to_string())
    }

    /// Try to detect if account is verified
    fn extract_verified(&self, html: &str) -> Option<bool> {
        let verified_indicators = [
            "verified",
            "badge-verified",
            "verifiedBadge",
            r#""is_verified":true"#,
            r#""verified":true"#,
            "verified-check",
            "blue-check",
        ];

        for indicator in verified_indicators {
            if html.contains(indicator) {
                return Some(true);
            }
        }

        None
    }

    /// Simple regex-like match (no regex crate)
    fn simple_regex_match(html: &str, pattern: &str) -> Option<String> {
        // This is a simplified matcher for common patterns
        // For production, consider using the regex crate

        // Handle pattern: "keyword"[^>]*>([0-9,KMB.]+)"
        if pattern.contains("[0-9,KMB.]+") {
            let keyword_start_idx = pattern.find('"')? + 1;
            let keyword_end_idx = pattern[keyword_start_idx..].find('"')? + keyword_start_idx;
            let keyword = &pattern[keyword_start_idx..keyword_end_idx];
            
            let pos = html.find(keyword)?;
            let rest = &html[pos..];

            // Find next > and extract number
            let gt_pos = rest.find('>')?;
            let after_gt = &rest[gt_pos + 1..];

            // Extract numbers
            let mut num = String::new();
            for c in after_gt.chars() {
                if c.is_ascii_digit() || c == ',' || c == '.' || c == 'K' || c == 'M' || c == 'B' {
                    num.push(c);
                } else if !num.is_empty() {
                    break;
                }
            }

            if !num.is_empty() {
                return Some(num);
            }
        }
        // Handle location pattern: >Location<[^>]*>([A-Za-z\s,]+)<
        else if pattern.contains(">Location<") {
            if let Some(pos) = html.find(">Location<") {
                let rest = &html[pos..];
                if let Some(p_start) = rest.find('>') {
                    let p_rest = &rest[p_start + 1..];
                    if let Some(p_end) = p_rest.find('<') {
                        let location = p_rest[..p_end].trim();
                        if !location.is_empty() {
                            return Some(location.to_string());
                        }
                    }
                }
            }
        }
        // Handle meta name="geo.placename" content="([^\"]+)"
        else if pattern.contains("<meta name=\"geo.placename\"") {
             if let Some(start) = html.find("<meta name=\"geo.placename\" content=\"") {
                let rest = &html[start + 36..];
                if let Some(end) = rest.find('"') {
                    let location = rest[..end].trim();
                     if !location.is_empty() {
                        return Some(location.to_string());
                    }
                }
            }
        }

        None
    }

    /// Decode HTML entities
    fn html_decode(s: &str) -> String {
        s.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ")
    }

    fn extract_base_domain(host: &str) -> String {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() > 2 {
            return parts[parts.len() - 2..].join(".");
        }
        host.to_string()
    }

    fn extract_company_name(domain: &str) -> String {
        domain.split('.').next().unwrap_or(domain).to_string()
    }
}

impl Default for SocialMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick helper to check a single platform for a username
pub fn check_platform(platform: &str, username: &str) -> Option<SocialProfile> {
    let http = HttpClient::new().with_timeout(Duration::from_secs(10));

    let url = match platform.to_lowercase().as_str() {
        "twitter" | "x" => format!("https://x.com/{}", username),
        "linkedin" => format!("https://www.linkedin.com/in/{}", username),
        "facebook" => format!("https://www.facebook.com/{}", username),
        "instagram" => format!("https://www.instagram.com/{}/", username),
        "github" => format!("https://github.com/{}", username),
        "youtube" => format!("https://www.youtube.com/@{}", username),
        "tiktok" => format!("https://www.tiktok.com/@{}", username),
        "telegram" => format!("https://t.me/{}", username),
        "medium" => format!("https://medium.com/@{}", username),
        "reddit" => format!("https://www.reddit.com/user/{}", username),
        _ => return None,
    };

    let response = http.get(&url).ok()?;

    Some(SocialProfile {
        platform: platform.to_string(),
        url,
        found: response.status_code == 200,
        username: Some(username.to_string()),
        followers: None,
        bio: None,
        verified: None,
        location: None, // Added location
        activity: None, // Added activity
    })
}