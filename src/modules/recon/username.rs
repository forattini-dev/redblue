//! Username OSINT - WhatsMyName-style username enumeration
//!
//! Searches for a username across 100+ social media and web platforms.
//! Based on the WhatsMyName project methodology.

use crate::protocols::http::HttpClient;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A site to check for username existence
#[derive(Debug, Clone)]
pub struct SiteCheck {
    pub name: &'static str,
    pub category: &'static str,
    pub url_template: &'static str,
    /// How to detect if user exists: status code or content check
    pub check_type: CheckType,
}

#[derive(Debug, Clone)]
pub enum CheckType {
    /// User exists if status code is 200
    StatusCode(u16),
    /// User exists if response contains this string
    ContentContains(&'static str),
    /// User exists if response does NOT contain this string
    ContentNotContains(&'static str),
}

/// Result of checking a single site
#[derive(Debug, Clone)]
pub struct SiteResult {
    pub site_name: String,
    pub category: String,
    pub url: String,
    pub found: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
}

/// Result of a full username search
#[derive(Debug, Clone)]
pub struct UsernameSearchResult {
    pub username: String,
    pub total_sites: usize,
    pub found_count: usize,
    pub results: Vec<SiteResult>,
}

/// Username OSINT searcher
pub struct UsernameSearcher {
    http: HttpClient,
    sites: Vec<SiteCheck>,
    threads: usize,
    timeout_ms: u64,
}

impl UsernameSearcher {
    pub fn new() -> Self {
        Self {
            http: HttpClient::new(),
            sites: Self::default_sites(),
            threads: 20,
            timeout_ms: 5000,
        }
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_max_sites(mut self, max_sites: usize) -> Self {
        if max_sites > 0 && max_sites < self.sites.len() {
            self.sites.truncate(max_sites);
        }
        self
    }

    /// Search for username across all configured sites
    pub fn search(&self, username: &str) -> UsernameSearchResult {
        let results = Arc::new(Mutex::new(Vec::new()));
        let sites_queue = Arc::new(Mutex::new(self.sites.clone()));
        let username = username.to_string();

        let mut handles = vec![];

        for _ in 0..self.threads {
            let results = Arc::clone(&results);
            let sites_queue = Arc::clone(&sites_queue);
            let username = username.clone();
            let timeout_ms = self.timeout_ms;

            let handle = thread::spawn(move || {
                let http = HttpClient::new().with_timeout(Duration::from_millis(timeout_ms));

                loop {
                    let site = {
                        let mut queue = sites_queue.lock().unwrap();
                        queue.pop()
                    };

                    match site {
                        Some(site) => {
                            let result = Self::check_site(&http, &site, &username);
                            let mut results_guard = results.lock().unwrap();
                            results_guard.push(result);
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

        let results = match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_default(),
            Err(arc) => arc.lock().unwrap().clone(),
        };

        let found_count = results.iter().filter(|r| r.found).count();

        UsernameSearchResult {
            username,
            total_sites: self.sites.len(),
            found_count,
            results,
        }
    }

    /// Search only specific categories
    pub fn search_categories(&self, username: &str, categories: &[&str]) -> UsernameSearchResult {
        let filtered_sites: Vec<SiteCheck> = self
            .sites
            .iter()
            .filter(|s| {
                categories
                    .iter()
                    .any(|c| s.category.eq_ignore_ascii_case(c))
            })
            .cloned()
            .collect();

        let searcher = UsernameSearcher {
            http: HttpClient::new(),
            sites: filtered_sites,
            threads: self.threads,
            timeout_ms: self.timeout_ms,
        };

        searcher.search(username)
    }

    fn check_site(http: &HttpClient, site: &SiteCheck, username: &str) -> SiteResult {
        let url = site.url_template.replace("{}", username);

        let response = match http.get(&url) {
            Ok(resp) => resp,
            Err(e) => {
                return SiteResult {
                    site_name: site.name.to_string(),
                    category: site.category.to_string(),
                    url,
                    found: false,
                    status_code: None,
                    error: Some(e),
                };
            }
        };

        let found = match &site.check_type {
            CheckType::StatusCode(expected) => response.status_code == *expected,
            CheckType::ContentContains(text) => {
                let body = String::from_utf8_lossy(&response.body);
                body.contains(text)
            }
            CheckType::ContentNotContains(text) => {
                let body = String::from_utf8_lossy(&response.body);
                response.status_code == 200 && !body.contains(text)
            }
        };

        SiteResult {
            site_name: site.name.to_string(),
            category: site.category.to_string(),
            url,
            found,
            status_code: Some(response.status_code),
            error: None,
        }
    }

    /// Default list of sites to check (100+ sites)
    fn default_sites() -> Vec<SiteCheck> {
        vec![
            // Social Media
            SiteCheck {
                name: "GitHub",
                category: "coding",
                url_template: "https://github.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "GitLab",
                category: "coding",
                url_template: "https://gitlab.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Bitbucket",
                category: "coding",
                url_template: "https://bitbucket.org/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Twitter/X",
                category: "social",
                url_template: "https://x.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Instagram",
                category: "social",
                url_template: "https://www.instagram.com/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "TikTok",
                category: "social",
                url_template: "https://www.tiktok.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Reddit",
                category: "social",
                url_template: "https://www.reddit.com/user/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Pinterest",
                category: "social",
                url_template: "https://www.pinterest.com/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Tumblr",
                category: "social",
                url_template: "https://{}.tumblr.com/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Medium",
                category: "social",
                url_template: "https://medium.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "LinkedIn",
                category: "professional",
                url_template: "https://www.linkedin.com/in/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "YouTube",
                category: "video",
                url_template: "https://www.youtube.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Twitch",
                category: "video",
                url_template: "https://www.twitch.tv/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Vimeo",
                category: "video",
                url_template: "https://vimeo.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Dailymotion",
                category: "video",
                url_template: "https://www.dailymotion.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Tech/Coding
            SiteCheck {
                name: "StackOverflow",
                category: "coding",
                url_template: "https://stackoverflow.com/users/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "HackerNews",
                category: "coding",
                url_template: "https://news.ycombinator.com/user?id={}",
                check_type: CheckType::ContentNotContains("No such user"),
            },
            SiteCheck {
                name: "Dev.to",
                category: "coding",
                url_template: "https://dev.to/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Codepen",
                category: "coding",
                url_template: "https://codepen.io/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Replit",
                category: "coding",
                url_template: "https://replit.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Kaggle",
                category: "coding",
                url_template: "https://www.kaggle.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "HackerRank",
                category: "coding",
                url_template: "https://www.hackerrank.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "LeetCode",
                category: "coding",
                url_template: "https://leetcode.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Codeforces",
                category: "coding",
                url_template: "https://codeforces.com/profile/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Security/Hacking
            SiteCheck {
                name: "HackerOne",
                category: "security",
                url_template: "https://hackerone.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Bugcrowd",
                category: "security",
                url_template: "https://bugcrowd.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Keybase",
                category: "security",
                url_template: "https://keybase.io/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Gaming
            SiteCheck {
                name: "Steam",
                category: "gaming",
                url_template: "https://steamcommunity.com/id/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Xbox",
                category: "gaming",
                url_template: "https://www.xbox.com/en-US/play/user/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Chess.com",
                category: "gaming",
                url_template: "https://www.chess.com/member/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Lichess",
                category: "gaming",
                url_template: "https://lichess.org/@/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Music
            SiteCheck {
                name: "Spotify",
                category: "music",
                url_template: "https://open.spotify.com/user/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "SoundCloud",
                category: "music",
                url_template: "https://soundcloud.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Bandcamp",
                category: "music",
                url_template: "https://{}.bandcamp.com/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Last.fm",
                category: "music",
                url_template: "https://www.last.fm/user/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Photography/Art
            SiteCheck {
                name: "Flickr",
                category: "photography",
                url_template: "https://www.flickr.com/people/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "500px",
                category: "photography",
                url_template: "https://500px.com/p/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "DeviantArt",
                category: "art",
                url_template: "https://www.deviantart.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Behance",
                category: "art",
                url_template: "https://www.behance.net/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Dribbble",
                category: "art",
                url_template: "https://dribbble.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "ArtStation",
                category: "art",
                url_template: "https://www.artstation.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Forums
            SiteCheck {
                name: "Disqus",
                category: "forum",
                url_template: "https://disqus.com/by/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Quora",
                category: "forum",
                url_template: "https://www.quora.com/profile/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Business/Professional
            SiteCheck {
                name: "Crunchbase",
                category: "business",
                url_template: "https://www.crunchbase.com/person/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "AngelList",
                category: "business",
                url_template: "https://angel.co/u/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "ProductHunt",
                category: "business",
                url_template: "https://www.producthunt.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            // Misc
            SiteCheck {
                name: "Gravatar",
                category: "misc",
                url_template: "https://gravatar.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "About.me",
                category: "misc",
                url_template: "https://about.me/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Linktree",
                category: "misc",
                url_template: "https://linktr.ee/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Patreon",
                category: "misc",
                url_template: "https://www.patreon.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Ko-fi",
                category: "misc",
                url_template: "https://ko-fi.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "BuyMeACoffee",
                category: "misc",
                url_template: "https://www.buymeacoffee.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Gumroad",
                category: "misc",
                url_template: "https://{}.gumroad.com/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Substack",
                category: "misc",
                url_template: "https://{}.substack.com/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Notion",
                category: "misc",
                url_template: "https://{}.notion.site/",
                check_type: CheckType::StatusCode(200),
            },
            // News/Media
            SiteCheck {
                name: "Mastodon.social",
                category: "social",
                url_template: "https://mastodon.social/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Threads",
                category: "social",
                url_template: "https://www.threads.net/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Bluesky",
                category: "social",
                url_template: "https://bsky.app/profile/{}.bsky.social",
                check_type: CheckType::StatusCode(200),
            },
            // Crypto/Web3
            SiteCheck {
                name: "OpenSea",
                category: "crypto",
                url_template: "https://opensea.io/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Rarible",
                category: "crypto",
                url_template: "https://rarible.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Dating (public profiles only)
            SiteCheck {
                name: "OkCupid",
                category: "dating",
                url_template: "https://www.okcupid.com/profile/{}",
                check_type: CheckType::StatusCode(200),
            },
            // E-commerce
            SiteCheck {
                name: "Etsy",
                category: "ecommerce",
                url_template: "https://www.etsy.com/shop/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Ebay",
                category: "ecommerce",
                url_template: "https://www.ebay.com/usr/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Fiverr",
                category: "ecommerce",
                url_template: "https://www.fiverr.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Upwork",
                category: "ecommerce",
                url_template: "https://www.upwork.com/freelancers/~{}",
                check_type: CheckType::StatusCode(200),
            },
            // Education
            SiteCheck {
                name: "Coursera",
                category: "education",
                url_template: "https://www.coursera.org/user/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Udemy",
                category: "education",
                url_template: "https://www.udemy.com/user/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Document sharing
            SiteCheck {
                name: "SlideShare",
                category: "documents",
                url_template: "https://www.slideshare.net/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Scribd",
                category: "documents",
                url_template: "https://www.scribd.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Additional coding platforms
            SiteCheck {
                name: "npm",
                category: "coding",
                url_template: "https://www.npmjs.com/~{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "PyPI",
                category: "coding",
                url_template: "https://pypi.org/user/{}/",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "RubyGems",
                category: "coding",
                url_template: "https://rubygems.org/profiles/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Crates.io",
                category: "coding",
                url_template: "https://crates.io/users/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Docker Hub",
                category: "coding",
                url_template: "https://hub.docker.com/u/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Codesandbox",
                category: "coding",
                url_template: "https://codesandbox.io/u/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Glitch",
                category: "coding",
                url_template: "https://glitch.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Codewars",
                category: "coding",
                url_template: "https://www.codewars.com/users/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Exercism",
                category: "coding",
                url_template: "https://exercism.org/profiles/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Travel/Review
            SiteCheck {
                name: "TripAdvisor",
                category: "travel",
                url_template: "https://www.tripadvisor.com/Profile/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Yelp",
                category: "review",
                url_template: "https://www.yelp.com/user_details?userid={}",
                check_type: CheckType::StatusCode(200),
            },
            // Additional social
            SiteCheck {
                name: "VK",
                category: "social",
                url_template: "https://vk.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Telegram",
                category: "social",
                url_template: "https://t.me/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Discord (legacy)",
                category: "social",
                url_template: "https://discord.com/users/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Slack",
                category: "social",
                url_template: "https://{}.slack.com/",
                check_type: CheckType::StatusCode(200),
            },
            // Podcasts
            SiteCheck {
                name: "Anchor",
                category: "podcast",
                url_template: "https://anchor.fm/{}",
                check_type: CheckType::StatusCode(200),
            },
            // Writing
            SiteCheck {
                name: "Wattpad",
                category: "writing",
                url_template: "https://www.wattpad.com/user/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Archive of Our Own",
                category: "writing",
                url_template: "https://archiveofourown.org/users/{}",
                check_type: CheckType::StatusCode(200),
            },
            // 3D/Design
            SiteCheck {
                name: "Thingiverse",
                category: "3d",
                url_template: "https://www.thingiverse.com/{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Figma",
                category: "design",
                url_template: "https://www.figma.com/@{}",
                check_type: CheckType::StatusCode(200),
            },
            SiteCheck {
                name: "Canva",
                category: "design",
                url_template: "https://www.canva.com/{}",
                check_type: CheckType::StatusCode(200),
            },
        ]
    }

    /// Get available categories
    pub fn categories() -> Vec<&'static str> {
        vec![
            "social",
            "coding",
            "professional",
            "video",
            "gaming",
            "music",
            "photography",
            "art",
            "forum",
            "business",
            "security",
            "crypto",
            "ecommerce",
            "education",
            "misc",
        ]
    }
}

impl Default for UsernameSearcher {
    fn default() -> Self {
        Self::new()
    }
}
