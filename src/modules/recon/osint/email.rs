/// Email Intelligence Module
///
/// Replaces: holehe, h8mail, email2phonenumber
///
/// Features:
/// - Email validation
/// - Provider detection
/// - Service registration check (via password reset)
/// - Social profile discovery
/// - Email format analysis
use super::{EmailResult, OsintConfig, ProfileResult};
use crate::protocols::http::HttpClient;
use std::time::Duration;

/// Email Intelligence Checker
pub struct EmailIntel {
    config: OsintConfig,
    http: HttpClient,
}

impl EmailIntel {
    pub fn new(config: OsintConfig) -> Self {
        let mut http = HttpClient::new();
        http.set_timeout(config.timeout);
        http.set_user_agent(&config.user_agent);

        Self { config, http }
    }

    /// Full email intelligence gathering
    pub fn investigate(&self, email: &str) -> EmailResult {
        let mut result = EmailResult {
            email: email.to_string(),
            valid: false,
            provider: None,
            breaches: Vec::new(),
            pastes: Vec::new(),
            services: Vec::new(),
            social_profiles: Vec::new(),
        };

        // Validate email format
        if !self.is_valid_format(email) {
            return result;
        }
        result.valid = true;

        // Detect provider
        result.provider = self.detect_provider(email);

        // Check service registrations via password reset
        result.services = self.check_service_registrations(email);

        // Check social profiles
        result.social_profiles = self.check_social_profiles(email);

        result
    }

    /// Check if email format is valid
    pub fn is_valid_format(&self, email: &str) -> bool {
        // Basic email validation
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let local = parts[0];
        let domain = parts[1];

        // Local part checks
        if local.is_empty() || local.len() > 64 {
            return false;
        }

        // Domain checks
        if domain.is_empty() || domain.len() > 255 {
            return false;
        }

        // Must have at least one dot in domain
        if !domain.contains('.') {
            return false;
        }

        // No consecutive dots
        if email.contains("..") {
            return false;
        }

        true
    }

    /// Detect email provider
    pub fn detect_provider(&self, email: &str) -> Option<String> {
        let domain = email.split('@').nth(1)?.to_lowercase();

        let provider = match domain.as_str() {
            // Gmail variants
            "gmail.com" | "googlemail.com" => "Google",
            d if d.ends_with(".gmail.com") => "Google Workspace",

            // Microsoft
            "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => "Microsoft",

            // Yahoo
            "yahoo.com" | "yahoo.co.uk" | "yahoo.fr" | "ymail.com" => "Yahoo",

            // Apple
            "icloud.com" | "me.com" | "mac.com" => "Apple",

            // ProtonMail
            "protonmail.com" | "proton.me" | "pm.me" => "ProtonMail",

            // Tutanota
            "tutanota.com" | "tutanota.de" | "tutamail.com" | "tuta.io" => "Tutanota",

            // Fastmail
            "fastmail.com" | "fastmail.fm" => "FastMail",

            // Zoho
            "zoho.com" | "zohomail.com" => "Zoho",

            // GMX
            "gmx.com" | "gmx.de" | "gmx.net" => "GMX",

            // Mail.com
            "mail.com" | "email.com" => "Mail.com",

            // Yandex
            "yandex.com" | "yandex.ru" => "Yandex",

            // AOL
            "aol.com" | "aim.com" => "AOL",

            // Common disposable email domains
            "mailinator.com" | "guerrillamail.com" | "tempmail.com" | "10minutemail.com"
            | "temp-mail.org" | "throwaway.email" | "sharklasers.com" => "Disposable Email",

            // Corporate/custom domain
            _ => return Some(format!("Custom ({})", domain)),
        };

        Some(provider.to_string())
    }

    /// Check if email is potentially disposable
    pub fn is_disposable(&self, email: &str) -> bool {
        let disposable_domains = [
            "mailinator.com",
            "guerrillamail.com",
            "tempmail.com",
            "10minutemail.com",
            "temp-mail.org",
            "throwaway.email",
            "sharklasers.com",
            "getairmail.com",
            "getnada.com",
            "mohmal.com",
            "fakeinbox.com",
            "dispostable.com",
            "yopmail.com",
            "trashmail.com",
            "mailnesia.com",
            "tempr.email",
            "discard.email",
            "maildrop.cc",
            "mailsac.com",
            "inboxkitten.com",
        ];

        if let Some(domain) = email.split('@').nth(1) {
            return disposable_domains.contains(&domain.to_lowercase().as_str());
        }

        false
    }

    /// Check service registrations using password reset endpoints
    fn check_service_registrations(&self, email: &str) -> Vec<String> {
        let mut registered = Vec::new();

        // Service definitions with password reset endpoints
        let services = vec![
            ServiceCheck {
                name: "Twitter/X",
                url: "https://twitter.com/account/begin_password_reset".to_string(),
                method: "POST",
                data: Some(format!("account_identifier={}", email)),
                success_indicator: CheckIndicator::ResponseContains("email has been sent"),
            },
            ServiceCheck {
                name: "Instagram",
                url: "https://www.instagram.com/accounts/account_recovery_send_ajax/".to_string(),
                method: "POST",
                data: Some(format!("email_or_username={}", email)),
                success_indicator: CheckIndicator::StatusCode(200),
            },
            ServiceCheck {
                name: "LinkedIn",
                url: format!(
                    "https://www.linkedin.com/checkpoint/rp/request-password-reset-submit?email={}",
                    email
                ),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::ResponseContains("check your email"),
            },
            ServiceCheck {
                name: "Spotify",
                url: format!(
                    "https://accounts.spotify.com/password-reset?email={}",
                    email
                ),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::ResponseNotContains("wasn't found"),
            },
            ServiceCheck {
                name: "Discord",
                url: "https://discord.com/api/v9/auth/forgot".to_string(),
                method: "POST",
                data: Some(format!("{{\"login\":\"{}\"}}", email)),
                success_indicator: CheckIndicator::StatusCode(204),
            },
            ServiceCheck {
                name: "GitHub",
                url: "https://github.com/password_reset".to_string(),
                method: "POST",
                data: Some(format!("email={}", email)),
                success_indicator: CheckIndicator::ResponseContains("check your email"),
            },
            ServiceCheck {
                name: "Pinterest",
                url: format!(
                    "https://www.pinterest.com/password/reset/?username_or_email={}",
                    email
                ),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::StatusCode(200),
            },
            ServiceCheck {
                name: "Netflix",
                url: format!("https://www.netflix.com/LoginHelp?email={}", email),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::ResponseContains("send you an email"),
            },
            ServiceCheck {
                name: "Amazon",
                url: "https://www.amazon.com/ap/forgotpassword".to_string(),
                method: "POST",
                data: Some(format!("email={}", email)),
                success_indicator: CheckIndicator::ResponseContains("verification code"),
            },
            ServiceCheck {
                name: "Dropbox",
                url: "https://www.dropbox.com/forgot".to_string(),
                method: "POST",
                data: Some(format!("email={}", email)),
                success_indicator: CheckIndicator::ResponseContains("email sent"),
            },
            ServiceCheck {
                name: "Adobe",
                url: format!("https://account.adobe.com/email-exists?email={}", email),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::JsonContains("exists", "true"),
            },
            ServiceCheck {
                name: "Slack",
                url: "https://slack.com/api/auth.findTeam".to_string(),
                method: "POST",
                data: Some(format!("email={}", email)),
                success_indicator: CheckIndicator::JsonContains("ok", "true"),
            },
            ServiceCheck {
                name: "Twitch",
                url: format!(
                    "https://passport.twitch.tv/usernames/{}",
                    email.split('@').next().unwrap_or("")
                ),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::StatusCode(200),
            },
            ServiceCheck {
                name: "Reddit",
                url: "https://www.reddit.com/api/v1/username_available".to_string(),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::StatusCode(200),
            },
            ServiceCheck {
                name: "Tumblr",
                url: "https://www.tumblr.com/forgot_password".to_string(),
                method: "POST",
                data: Some(format!("email={}", email)),
                success_indicator: CheckIndicator::ResponseContains("email was sent"),
            },
            ServiceCheck {
                name: "WordPress",
                url: format!(
                    "https://wordpress.com/wp-login.php?action=lostpassword&user_login={}",
                    email
                ),
                method: "GET",
                data: None,
                success_indicator: CheckIndicator::ResponseContains("check your email"),
            },
            ServiceCheck {
                name: "Zoom",
                url: "https://zoom.us/signin/forgot_password".to_string(),
                method: "POST",
                data: Some(format!("email={}", email)),
                success_indicator: CheckIndicator::ResponseContains("email has been sent"),
            },
        ];

        for service in services {
            if let Ok(exists) = self.check_service(&service) {
                if exists {
                    registered.push(service.name.to_string());
                }
            }
        }

        registered
    }

    /// Check a single service
    fn check_service(&self, service: &ServiceCheck) -> Result<bool, String> {
        let response = match service.method {
            "GET" => self.http.get(&service.url),
            "POST" => {
                let data = service
                    .data
                    .as_ref()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                self.http.post(&service.url, data)
            }
            _ => return Err("Invalid method".to_string()),
        };

        match response {
            Ok(resp) => match &service.success_indicator {
                CheckIndicator::StatusCode(code) => Ok(resp.status_code == *code),
                CheckIndicator::ResponseContains(text) => {
                    let body = String::from_utf8_lossy(&resp.body);
                    Ok(body.to_lowercase().contains(&text.to_lowercase()))
                }
                CheckIndicator::ResponseNotContains(text) => {
                    let body = String::from_utf8_lossy(&resp.body);
                    Ok(!body.to_lowercase().contains(&text.to_lowercase()))
                }
                CheckIndicator::JsonContains(key, value) => {
                    let body = String::from_utf8_lossy(&resp.body);
                    Ok(body.contains(&format!("\"{}\"", key)) && body.contains(value))
                }
            },
            Err(_) => Ok(false),
        }
    }

    /// Check social profiles by email
    fn check_social_profiles(&self, email: &str) -> Vec<ProfileResult> {
        let mut profiles = Vec::new();

        // Gravatar
        if let Some(profile) = self.check_gravatar(email) {
            profiles.push(profile);
        }

        // GitHub (public email search)
        if let Some(profile) = self.check_github_email(email) {
            profiles.push(profile);
        }

        profiles
    }

    /// Check Gravatar profile
    fn check_gravatar(&self, email: &str) -> Option<ProfileResult> {
        // MD5 hash of lowercase, trimmed email
        let hash = self.md5_hash(&email.to_lowercase().trim());
        let url = format!("https://www.gravatar.com/{}", hash);

        match self.http.get(&format!("{}.json", url)) {
            Ok(resp) if resp.status_code == 200 => Some(ProfileResult::found(
                "Gravatar",
                super::PlatformCategory::Business,
                &url,
            )),
            _ => None,
        }
    }

    /// Check GitHub for public email
    fn check_github_email(&self, email: &str) -> Option<ProfileResult> {
        let url = format!("https://api.github.com/search/users?q={}+in:email", email);

        match self.http.get(&url) {
            Ok(resp) if resp.status_code == 200 => {
                let body = String::from_utf8_lossy(&resp.body);
                if body.contains("\"total_count\":0") || body.contains("\"total_count\": 0") {
                    return None;
                }

                // Extract username from response
                if let Some(login_pos) = body.find("\"login\":") {
                    let after = &body[login_pos + 9..];
                    if let Some(end) = after.find('"') {
                        let username = &after[..end];
                        let profile_url = format!("https://github.com/{}", username);
                        return Some(ProfileResult::found(
                            "GitHub",
                            super::PlatformCategory::Development,
                            &profile_url,
                        ));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Simple MD5 hash (implemented from scratch)
    fn md5_hash(&self, input: &str) -> String {
        // MD5 constants
        let s: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];

        let k: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];

        // Initial hash values
        let mut a0: u32 = 0x67452301;
        let mut b0: u32 = 0xefcdab89;
        let mut c0: u32 = 0x98badcfe;
        let mut d0: u32 = 0x10325476;

        // Prepare message
        let mut message = input.as_bytes().to_vec();
        let original_len_bits = (message.len() as u64) * 8;

        // Append bit '1'
        message.push(0x80);

        // Pad to 448 bits mod 512
        while message.len() % 64 != 56 {
            message.push(0x00);
        }

        // Append original length
        message.extend_from_slice(&original_len_bits.to_le_bytes());

        // Process each 512-bit chunk
        for chunk in message.chunks(64) {
            let mut m = [0u32; 16];
            for (i, bytes) in chunk.chunks(4).enumerate() {
                m[i] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }

            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;

            for i in 0..64 {
                let (f, g) = if i < 16 {
                    ((b & c) | ((!b) & d), i)
                } else if i < 32 {
                    ((d & b) | ((!d) & c), (5 * i + 1) % 16)
                } else if i < 48 {
                    (b ^ c ^ d, (3 * i + 5) % 16)
                } else {
                    (c ^ (b | (!d)), (7 * i) % 16)
                };

                let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(f.rotate_left(s[i]));
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }

        // Produce hash
        let mut result = Vec::new();
        result.extend_from_slice(&a0.to_le_bytes());
        result.extend_from_slice(&b0.to_le_bytes());
        result.extend_from_slice(&c0.to_le_bytes());
        result.extend_from_slice(&d0.to_le_bytes());

        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Extract username from email
    pub fn extract_username(&self, email: &str) -> Option<String> {
        email.split('@').next().map(|s| s.to_string())
    }

    /// Extract domain from email
    pub fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_string())
    }

    /// Generate possible email variations
    pub fn generate_variations(&self, base: &str, domain: &str) -> Vec<String> {
        let mut variations = Vec::new();

        // Direct
        variations.push(format!("{}@{}", base, domain));

        // With dots
        if base.len() >= 2 {
            for i in 1..base.len() {
                let with_dot = format!("{}.{}@{}", &base[..i], &base[i..], domain);
                variations.push(with_dot);
            }
        }

        // With numbers
        for i in 0..10 {
            variations.push(format!("{}{}@{}", base, i, domain));
        }

        // Common suffixes
        for suffix in &["1", "123", "007", "69", "420", "2023", "2024"] {
            variations.push(format!("{}{}@{}", base, suffix, domain));
        }

        variations
    }
}

impl Default for EmailIntel {
    fn default() -> Self {
        Self::new(OsintConfig::default())
    }
}

/// Service registration check definition
struct ServiceCheck {
    name: &'static str,
    url: String,
    method: &'static str,
    data: Option<String>,
    success_indicator: CheckIndicator,
}

/// How to check if registration exists
enum CheckIndicator {
    StatusCode(u16),
    ResponseContains(&'static str),
    ResponseNotContains(&'static str),
    JsonContains(&'static str, &'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        let intel = EmailIntel::default();

        assert!(intel.is_valid_format("test@example.com"));
        assert!(intel.is_valid_format("user.name@domain.org"));
        assert!(!intel.is_valid_format("invalid"));
        assert!(!intel.is_valid_format("@domain.com"));
        assert!(!intel.is_valid_format("user@"));
        assert!(!intel.is_valid_format("user@domain"));
    }

    #[test]
    fn test_provider_detection() {
        let intel = EmailIntel::default();

        assert_eq!(
            intel.detect_provider("user@gmail.com"),
            Some("Google".to_string())
        );
        assert_eq!(
            intel.detect_provider("user@outlook.com"),
            Some("Microsoft".to_string())
        );
        assert_eq!(
            intel.detect_provider("user@protonmail.com"),
            Some("ProtonMail".to_string())
        );
    }

    #[test]
    fn test_disposable_detection() {
        let intel = EmailIntel::default();

        assert!(intel.is_disposable("user@mailinator.com"));
        assert!(intel.is_disposable("user@tempmail.com"));
        assert!(!intel.is_disposable("user@gmail.com"));
    }

    #[test]
    fn test_md5_hash() {
        let intel = EmailIntel::default();

        // Known MD5 hash for empty string
        assert_eq!(intel.md5_hash(""), "d41d8cd98f00b204e9800998ecf8427e");

        // Known hash for "hello"
        assert_eq!(intel.md5_hash("hello"), "5d41402abc4b2a76b9719d911017c592");
    }
}
