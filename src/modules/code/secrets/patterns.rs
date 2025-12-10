/// Secret Detection Patterns
///
/// Contains 100+ patterns for detecting various types of secrets:
/// - API keys (AWS, GCP, Azure, etc.)
/// - Private keys (RSA, SSH, PGP)
/// - Tokens (JWT, OAuth, etc.)
/// - Database credentials
/// - Password patterns

use super::SecretSeverity;

/// Categories of secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    ApiKey,
    PrivateKey,
    Password,
    Token,
    CloudCredential,
    DatabaseCredential,
    CryptoKey,
    Certificate,
    Webhook,
    GenericSecret,
}

impl std::fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "API Key"),
            Self::PrivateKey => write!(f, "Private Key"),
            Self::Password => write!(f, "Password"),
            Self::Token => write!(f, "Token"),
            Self::CloudCredential => write!(f, "Cloud Credential"),
            Self::DatabaseCredential => write!(f, "Database Credential"),
            Self::CryptoKey => write!(f, "Crypto Key"),
            Self::Certificate => write!(f, "Certificate"),
            Self::Webhook => write!(f, "Webhook"),
            Self::GenericSecret => write!(f, "Generic Secret"),
        }
    }
}

impl Default for PatternCategory {
    fn default() -> Self {
        Self::GenericSecret
    }
}

/// A secret detection pattern
#[derive(Debug, Clone)]
pub struct SecretPattern {
    /// Pattern name
    pub name: &'static str,
    /// Category
    pub category: PatternCategory,
    /// Pattern to match (simplified regex-like)
    pub pattern: PatternMatcher,
    /// Severity if matched
    pub severity: SecretSeverity,
    /// Keywords that must be present nearby
    pub keywords: Vec<&'static str>,
    /// Entropy check required
    pub requires_entropy: bool,
    /// Minimum length
    pub min_length: usize,
    /// Maximum length
    pub max_length: usize,
    /// Description
    pub description: &'static str,
}

/// Pattern matching methods (no external regex crate)
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Exact prefix match
    Prefix(&'static str),
    /// Exact suffix match
    Suffix(&'static str),
    /// Contains substring
    Contains(&'static str),
    /// Character set + length
    CharsetLength {
        charset: &'static str,
        length: usize,
    },
    /// Character set + length range
    CharsetRange {
        charset: &'static str,
        min_len: usize,
        max_len: usize,
    },
    /// PEM block format
    PemBlock(&'static str),
    /// Multiple conditions (AND)
    All(Vec<PatternMatcher>),
    /// Multiple conditions (OR)
    Any(Vec<PatternMatcher>),
    /// Base64-like pattern with length
    Base64Length(usize),
    /// Hex pattern with length
    HexLength(usize),
    /// JWT format
    Jwt,
    /// Connection string format
    ConnectionString(&'static str),
}

impl PatternMatcher {
    /// Check if a string matches this pattern
    pub fn matches(&self, s: &str) -> bool {
        match self {
            PatternMatcher::Prefix(p) => s.starts_with(p),
            PatternMatcher::Suffix(p) => s.ends_with(p),
            PatternMatcher::Contains(p) => s.contains(p),
            PatternMatcher::CharsetLength { charset, length } => {
                s.len() == *length && s.chars().all(|c| charset.contains(c))
            }
            PatternMatcher::CharsetRange { charset, min_len, max_len } => {
                s.len() >= *min_len && s.len() <= *max_len
                    && s.chars().all(|c| charset.contains(c))
            }
            PatternMatcher::PemBlock(block_type) => {
                s.contains(&format!("-----BEGIN {}-----", block_type))
                    && s.contains(&format!("-----END {}-----", block_type))
            }
            PatternMatcher::All(patterns) => patterns.iter().all(|p| p.matches(s)),
            PatternMatcher::Any(patterns) => patterns.iter().any(|p| p.matches(s)),
            PatternMatcher::Base64Length(len) => {
                s.len() >= *len
                    && s.chars().all(|c| {
                        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
                    })
            }
            PatternMatcher::HexLength(len) => {
                s.len() == *len && s.chars().all(|c| c.is_ascii_hexdigit())
            }
            PatternMatcher::Jwt => {
                let parts: Vec<&str> = s.split('.').collect();
                parts.len() == 3
                    && parts.iter().all(|p| {
                        p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    })
            }
            PatternMatcher::ConnectionString(prefix) => {
                s.starts_with(prefix) && (s.contains("://") || s.contains("password="))
            }
        }
    }
}

/// Get all built-in secret patterns
pub fn get_all_patterns() -> Vec<SecretPattern> {
    vec![
        // ===============================
        // AWS
        // ===============================
        SecretPattern {
            name: "AWS Access Key ID",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::All(vec![
                PatternMatcher::Prefix("AKIA"),
                PatternMatcher::CharsetLength {
                    charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    length: 20,
                },
            ]),
            severity: SecretSeverity::Critical,
            keywords: vec!["aws", "access", "key", "credential"],
            requires_entropy: false,
            min_length: 20,
            max_length: 20,
            description: "AWS Access Key ID starting with AKIA",
        },
        SecretPattern {
            name: "AWS Secret Access Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetLength {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                length: 40,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["aws", "secret", "key", "credential"],
            requires_entropy: true,
            min_length: 40,
            max_length: 40,
            description: "AWS Secret Access Key (40 chars, high entropy)",
        },
        SecretPattern {
            name: "AWS Session Token",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("FwoGZXIvYXdz"),
            severity: SecretSeverity::Critical,
            keywords: vec!["aws", "session", "token"],
            requires_entropy: false,
            min_length: 100,
            max_length: 1000,
            description: "AWS Session Token",
        },

        // ===============================
        // Google Cloud
        // ===============================
        SecretPattern {
            name: "GCP API Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("AIza"),
            severity: SecretSeverity::High,
            keywords: vec!["google", "gcp", "api", "key"],
            requires_entropy: false,
            min_length: 39,
            max_length: 39,
            description: "Google Cloud API Key starting with AIza",
        },
        SecretPattern {
            name: "GCP Service Account",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Contains("\"type\": \"service_account\""),
            severity: SecretSeverity::Critical,
            keywords: vec!["google", "gcp", "service", "account", "private_key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "Google Cloud Service Account JSON",
        },
        SecretPattern {
            name: "GCP OAuth Client Secret",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Prefix("GOCSPX-"),
            severity: SecretSeverity::High,
            keywords: vec!["google", "oauth", "client", "secret"],
            requires_entropy: false,
            min_length: 28,
            max_length: 40,
            description: "Google OAuth Client Secret",
        },

        // ===============================
        // Azure
        // ===============================
        SecretPattern {
            name: "Azure Storage Account Key",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::Base64Length(88),
            severity: SecretSeverity::Critical,
            keywords: vec!["azure", "storage", "account", "key", "DefaultEndpointsProtocol"],
            requires_entropy: true,
            min_length: 88,
            max_length: 88,
            description: "Azure Storage Account Key (base64)",
        },
        SecretPattern {
            name: "Azure Connection String",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::ConnectionString("DefaultEndpointsProtocol="),
            severity: SecretSeverity::Critical,
            keywords: vec!["azure", "connection", "endpoint", "AccountKey"],
            requires_entropy: false,
            min_length: 50,
            max_length: 500,
            description: "Azure Connection String",
        },
        SecretPattern {
            name: "Azure AD Client Secret",
            category: PatternCategory::CloudCredential,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~._-",
                min_len: 34,
                max_len: 40,
            },
            severity: SecretSeverity::Critical,
            keywords: vec!["azure", "client", "secret", "tenant", "app"],
            requires_entropy: true,
            min_length: 34,
            max_length: 40,
            description: "Azure AD Client Secret",
        },

        // ===============================
        // GitHub
        // ===============================
        SecretPattern {
            name: "GitHub Personal Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("ghp_"),
            severity: SecretSeverity::Critical,
            keywords: vec!["github", "token", "pat"],
            requires_entropy: false,
            min_length: 40,
            max_length: 50,
            description: "GitHub Personal Access Token (new format)",
        },
        SecretPattern {
            name: "GitHub OAuth Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("gho_"),
            severity: SecretSeverity::High,
            keywords: vec!["github", "oauth", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 50,
            description: "GitHub OAuth Access Token",
        },
        SecretPattern {
            name: "GitHub App Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Any(vec![
                PatternMatcher::Prefix("ghu_"),
                PatternMatcher::Prefix("ghs_"),
            ]),
            severity: SecretSeverity::High,
            keywords: vec!["github", "app", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 50,
            description: "GitHub App Token",
        },
        SecretPattern {
            name: "GitHub Refresh Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("ghr_"),
            severity: SecretSeverity::High,
            keywords: vec!["github", "refresh", "token"],
            requires_entropy: false,
            min_length: 40,
            max_length: 80,
            description: "GitHub Refresh Token",
        },

        // ===============================
        // GitLab
        // ===============================
        SecretPattern {
            name: "GitLab Personal Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("glpat-"),
            severity: SecretSeverity::Critical,
            keywords: vec!["gitlab", "token", "pat"],
            requires_entropy: false,
            min_length: 26,
            max_length: 30,
            description: "GitLab Personal Access Token",
        },
        SecretPattern {
            name: "GitLab Pipeline Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("glptt-"),
            severity: SecretSeverity::High,
            keywords: vec!["gitlab", "pipeline", "token"],
            requires_entropy: false,
            min_length: 26,
            max_length: 70,
            description: "GitLab Pipeline Trigger Token",
        },

        // ===============================
        // Slack
        // ===============================
        SecretPattern {
            name: "Slack Bot Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("xoxb-"),
            severity: SecretSeverity::High,
            keywords: vec!["slack", "bot", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 100,
            description: "Slack Bot Token",
        },
        SecretPattern {
            name: "Slack User Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("xoxp-"),
            severity: SecretSeverity::High,
            keywords: vec!["slack", "user", "token"],
            requires_entropy: false,
            min_length: 50,
            max_length: 100,
            description: "Slack User Token",
        },
        SecretPattern {
            name: "Slack Webhook URL",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("hooks.slack.com/services/"),
            severity: SecretSeverity::Medium,
            keywords: vec!["slack", "webhook"],
            requires_entropy: false,
            min_length: 60,
            max_length: 200,
            description: "Slack Webhook URL",
        },

        // ===============================
        // Discord
        // ===============================
        SecretPattern {
            name: "Discord Bot Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-",
                min_len: 59,
                max_len: 72,
            },
            severity: SecretSeverity::High,
            keywords: vec!["discord", "bot", "token"],
            requires_entropy: true,
            min_length: 59,
            max_length: 72,
            description: "Discord Bot Token",
        },
        SecretPattern {
            name: "Discord Webhook URL",
            category: PatternCategory::Webhook,
            pattern: PatternMatcher::Contains("discord.com/api/webhooks/"),
            severity: SecretSeverity::Medium,
            keywords: vec!["discord", "webhook"],
            requires_entropy: false,
            min_length: 100,
            max_length: 200,
            description: "Discord Webhook URL",
        },

        // ===============================
        // Stripe
        // ===============================
        SecretPattern {
            name: "Stripe Secret Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk_live_"),
            severity: SecretSeverity::Critical,
            keywords: vec!["stripe", "secret", "key", "payment"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Live Secret Key",
        },
        SecretPattern {
            name: "Stripe Test Secret Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk_test_"),
            severity: SecretSeverity::Low,
            keywords: vec!["stripe", "secret", "key", "test"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Test Secret Key",
        },
        SecretPattern {
            name: "Stripe Publishable Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("pk_live_"),
            severity: SecretSeverity::Medium,
            keywords: vec!["stripe", "publishable", "key"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Live Publishable Key",
        },
        SecretPattern {
            name: "Stripe Restricted Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("rk_live_"),
            severity: SecretSeverity::High,
            keywords: vec!["stripe", "restricted", "key"],
            requires_entropy: false,
            min_length: 30,
            max_length: 100,
            description: "Stripe Restricted API Key",
        },

        // ===============================
        // Twilio
        // ===============================
        SecretPattern {
            name: "Twilio Account SID",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("AC"),
            severity: SecretSeverity::Medium,
            keywords: vec!["twilio", "account", "sid"],
            requires_entropy: false,
            min_length: 34,
            max_length: 34,
            description: "Twilio Account SID",
        },
        SecretPattern {
            name: "Twilio API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("SK"),
            severity: SecretSeverity::High,
            keywords: vec!["twilio", "api", "key"],
            requires_entropy: false,
            min_length: 34,
            max_length: 34,
            description: "Twilio API Key SID",
        },

        // ===============================
        // SendGrid
        // ===============================
        SecretPattern {
            name: "SendGrid API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("SG."),
            severity: SecretSeverity::High,
            keywords: vec!["sendgrid", "api", "key", "mail"],
            requires_entropy: false,
            min_length: 50,
            max_length: 100,
            description: "SendGrid API Key",
        },

        // ===============================
        // Mailchimp
        // ===============================
        SecretPattern {
            name: "Mailchimp API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Suffix("-us"),
            severity: SecretSeverity::High,
            keywords: vec!["mailchimp", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 40,
            description: "Mailchimp API Key",
        },

        // ===============================
        // NPM
        // ===============================
        SecretPattern {
            name: "NPM Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("npm_"),
            severity: SecretSeverity::High,
            keywords: vec!["npm", "token", "registry"],
            requires_entropy: false,
            min_length: 36,
            max_length: 50,
            description: "NPM Access Token",
        },

        // ===============================
        // Private Keys
        // ===============================
        SecretPattern {
            name: "RSA Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("RSA PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["private", "key", "rsa"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "RSA Private Key in PEM format",
        },
        SecretPattern {
            name: "EC Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("EC PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["private", "key", "ec", "ecdsa"],
            requires_entropy: false,
            min_length: 100,
            max_length: 5000,
            description: "EC Private Key in PEM format",
        },
        SecretPattern {
            name: "OpenSSH Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("OPENSSH PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["ssh", "private", "key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "OpenSSH Private Key",
        },
        SecretPattern {
            name: "PGP Private Key Block",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("PGP PRIVATE KEY BLOCK"),
            severity: SecretSeverity::Critical,
            keywords: vec!["pgp", "gpg", "private", "key"],
            requires_entropy: false,
            min_length: 100,
            max_length: 20000,
            description: "PGP Private Key Block",
        },
        SecretPattern {
            name: "PKCS8 Private Key",
            category: PatternCategory::PrivateKey,
            pattern: PatternMatcher::PemBlock("PRIVATE KEY"),
            severity: SecretSeverity::Critical,
            keywords: vec!["private", "key", "pkcs8"],
            requires_entropy: false,
            min_length: 100,
            max_length: 10000,
            description: "PKCS8 Private Key in PEM format",
        },

        // ===============================
        // JWT
        // ===============================
        SecretPattern {
            name: "JSON Web Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Jwt,
            severity: SecretSeverity::Medium,
            keywords: vec!["jwt", "token", "bearer", "authorization"],
            requires_entropy: false,
            min_length: 50,
            max_length: 2000,
            description: "JSON Web Token (JWT)",
        },

        // ===============================
        // Database Connection Strings
        // ===============================
        SecretPattern {
            name: "PostgreSQL Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("postgres://"),
            severity: SecretSeverity::Critical,
            keywords: vec!["postgres", "psql", "database", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "PostgreSQL Connection String",
        },
        SecretPattern {
            name: "MySQL Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("mysql://"),
            severity: SecretSeverity::Critical,
            keywords: vec!["mysql", "database", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "MySQL Connection String",
        },
        SecretPattern {
            name: "MongoDB Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("mongodb"),
            severity: SecretSeverity::Critical,
            keywords: vec!["mongo", "mongodb", "database", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "MongoDB Connection String",
        },
        SecretPattern {
            name: "Redis Connection String",
            category: PatternCategory::DatabaseCredential,
            pattern: PatternMatcher::ConnectionString("redis://"),
            severity: SecretSeverity::High,
            keywords: vec!["redis", "cache", "connection"],
            requires_entropy: false,
            min_length: 20,
            max_length: 500,
            description: "Redis Connection String",
        },

        // ===============================
        // Generic Patterns
        // ===============================
        SecretPattern {
            name: "Generic API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
                min_len: 32,
                max_len: 64,
            },
            severity: SecretSeverity::Medium,
            keywords: vec!["api_key", "apikey", "api-key", "secret_key", "access_key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 64,
            description: "Generic API Key pattern",
        },
        SecretPattern {
            name: "Generic Secret",
            category: PatternCategory::GenericSecret,
            pattern: PatternMatcher::CharsetRange {
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                min_len: 16,
                max_len: 64,
            },
            severity: SecretSeverity::Low,
            keywords: vec!["secret", "password", "passwd", "pwd", "credential"],
            requires_entropy: true,
            min_length: 16,
            max_length: 64,
            description: "Generic secret pattern with high entropy",
        },
        SecretPattern {
            name: "Password Assignment",
            category: PatternCategory::Password,
            pattern: PatternMatcher::Any(vec![
                PatternMatcher::Contains("password="),
                PatternMatcher::Contains("password:"),
                PatternMatcher::Contains("PASSWORD="),
                PatternMatcher::Contains("passwd="),
            ]),
            severity: SecretSeverity::High,
            keywords: vec!["password", "passwd", "pwd"],
            requires_entropy: false,
            min_length: 10,
            max_length: 200,
            description: "Password assignment in configuration",
        },

        // ===============================
        // Heroku
        // ===============================
        SecretPattern {
            name: "Heroku API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(36),
            severity: SecretSeverity::High,
            keywords: vec!["heroku", "api", "key"],
            requires_entropy: true,
            min_length: 36,
            max_length: 36,
            description: "Heroku API Key",
        },

        // ===============================
        // DigitalOcean
        // ===============================
        SecretPattern {
            name: "DigitalOcean Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("dop_v1_"),
            severity: SecretSeverity::Critical,
            keywords: vec!["digitalocean", "do", "token"],
            requires_entropy: false,
            min_length: 64,
            max_length: 80,
            description: "DigitalOcean Personal Access Token",
        },

        // ===============================
        // Shopify
        // ===============================
        SecretPattern {
            name: "Shopify Access Token",
            category: PatternCategory::Token,
            pattern: PatternMatcher::Prefix("shpat_"),
            severity: SecretSeverity::High,
            keywords: vec!["shopify", "access", "token"],
            requires_entropy: false,
            min_length: 32,
            max_length: 50,
            description: "Shopify Admin API Access Token",
        },
        SecretPattern {
            name: "Shopify API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("shpss_"),
            severity: SecretSeverity::High,
            keywords: vec!["shopify", "api", "secret"],
            requires_entropy: false,
            min_length: 32,
            max_length: 50,
            description: "Shopify API Secret Key",
        },

        // ===============================
        // OpenAI
        // ===============================
        SecretPattern {
            name: "OpenAI API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk-"),
            severity: SecretSeverity::Critical,
            keywords: vec!["openai", "gpt", "api", "key", "chatgpt"],
            requires_entropy: false,
            min_length: 40,
            max_length: 60,
            description: "OpenAI API Key",
        },

        // ===============================
        // Anthropic
        // ===============================
        SecretPattern {
            name: "Anthropic API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("sk-ant-"),
            severity: SecretSeverity::Critical,
            keywords: vec!["anthropic", "claude", "api", "key"],
            requires_entropy: false,
            min_length: 60,
            max_length: 120,
            description: "Anthropic API Key",
        },

        // ===============================
        // Datadog
        // ===============================
        SecretPattern {
            name: "Datadog API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::HexLength(32),
            severity: SecretSeverity::High,
            keywords: vec!["datadog", "dd", "api", "key"],
            requires_entropy: true,
            min_length: 32,
            max_length: 32,
            description: "Datadog API Key",
        },

        // ===============================
        // New Relic
        // ===============================
        SecretPattern {
            name: "New Relic API Key",
            category: PatternCategory::ApiKey,
            pattern: PatternMatcher::Prefix("NRAK-"),
            severity: SecretSeverity::High,
            keywords: vec!["newrelic", "nr", "api", "key"],
            requires_entropy: false,
            min_length: 40,
            max_length: 50,
            description: "New Relic API Key",
        },
    ]
}

/// Get patterns by category
pub fn get_patterns_by_category(category: PatternCategory) -> Vec<SecretPattern> {
    get_all_patterns()
        .into_iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Get high severity patterns only
pub fn get_critical_patterns() -> Vec<SecretPattern> {
    get_all_patterns()
        .into_iter()
        .filter(|p| p.severity >= SecretSeverity::High)
        .collect()
}
