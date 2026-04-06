/// Secret Validation Module
///
/// Validates detected secrets against their respective provider APIs
/// to determine if they are active/valid.
///
/// Inspired by keyscope - supports 50+ providers including:
/// - Cloud: AWS, GCP, Azure, DigitalOcean, Heroku, Vercel
/// - Code: GitHub, GitLab, Bitbucket, CircleCI, Travis CI
/// - Communication: Slack, Discord, Telegram, Twilio, SendGrid
/// - Payment: Stripe, PayPal, Square, Coinbase
/// - SaaS: Datadog, OpenAI, Anthropic, Shodan, etc.
use crate::protocols::http::{HttpClient, HttpRequest};
use std::collections::HashMap;
use std::time::Duration;

/// Result of validating a secret
#[derive(Debug, Clone)]
pub struct ValidationResult {
  /// Provider name (e.g., "github", "aws", "stripe")
  pub provider: String,
  /// Whether the secret is valid/active
  pub is_valid: bool,
  /// Validation status
  pub status: ValidationStatus,
  /// Additional info (e.g., scopes, permissions, account info)
  pub info: HashMap<String, String>,
  /// Error message if validation failed
  pub error: Option<String>,
  /// Response time in milliseconds
  pub response_time_ms: u64,
}

/// Validation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
  /// Secret is valid and active
  Valid,
  /// Secret is invalid or expired
  Invalid,
  /// Rate limited by provider
  RateLimited,
  /// Provider unreachable or error
  Error,
  /// Provider not supported for validation
  Unsupported,
  /// Validation requires additional parameters
  IncompleteParams,
}

impl std::fmt::Display for ValidationStatus {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Valid => write!(f, "VALID"),
      Self::Invalid => write!(f, "INVALID"),
      Self::RateLimited => write!(f, "RATE_LIMITED"),
      Self::Error => write!(f, "ERROR"),
      Self::Unsupported => write!(f, "UNSUPPORTED"),
      Self::IncompleteParams => write!(f, "INCOMPLETE"),
    }
  }
}

/// HTTP method for validation request
#[derive(Debug, Clone, Copy)]
pub enum ValidatorMethod {
  Get,
  Post,
  Head,
}

/// Authentication type for the request
#[derive(Debug, Clone)]
pub enum AuthType {
  /// Bearer token in Authorization header
  Bearer,
  /// Basic auth (user:password or api:key)
  Basic { username: &'static str },
  /// API key in header
  Header { name: &'static str },
  /// API key in query parameter
  Query { name: &'static str },
  /// Custom header value (no Bearer/Basic prefix)
  CustomHeader {
    name: &'static str,
    prefix: &'static str,
  },
}

/// Provider validation configuration
#[derive(Debug, Clone)]
pub struct ProviderConfig {
  /// Provider name
  pub name: &'static str,
  /// Validation endpoint URL (with {{KEY}} placeholder)
  pub url: &'static str,
  /// HTTP method
  pub method: ValidatorMethod,
  /// Authentication type
  pub auth: AuthType,
  /// Additional headers
  pub headers: &'static [(&'static str, &'static str)],
  /// Request body (for POST)
  pub body: Option<&'static str>,
  /// Expected status code for valid key
  pub valid_status: u16,
  /// Pattern in response body indicating valid key
  pub valid_body_pattern: Option<&'static str>,
  /// Pattern in response body indicating invalid key
  pub invalid_body_pattern: Option<&'static str>,
}

/// Secret validator with provider registry
pub struct SecretValidator {
  providers: HashMap<String, ProviderConfig>,
  timeout: Duration,
}

impl SecretValidator {
  /// Create new validator with all providers
  pub fn new() -> Self {
    let mut providers = HashMap::new();

    // Register all providers
    for config in PROVIDERS.iter() {
      providers.insert(config.name.to_string(), config.clone());
    }

    Self {
      providers,
      timeout: Duration::from_secs(10),
    }
  }

  /// Set timeout for validation requests
  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// Get list of supported providers
  pub fn supported_providers(&self) -> Vec<&str> {
    self.providers.keys().map(|s| s.as_str()).collect()
  }

  /// Check if provider is supported
  pub fn is_supported(&self, provider: &str) -> bool {
    self.providers.contains_key(provider)
  }

  /// Validate a secret against a specific provider
  pub fn validate(&self, secret: &str, provider: &str) -> ValidationResult {
    let start = std::time::Instant::now();

    let config = match self.providers.get(provider) {
      Some(c) => c,
      None => {
        return ValidationResult {
          provider: provider.to_string(),
          is_valid: false,
          status: ValidationStatus::Unsupported,
          info: HashMap::new(),
          error: Some(format!("Provider '{}' not supported", provider)),
          response_time_ms: 0,
        };
      }
    };

    // Build the request URL with secret substitution
    let url = config.url.replace("{{KEY}}", secret);

    // Create HTTP client with timeout
    let mut client = HttpClient::new();
    client.set_timeout(self.timeout);

    // Build request based on method
    let mut request = match config.method {
      ValidatorMethod::Get => HttpRequest::get(&url),
      ValidatorMethod::Post => HttpRequest::post(&url),
      ValidatorMethod::Head => HttpRequest::head(&url),
    };

    // Set authentication
    match &config.auth {
      AuthType::Bearer => {
        request = request.with_header("Authorization", &format!("Bearer {}", secret));
      }
      AuthType::Basic { username } => {
        let credentials = format!("{}:{}", username, secret);
        let encoded = base64_encode(credentials.as_bytes());
        request = request.with_header("Authorization", &format!("Basic {}", encoded));
      }
      AuthType::Header { name } => {
        request = request.with_header(name, secret);
      }
      AuthType::Query { name: _ } => {
        // Already included in URL via {{KEY}} replacement
      }
      AuthType::CustomHeader { name, prefix } => {
        request = request.with_header(name, &format!("{}{}", prefix, secret));
      }
    }

    // Add additional headers
    for (name, value) in config.headers.iter() {
      request = request.with_header(name, value);
    }

    // Add body if present
    if let Some(body) = config.body {
      request = request.with_body(body.as_bytes().to_vec());
    }

    // Execute request
    let response = match client.send(&request) {
      Ok(resp) => resp,
      Err(e) => {
        return ValidationResult {
          provider: provider.to_string(),
          is_valid: false,
          status: ValidationStatus::Error,
          info: HashMap::new(),
          error: Some(format!("Request failed: {}", e)),
          response_time_ms: start.elapsed().as_millis() as u64,
        };
      }
    };

    let response_time_ms = start.elapsed().as_millis() as u64;

    // Check for rate limiting
    if response.status_code == 429 {
      return ValidationResult {
        provider: provider.to_string(),
        is_valid: false,
        status: ValidationStatus::RateLimited,
        info: HashMap::new(),
        error: Some("Rate limited by provider".to_string()),
        response_time_ms,
      };
    }

    // Validate response
    let body_str = String::from_utf8_lossy(&response.body);

    // Check for invalid patterns first
    if let Some(pattern) = config.invalid_body_pattern {
      if body_str.contains(pattern) {
        return ValidationResult {
          provider: provider.to_string(),
          is_valid: false,
          status: ValidationStatus::Invalid,
          info: HashMap::new(),
          error: None,
          response_time_ms,
        };
      }
    }

    // Check status code
    let status_valid = response.status_code == config.valid_status;

    // Check body pattern if specified
    let body_valid = config
      .valid_body_pattern
      .map(|p| body_str.contains(p))
      .unwrap_or(true);

    let is_valid = status_valid && body_valid;

    // Extract additional info from response (simple JSON field extraction)
    let mut info = HashMap::new();
    if is_valid {
      // Simple JSON field extraction without serde_json
      for field in ["login", "username", "email", "name", "id", "account_id"] {
        if let Some(value) = extract_json_string_field(&body_str, field) {
          info.insert(field.to_string(), value);
        }
      }
    }

    ValidationResult {
      provider: provider.to_string(),
      is_valid,
      status: if is_valid {
        ValidationStatus::Valid
      } else {
        ValidationStatus::Invalid
      },
      info,
      error: None,
      response_time_ms,
    }
  }

  /// Auto-detect provider from secret type and validate
  pub fn validate_auto(&self, secret: &str, secret_type: &str) -> ValidationResult {
    // Map secret types to providers
    let provider = match secret_type.to_lowercase().as_str() {
      s if s.contains("github") => "github",
      s if s.contains("gitlab") => "gitlab",
      s if s.contains("aws") => "aws",
      s if s.contains("stripe") => "stripe",
      s if s.contains("slack") => "slack",
      s if s.contains("discord") => "discord",
      s if s.contains("twilio") => "twilio",
      s if s.contains("sendgrid") => "sendgrid",
      s if s.contains("mailgun") => "mailgun",
      s if s.contains("openai") => "openai",
      s if s.contains("anthropic") => "anthropic",
      s if s.contains("datadog") => "datadog",
      s if s.contains("heroku") => "heroku",
      s if s.contains("digitalocean") => "digitalocean",
      s if s.contains("telegram") => "telegram",
      s if s.contains("firebase") => "firebase",
      s if s.contains("shopify") => "shopify",
      s if s.contains("paypal") => "paypal",
      s if s.contains("square") => "square",
      s if s.contains("sentry") => "sentry",
      s if s.contains("pagerduty") => "pagerduty",
      s if s.contains("circleci") => "circleci",
      s if s.contains("travisci") || s.contains("travis") => "travisci",
      s if s.contains("npm") => "npm",
      s if s.contains("pypi") => "pypi",
      s if s.contains("hubspot") => "hubspot",
      s if s.contains("zendesk") => "zendesk",
      s if s.contains("asana") => "asana",
      s if s.contains("notion") => "notion",
      s if s.contains("linear") => "linear",
      s if s.contains("shodan") => "shodan",
      s if s.contains("virustotal") => "virustotal",
      _ => {
        return ValidationResult {
          provider: "unknown".to_string(),
          is_valid: false,
          status: ValidationStatus::Unsupported,
          info: HashMap::new(),
          error: Some(format!(
            "Cannot auto-detect provider for secret type '{}'",
            secret_type
          )),
          response_time_ms: 0,
        };
      }
    };

    self.validate(secret, provider)
  }

  /// Validate multiple secrets in batch
  pub fn validate_batch(&self, secrets: &[(String, String)]) -> Vec<ValidationResult> {
    secrets
      .iter()
      .map(|(secret, provider)| self.validate(secret, provider))
      .collect()
  }
}

impl Default for SecretValidator {
  fn default() -> Self {
    Self::new()
  }
}

/// Simple base64 encoder (avoiding external deps)
fn base64_encode(data: &[u8]) -> String {
  const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  let mut result = String::new();
  let mut i = 0;

  while i < data.len() {
    let b0 = data[i] as usize;
    let b1 = if i + 1 < data.len() {
      data[i + 1] as usize
    } else {
      0
    };
    let b2 = if i + 2 < data.len() {
      data[i + 2] as usize
    } else {
      0
    };

    result.push(ALPHABET[b0 >> 2] as char);
    result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

    if i + 1 < data.len() {
      result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
    } else {
      result.push('=');
    }

    if i + 2 < data.len() {
      result.push(ALPHABET[b2 & 0x3f] as char);
    } else {
      result.push('=');
    }

    i += 3;
  }

  result
}

/// Simple JSON string field extraction without serde_json
/// Looks for "field": "value" patterns
fn extract_json_string_field(json: &str, field: &str) -> Option<String> {
  // Look for "field": "value" or "field":"value"
  let patterns = [
    format!("\"{}\":\"", field),
    format!("\"{}\": \"", field),
    format!("\"{}\" : \"", field),
  ];

  for pattern in &patterns {
    if let Some(start) = json.find(pattern) {
      let value_start = start + pattern.len();
      let rest = &json[value_start..];

      // Find the closing quote, handling escaped quotes
      let mut end = 0;
      let mut escaped = false;
      for (i, c) in rest.chars().enumerate() {
        if escaped {
          escaped = false;
          continue;
        }
        if c == '\\' {
          escaped = true;
          continue;
        }
        if c == '"' {
          end = i;
          break;
        }
      }

      if end > 0 {
        return Some(rest[..end].to_string());
      }
    }
  }

  None
}

// =============================================================================
// Provider Configurations (50+)
// =============================================================================

/// All supported provider configurations
/// Based on keyscope project patterns
pub static PROVIDERS: &[ProviderConfig] = &[
  // -------------------------------------------------------------------------
  // Cloud Providers
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "github",
    url: "https://api.github.com/user",
    method: ValidatorMethod::Get,
    auth: AuthType::CustomHeader {
      name: "Authorization",
      prefix: "token ",
    },
    headers: &[("User-Agent", "redblue-validator")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("login"),
    invalid_body_pattern: Some("Bad credentials"),
  },
  ProviderConfig {
    name: "gitlab",
    url: "https://gitlab.com/api/v4/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("username"),
    invalid_body_pattern: Some("401 Unauthorized"),
  },
  ProviderConfig {
    name: "bitbucket",
    url: "https://api.bitbucket.org/2.0/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("username"),
    invalid_body_pattern: None,
  },
  ProviderConfig {
    name: "digitalocean",
    url: "https://api.digitalocean.com/v2/account",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("account"),
    invalid_body_pattern: Some("Unable to authenticate"),
  },
  ProviderConfig {
    name: "heroku",
    url: "https://api.heroku.com/account",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[("Accept", "application/vnd.heroku+json; version=3")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("email"),
    invalid_body_pattern: Some("Invalid credentials"),
  },
  ProviderConfig {
    name: "vercel",
    url: "https://api.vercel.com/v2/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("user"),
    invalid_body_pattern: Some("Invalid token"),
  },
  ProviderConfig {
    name: "netlify",
    url: "https://api.netlify.com/api/v1/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("email"),
    invalid_body_pattern: None,
  },
  ProviderConfig {
    name: "linode",
    url: "https://api.linode.com/v4/profile",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("username"),
    invalid_body_pattern: Some("Invalid Token"),
  },
  ProviderConfig {
    name: "vultr",
    url: "https://api.vultr.com/v2/account",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("account"),
    invalid_body_pattern: Some("Invalid API token"),
  },
  // -------------------------------------------------------------------------
  // Communication Platforms
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "slack",
    url: "https://slack.com/api/auth.test",
    method: ValidatorMethod::Post,
    auth: AuthType::Bearer,
    headers: &[("Content-Type", "application/x-www-form-urlencoded")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("\"ok\":true"),
    invalid_body_pattern: Some("\"ok\":false"),
  },
  ProviderConfig {
    name: "discord",
    url: "https://discord.com/api/v10/users/@me",
    method: ValidatorMethod::Get,
    auth: AuthType::CustomHeader {
      name: "Authorization",
      prefix: "Bot ",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("username"),
    invalid_body_pattern: Some("401: Unauthorized"),
  },
  ProviderConfig {
    name: "telegram",
    url: "https://api.telegram.org/bot{{KEY}}/getMe",
    method: ValidatorMethod::Get,
    auth: AuthType::Query { name: "token" }, // Token is in URL
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("\"ok\":true"),
    invalid_body_pattern: Some("\"ok\":false"),
  },
  ProviderConfig {
    name: "twilio",
    url: "https://api.twilio.com/2010-04-01/Accounts.json",
    method: ValidatorMethod::Get,
    auth: AuthType::Basic { username: "" }, // SID:Token format
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("accounts"),
    invalid_body_pattern: Some("Authenticate"),
  },
  ProviderConfig {
    name: "sendgrid",
    url: "https://api.sendgrid.com/v3/user/account",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("type"),
    invalid_body_pattern: Some("authorization required"),
  },
  ProviderConfig {
    name: "mailgun",
    url: "https://api.mailgun.net/v3/domains",
    method: ValidatorMethod::Get,
    auth: AuthType::Basic { username: "api" },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("items"),
    invalid_body_pattern: Some("Forbidden"),
  },
  ProviderConfig {
    name: "postmark",
    url: "https://api.postmarkapp.com/server",
    method: ValidatorMethod::Get,
    auth: AuthType::Header {
      name: "X-Postmark-Server-Token",
    },
    headers: &[("Accept", "application/json")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("Name"),
    invalid_body_pattern: Some("InvalidAPIKeyError"),
  },
  // -------------------------------------------------------------------------
  // Payment Providers
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "stripe",
    url: "https://api.stripe.com/v1/charges?limit=1",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("data"),
    invalid_body_pattern: Some("Invalid API Key"),
  },
  ProviderConfig {
    name: "square",
    url: "https://connect.squareup.com/v2/merchants",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("merchant"),
    invalid_body_pattern: Some("UNAUTHORIZED"),
  },
  ProviderConfig {
    name: "paypal",
    url: "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("user_id"),
    invalid_body_pattern: Some("invalid_token"),
  },
  ProviderConfig {
    name: "coinbase",
    url: "https://api.coinbase.com/v2/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[("CB-VERSION", "2023-01-01")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("data"),
    invalid_body_pattern: Some("invalid_token"),
  },
  // -------------------------------------------------------------------------
  // AI/ML Providers
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "openai",
    url: "https://api.openai.com/v1/models",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("data"),
    invalid_body_pattern: Some("invalid_api_key"),
  },
  ProviderConfig {
    name: "anthropic",
    url: "https://api.anthropic.com/v1/messages",
    method: ValidatorMethod::Post,
    auth: AuthType::Header { name: "x-api-key" },
    headers: &[
      ("Content-Type", "application/json"),
      ("anthropic-version", "2023-06-01"),
    ],
    body: Some(
      r#"{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#,
    ),
    valid_status: 200,
    valid_body_pattern: Some("content"),
    invalid_body_pattern: Some("invalid_api_key"),
  },
  ProviderConfig {
    name: "replicate",
    url: "https://api.replicate.com/v1/account",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("username"),
    invalid_body_pattern: Some("Invalid token"),
  },
  ProviderConfig {
    name: "huggingface",
    url: "https://huggingface.co/api/whoami-v2",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("name"),
    invalid_body_pattern: Some("Unauthorized"),
  },
  // -------------------------------------------------------------------------
  // Monitoring & Observability
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "datadog",
    url: "https://api.datadoghq.com/api/v1/validate",
    method: ValidatorMethod::Get,
    auth: AuthType::Header { name: "DD-API-KEY" },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("valid"),
    invalid_body_pattern: Some("Forbidden"),
  },
  ProviderConfig {
    name: "sentry",
    url: "https://sentry.io/api/0/",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("user"),
    invalid_body_pattern: Some("Invalid token"),
  },
  ProviderConfig {
    name: "pagerduty",
    url: "https://api.pagerduty.com/users/me",
    method: ValidatorMethod::Get,
    auth: AuthType::CustomHeader {
      name: "Authorization",
      prefix: "Token token=",
    },
    headers: &[("Accept", "application/vnd.pagerduty+json;version=2")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("user"),
    invalid_body_pattern: Some("Invalid"),
  },
  ProviderConfig {
    name: "newrelic",
    url: "https://api.newrelic.com/v2/users.json",
    method: ValidatorMethod::Get,
    auth: AuthType::Header { name: "Api-Key" },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("users"),
    invalid_body_pattern: Some("Invalid API key"),
  },
  // -------------------------------------------------------------------------
  // CI/CD Platforms
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "circleci",
    url: "https://circleci.com/api/v2/me",
    method: ValidatorMethod::Get,
    auth: AuthType::Header {
      name: "Circle-Token",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("login"),
    invalid_body_pattern: Some("Invalid token"),
  },
  ProviderConfig {
    name: "travisci",
    url: "https://api.travis-ci.com/user",
    method: ValidatorMethod::Get,
    auth: AuthType::CustomHeader {
      name: "Authorization",
      prefix: "token ",
    },
    headers: &[("Travis-API-Version", "3")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("login"),
    invalid_body_pattern: Some("access denied"),
  },
  ProviderConfig {
    name: "buildkite",
    url: "https://api.buildkite.com/v2/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("name"),
    invalid_body_pattern: Some("Unauthorized"),
  },
  // -------------------------------------------------------------------------
  // Package Registries
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "npm",
    url: "https://registry.npmjs.org/-/npm/v1/user",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("name"),
    invalid_body_pattern: Some("Unauthorized"),
  },
  ProviderConfig {
    name: "pypi",
    url: "https://upload.pypi.org/legacy/",
    method: ValidatorMethod::Post,
    auth: AuthType::Basic {
      username: "__token__",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: None,
    invalid_body_pattern: Some("Invalid or non-existent"),
  },
  // -------------------------------------------------------------------------
  // SaaS Platforms
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "hubspot",
    url: "https://api.hubapi.com/integrations/v1/me",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("portalId"),
    invalid_body_pattern: Some("UNAUTHORIZED"),
  },
  ProviderConfig {
    name: "zendesk",
    url: "https://{{SUBDOMAIN}}.zendesk.com/api/v2/users/me.json",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("user"),
    invalid_body_pattern: Some("Couldn't authenticate"),
  },
  ProviderConfig {
    name: "asana",
    url: "https://app.asana.com/api/1.0/users/me",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("data"),
    invalid_body_pattern: Some("Not Authorized"),
  },
  ProviderConfig {
    name: "notion",
    url: "https://api.notion.com/v1/users/me",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[("Notion-Version", "2022-06-28")],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("object"),
    invalid_body_pattern: Some("unauthorized"),
  },
  ProviderConfig {
    name: "linear",
    url: "https://api.linear.app/graphql",
    method: ValidatorMethod::Post,
    auth: AuthType::Bearer,
    headers: &[("Content-Type", "application/json")],
    body: Some(r#"{"query":"{ viewer { id } }"}"#),
    valid_status: 200,
    valid_body_pattern: Some("viewer"),
    invalid_body_pattern: Some("Authentication required"),
  },
  ProviderConfig {
    name: "airtable",
    url: "https://api.airtable.com/v0/meta/whoami",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("id"),
    invalid_body_pattern: Some("UNAUTHORIZED"),
  },
  // -------------------------------------------------------------------------
  // Security & Threat Intel
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "shodan",
    url: "https://api.shodan.io/api-info?key={{KEY}}",
    method: ValidatorMethod::Get,
    auth: AuthType::Query { name: "key" },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("query_credits"),
    invalid_body_pattern: Some("Invalid API key"),
  },
  ProviderConfig {
    name: "virustotal",
    url: "https://www.virustotal.com/api/v3/users/{{KEY}}",
    method: ValidatorMethod::Get,
    auth: AuthType::Header { name: "x-apikey" },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("data"),
    invalid_body_pattern: Some("WrongCredentialsError"),
  },
  ProviderConfig {
    name: "securitytrails",
    url: "https://api.securitytrails.com/v1/ping",
    method: ValidatorMethod::Get,
    auth: AuthType::Header { name: "apikey" },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("success"),
    invalid_body_pattern: Some("invalid authentication"),
  },
  ProviderConfig {
    name: "censys",
    url: "https://search.censys.io/api/v1/account",
    method: ValidatorMethod::Get,
    auth: AuthType::Basic { username: "" }, // API_ID:API_SECRET
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("quota"),
    invalid_body_pattern: Some("Unauthorized"),
  },
  // -------------------------------------------------------------------------
  // Firebase & Google
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "firebase",
    url: "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={{KEY}}",
    method: ValidatorMethod::Post,
    auth: AuthType::Query { name: "key" },
    headers: &[("Content-Type", "application/json")],
    body: Some(r#"{"idToken":"test"}"#),
    valid_status: 400, // Returns 400 with "INVALID_ID_TOKEN" if key is valid
    valid_body_pattern: Some("INVALID_ID_TOKEN"),
    invalid_body_pattern: Some("API key not valid"),
  },
  ProviderConfig {
    name: "gcp",
    url: "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={{KEY}}",
    method: ValidatorMethod::Get,
    auth: AuthType::Query {
      name: "access_token",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("expires_in"),
    invalid_body_pattern: Some("invalid_token"),
  },
  // -------------------------------------------------------------------------
  // Miscellaneous
  // -------------------------------------------------------------------------
  ProviderConfig {
    name: "algolia",
    url: "https://{{APP_ID}}-dsn.algolia.net/1/keys/{{KEY}}",
    method: ValidatorMethod::Get,
    auth: AuthType::Header {
      name: "X-Algolia-API-Key",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("acl"),
    invalid_body_pattern: Some("Invalid Application-ID"),
  },
  ProviderConfig {
    name: "cloudflare",
    url: "https://api.cloudflare.com/client/v4/user/tokens/verify",
    method: ValidatorMethod::Get,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("\"success\":true"),
    invalid_body_pattern: Some("\"success\":false"),
  },
  ProviderConfig {
    name: "shopify",
    url: "https://{{SHOP}}.myshopify.com/admin/api/2023-10/shop.json",
    method: ValidatorMethod::Get,
    auth: AuthType::Header {
      name: "X-Shopify-Access-Token",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("shop"),
    invalid_body_pattern: Some("Unauthorized"),
  },
  ProviderConfig {
    name: "dropbox",
    url: "https://api.dropboxapi.com/2/users/get_current_account",
    method: ValidatorMethod::Post,
    auth: AuthType::Bearer,
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("account_id"),
    invalid_body_pattern: Some("invalid_access_token"),
  },
  ProviderConfig {
    name: "mapbox",
    url: "https://api.mapbox.com/tokens/v2?access_token={{KEY}}",
    method: ValidatorMethod::Get,
    auth: AuthType::Query {
      name: "access_token",
    },
    headers: &[],
    body: None,
    valid_status: 200,
    valid_body_pattern: Some("code"),
    invalid_body_pattern: Some("Invalid token"),
  },
];

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_validator_creation() {
    let validator = SecretValidator::new();
    assert!(validator.supported_providers().len() >= 50);
  }

  #[test]
  fn test_provider_lookup() {
    let validator = SecretValidator::new();
    assert!(validator.is_supported("github"));
    assert!(validator.is_supported("stripe"));
    assert!(validator.is_supported("openai"));
    assert!(!validator.is_supported("nonexistent"));
  }

  #[test]
  fn test_base64_encode() {
    assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    assert_eq!(base64_encode(b"world"), "d29ybGQ=");
    assert_eq!(base64_encode(b"api:secret"), "YXBpOnNlY3JldA==");
  }

  #[test]
  fn test_unsupported_provider() {
    let validator = SecretValidator::new();
    let result = validator.validate("test-secret", "nonexistent");
    assert_eq!(result.status, ValidationStatus::Unsupported);
    assert!(!result.is_valid);
  }

  #[test]
  fn test_auto_detect_github() {
    let validator = SecretValidator::new();
    // Just test the provider detection logic, not actual validation
    let result = validator.validate_auto("ghp_test", "GitHub Token");
    // Should detect github provider
    assert_eq!(result.provider, "github");
  }

  #[test]
  fn test_auto_detect_stripe() {
    let validator = SecretValidator::new();
    let result = validator.validate_auto("sk_test_xxx", "Stripe API Key");
    assert_eq!(result.provider, "stripe");
  }

  #[test]
  fn test_auto_detect_unknown() {
    let validator = SecretValidator::new();
    let result = validator.validate_auto("xxx", "Unknown Secret Type");
    assert_eq!(result.status, ValidationStatus::Unsupported);
  }
}
