#![allow(dead_code)]

/// Cookie security analyzer
///
/// Parses Set-Cookie headers and evaluates each cookie against security best
/// practices: Secure flag, HttpOnly flag, SameSite policy, overly broad Domain
/// attributes, and session-cookie identification heuristics.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Severity of a cookie security issue.
#[derive(Debug, Clone, PartialEq)]
pub enum CookieSeverity {
  High,
  Medium,
  Low,
  Info,
}

impl std::fmt::Display for CookieSeverity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      CookieSeverity::High => write!(f, "HIGH"),
      CookieSeverity::Medium => write!(f, "MEDIUM"),
      CookieSeverity::Low => write!(f, "LOW"),
      CookieSeverity::Info => write!(f, "INFO"),
    }
  }
}

/// Parsed SameSite policy.
#[derive(Debug, Clone, PartialEq)]
pub enum SameSitePolicy {
  Strict,
  Lax,
  None,
}

/// Boolean and key-value cookie attributes.
#[derive(Debug, Clone)]
pub struct CookieFlags {
  pub secure: bool,
  pub http_only: bool,
  pub same_site: Option<SameSitePolicy>,
  pub max_age: Option<i64>,
  pub expires: Option<String>,
  pub path: Option<String>,
  pub domain: Option<String>,
}

/// A single issue found on a cookie.
#[derive(Debug, Clone)]
pub struct CookieIssue {
  pub severity: CookieSeverity,
  pub description: String,
}

/// Full analysis result for one cookie.
#[derive(Debug, Clone)]
pub struct CookieAnalysis {
  pub name: String,
  /// First 20 characters of the value (or the full value if shorter).
  pub value_preview: String,
  pub flags: CookieFlags,
  pub issues: Vec<CookieIssue>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a single `Set-Cookie` header value and analyse its security posture.
///
/// `is_https` indicates whether the cookie was received over a TLS connection,
/// which affects the Secure-flag check.
pub fn analyze_cookie(set_cookie_header: &str, is_https: bool) -> CookieAnalysis {
  let parts: Vec<&str> = set_cookie_header.split(';').collect();

  // First part is name=value
  let (name, value) = if let Some(first) = parts.first() {
    let trimmed = first.trim();
    if let Some(eq) = trimmed.find('=') {
      let n = trimmed[..eq].trim().to_string();
      let v = trimmed[eq + 1..].trim().to_string();
      (n, v)
    } else {
      (trimmed.to_string(), String::new())
    }
  } else {
    return empty_analysis();
  };

  let value_preview = if value.len() > 20 {
    format!("{}...", &value[..20])
  } else {
    value.clone()
  };

  // Parse attributes
  let mut flags = CookieFlags {
    secure: false,
    http_only: false,
    same_site: Option::None,
    max_age: Option::None,
    expires: Option::None,
    path: Option::None,
    domain: Option::None,
  };

  for part in parts.iter().skip(1) {
    let trimmed = part.trim();
    let lower = trimmed.to_lowercase();

    if lower == "secure" {
      flags.secure = true;
    } else if lower == "httponly" {
      flags.http_only = true;
    } else if let Some(eq) = trimmed.find('=') {
      let attr_name = trimmed[..eq].trim().to_lowercase();
      let attr_value = trimmed[eq + 1..].trim();

      match attr_name.as_str() {
        "samesite" => {
          flags.same_site = match attr_value.to_lowercase().as_str() {
            "strict" => Some(SameSitePolicy::Strict),
            "lax" => Some(SameSitePolicy::Lax),
            "none" => Some(SameSitePolicy::None),
            _ => Option::None,
          };
        }
        "max-age" => {
          flags.max_age = attr_value.parse().ok();
        }
        "expires" => {
          flags.expires = Some(attr_value.to_string());
        }
        "path" => {
          flags.path = Some(attr_value.to_string());
        }
        "domain" => {
          flags.domain = Some(attr_value.to_string());
        }
        _ => {}
      }
    }
  }

  // Detect issues
  let mut issues = Vec::new();
  check_issues(&name, &flags, is_https, &mut issues);

  CookieAnalysis {
    name,
    value_preview,
    flags,
    issues,
  }
}

/// Analyse all `Set-Cookie` headers found in a response.
///
/// `headers` is the full list of response headers as (name, value) pairs.
/// Only entries whose name matches `set-cookie` (case-insensitive) are
/// processed.
pub fn analyze_cookies(headers: &[(String, String)], is_https: bool) -> Vec<CookieAnalysis> {
  headers
    .iter()
    .filter(|(name, _)| name.to_lowercase() == "set-cookie")
    .map(|(_, value)| analyze_cookie(value, is_https))
    .collect()
}

// ---------------------------------------------------------------------------
// Issue detection
// ---------------------------------------------------------------------------

/// Cookie name patterns that suggest a session or authentication token.
const SESSION_PATTERNS: &[&str] = &[
  "session",
  "sess",
  "sid",
  "token",
  "auth",
  "jwt",
  "csrf",
  "xsrf",
  "login",
  "access_token",
  "refresh_token",
  "id_token",
];

fn looks_like_session(name: &str) -> bool {
  let lower = name.to_lowercase();
  SESSION_PATTERNS.iter().any(|p| lower.contains(p))
}

fn check_issues(name: &str, flags: &CookieFlags, is_https: bool, issues: &mut Vec<CookieIssue>) {
  // Missing Secure on HTTPS
  if is_https && !flags.secure {
    issues.push(CookieIssue {
      severity: CookieSeverity::High,
      description: format!(
        "Cookie '{}' served over HTTPS without Secure flag; may be sent over plain HTTP",
        name
      ),
    });
  }

  // Session-looking cookie without HttpOnly
  if looks_like_session(name) && !flags.http_only {
    issues.push(CookieIssue {
      severity: CookieSeverity::High,
      description: format!(
        "Cookie '{}' appears to be a session/auth token but lacks HttpOnly; accessible to JavaScript via XSS",
        name
      ),
    });
  }

  // SameSite=None without Secure
  if flags.same_site == Some(SameSitePolicy::None) && !flags.secure {
    issues.push(CookieIssue {
      severity: CookieSeverity::High,
      description: format!(
        "Cookie '{}' has SameSite=None without Secure; browsers will reject or allow CSRF",
        name
      ),
    });
  }

  // Missing SameSite
  if flags.same_site.is_none() {
    issues.push(CookieIssue {
      severity: CookieSeverity::Medium,
      description: format!(
        "Cookie '{}' has no SameSite attribute; defaults to Lax in modern browsers but older browsers allow CSRF",
        name
      ),
    });
  }

  // Overly long Max-Age (> 1 year = 31536000 seconds)
  if let Some(age) = flags.max_age {
    if age > 31_536_000 {
      issues.push(CookieIssue {
        severity: CookieSeverity::Low,
        description: format!(
          "Cookie '{}' has Max-Age > 1 year ({}s); enables long-term tracking",
          name, age
        ),
      });
    }
  }

  // Broad domain
  if let Some(ref domain) = flags.domain {
    if domain.starts_with('.') {
      issues.push(CookieIssue {
        severity: CookieSeverity::Medium,
        description: format!(
          "Cookie '{}' has a broad domain scope '{}'; accessible to all subdomains",
          name, domain
        ),
      });
    }
  }
}

fn empty_analysis() -> CookieAnalysis {
  CookieAnalysis {
    name: String::new(),
    value_preview: String::new(),
    flags: CookieFlags {
      secure: false,
      http_only: false,
      same_site: Option::None,
      max_age: Option::None,
      expires: Option::None,
      path: Option::None,
      domain: Option::None,
    },
    issues: Vec::new(),
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_simple_cookie() {
    let c = analyze_cookie("theme=dark", false);
    assert_eq!(c.name, "theme");
    assert_eq!(c.value_preview, "dark");
    assert!(!c.flags.secure);
    assert!(!c.flags.http_only);
  }

  #[test]
  fn test_parse_with_all_flags() {
    let header =
      "session_id=abc123; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; Path=/; Domain=example.com";
    let c = analyze_cookie(header, true);
    assert_eq!(c.name, "session_id");
    assert!(c.flags.secure);
    assert!(c.flags.http_only);
    assert_eq!(c.flags.same_site, Some(SameSitePolicy::Strict));
    assert_eq!(c.flags.max_age, Some(3600));
    assert_eq!(c.flags.path.as_deref(), Some("/"));
    assert_eq!(c.flags.domain.as_deref(), Some("example.com"));
  }

  #[test]
  fn test_missing_secure_on_https() {
    let c = analyze_cookie("id=xyz", true);
    let found = c
      .issues
      .iter()
      .any(|i| i.severity == CookieSeverity::High && i.description.contains("Secure flag"));
    assert!(found);
  }

  #[test]
  fn test_no_secure_issue_on_http() {
    // On plain HTTP we should NOT flag missing Secure
    let c = analyze_cookie("id=xyz", false);
    let found = c
      .issues
      .iter()
      .any(|i| i.description.contains("Secure flag"));
    assert!(!found);
  }

  #[test]
  fn test_missing_httponly_session() {
    let c = analyze_cookie("session_id=abc123; Secure", true);
    let found = c
      .issues
      .iter()
      .any(|i| i.severity == CookieSeverity::High && i.description.contains("HttpOnly"));
    assert!(found);
  }

  #[test]
  fn test_samesite_none_without_secure() {
    let c = analyze_cookie("id=abc; SameSite=None", true);
    let found = c
      .issues
      .iter()
      .any(|i| i.severity == CookieSeverity::High && i.description.contains("SameSite=None"));
    assert!(found);
  }

  #[test]
  fn test_samesite_none_with_secure() {
    let c = analyze_cookie("id=abc; SameSite=None; Secure", true);
    // Should NOT flag SameSite=None when Secure is set
    let found = c
      .issues
      .iter()
      .any(|i| i.description.contains("SameSite=None without Secure"));
    assert!(!found);
  }

  #[test]
  fn test_broad_domain() {
    let c = analyze_cookie("id=abc; Domain=.example.com", false);
    let found = c
      .issues
      .iter()
      .any(|i| i.severity == CookieSeverity::Medium && i.description.contains("broad domain"));
    assert!(found);
  }

  #[test]
  fn test_analyze_multiple_cookies() {
    let headers = vec![
      (
        "Set-Cookie".to_string(),
        "a=1; Secure; HttpOnly".to_string(),
      ),
      ("Set-Cookie".to_string(), "session=xyz".to_string()),
      ("Content-Type".to_string(), "text/html".to_string()),
    ];
    let results = analyze_cookies(&headers, true);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name, "a");
    assert_eq!(results[1].name, "session");
  }

  #[test]
  fn test_session_cookie_detection() {
    // Various session-like names should be detected
    for name in &["session", "sid", "auth_token", "jwt", "csrf_token"] {
      let header = format!("{}=value123", name);
      let c = analyze_cookie(&header, true);
      let httponly_issue = c.issues.iter().any(|i| i.description.contains("HttpOnly"));
      assert!(
        httponly_issue,
        "Expected HttpOnly warning for cookie '{}'",
        name
      );
    }
  }

  #[test]
  fn test_long_max_age() {
    // 2 years in seconds
    let c = analyze_cookie("track=1; Max-Age=63072000", false);
    let found = c
      .issues
      .iter()
      .any(|i| i.severity == CookieSeverity::Low && i.description.contains("Max-Age > 1 year"));
    assert!(found);
  }

  #[test]
  fn test_value_preview_truncation() {
    let long_value = "a".repeat(50);
    let header = format!("id={}", long_value);
    let c = analyze_cookie(&header, false);
    assert_eq!(c.value_preview.len(), 23); // 20 chars + "..."
    assert!(c.value_preview.ends_with("..."));
  }

  #[test]
  fn test_missing_samesite() {
    let c = analyze_cookie("id=abc", false);
    let found = c
      .issues
      .iter()
      .any(|i| i.severity == CookieSeverity::Medium && i.description.contains("no SameSite"));
    assert!(found);
  }
}
