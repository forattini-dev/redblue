#![allow(dead_code)]

/// CORS misconfiguration scanner
///
/// Detects common CORS misconfigurations by probing endpoints with crafted
/// Origin headers and analysing the Access-Control-Allow-* response headers.
/// Identifies critical issues such as reflected origins with credentials,
/// wildcard policies, and null origin allowance.
use crate::protocols::http::{HttpClient, HttpRequest};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How the server handles cross-origin requests.
#[derive(Debug, Clone, PartialEq)]
pub enum OriginPolicy {
  /// `Access-Control-Allow-Origin: *`
  Wildcard,
  /// Server echoes back whatever Origin it receives.
  Reflected,
  /// Server accepts `Origin: null`.
  NullAllowed,
  /// Server returns a fixed, specific origin.
  Specific(String),
  /// No CORS headers present in the response.
  None,
}

/// Risk level for a CORS finding.
#[derive(Debug, Clone, PartialEq)]
pub enum CorsRisk {
  Critical,
  High,
  Medium,
  Low,
  None,
}

impl std::fmt::Display for CorsRisk {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      CorsRisk::Critical => write!(f, "CRITICAL"),
      CorsRisk::High => write!(f, "HIGH"),
      CorsRisk::Medium => write!(f, "MEDIUM"),
      CorsRisk::Low => write!(f, "LOW"),
      CorsRisk::None => write!(f, "NONE"),
    }
  }
}

/// A single CORS issue.
#[derive(Debug, Clone)]
pub struct CorsIssue {
  pub severity: CorsRisk,
  pub description: String,
}

/// Full CORS scan result.
#[derive(Debug, Clone)]
pub struct CorsAnalysis {
  pub origin_policy: OriginPolicy,
  pub allows_credentials: bool,
  pub exposed_headers: Vec<String>,
  pub max_age: Option<u32>,
  pub issues: Vec<CorsIssue>,
  pub risk_level: CorsRisk,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Case-insensitive header lookup.
fn get_header(headers: &std::collections::HashMap<String, String>, name: &str) -> Option<String> {
  let lower = name.to_lowercase();
  for (k, v) in headers {
    if k.to_lowercase() == lower {
      return Some(v.clone());
    }
  }
  Option::None
}

/// Send a GET with a specific Origin and return the CORS-related headers.
struct CorsProbe {
  allow_origin: Option<String>,
  allow_credentials: Option<String>,
  expose_headers: Option<String>,
  max_age: Option<String>,
}

fn probe(client: &HttpClient, url: &str, origin: &str) -> Result<CorsProbe, String> {
  let mut req = HttpRequest::get(url);
  req.headers.insert("Origin".to_string(), origin.to_string());
  let resp = client.send(&req)?;

  Ok(CorsProbe {
    allow_origin: get_header(&resp.headers, "access-control-allow-origin"),
    allow_credentials: get_header(&resp.headers, "access-control-allow-credentials"),
    expose_headers: get_header(&resp.headers, "access-control-expose-headers"),
    max_age: get_header(&resp.headers, "access-control-max-age"),
  })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan a URL for CORS misconfigurations.
///
/// Sends multiple probes with different Origin values and analyses the
/// server's behaviour to determine the origin policy and any security issues.
pub fn scan_cors(url: &str) -> Result<CorsAnalysis, String> {
  let client = HttpClient::new();

  // Probe 1: arbitrary evil origin
  let evil_origin = "https://evil.example.com";
  let probe1 = probe(&client, url, evil_origin)?;

  // Probe 2: null origin
  let probe2 = probe(&client, url, "null")?;

  // Determine origin policy
  let origin_policy = determine_policy(&probe1, evil_origin, &probe2);

  // Credentials flag from first probe
  let allows_credentials = probe1
    .allow_credentials
    .as_deref()
    .map(|v| v.trim().eq_ignore_ascii_case("true"))
    .unwrap_or(false);

  // Exposed headers
  let exposed_headers: Vec<String> = probe1
    .expose_headers
    .as_deref()
    .map(|h| h.split(',').map(|s| s.trim().to_string()).collect())
    .unwrap_or_default();

  // Max-Age
  let max_age: Option<u32> = probe1
    .max_age
    .as_deref()
    .and_then(|v| v.trim().parse().ok());

  // Detect issues
  let mut issues = Vec::new();
  detect_issues(&origin_policy, allows_credentials, &mut issues);

  // Overall risk = highest severity among issues
  let risk_level = issues
    .iter()
    .map(|i| &i.severity)
    .max_by_key(|s| match s {
      CorsRisk::Critical => 4,
      CorsRisk::High => 3,
      CorsRisk::Medium => 2,
      CorsRisk::Low => 1,
      CorsRisk::None => 0,
    })
    .cloned()
    .unwrap_or(CorsRisk::None);

  Ok(CorsAnalysis {
    origin_policy,
    allows_credentials,
    exposed_headers,
    max_age,
    issues,
    risk_level,
  })
}

/// Analyse pre-fetched CORS headers without making live requests.
///
/// Useful when the caller already has response headers (e.g. from a crawler).
/// `acao` is the Access-Control-Allow-Origin value (if any), `acac` is the
/// Access-Control-Allow-Credentials value (if any), `sent_origin` is the
/// Origin that was sent in the request.
pub fn analyze_cors_headers(
  acao: Option<&str>,
  acac: Option<&str>,
  expose: Option<&str>,
  max_age_val: Option<&str>,
  sent_origin: &str,
) -> CorsAnalysis {
  let origin_policy = match acao {
    Some(v) if v.trim() == "*" => OriginPolicy::Wildcard,
    Some(v) if v.trim().eq_ignore_ascii_case("null") => OriginPolicy::NullAllowed,
    Some(v) if v.trim() == sent_origin => OriginPolicy::Reflected,
    Some(v) if !v.trim().is_empty() => OriginPolicy::Specific(v.trim().to_string()),
    _ => OriginPolicy::None,
  };

  let allows_credentials = acac
    .map(|v| v.trim().eq_ignore_ascii_case("true"))
    .unwrap_or(false);

  let exposed_headers: Vec<String> = expose
    .map(|h| h.split(',').map(|s| s.trim().to_string()).collect())
    .unwrap_or_default();

  let max_age: Option<u32> = max_age_val.and_then(|v| v.trim().parse().ok());

  let mut issues = Vec::new();
  detect_issues(&origin_policy, allows_credentials, &mut issues);

  let risk_level = issues
    .iter()
    .map(|i| &i.severity)
    .max_by_key(|s| match s {
      CorsRisk::Critical => 4,
      CorsRisk::High => 3,
      CorsRisk::Medium => 2,
      CorsRisk::Low => 1,
      CorsRisk::None => 0,
    })
    .cloned()
    .unwrap_or(CorsRisk::None);

  CorsAnalysis {
    origin_policy,
    allows_credentials,
    exposed_headers,
    max_age,
    issues,
    risk_level,
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn determine_policy(probe1: &CorsProbe, evil_origin: &str, probe2: &CorsProbe) -> OriginPolicy {
  match probe1.allow_origin.as_deref() {
    Some(v) if v.trim() == "*" => OriginPolicy::Wildcard,
    Some(v) if v.trim() == evil_origin => {
      // Server reflected the evil origin back -- that is the Reflected policy
      OriginPolicy::Reflected
    }
    Some(v) if !v.trim().is_empty() => {
      // Check null probe as well
      if let Some(null_val) = probe2.allow_origin.as_deref() {
        if null_val.trim().eq_ignore_ascii_case("null") {
          return OriginPolicy::NullAllowed;
        }
      }
      OriginPolicy::Specific(v.trim().to_string())
    }
    _ => {
      // No ACAO on first probe; still check null probe
      if let Some(null_val) = probe2.allow_origin.as_deref() {
        if null_val.trim().eq_ignore_ascii_case("null") {
          return OriginPolicy::NullAllowed;
        }
      }
      OriginPolicy::None
    }
  }
}

fn detect_issues(policy: &OriginPolicy, allows_credentials: bool, issues: &mut Vec<CorsIssue>) {
  match policy {
    OriginPolicy::Wildcard if allows_credentials => {
      issues.push(CorsIssue {
        severity: CorsRisk::Critical,
        description: "Wildcard Access-Control-Allow-Origin with credentials allows any site to read authenticated responses".into(),
      });
    }
    OriginPolicy::Reflected if allows_credentials => {
      issues.push(CorsIssue {
        severity: CorsRisk::Critical,
        description:
          "Origin reflection with credentials allows any site to read authenticated responses"
            .into(),
      });
    }
    OriginPolicy::NullAllowed if allows_credentials => {
      issues.push(CorsIssue {
        severity: CorsRisk::High,
        description: "null origin allowed with credentials is exploitable via sandboxed iframes"
          .into(),
      });
    }
    OriginPolicy::Wildcard => {
      issues.push(CorsIssue {
        severity: CorsRisk::Medium,
        description: "Wildcard Access-Control-Allow-Origin exposes responses to any origin".into(),
      });
    }
    OriginPolicy::Reflected => {
      issues.push(CorsIssue {
        severity: CorsRisk::Medium,
        description: "Origin reflection without credentials still indicates misconfiguration"
          .into(),
      });
    }
    OriginPolicy::NullAllowed => {
      issues.push(CorsIssue {
        severity: CorsRisk::Medium,
        description: "null origin allowed can be exploited via sandboxed iframes".into(),
      });
    }
    OriginPolicy::Specific(_) | OriginPolicy::None => {
      // Specific origin or no CORS at all -- no issue
    }
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  // Helper to build analysis from raw header values without network I/O.
  fn make(acao: Option<&str>, acac: Option<&str>, origin: &str) -> CorsAnalysis {
    analyze_cors_headers(acao, acac, None, None, origin)
  }

  #[test]
  fn test_detect_wildcard() {
    let a = make(Some("*"), None, "https://evil.example.com");
    assert_eq!(a.origin_policy, OriginPolicy::Wildcard);
    assert!(!a.issues.is_empty());
  }

  #[test]
  fn test_detect_reflected_origin() {
    let origin = "https://evil.example.com";
    let a = make(Some(origin), None, origin);
    assert_eq!(a.origin_policy, OriginPolicy::Reflected);
  }

  #[test]
  fn test_detect_null_origin() {
    let a = make(Some("null"), None, "https://evil.example.com");
    assert_eq!(a.origin_policy, OriginPolicy::NullAllowed);
  }

  #[test]
  fn test_wildcard_with_credentials() {
    let a = make(Some("*"), Some("true"), "https://evil.example.com");
    assert_eq!(a.risk_level, CorsRisk::Critical);
    assert!(a.issues.iter().any(|i| i.severity == CorsRisk::Critical));
  }

  #[test]
  fn test_reflected_with_credentials() {
    let origin = "https://evil.example.com";
    let a = make(Some(origin), Some("true"), origin);
    assert_eq!(a.risk_level, CorsRisk::Critical);
  }

  #[test]
  fn test_no_cors_headers() {
    let a = make(None, None, "https://evil.example.com");
    assert_eq!(a.origin_policy, OriginPolicy::None);
    assert!(a.issues.is_empty());
    assert_eq!(a.risk_level, CorsRisk::None);
  }

  #[test]
  fn test_specific_origin() {
    let a = make(
      Some("https://app.example.com"),
      None,
      "https://evil.example.com",
    );
    assert!(matches!(a.origin_policy, OriginPolicy::Specific(_)));
    assert!(a.issues.is_empty());
  }

  #[test]
  fn test_risk_critical() {
    let origin = "https://evil.example.com";
    let a = make(Some(origin), Some("true"), origin);
    assert_eq!(a.risk_level, CorsRisk::Critical);
  }

  #[test]
  fn test_risk_none() {
    let a = make(None, None, "https://evil.example.com");
    assert_eq!(a.risk_level, CorsRisk::None);
  }

  #[test]
  fn test_exposed_headers_parsing() {
    let a = analyze_cors_headers(
      Some("*"),
      None,
      Some("X-Custom, X-Request-Id, Content-Length"),
      None,
      "https://evil.example.com",
    );
    assert_eq!(a.exposed_headers.len(), 3);
    assert!(a.exposed_headers.contains(&"X-Custom".to_string()));
    assert!(a.exposed_headers.contains(&"X-Request-Id".to_string()));
  }

  #[test]
  fn test_max_age_parsing() {
    let a = analyze_cors_headers(
      Some("*"),
      None,
      None,
      Some("86400"),
      "https://evil.example.com",
    );
    assert_eq!(a.max_age, Some(86400));
  }

  #[test]
  fn test_null_with_credentials() {
    let a = make(Some("null"), Some("true"), "https://evil.example.com");
    assert_eq!(a.origin_policy, OriginPolicy::NullAllowed);
    assert_eq!(a.risk_level, CorsRisk::High);
    assert!(a
      .issues
      .iter()
      .any(|i| i.description.contains("sandboxed iframes")));
  }
}
