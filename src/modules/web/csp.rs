#![allow(dead_code)]

/// Content-Security-Policy parser and analyzer
///
/// Parses CSP header values into structured directives and analyzes them
/// for common security misconfigurations. Detects unsafe-inline, unsafe-eval,
/// wildcards, missing directives, and grades the overall policy strength.

/// Severity level for a CSP issue.
#[derive(Debug, Clone, PartialEq)]
pub enum CspSeverity {
  Critical,
  High,
  Medium,
  Low,
  Info,
}

impl CspSeverity {
  /// Numeric weight used for grade calculation (higher = worse).
  fn weight(&self) -> u32 {
    match self {
      CspSeverity::Critical => 40,
      CspSeverity::High => 20,
      CspSeverity::Medium => 10,
      CspSeverity::Low => 5,
      CspSeverity::Info => 0,
    }
  }
}

impl std::fmt::Display for CspSeverity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      CspSeverity::Critical => write!(f, "CRITICAL"),
      CspSeverity::High => write!(f, "HIGH"),
      CspSeverity::Medium => write!(f, "MEDIUM"),
      CspSeverity::Low => write!(f, "LOW"),
      CspSeverity::Info => write!(f, "INFO"),
    }
  }
}

/// A single CSP directive (e.g. `script-src 'self' https:`).
#[derive(Debug, Clone)]
pub struct CspDirective {
  /// Directive name, e.g. "script-src", "default-src".
  pub name: String,
  /// Source values, e.g. ["'self'", "https:", "*.example.com"].
  pub values: Vec<String>,
}

/// A single issue found during CSP analysis.
#[derive(Debug, Clone)]
pub struct CspIssue {
  pub severity: CspSeverity,
  /// Which directive triggered the issue (or empty for missing directives).
  pub directive: String,
  pub description: String,
}

/// Full CSP analysis result.
#[derive(Debug, Clone)]
pub struct CspAnalysis {
  pub raw_policy: String,
  pub directives: Vec<CspDirective>,
  pub issues: Vec<CspIssue>,
  /// Overall grade: A (best) through F (worst).
  pub grade: char,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a raw CSP header value into a list of directives.
///
/// Each directive is separated by `;`. The first token in each directive is
/// the name; subsequent tokens are source values. All values are normalised
/// to lowercase.
pub fn parse_csp(header_value: &str) -> Vec<CspDirective> {
  header_value
    .split(';')
    .filter_map(|part| {
      let trimmed = part.trim();
      if trimmed.is_empty() {
        return None;
      }
      let mut tokens = trimmed.split_whitespace();
      let name = tokens.next()?.to_lowercase();
      let values: Vec<String> = tokens.map(|t| t.to_lowercase()).collect();
      Some(CspDirective { name, values })
    })
    .collect()
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

/// Return `true` if the given directive name is present in the list.
fn has_directive(directives: &[CspDirective], name: &str) -> bool {
  directives.iter().any(|d| d.name == name)
}

/// Return the effective sources for a directive, falling back to `default-src`.
fn effective_values<'a>(directives: &'a [CspDirective], name: &str) -> &'a [String] {
  for d in directives {
    if d.name == name {
      return &d.values;
    }
  }
  // Fall back to default-src
  for d in directives {
    if d.name == "default-src" {
      return &d.values;
    }
  }
  &[]
}

/// Check whether a value list contains a specific token.
fn values_contain(values: &[String], token: &str) -> bool {
  values.iter().any(|v| v == token)
}

// ---------------------------------------------------------------------------
// Core analyser
// ---------------------------------------------------------------------------

/// Analyze a CSP header value for security issues and produce a graded result.
///
/// If `header_value` is empty the result is grade F with a single Critical
/// issue indicating the absence of a CSP.
pub fn analyze_csp(header_value: &str) -> CspAnalysis {
  let trimmed = header_value.trim();

  // Empty / missing CSP
  if trimmed.is_empty() {
    return CspAnalysis {
      raw_policy: String::new(),
      directives: Vec::new(),
      issues: vec![CspIssue {
        severity: CspSeverity::Critical,
        directive: String::new(),
        description: "No Content-Security-Policy header present".into(),
      }],
      grade: 'F',
    };
  }

  let directives = parse_csp(trimmed);
  let mut issues: Vec<CspIssue> = Vec::new();

  // --- unsafe-inline in script-src / default-src ---
  for name in &["script-src", "default-src"] {
    let vals = effective_values(&directives, name);
    if values_contain(vals, "'unsafe-inline'") {
      issues.push(CspIssue {
        severity: CspSeverity::Critical,
        directive: name.to_string(),
        description: format!(
          "'unsafe-inline' in {} allows inline scripts, enabling XSS attacks",
          name
        ),
      });
    }
  }

  // --- unsafe-eval in script-src / default-src ---
  for name in &["script-src", "default-src"] {
    let vals = effective_values(&directives, name);
    if values_contain(vals, "'unsafe-eval'") {
      issues.push(CspIssue {
        severity: CspSeverity::Critical,
        directive: name.to_string(),
        description: format!(
          "'unsafe-eval' in {} allows eval() and similar, enabling XSS attacks",
          name
        ),
      });
    }
  }

  // --- Wildcard in any directive ---
  for d in &directives {
    if values_contain(&d.values, "*") {
      issues.push(CspIssue {
        severity: CspSeverity::High,
        directive: d.name.clone(),
        description: format!("Wildcard '*' in {} allows loading from any source", d.name),
      });
    }
  }

  // --- data: in script-src ---
  {
    let vals = effective_values(&directives, "script-src");
    if values_contain(vals, "data:") {
      issues.push(CspIssue {
        severity: CspSeverity::High,
        directive: "script-src".into(),
        description: "'data:' URI in script-src allows arbitrary script injection".into(),
      });
    }
  }

  // --- blob: in script-src ---
  {
    let vals = effective_values(&directives, "script-src");
    if values_contain(vals, "blob:") {
      issues.push(CspIssue {
        severity: CspSeverity::High,
        directive: "script-src".into(),
        description: "'blob:' URI in script-src allows scripts loaded from blob URLs".into(),
      });
    }
  }

  // --- Missing base-uri ---
  if !has_directive(&directives, "base-uri") {
    issues.push(CspIssue {
      severity: CspSeverity::Medium,
      directive: "base-uri".into(),
      description: "Missing base-uri directive allows <base> tag injection".into(),
    });
  }

  // --- Missing frame-ancestors ---
  if !has_directive(&directives, "frame-ancestors") {
    issues.push(CspIssue {
      severity: CspSeverity::Medium,
      directive: "frame-ancestors".into(),
      description: "Missing frame-ancestors allows clickjacking via iframes".into(),
    });
  }

  // --- Missing form-action ---
  if !has_directive(&directives, "form-action") {
    issues.push(CspIssue {
      severity: CspSeverity::Medium,
      directive: "form-action".into(),
      description: "Missing form-action allows form submission to any origin".into(),
    });
  }

  // --- http: sources (mixed content) ---
  for d in &directives {
    if values_contain(&d.values, "http:") {
      issues.push(CspIssue {
        severity: CspSeverity::Medium,
        directive: d.name.clone(),
        description: format!(
          "http: source in {} allows mixed content on HTTPS pages",
          d.name
        ),
      });
    }
  }

  // --- Missing default-src ---
  if !has_directive(&directives, "default-src") {
    issues.push(CspIssue {
      severity: CspSeverity::Low,
      directive: "default-src".into(),
      description: "Missing default-src means no fallback policy for unlisted directives".into(),
    });
  }

  // --- Reporting configured (informational) ---
  if has_directive(&directives, "report-uri") || has_directive(&directives, "report-to") {
    issues.push(CspIssue {
      severity: CspSeverity::Info,
      directive: if has_directive(&directives, "report-to") {
        "report-to"
      } else {
        "report-uri"
      }
      .into(),
      description: "CSP reporting is configured".into(),
    });
  }

  let grade = compute_grade(&directives, &issues);

  CspAnalysis {
    raw_policy: trimmed.to_string(),
    directives,
    issues,
    grade,
  }
}

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

fn compute_grade(directives: &[CspDirective], issues: &[CspIssue]) -> char {
  // F: no CSP handled earlier; also F when both unsafe-inline AND unsafe-eval.
  let has_unsafe_inline = issues
    .iter()
    .any(|i| i.description.contains("'unsafe-inline'"));
  let has_unsafe_eval = issues
    .iter()
    .any(|i| i.description.contains("'unsafe-eval'"));

  if has_unsafe_inline && has_unsafe_eval {
    return 'F';
  }

  // D: unsafe-inline or unsafe-eval present
  if has_unsafe_inline || has_unsafe_eval {
    return 'D';
  }

  // Sum non-info issue weights
  let penalty: u32 = issues
    .iter()
    .filter(|i| i.severity != CspSeverity::Info)
    .map(|i| i.severity.weight())
    .sum();

  // A: no unsafe patterns, no wildcards, has base-uri + frame-ancestors + form-action
  let has_critical_directives = has_directive(directives, "base-uri")
    && has_directive(directives, "frame-ancestors")
    && has_directive(directives, "form-action");

  if penalty == 0 && has_critical_directives {
    return 'A';
  }

  // B: penalty low, no high+ issues
  let has_high_or_above = issues
    .iter()
    .any(|i| matches!(i.severity, CspSeverity::Critical | CspSeverity::High));

  if !has_high_or_above && penalty <= 30 {
    return 'B';
  }

  // C: wildcards or missing important directives but no unsafe-*
  'C'
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_simple_csp() {
    let directives = parse_csp("default-src 'self'");
    assert_eq!(directives.len(), 1);
    assert_eq!(directives[0].name, "default-src");
    assert_eq!(directives[0].values, vec!["'self'"]);
  }

  #[test]
  fn test_parse_multiple_directives() {
    let directives = parse_csp(
      "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'unsafe-inline'",
    );
    assert_eq!(directives.len(), 3);
    assert_eq!(directives[0].name, "default-src");
    assert_eq!(directives[1].name, "script-src");
    assert_eq!(
      directives[1].values,
      vec!["'self'", "https://cdn.example.com"]
    );
    assert_eq!(directives[2].name, "style-src");
    assert_eq!(directives[2].values, vec!["'unsafe-inline'"]);
  }

  #[test]
  fn test_parse_trailing_semicolon() {
    let directives = parse_csp("default-src 'none';");
    assert_eq!(directives.len(), 1);
    assert_eq!(directives[0].name, "default-src");
  }

  #[test]
  fn test_detect_unsafe_inline() {
    let result = analyze_csp("default-src 'self'; script-src 'unsafe-inline'");
    let critical = result
      .issues
      .iter()
      .filter(|i| i.severity == CspSeverity::Critical)
      .any(|i| i.description.contains("'unsafe-inline'"));
    assert!(critical);
  }

  #[test]
  fn test_detect_unsafe_eval() {
    let result = analyze_csp("default-src 'self'; script-src 'unsafe-eval'");
    let critical = result
      .issues
      .iter()
      .filter(|i| i.severity == CspSeverity::Critical)
      .any(|i| i.description.contains("'unsafe-eval'"));
    assert!(critical);
  }

  #[test]
  fn test_detect_wildcard() {
    let result = analyze_csp("default-src *");
    let high = result
      .issues
      .iter()
      .any(|i| i.severity == CspSeverity::High && i.description.contains("Wildcard"));
    assert!(high);
  }

  #[test]
  fn test_detect_missing_base_uri() {
    let result = analyze_csp("default-src 'self'");
    let found = result
      .issues
      .iter()
      .any(|i| i.directive == "base-uri" && i.severity == CspSeverity::Medium);
    assert!(found);
  }

  #[test]
  fn test_detect_missing_frame_ancestors() {
    let result = analyze_csp("default-src 'self'");
    let found = result
      .issues
      .iter()
      .any(|i| i.directive == "frame-ancestors" && i.severity == CspSeverity::Medium);
    assert!(found);
  }

  #[test]
  fn test_grade_a() {
    let result = analyze_csp(
      "default-src 'none'; script-src 'self'; style-src 'self'; \
       img-src 'self'; base-uri 'self'; frame-ancestors 'none'; \
       form-action 'self'; report-to csp-endpoint",
    );
    assert_eq!(result.grade, 'A');
  }

  #[test]
  fn test_grade_f_no_policy() {
    let result = analyze_csp("");
    assert_eq!(result.grade, 'F');
    assert!(result
      .issues
      .iter()
      .any(|i| i.description.contains("No Content-Security-Policy")));
  }

  #[test]
  fn test_grade_f_both_unsafe() {
    let result = analyze_csp("default-src 'self' 'unsafe-inline' 'unsafe-eval'");
    assert_eq!(result.grade, 'F');
  }

  #[test]
  fn test_grade_d_unsafe_inline() {
    let result = analyze_csp(
      "default-src 'self'; script-src 'self' 'unsafe-inline'; \
       base-uri 'self'; frame-ancestors 'self'; form-action 'self'",
    );
    assert_eq!(result.grade, 'D');
  }

  #[test]
  fn test_data_uri_detection() {
    let result = analyze_csp("default-src 'self'; script-src 'self' data:");
    let found = result
      .issues
      .iter()
      .any(|i| i.severity == CspSeverity::High && i.description.contains("data:"));
    assert!(found);
  }

  #[test]
  fn test_blob_uri_detection() {
    let result = analyze_csp("default-src 'self'; script-src 'self' blob:");
    let found = result
      .issues
      .iter()
      .any(|i| i.severity == CspSeverity::High && i.description.contains("blob:"));
    assert!(found);
  }

  #[test]
  fn test_report_info() {
    let result = analyze_csp("default-src 'self'; report-uri /csp-report");
    let found = result
      .issues
      .iter()
      .any(|i| i.severity == CspSeverity::Info && i.description.contains("reporting"));
    assert!(found);
  }

  #[test]
  fn test_real_github_csp() {
    // Simplified version of a real GitHub CSP
    let csp = "default-src 'none'; base-uri 'self'; connect-src 'self' \
               uploads.github.com; font-src github.githubassets.com; \
               form-action 'self' github.com; frame-ancestors 'none'; \
               frame-src github.com; img-src 'self' data: github.githubassets.com; \
               script-src github.githubassets.com; style-src 'unsafe-inline' \
               github.githubassets.com";
    let result = analyze_csp(csp);

    // GitHub uses unsafe-inline in style-src, not script-src
    assert!(!result.directives.is_empty());
    assert!(result.directives.iter().any(|d| d.name == "default-src"));
    assert!(result
      .directives
      .iter()
      .any(|d| d.name == "frame-ancestors"));
    assert!(result.directives.iter().any(|d| d.name == "base-uri"));
    // script-src should NOT have unsafe-inline
    let script_issues: Vec<_> = result
      .issues
      .iter()
      .filter(|i| i.directive == "script-src" && i.description.contains("'unsafe-inline'"))
      .collect();
    assert!(script_issues.is_empty());
  }

  #[test]
  fn test_mixed_content_detection() {
    let result = analyze_csp("default-src 'self'; script-src http: 'self'");
    let found = result
      .issues
      .iter()
      .any(|i| i.severity == CspSeverity::Medium && i.description.contains("mixed content"));
    assert!(found);
  }
}
