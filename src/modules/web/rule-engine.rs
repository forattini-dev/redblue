/// Data-driven technology fingerprinting rule engine
///
/// Replaces hardcoded detection patterns with a JSON rules database
/// embedded at compile time via `include_str!`. Inspired by Wappalyzer's
/// approach but simplified for zero-dependency operation.
///
/// The rule engine loads technology detection rules from `fingerprint-rules.json`
/// and matches them against HTTP response data (headers, body, cookies).
///
/// NO external dependencies - pure Rust implementation using crate::utils::json.
use crate::utils::json::{parse_json, JsonValue};
use std::collections::HashMap;

/// Embedded rules database - compiled into the binary
const RULES_JSON: &str = include_str!("fingerprint-rules.json");

/// A technology detection rule loaded from the JSON database
#[derive(Debug, Clone)]
pub struct TechRule {
  pub name: String,
  pub categories: Vec<String>,
  pub headers: HashMap<String, String>,
  pub meta: HashMap<String, String>,
  pub html: Vec<String>,
  pub cookies: HashMap<String, String>,
  pub scripts: Vec<String>,
  pub implies: Vec<String>,
  pub website: String,
}

/// A detected technology from rule matching
#[derive(Debug, Clone)]
pub struct RuleMatch {
  pub name: String,
  pub categories: Vec<String>,
  pub version: Option<String>,
  pub confidence: u8,
  pub matched_by: Vec<String>,
  pub implies: Vec<String>,
  pub website: String,
}

/// Load all technology detection rules from the embedded JSON database.
///
/// Parses `fingerprint-rules.json` at runtime (data is embedded at compile time).
/// Returns an empty Vec if parsing fails, so callers can fall back to the
/// hardcoded fingerprinter.
pub fn load_rules() -> Vec<TechRule> {
  let json = match parse_json(RULES_JSON) {
    Ok(v) => v,
    Err(_) => return Vec::new(),
  };

  let technologies = match json.get("technologies") {
    Some(t) => t,
    None => return Vec::new(),
  };

  let entries = match technologies.as_object() {
    Some(e) => e,
    None => return Vec::new(),
  };

  let mut rules = Vec::with_capacity(entries.len());

  for (name, value) in entries {
    if let Some(rule) = parse_tech_rule(name, value) {
      rules.push(rule);
    }
  }

  rules
}

/// Parse a single technology rule from a JSON object.
fn parse_tech_rule(name: &str, value: &JsonValue) -> Option<TechRule> {
  let categories = extract_string_array(value.get("cats")?);
  let headers = extract_string_map(value.get("headers"));
  let meta = extract_string_map(value.get("meta"));
  let html = extract_string_array_opt(value.get("html"));
  let cookies = extract_string_map(value.get("cookies"));
  let scripts = extract_string_array_opt(value.get("scripts"));
  let implies = extract_string_array_opt(value.get("implies"));
  let website = value
    .get("website")
    .and_then(|v| v.as_str())
    .unwrap_or("")
    .to_string();

  Some(TechRule {
    name: name.to_string(),
    categories,
    headers,
    meta,
    html,
    cookies,
    scripts,
    implies,
    website,
  })
}

/// Extract a Vec<String> from a JsonValue::Array of strings.
fn extract_string_array(value: &JsonValue) -> Vec<String> {
  match value.as_array() {
    Some(items) => items
      .iter()
      .filter_map(|v| v.as_str().map(|s| s.to_string()))
      .collect(),
    None => Vec::new(),
  }
}

/// Extract a Vec<String> from an optional JsonValue.
fn extract_string_array_opt(value: Option<&JsonValue>) -> Vec<String> {
  match value {
    Some(v) => extract_string_array(v),
    None => Vec::new(),
  }
}

/// Extract a HashMap<String, String> from a JsonValue::Object.
fn extract_string_map(value: Option<&JsonValue>) -> HashMap<String, String> {
  let mut map = HashMap::new();
  if let Some(obj) = value.and_then(|v| v.as_object()) {
    for (k, v) in obj {
      let val = v.as_str().unwrap_or("").to_string();
      map.insert(k.clone(), val);
    }
  }
  map
}

/// Match all rules against HTTP response data and return detected technologies.
///
/// # Arguments
/// * `rules` - Loaded technology rules from `load_rules()`
/// * `headers` - HTTP response headers (name -> value)
/// * `body` - HTTP response body as string
/// * `cookies` - Raw Set-Cookie header values
///
/// # Returns
/// A deduplicated list of `RuleMatch` results, sorted by confidence descending.
/// Implied technologies are appended with 50% confidence.
pub fn match_rules(
  rules: &[TechRule],
  headers: &HashMap<String, String>,
  body: &str,
  cookies: &[String],
) -> Vec<RuleMatch> {
  let body_lower = body.to_lowercase();
  let mut matches: HashMap<String, RuleMatch> = HashMap::new();

  for rule in rules {
    if let Some(m) = match_single_rule(rule, headers, body, &body_lower, cookies) {
      // Merge: keep higher confidence, accumulate matched_by
      match matches.get_mut(&m.name) {
        Some(existing) => {
          if m.confidence > existing.confidence {
            existing.confidence = m.confidence;
          }
          for reason in &m.matched_by {
            if !existing.matched_by.contains(reason) {
              existing.matched_by.push(reason.clone());
            }
          }
          // Prefer a version if we did not have one
          if existing.version.is_none() && m.version.is_some() {
            existing.version = m.version.clone();
          }
        }
        None => {
          matches.insert(m.name.clone(), m);
        }
      }
    }
  }

  // Collect implied technologies
  let implied: Vec<(String, Vec<String>, String)> = matches
    .values()
    .flat_map(|m| {
      m.implies
        .iter()
        .map(|imp| (imp.clone(), m.categories.clone(), m.website.clone()))
    })
    .collect();

  for (imp_name, _parent_cats, _parent_website) in &implied {
    if !matches.contains_key(imp_name.as_str()) {
      // Find the implied technology's categories from the rules
      let (cats, website) = rules
        .iter()
        .find(|r| r.name == *imp_name)
        .map(|r| (r.categories.clone(), r.website.clone()))
        .unwrap_or_else(|| (vec!["other".to_string()], String::new()));

      matches.insert(
        imp_name.clone(),
        RuleMatch {
          name: imp_name.clone(),
          categories: cats,
          version: None,
          confidence: 50,
          matched_by: vec![format!("implied")],
          implies: Vec::new(),
          website,
        },
      );
    }
  }

  let mut results: Vec<RuleMatch> = matches.into_values().collect();
  results.sort_by(|a, b| {
    b.confidence
      .cmp(&a.confidence)
      .then_with(|| a.name.cmp(&b.name))
  });
  results
}

/// Match a single rule against the response data.
/// Returns None if no detection methods matched.
fn match_single_rule(
  rule: &TechRule,
  headers: &HashMap<String, String>,
  body: &str,
  body_lower: &str,
  cookies: &[String],
) -> Option<RuleMatch> {
  let mut matched_by: Vec<String> = Vec::new();
  let mut total_methods: u32 = 0;
  let mut matched_methods: u32 = 0;
  let mut version: Option<String> = None;

  // --- Header matching ---
  if !rule.headers.is_empty() {
    total_methods += 1;
    let mut header_hit = false;
    for (hdr_name, hdr_pattern) in &rule.headers {
      // Case-insensitive header lookup
      if let Some(hdr_value) = find_header_value(headers, hdr_name) {
        if hdr_pattern.is_empty() {
          // Existence check only
          header_hit = true;
          matched_by.push(format!("header:{}", hdr_name));
        } else {
          let hdr_lower = hdr_value.to_lowercase();
          let pat_lower = hdr_pattern.to_lowercase();
          if hdr_lower.contains(&pat_lower) {
            header_hit = true;
            matched_by.push(format!("header:{}", hdr_name));
            if version.is_none() {
              version = extract_version_near(&hdr_value, &hdr_pattern);
            }
          }
        }
      }
    }
    if header_hit {
      matched_methods += 1;
    }
  }

  // --- Meta tag matching ---
  if !rule.meta.is_empty() {
    total_methods += 1;
    let mut meta_hit = false;
    for (meta_name, meta_pattern) in &rule.meta {
      if let Some(content) = extract_meta_content(body, body_lower, meta_name) {
        if meta_pattern.is_empty() {
          meta_hit = true;
          matched_by.push(format!("meta:{}", meta_name));
        } else {
          let content_lower = content.to_lowercase();
          let pat_lower = meta_pattern.to_lowercase();
          if content_lower.contains(&pat_lower) {
            meta_hit = true;
            matched_by.push(format!("meta:{}", meta_name));
            if version.is_none() {
              version = extract_version_from_text(&content);
            }
          }
        }
      }
    }
    if meta_hit {
      matched_methods += 1;
    }
  }

  // --- HTML body matching ---
  if !rule.html.is_empty() {
    total_methods += 1;
    let mut html_hit = false;
    for pattern in &rule.html {
      let pat_lower = pattern.to_lowercase();
      if body_lower.contains(&pat_lower) {
        html_hit = true;
        matched_by.push(format!("html:{}", pattern));
      }
    }
    if html_hit {
      matched_methods += 1;
    }
  }

  // --- Cookie matching ---
  if !rule.cookies.is_empty() {
    total_methods += 1;
    let mut cookie_hit = false;
    for (cookie_name, _cookie_pattern) in &rule.cookies {
      // Check Set-Cookie headers from the raw cookies list
      let cn_lower = cookie_name.to_lowercase();
      for raw_cookie in cookies {
        let rc_lower = raw_cookie.to_lowercase();
        if rc_lower.starts_with(&cn_lower) || rc_lower.contains(&format!("{}=", cn_lower)) {
          cookie_hit = true;
          matched_by.push(format!("cookie:{}", cookie_name));
          break;
        }
      }
      // Also check if any header named Set-Cookie contains the cookie name
      if !cookie_hit {
        if let Some(set_cookie) = find_header_value(headers, "Set-Cookie") {
          if set_cookie.to_lowercase().contains(&cn_lower) {
            cookie_hit = true;
            matched_by.push(format!("cookie:{}", cookie_name));
          }
        }
      }
    }
    if cookie_hit {
      matched_methods += 1;
    }
  }

  // --- Script matching ---
  if !rule.scripts.is_empty() {
    total_methods += 1;
    let mut script_hit = false;
    for pattern in &rule.scripts {
      let pat_lower = pattern.to_lowercase();
      // Look for <script ... src="...pattern..."> in body
      if body_lower.contains(&pat_lower) {
        script_hit = true;
        matched_by.push(format!("script:{}", pattern));
        if version.is_none() {
          // Try to extract version from script src (e.g., lib@1.2.3 or lib-1.2.3)
          if let Some(pos) = body_lower.find(&pat_lower) {
            let search_region = &body[pos..std::cmp::min(pos + pat_lower.len() + 30, body.len())];
            version = extract_version_from_text(search_region);
          }
        }
      }
    }
    if script_hit {
      matched_methods += 1;
    }
  }

  if matched_methods == 0 {
    return None;
  }

  // Confidence: percentage of detection methods that matched
  let confidence = if total_methods > 0 {
    ((matched_methods as u16 * 100) / total_methods as u16) as u8
  } else {
    0
  };

  Some(RuleMatch {
    name: rule.name.clone(),
    categories: rule.categories.clone(),
    version,
    confidence,
    matched_by,
    implies: rule.implies.clone(),
    website: rule.website.clone(),
  })
}

/// Case-insensitive header lookup.
/// HTTP headers are case-insensitive per RFC 7230.
fn find_header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a String> {
  let name_lower = name.to_lowercase();
  for (k, v) in headers {
    if k.to_lowercase() == name_lower {
      return Some(v);
    }
  }
  None
}

/// Extract the content attribute from a <meta> tag by name.
/// Handles both `name="X" content="Y"` and `content="Y" name="X"` orderings.
fn extract_meta_content(body: &str, body_lower: &str, meta_name: &str) -> Option<String> {
  let meta_lower = meta_name.to_lowercase();
  let search = format!("name=\"{}\"", meta_lower);

  let mut search_start = 0;
  while let Some(pos) = body_lower[search_start..].find(&search) {
    let abs_pos = search_start + pos;

    // Find the enclosing <meta ...> tag boundaries
    let tag_start = body_lower[..abs_pos].rfind('<')?;
    let tag_end_offset = body_lower[tag_start..].find('>')?;
    let tag = &body[tag_start..tag_start + tag_end_offset + 1];

    // Extract content="..." from the tag
    let tag_lower = tag.to_lowercase();
    if let Some(content_pos) = tag_lower.find("content=\"") {
      let value_start = content_pos + 9;
      if let Some(value_end) = tag[value_start..].find('"') {
        return Some(tag[value_start..value_start + value_end].to_string());
      }
    }
    // Also handle content='...'
    if let Some(content_pos) = tag_lower.find("content='") {
      let value_start = content_pos + 9;
      if let Some(value_end) = tag[value_start..].find('\'') {
        return Some(tag[value_start..value_start + value_end].to_string());
      }
    }

    search_start = abs_pos + search.len();
  }

  None
}

/// Extract a version number (X.Y or X.Y.Z pattern) from text.
/// Scans for the first sequence matching digits and dots that has at least one dot.
fn extract_version_from_text(text: &str) -> Option<String> {
  let chars: Vec<char> = text.chars().collect();
  let mut i = 0;
  while i < chars.len() {
    if chars[i].is_ascii_digit() {
      let start = i;
      while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
        i += 1;
      }
      let candidate = &text[start..i];
      let trimmed = candidate.trim_end_matches('.');
      if trimmed.contains('.') && trimmed.len() >= 3 {
        return Some(trimmed.to_string());
      }
    } else {
      i += 1;
    }
  }
  None
}

/// Extract a version that appears near a pattern match in text.
/// For patterns like "nginx/1.18.0" or "PHP/8.1.2", the version follows
/// the pattern with a separator (/, space, @, -).
fn extract_version_near(text: &str, pattern: &str) -> Option<String> {
  let text_lower = text.to_lowercase();
  let pat_lower = pattern.to_lowercase();
  if let Some(pos) = text_lower.find(&pat_lower) {
    let after = pos + pat_lower.len();
    if after < text.len() {
      let remaining = &text[after..];
      // Skip separator character
      let skip = match remaining.as_bytes().first() {
        Some(b'/' | b'@' | b'-' | b' ') => 1,
        _ => 0,
      };
      return extract_version_from_text(&remaining[skip..]);
    }
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_load_rules_count() {
    let rules = load_rules();
    assert!(
      rules.len() >= 200,
      "Expected at least 200 rules, got {}",
      rules.len()
    );
  }

  #[test]
  fn test_match_wordpress() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert(
      "X-Powered-By".to_string(),
      "WordPress something".to_string(),
    );

    let body = r#"
      <html>
        <head>
          <meta name="generator" content="WordPress 6.4.2">
        </head>
        <body>
          <link rel="stylesheet" href="/wp-content/themes/flavor/style.css">
          <script src="/wp-includes/js/jquery.js"></script>
        </body>
      </html>
    "#;

    let results = match_rules(&rules, &headers, body, &[]);
    let wp = results.iter().find(|m| m.name == "WordPress");
    assert!(wp.is_some(), "WordPress should be detected");

    let wp = wp.unwrap();
    assert!(
      wp.confidence >= 75,
      "WordPress confidence should be >= 75, got {}",
      wp.confidence
    );
    assert!(!wp.matched_by.is_empty(), "Should have matched_by entries");

    // WordPress implies PHP and MySQL
    let php = results.iter().find(|m| m.name == "PHP");
    assert!(php.is_some(), "PHP should be implied by WordPress");
  }

  #[test]
  fn test_match_react() {
    let rules = load_rules();
    let headers = HashMap::new();

    let body = r#"
      <html>
        <body>
          <div id="root" data-reactroot>
            <div data-react-helmet="true"></div>
          </div>
          <script src="/static/js/react-dom.production.min.js"></script>
        </body>
      </html>
    "#;

    let results = match_rules(&rules, &headers, body, &[]);
    let react = results.iter().find(|m| m.name == "React");
    assert!(react.is_some(), "React should be detected");

    let react = react.unwrap();
    assert!(react.confidence >= 50, "React confidence should be >= 50");
    assert!(
      react
        .matched_by
        .iter()
        .any(|m| m.starts_with("html:") || m.starts_with("script:")),
      "React should be matched by html or script patterns"
    );
  }

  #[test]
  fn test_match_cloudflare() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "cloudflare".to_string());
    headers.insert("CF-RAY".to_string(), "abc123-LAX".to_string());

    let results = match_rules(&rules, &headers, "", &[]);
    let cf = results.iter().find(|m| m.name == "Cloudflare");
    assert!(cf.is_some(), "Cloudflare should be detected from headers");

    let cf = cf.unwrap();
    assert!(
      cf.matched_by.iter().any(|m| m.starts_with("header:")),
      "Cloudflare should be matched by header patterns"
    );
  }

  #[test]
  fn test_match_nginx() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "nginx/1.24.0".to_string());

    let results = match_rules(&rules, &headers, "", &[]);
    let nginx = results.iter().find(|m| m.name == "Nginx");
    assert!(
      nginx.is_some(),
      "Nginx should be detected from Server header"
    );

    let nginx = nginx.unwrap();
    assert_eq!(
      nginx
        .matched_by
        .iter()
        .filter(|m| m.starts_with("header:"))
        .count(),
      1,
      "Should have exactly one header match"
    );
  }

  #[test]
  fn test_no_match_empty_body() {
    let rules = load_rules();
    let headers = HashMap::new();
    let results = match_rules(&rules, &headers, "", &[]);
    assert!(
      results.is_empty(),
      "Empty body and headers should produce no matches"
    );
  }

  #[test]
  fn test_confidence_calculation() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "cloudflare".to_string());
    headers.insert("CF-RAY".to_string(), "test-123".to_string());
    headers.insert("CF-Cache-Status".to_string(), "HIT".to_string());

    // Match Cloudflare with headers + html + cookies + scripts
    let body = r#"<html><body>This is a cloudflare protected site.
      <script src="https://challenges.cloudflare.com/cdn-cgi/scripts/challenge.js"></script>
    </body></html>"#;

    let cookies = vec!["__cflb=abc123; path=/".to_string()];

    let results = match_rules(&rules, &headers, body, &cookies);
    let cf = results.iter().find(|m| m.name == "Cloudflare");
    assert!(cf.is_some(), "Cloudflare should be detected");

    let cf = cf.unwrap();
    // With headers, html, cookies, scripts all matching, confidence should be high
    assert!(
      cf.confidence >= 75,
      "Cloudflare with multiple method matches should have high confidence, got {}",
      cf.confidence
    );
  }

  #[test]
  fn test_implied_technologies() {
    let rules = load_rules();
    let headers = HashMap::new();

    // A page with Next.js markers only
    let body = r#"
      <html>
        <head></head>
        <body>
          <script id="__NEXT_DATA__" type="application/json">{}</script>
          <script src="/_next/static/chunks/main.js"></script>
        </body>
      </html>
    "#;

    let results = match_rules(&rules, &headers, body, &[]);
    let nextjs = results.iter().find(|m| m.name == "Next.js");
    assert!(nextjs.is_some(), "Next.js should be detected");

    // Next.js implies React and Node.js
    let react = results.iter().find(|m| m.name == "React");
    assert!(
      react.is_some(),
      "React should be implied by Next.js detection"
    );
    let react = react.unwrap();
    assert_eq!(
      react.confidence, 50,
      "Implied technology should have 50% confidence"
    );
    assert!(
      react.matched_by.contains(&"implied".to_string()),
      "Implied tech should have 'implied' in matched_by"
    );

    let nodejs = results.iter().find(|m| m.name == "Node.js");
    assert!(
      nodejs.is_some(),
      "Node.js should be implied by Next.js detection"
    );
  }

  #[test]
  fn test_version_extraction() {
    // Test basic version extraction
    assert_eq!(
      extract_version_from_text("WordPress 6.4.2"),
      Some("6.4.2".to_string())
    );
    assert_eq!(
      extract_version_from_text("nginx/1.24.0 (Ubuntu)"),
      Some("1.24.0".to_string())
    );
    assert_eq!(
      extract_version_from_text("PHP/8.1.2-1ubuntu2.14"),
      Some("8.1.2".to_string())
    );
    assert_eq!(extract_version_from_text("no version here"), None);
    assert_eq!(extract_version_from_text("single 5 digit"), None);
  }

  #[test]
  fn test_version_extraction_from_headers() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("X-Powered-By".to_string(), "PHP/8.2.15".to_string());

    let results = match_rules(&rules, &headers, "", &[]);
    let php = results.iter().find(|m| m.name == "PHP");
    assert!(php.is_some(), "PHP should be detected");
    let php = php.unwrap();
    assert_eq!(
      php.version,
      Some("8.2.15".to_string()),
      "PHP version should be extracted from header"
    );
  }

  #[test]
  fn test_meta_tag_extraction() {
    let body =
      r#"<html><head><meta name="generator" content="Hugo 0.121.1"></head><body></body></html>"#;
    let content = extract_meta_content(body, &body.to_lowercase(), "generator");
    assert_eq!(content, Some("Hugo 0.121.1".to_string()));
  }

  #[test]
  fn test_cookie_matching() {
    let rules = load_rules();
    let headers = HashMap::new();
    let cookies = vec!["PHPSESSID=abc123def456; path=/; HttpOnly".to_string()];

    let results = match_rules(&rules, &headers, "", &cookies);
    let php = results.iter().find(|m| m.name == "PHP");
    assert!(php.is_some(), "PHP should be detected via PHPSESSID cookie");
    assert!(
      php
        .unwrap()
        .matched_by
        .iter()
        .any(|m| m.starts_with("cookie:")),
      "Should be matched by cookie"
    );
  }

  #[test]
  fn test_multiple_technologies_detected() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "nginx/1.24.0".to_string());

    let body = r#"
      <html>
        <head>
          <meta name="generator" content="WordPress 6.4">
          <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans">
          <link rel="stylesheet" href="/wp-content/themes/flavor/style.css">
        </head>
        <body>
          <div id="root">
            <script src="https://www.google-analytics.com/analytics.js"></script>
            <script src="/wp-includes/js/jquery.js"></script>
          </div>
        </body>
      </html>
    "#;

    let results = match_rules(&rules, &headers, body, &[]);

    // Should detect multiple technologies
    let names: Vec<&str> = results.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"Nginx"), "Should detect Nginx");
    assert!(names.contains(&"WordPress"), "Should detect WordPress");
    assert!(
      names.contains(&"Google Analytics"),
      "Should detect Google Analytics"
    );
    assert!(
      names.contains(&"Google Fonts"),
      "Should detect Google Fonts"
    );
  }

  #[test]
  fn test_case_insensitive_header_lookup() {
    let mut headers = HashMap::new();
    headers.insert("x-powered-by".to_string(), "PHP/8.1".to_string());

    let result = find_header_value(&headers, "X-Powered-By");
    assert!(result.is_some(), "Header lookup should be case-insensitive");
    assert_eq!(result.unwrap(), "PHP/8.1");
  }

  #[test]
  fn test_rules_have_valid_structure() {
    let rules = load_rules();
    for rule in &rules {
      assert!(!rule.name.is_empty(), "Rule name should not be empty");
      assert!(
        !rule.categories.is_empty(),
        "Rule '{}' should have at least one category",
        rule.name
      );

      // Each rule should have at least one detection method (unless it is
      // only used as an implied dependency like MySQL)
      let has_detection = !rule.headers.is_empty()
        || !rule.meta.is_empty()
        || !rule.html.is_empty()
        || !rule.cookies.is_empty()
        || !rule.scripts.is_empty();
      let is_implied_only = matches!(
        rule.name.as_str(),
        "MySQL" | "PostgreSQL" | "MongoDB" | "Redis" | "esbuild" | "Drizzle" | "Kubernetes"
      );
      assert!(
        has_detection || is_implied_only,
        "Rule '{}' should have at least one detection method or be implied-only",
        rule.name
      );
    }
  }

  #[test]
  fn test_deduplication() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "cloudflare".to_string());
    headers.insert("CF-RAY".to_string(), "abcd-LAX".to_string());

    let body = r#"<html><body>cloudflare protected</body></html>"#;
    let cookies = vec!["__cflb=test; path=/".to_string()];

    let results = match_rules(&rules, &headers, body, &cookies);
    let cf_count = results.iter().filter(|m| m.name == "Cloudflare").count();
    assert_eq!(
      cf_count, 1,
      "Cloudflare should appear exactly once (deduplicated), got {}",
      cf_count
    );
  }

  #[test]
  fn test_sorted_by_confidence() {
    let rules = load_rules();
    let mut headers = HashMap::new();
    headers.insert("Server".to_string(), "nginx".to_string());

    let body = r#"
      <html>
        <body>
          <div data-reactroot></div>
          <script src="/_next/static/chunks/main.js"></script>
          <div id="__NEXT_DATA__"></div>
        </body>
      </html>
    "#;

    let results = match_rules(&rules, &headers, body, &[]);
    for window in results.windows(2) {
      assert!(
        window[0].confidence >= window[1].confidence,
        "Results should be sorted by confidence descending: {} ({}) >= {} ({})",
        window[0].name,
        window[0].confidence,
        window[1].name,
        window[1].confidence
      );
    }
  }
}
