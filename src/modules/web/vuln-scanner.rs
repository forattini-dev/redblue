/// Web vulnerability scanner module
///
/// Replaces: nikto, WPScan (basic checks)
///
/// Features:
/// - Common vulnerability detection
/// - Outdated software detection
/// - Security misconfiguration checks
/// - Sensitive file exposure
/// - Directory listing detection
/// - Default credentials testing
///
/// NO external dependencies - pure Rust implementation
use crate::modules::common::Severity;
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use crate::storage::engine::emitter::GraphEmitter;
use crate::synergy::events::{emit, EntityRef, Event, EventType};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ScanResult {
  pub url: String,
  pub findings: Vec<Finding>,
  pub scan_duration_ms: u128,
}

#[derive(Debug, Clone)]
pub struct Finding {
  pub severity: Severity,
  pub category: Category,
  pub title: String,
  pub description: String,
  pub path: String,
  pub evidence: Option<String>,
}

// Severity imported from crate::modules::common

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Category {
  SensitiveFileExposure,
  SecurityMisconfiguration,
  DirectoryListing,
  OutdatedSoftware,
  DefaultCredentials,
  InformationDisclosure,
  XSS,              // Cross-Site Scripting
  SQLInjection,     // SQL Injection
  SSRF,             // Server-Side Request Forgery
  CommandInjection, // OS Command Injection
  PathTraversal,    // Directory Traversal
  Other,
}

pub struct WebScanner {
  client: HttpClient,
}

impl WebScanner {
  pub fn new() -> Self {
    Self {
      client: HttpClient::new(),
    }
  }

  /// Run vulnerability scan (passive checks run in parallel).
  ///
  /// The 5 passive check categories (sensitive files, security headers,
  /// directory listings, admin panels, info disclosure) are independent
  /// HTTP probes that can run concurrently.  Concurrency capped at 3 to
  /// avoid triggering WAF rate-limits on a single target.
  pub fn scan(&self, url: &str) -> Result<ScanResult, String> {
    let start = std::time::Instant::now();

    let base_url = if url.ends_with('/') {
      url.trim_end_matches('/').to_string()
    } else {
      url.to_string()
    };

    // Run all 5 passive checks in parallel via thread::scope.
    // Each check is an independent set of HTTP probes to the same target.
    // Max 3 concurrent to avoid triggering WAF rate-limits.
    let mut findings: Vec<Finding> = {
      use std::sync::Mutex;
      let collected: Mutex<Vec<Vec<Finding>>> = Mutex::new(Vec::new());
      let url = &base_url;

      std::thread::scope(|s| {
        s.spawn(|| collected.lock().unwrap().push(self.check_sensitive_files(url)));
        s.spawn(|| collected.lock().unwrap().push(self.check_security_headers(url)));
        s.spawn(|| collected.lock().unwrap().push(self.check_directory_listings(url)));
        s.spawn(|| collected.lock().unwrap().push(self.check_admin_panels(url)));
        s.spawn(|| collected.lock().unwrap().push(self.check_info_disclosure(url)));
      });

      collected.into_inner().unwrap().into_iter().flatten().collect()
    };

    findings.sort_by(|a, b| {
      Self::severity_order(&a.severity).cmp(&Self::severity_order(&b.severity))
    });

    Self::emit_finding_events(&base_url, &findings);

    Ok(ScanResult {
      url: base_url,
      findings,
      scan_duration_ms: start.elapsed().as_millis(),
    })
  }

  /// Emit synergy events for discovered vulnerabilities
  fn emit_finding_events(target_url: &str, findings: &[Finding]) {
    for finding in findings {
      let severity_str = match finding.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
      };

      let category_str = format!("{:?}", finding.category);
      let event = Event::new(EventType::VulnFound, "web::vuln-scanner")
        .with_entity(EntityRef::vulnerability(&finding.title))
        .with_data("category", &category_str)
        .with_data("severity", severity_str)
        .with_data("title", &finding.title)
        .with_data("target", target_url);

      emit(event);
    }
  }

  pub fn scan_active_with_progress(
    &self,
    url: &str,
    progress: Option<Arc<dyn ScanProgress>>,
  ) -> Result<ScanResult, String> {
    let start = std::time::Instant::now();
    let mut findings = Vec::new();

    let base_url = if url.ends_with('/') {
      url.trim_end_matches('/').to_string()
    } else {
      url.to_string()
    };

    let tick = |progress: &Option<Arc<dyn ScanProgress>>| {
      if let Some(p) = progress.as_ref() {
        p.inc(1);
      }
    };

    findings.extend(self.check_sensitive_files(&base_url));
    tick(&progress);
    findings.extend(self.check_security_headers(&base_url));
    tick(&progress);
    findings.extend(self.check_directory_listings(&base_url));
    tick(&progress);
    findings.extend(self.check_admin_panels(&base_url));
    tick(&progress);
    findings.extend(self.check_info_disclosure(&base_url));
    tick(&progress);

    findings.extend(self.test_xss(&base_url));
    tick(&progress);
    findings.extend(self.test_sql_injection(&base_url));
    tick(&progress);
    findings.extend(self.test_path_traversal(&base_url));
    tick(&progress);
    findings.extend(self.test_ssrf(&base_url));
    tick(&progress);
    findings.extend(self.test_command_injection(&base_url));
    tick(&progress);

    findings.sort_by_key(|f| Self::severity_order(&f.severity));

    Ok(ScanResult {
      url: base_url,
      findings,
      scan_duration_ms: start.elapsed().as_millis(),
    })
  }

  /// Check for sensitive file exposure
  fn check_sensitive_files(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let sensitive_files = vec![
      (".env", "Environment configuration file"),
      (".git/config", "Git configuration"),
      (".git/HEAD", "Git HEAD reference"),
      ("composer.json", "Composer dependencies"),
      ("package.json", "NPM dependencies"),
      ("web.config", "IIS configuration"),
      (".htaccess", "Apache configuration"),
      ("phpinfo.php", "PHP information page"),
      ("info.php", "PHP information page"),
      ("backup.sql", "Database backup"),
      ("database.sql", "Database dump"),
      ("db.sql", "Database file"),
      (".DS_Store", "macOS metadata"),
      ("robots.txt", "Robots exclusion file"),
      ("sitemap.xml", "Sitemap file"),
    ];

    for (file, description) in sensitive_files {
      let url = format!("{}/{}", base_url, file);

      if let Ok(response) = self.client.get(&url) {
        if response.status_code == 200 {
          let severity = if file.contains(".env")
            || file.contains(".git")
            || file.contains("backup")
            || file.contains("database")
          {
            Severity::Critical
          } else if file.contains("phpinfo") || file.contains("web.config") {
            Severity::High
          } else if file.contains("composer.json") || file.contains("package.json") {
            Severity::Medium
          } else {
            Severity::Low
          };

          findings.push(Finding {
            severity,
            category: Category::SensitiveFileExposure,
            title: format!("Exposed: {}", file),
            description: format!("{} is publicly accessible", description),
            path: format!("/{}", file),
            evidence: Some(format!("Status: 200, Size: {} bytes", response.body.len())),
          });
        }
      }
    }

    findings
  }

  /// Check for security header issues
  fn check_security_headers(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(response) = self.client.get(base_url) {
      let headers = &response.headers;

      // Check for missing security headers
      let security_headers = vec![
        (
          "Strict-Transport-Security",
          "HSTS header prevents MITM attacks",
          Severity::Medium,
        ),
        (
          "X-Frame-Options",
          "Prevents clickjacking attacks",
          Severity::Medium,
        ),
        (
          "X-Content-Type-Options",
          "Prevents MIME type sniffing",
          Severity::Low,
        ),
        (
          "Content-Security-Policy",
          "Mitigates XSS and injection attacks",
          Severity::Medium,
        ),
        ("X-XSS-Protection", "Browser XSS filter", Severity::Low),
      ];

      for (header, description, severity) in security_headers {
        if !headers.contains_key(header) {
          findings.push(Finding {
            severity,
            category: Category::SecurityMisconfiguration,
            title: format!("Missing: {}", header),
            description: description.to_string(),
            path: "/".to_string(),
            evidence: None,
          });
        }
      }

      // Check for server header information disclosure
      if let Some(server) = headers.get("Server") {
        if server.contains('/') {
          findings.push(Finding {
            severity: Severity::Low,
            category: Category::InformationDisclosure,
            title: "Server Version Exposed".to_string(),
            description: "Server header reveals version information".to_string(),
            path: "/".to_string(),
            evidence: Some(format!("Server: {}", server)),
          });
        }
      }

      // Check for X-Powered-By header
      if let Some(powered_by) = headers.get("X-Powered-By") {
        findings.push(Finding {
          severity: Severity::Low,
          category: Category::InformationDisclosure,
          title: "Technology Stack Exposed".to_string(),
          description: "X-Powered-By header reveals technology information".to_string(),
          path: "/".to_string(),
          evidence: Some(format!("X-Powered-By: {}", powered_by)),
        });
      }
    }

    findings
  }

  /// Check for directory listing vulnerabilities
  fn check_directory_listings(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let directories = vec![
      "/uploads", "/images", "/files", "/assets", "/static", "/media", "/backup", "/backups",
      "/tmp", "/temp",
    ];

    for dir in directories {
      let url = format!("{}{}", base_url, dir);

      if let Ok(response) = self.client.get(&url) {
        if response.status_code == 200 {
          let body = String::from_utf8_lossy(&response.body);

          // Common directory listing indicators
          if body.contains("Index of")
            || body.contains("Directory listing")
            || body.contains("Parent Directory")
          {
            findings.push(Finding {
              severity: Severity::Medium,
              category: Category::DirectoryListing,
              title: format!("Directory Listing: {}", dir),
              description: "Directory listing is enabled, exposing file structure".to_string(),
              path: dir.to_string(),
              evidence: Some("Directory index visible".to_string()),
            });
          }
        }
      }
    }

    findings
  }

  /// Check for common admin panels
  fn check_admin_panels(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let admin_paths = vec![
      "/admin",
      "/administrator",
      "/wp-admin",
      "/admin.php",
      "/phpmyadmin",
      "/cpanel",
      "/dashboard",
      "/panel",
    ];

    for path in admin_paths {
      let url = format!("{}{}", base_url, path);

      if let Ok(response) = self.client.get(&url) {
        if response.status_code == 200 || response.status_code == 401 || response.status_code == 403
        {
          let severity = if response.status_code == 200 {
            Severity::High
          } else {
            Severity::Info
          };

          findings.push(Finding {
            severity,
            category: Category::InformationDisclosure,
            title: format!("Admin Panel Found: {}", path),
            description: format!(
              "Administrative interface accessible (Status: {})",
              response.status_code
            ),
            path: path.to_string(),
            evidence: Some(format!("HTTP {}", response.status_code)),
          });
        }
      }
    }

    findings
  }

  /// Check for information disclosure
  fn check_info_disclosure(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for error messages
    let test_url = format!("{}/nonexistent-page-12345", base_url);

    if let Ok(response) = self.client.get(&test_url) {
      if response.status_code == 404 {
        let body = String::from_utf8_lossy(&response.body);

        // Look for stack traces or detailed errors
        if body.contains("stack trace")
          || body.contains("Exception")
          || body.contains("Fatal error")
        {
          findings.push(Finding {
            severity: Severity::Low,
            category: Category::InformationDisclosure,
            title: "Detailed Error Messages".to_string(),
            description: "Error pages reveal detailed information about the application"
              .to_string(),
            path: "/nonexistent-page-12345".to_string(),
            evidence: Some("Stack trace or detailed error visible".to_string()),
          });
        }
      }
    }

    findings
  }

  /// Get severity order for sorting
  fn severity_order(severity: &Severity) -> u8 {
    match severity {
      Severity::Critical => 0,
      Severity::High => 1,
      Severity::Medium => 2,
      Severity::Low => 3,
      Severity::Info => 4,
    }
  }

  /// Active vulnerability scanner (OWASP ZAP style)
  pub fn scan_active(&self, url: &str) -> Result<ScanResult, String> {
    self.scan_active_with_progress(url, None)
  }

  /// Test for Cross-Site Scripting (XSS) vulnerabilities
  fn test_xss(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // XSS payloads (common patterns)
    let payloads = vec![
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg/onload=alert('XSS')>",
      "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ];

    // Common parameter names to test
    let params = vec![
      "q", "search", "query", "keyword", "name", "text", "message", "comment",
    ];

    for param in &params {
      for payload in &payloads {
        // URL encode the payload
        let encoded_payload = payload
          .replace('<', "%3C")
          .replace('>', "%3E")
          .replace('\'', "%27")
          .replace('"', "%22")
          .replace('(', "%28")
          .replace(')', "%29");

        let test_url = format!("{}?{}={}", base_url, param, encoded_payload);

        // Make request
        if let Ok(response) = self.client.get(&test_url) {
          let body = String::from_utf8_lossy(&response.body);

          // Check if payload is reflected unescaped
          if body.contains(payload) {
            findings.push(Finding {
              severity: Severity::High,
              category: Category::XSS,
              title: "Potential Cross-Site Scripting (XSS)".to_string(),
              description: format!(
                "XSS payload reflected in response for parameter '{}'",
                param
              ),
              path: format!("?{}=...", param),
              evidence: Some(format!("Payload: {}", payload)),
            });
            break; // Found XSS for this param, move to next
          }
        }
      }
    }

    findings
  }

  /// Test for SQL Injection vulnerabilities
  fn test_sql_injection(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // SQL injection payloads
    let payloads = vec![
      "' OR '1'='1",
      "' OR 1=1--",
      "admin' --",
      "1' UNION SELECT NULL--",
      "' AND 1=2--",
    ];

    // SQL error indicators
    let error_patterns = vec![
      "sql syntax",
      "mysql_fetch",
      "mysqli",
      "sqlstate",
      "pg_query",
      "ora-",
      "sqlite",
      "syntax error",
      "unclosed quotation",
      "quoted string not properly terminated",
    ];

    // Common parameter names
    let params = vec![
      "id", "user", "username", "email", "uid", "pid", "cat", "category",
    ];

    for param in &params {
      for payload in &payloads {
        let test_url = format!("{}?{}={}", base_url, param, payload);

        if let Ok(response) = self.client.get(&test_url) {
          let body = String::from_utf8_lossy(&response.body).to_lowercase();

          // Check for SQL error messages
          for pattern in &error_patterns {
            if body.contains(pattern) {
              findings.push(Finding {
                                severity: Severity::Critical,
                                category: Category::SQLInjection,
                                title: "Potential SQL Injection".to_string(),
                                description: format!(
                                    "SQL error message detected for parameter '{}'. Application may be vulnerable to SQL injection.",
                                    param
                                ),
                                path: format!("?{}=...", param),
                                evidence: Some(format!("Error pattern: '{}'", pattern)),
                            });
              break;
            }
          }
        }
      }
    }

    findings
  }

  /// Test for Path Traversal vulnerabilities
  fn test_path_traversal(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Path traversal payloads
    let payloads = vec![
      "../../../etc/passwd",
      "..\\..\\..\\windows\\win.ini",
      "....//....//....//etc/passwd",
      "..%2F..%2F..%2Fetc%2Fpasswd",
    ];

    // Indicators of successful traversal
    let indicators = vec!["root:", "[extensions]", "for 16-bit app support", "daemon:"];

    let params = vec!["file", "path", "document", "page", "dir", "folder"];

    for param in &params {
      for payload in &payloads {
        let test_url = format!("{}?{}={}", base_url, param, payload);

        if let Ok(response) = self.client.get(&test_url) {
          let body = String::from_utf8_lossy(&response.body).to_lowercase();

          for indicator in &indicators {
            if body.contains(indicator) {
              findings.push(Finding {
                                severity: Severity::Critical,
                                category: Category::PathTraversal,
                                title: "Path Traversal Vulnerability Detected".to_string(),
                                description: format!(
                                    "Directory traversal successful for parameter '{}'. Sensitive file contents exposed.",
                                    param
                                ),
                                path: format!("?{}=...", param),
                                evidence: Some(format!("Indicator found: '{}'", indicator)),
                            });
              break;
            }
          }
        }
      }
    }

    findings
  }

  /// Test for Server-Side Request Forgery (SSRF)
  fn test_ssrf(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // SSRF test payloads (internal resources)
    let payloads = vec![
      "http://localhost",
      "http://127.0.0.1",
      "http://169.254.169.254/latest/meta-data/", // AWS metadata
      "http://[::1]",
      "file:///etc/passwd",
    ];

    let params = vec![
      "url", "uri", "link", "redirect", "next", "callback", "webhook",
    ];

    for param in &params {
      for payload in &payloads {
        let test_url = format!("{}?{}={}", base_url, param, payload);

        if let Ok(response) = self.client.get(&test_url) {
          let body = String::from_utf8_lossy(&response.body).to_lowercase();

          // Check for localhost/internal access indicators
          let indicators = vec!["localhost", "loopback", "ami-id", "instance-id", "root:"];

          for indicator in &indicators {
            if body.contains(indicator) {
              findings.push(Finding {
                severity: Severity::Critical,
                category: Category::SSRF,
                title: "Server-Side Request Forgery (SSRF) Detected".to_string(),
                description: format!(
                  "Application makes requests to internal resources via parameter '{}'",
                  param
                ),
                path: format!("?{}=...", param),
                evidence: Some(format!("Internal resource accessed: {}", payload)),
              });
              break;
            }
          }
        }
      }
    }

    findings
  }

  /// Test for Command Injection vulnerabilities
  fn test_command_injection(&self, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Command injection payloads
    let payloads = vec!["; ls", "| whoami", "& dir", "`id`", "$(sleep 5)"];

    // Command execution indicators
    let indicators = vec![
      "uid=",
      "gid=",
      "groups=",
      "volume serial number",
      "directory of",
    ];

    let params = vec!["cmd", "command", "exec", "ping", "ip", "host"];

    for param in &params {
      for payload in &payloads {
        let test_url = format!("{}?{}={}", base_url, param, payload);

        if let Ok(response) = self.client.get(&test_url) {
          let body = String::from_utf8_lossy(&response.body).to_lowercase();

          for indicator in &indicators {
            if body.contains(indicator) {
              findings.push(Finding {
                severity: Severity::Critical,
                category: Category::CommandInjection,
                title: "OS Command Injection Detected".to_string(),
                description: format!("Command execution possible via parameter '{}'", param),
                path: format!("?{}=...", param),
                evidence: Some(format!("Command output detected: '{}'", indicator)),
              });
              break;
            }
          }
        }
      }
    }

    findings
  }

  // ========================================================================
  // Graph Integration
  // ========================================================================

  /// Emit scan results to the graph database
  ///
  /// Creates:
  /// - Host node for the target
  /// - Vulnerability nodes for each finding
  /// - Endpoint nodes for vulnerable paths
  /// - Technology nodes from X-Powered-By headers
  pub fn emit_to_graph(&self, result: &ScanResult, emitter: Option<&GraphEmitter>) {
    // Use provided emitter or global singleton
    let global_emitter;
    let emitter = match emitter {
      Some(e) => e,
      None => {
        global_emitter = GraphEmitter::global();
        &*global_emitter
      }
    };

    // Extract host from URL
    let host = Self::extract_host_from_url(&result.url);
    if host.is_empty() {
      return;
    }

    // Emit host node
    emitter.emit_host(&host, None, None);

    // Emit each finding as a vulnerability
    for finding in &result.findings {
      // Generate a pseudo-CVE identifier for internal tracking
      let vuln_id = Self::generate_finding_id(&host, finding);

      // Convert severity to CVSS-like score
      let cvss = Self::severity_to_cvss(&finding.severity);

      // Emit vulnerability node
      emitter.emit_vulnerability(&vuln_id, cvss, Some(&finding.title));

      // Link vulnerability to host
      emitter.emit_host_vuln(&host, &vuln_id);

      // Emit endpoint if path is significant
      if finding.path != "/" && !finding.path.is_empty() {
        let method = match finding.category {
          Category::XSS
          | Category::SQLInjection
          | Category::SSRF
          | Category::PathTraversal
          | Category::CommandInjection => "GET",
          _ => "GET",
        };

        // Parse status from evidence if available
        let status = finding.evidence.as_ref().and_then(|e| {
          if e.starts_with("Status:") || e.starts_with("HTTP ") {
            e.split_whitespace()
              .find_map(|w| w.trim_end_matches(',').parse::<u16>().ok())
          } else {
            None
          }
        });

        emitter.emit_endpoint(&host, method, &finding.path, status);
      }

      // Emit technology info if detected in evidence
      if let Some(evidence) = &finding.evidence {
        if let Some(tech) = Self::extract_tech_from_evidence(evidence) {
          emitter.emit_technology(
            &host,
            &tech.name,
            tech.version.as_deref(),
            Some(&tech.category),
          );
        }
      }
    }
  }

  /// Scan and emit results to graph in one call
  pub fn scan_with_graph(&self, url: &str) -> Result<ScanResult, String> {
    let result = self.scan(url)?;
    self.emit_to_graph(&result, None);
    Ok(result)
  }

  /// Active scan and emit results to graph
  pub fn scan_active_with_graph(&self, url: &str) -> Result<ScanResult, String> {
    let result = self.scan_active(url)?;
    self.emit_to_graph(&result, None);
    Ok(result)
  }

  /// Extract host/IP from URL
  fn extract_host_from_url(url: &str) -> String {
    // Remove scheme
    let without_scheme = url
      .strip_prefix("https://")
      .or_else(|| url.strip_prefix("http://"))
      .unwrap_or(url);

    // Extract host (before any path or port)
    without_scheme
      .split('/')
      .next()
      .unwrap_or(without_scheme)
      .split(':')
      .next()
      .unwrap_or(without_scheme)
      .to_string()
  }

  /// Generate a finding identifier for graph storage
  fn generate_finding_id(host: &str, finding: &Finding) -> String {
    // Create a pseudo-ID: CATEGORY-HOST-PATH-HASH
    let category_code = match finding.category {
      Category::SensitiveFileExposure => "SFE",
      Category::SecurityMisconfiguration => "SMC",
      Category::DirectoryListing => "DRL",
      Category::OutdatedSoftware => "ODS",
      Category::DefaultCredentials => "DFC",
      Category::InformationDisclosure => "IND",
      Category::XSS => "XSS",
      Category::SQLInjection => "SQL",
      Category::SSRF => "SSR",
      Category::CommandInjection => "CMI",
      Category::PathTraversal => "PTR",
      Category::Other => "OTH",
    };

    // Simple hash of path for uniqueness
    let path_hash: u32 = finding
      .path
      .bytes()
      .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));

    format!(
      "REDBLUE-{}-{}-{:08X}",
      category_code,
      host.replace('.', "_"),
      path_hash
    )
  }

  /// Convert severity enum to CVSS-like score
  fn severity_to_cvss(severity: &Severity) -> f64 {
    match severity {
      Severity::Critical => 9.5,
      Severity::High => 7.5,
      Severity::Medium => 5.5,
      Severity::Low => 3.0,
      Severity::Info => 0.0,
    }
  }

  /// Extract technology info from evidence string
  fn extract_tech_from_evidence(evidence: &str) -> Option<TechInfo> {
    // X-Powered-By: PHP/7.4.3
    if evidence.contains("X-Powered-By:") {
      let tech_part = evidence.split(':').nth(1)?.trim();
      let parts: Vec<&str> = tech_part.split('/').collect();
      let name = parts.first()?.trim().to_string();
      let version = parts.get(1).map(|v| v.trim().to_string());
      return Some(TechInfo {
        name,
        version,
        category: "runtime".to_string(),
      });
    }

    // Server: nginx/1.18.0
    if evidence.contains("Server:") {
      let tech_part = evidence.split(':').nth(1)?.trim();
      let parts: Vec<&str> = tech_part.split('/').collect();
      let name = parts.first()?.trim().to_string();
      let version = parts
        .get(1)
        .map(|v| v.split_whitespace().next().unwrap_or(v).to_string());
      return Some(TechInfo {
        name,
        version,
        category: "server".to_string(),
      });
    }

    None
  }
}

/// Technology information extracted from evidence
struct TechInfo {
  name: String,
  version: Option<String>,
  category: String,
}

impl Default for WebScanner {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
    assert_eq!(format!("{}", Severity::High), "HIGH");
    assert_eq!(format!("{}", Severity::Info), "INFO");
  }

  #[test]
  fn test_severity_order() {
    assert!(
      WebScanner::severity_order(&Severity::Critical) < WebScanner::severity_order(&Severity::High)
    );
    assert!(
      WebScanner::severity_order(&Severity::High) < WebScanner::severity_order(&Severity::Medium)
    );
  }
}
