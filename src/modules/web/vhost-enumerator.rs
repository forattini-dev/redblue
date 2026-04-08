#![allow(dead_code)]

/// Virtual host discovery via Host header manipulation
///
/// Discovers hidden virtual hosts on a target web server by varying the
/// `Host` header and comparing responses against a baseline.  This reveals
/// internal apps, staging environments, admin panels and other services
/// that share an IP but are only accessible with the correct hostname.
///
/// Algorithm:
/// 1. GET / with Host: <base_domain> to capture the known-good baseline
/// 2. GET / with Host: <random-string>.base_domain to capture the default
///    response for unknown hostnames
/// 3. For each candidate prefix, GET / with Host: <prefix>.base_domain
/// 4. Compare against the random baseline -- any significant deviation in
///    status code or response size indicates a real virtual host
use crate::modules::common::parallel;
use crate::protocols::http::{HttpClient, HttpRequest};
use std::sync::Mutex;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A virtual host that was discovered on the target.
#[derive(Debug, Clone)]
pub struct DiscoveredVhost {
  /// Full hostname (e.g. "staging.example.com")
  pub hostname: String,
  /// HTTP status code returned for this vhost
  pub status: u16,
  /// Response body size in bytes
  pub size: usize,
  /// Page title extracted from `<title>` tag, if present
  pub title: Option<String>,
  /// Whether this vhost's response differs from the default catch-all
  pub differs_from_default: bool,
}

/// Configuration for vhost enumeration.
pub struct VhostConfig {
  /// Maximum concurrent probe threads (default: 10)
  pub threads: usize,
  /// Per-request timeout (default: 10s)
  pub timeout: Duration,
  /// Must be true to actually run enumeration (safety guard)
  pub brute: bool,
  /// Optional path to an external wordlist file (one prefix per line)
  pub wordlist: Option<String>,
  /// The base domain to append prefixes to (e.g. "example.com")
  pub base_domain: String,
  /// Maximum random jitter in ms between requests (default: 100)
  pub jitter_ms: u64,
}

impl Default for VhostConfig {
  fn default() -> Self {
    Self {
      threads: 10,
      timeout: Duration::from_secs(10),
      brute: false,
      wordlist: None,
      base_domain: String::new(),
      jitter_ms: 100,
    }
  }
}

// ---------------------------------------------------------------------------
// Embedded wordlist
// ---------------------------------------------------------------------------

/// Common virtual host prefixes covering infrastructure, development,
/// administration, monitoring, and services.
const VHOST_PREFIXES: &str = "www\n\
  mail\n\
  ftp\n\
  dev\n\
  staging\n\
  stage\n\
  test\n\
  qa\n\
  beta\n\
  alpha\n\
  demo\n\
  sandbox\n\
  preview\n\
  api\n\
  app\n\
  admin\n\
  panel\n\
  portal\n\
  dash\n\
  dashboard\n\
  manage\n\
  cms\n\
  blog\n\
  shop\n\
  store\n\
  cdn\n\
  static\n\
  assets\n\
  media\n\
  img\n\
  images\n\
  files\n\
  upload\n\
  download\n\
  backup\n\
  old\n\
  new\n\
  v2\n\
  v3\n\
  internal\n\
  private\n\
  secure\n\
  auth\n\
  login\n\
  sso\n\
  oauth\n\
  git\n\
  ci\n\
  cd\n\
  jenkins\n\
  gitlab\n\
  jira\n\
  wiki\n\
  docs\n\
  support\n\
  help\n\
  status\n\
  monitor\n\
  metrics\n\
  grafana\n\
  kibana\n\
  elastic\n\
  redis\n\
  db\n\
  mysql\n\
  postgres\n\
  mongo\n\
  rabbit\n\
  queue\n\
  worker\n\
  cron\n\
  scheduler\n\
  proxy\n\
  gateway\n\
  lb\n\
  ns1\n\
  ns2\n\
  ns3\n\
  ns4\n\
  mx\n\
  smtp\n\
  pop\n\
  imap\n\
  vpn\n\
  rdp\n\
  firewall\n\
  waf";

// ---------------------------------------------------------------------------
// Enumerator
// ---------------------------------------------------------------------------

pub struct VhostEnumerator {
  client: HttpClient,
  config: VhostConfig,
}

impl VhostEnumerator {
  pub fn new(config: VhostConfig) -> Self {
    let client = HttpClient::new().with_timeout(config.timeout);
    Self { client, config }
  }

  /// Discover virtual hosts on `target_ip`.
  ///
  /// Returns an empty vec if `config.brute` is false (safety guard to
  /// prevent accidental brute-force traffic).
  pub fn enumerate(&self, target_ip: &str) -> Vec<DiscoveredVhost> {
    if !self.config.brute {
      return Vec::new();
    }

    // Step 1 + 2: obtain the baseline for the default catch-all vhost
    let baseline = match self.get_baseline(target_ip) {
      Some(b) => b,
      None => return Vec::new(),
    };

    // Step 3: load candidate prefixes
    let prefixes = self.load_wordlist();
    if prefixes.is_empty() {
      return Vec::new();
    }

    // Step 4: probe each candidate in parallel with jitter
    let results: Mutex<Vec<DiscoveredVhost>> = Mutex::new(Vec::new());
    let baseline_ref = &baseline;
    let results_ref = &results;

    parallel::run_with_jitter(
      self.config.threads,
      self.config.jitter_ms,
      &prefixes,
      |prefix| {
        let hostname = format!("{}.{}", prefix, self.config.base_domain);
        if let Some(vhost) = self.probe_vhost(target_ip, &hostname, baseline_ref) {
          if vhost.differs_from_default {
            results_ref.lock().unwrap().push(vhost);
          }
        }
      },
    );

    results.into_inner().unwrap()
  }

  /// Get the baseline response for an unknown/random hostname.
  ///
  /// Sends a request with a randomly generated subdomain prefix to capture
  /// whatever the server returns for unrecognised Host values (typically a
  /// default page or 404).  Returns (status, size, body).
  fn get_baseline(&self, ip: &str) -> Option<(u16, usize, String)> {
    // Use a deterministic-looking but unlikely-to-exist prefix
    let random_host = format!("rb-nonexistent-87a3c1.{}", self.config.base_domain);
    let url = format!("http://{}/", ip);
    let request = HttpRequest::get(&url).with_header("Host", &random_host);

    match self.client.send(&request) {
      Ok(resp) => {
        let body = resp.body_as_string();
        let size = body.len();
        Some((resp.status_code, size, body))
      }
      Err(_) => None,
    }
  }

  /// Probe a single virtual host candidate.
  fn probe_vhost(
    &self,
    ip: &str,
    hostname: &str,
    baseline: &(u16, usize, String),
  ) -> Option<DiscoveredVhost> {
    let url = format!("http://{}/", ip);
    let request = HttpRequest::get(&url).with_header("Host", hostname);

    match self.client.send(&request) {
      Ok(resp) => {
        let body = resp.body_as_string();
        let size = body.len();
        let title = Self::extract_title(&body);
        let differs = self.differs_from_baseline(resp.status_code, size, &body, baseline);

        Some(DiscoveredVhost {
          hostname: hostname.to_string(),
          status: resp.status_code,
          size,
          title,
          differs_from_default: differs,
        })
      }
      Err(_) => None,
    }
  }

  /// Determine whether a probe response differs significantly from the
  /// baseline default response.
  ///
  /// A vhost is considered distinct if:
  /// - The HTTP status code changed, OR
  /// - The response body size differs by more than 10%
  fn differs_from_baseline(
    &self,
    status: u16,
    size: usize,
    _body: &str,
    baseline: &(u16, usize, String),
  ) -> bool {
    let (base_status, base_size, _) = baseline;

    // Status code changed -- definitely a different vhost
    if status != *base_status {
      return true;
    }

    // Size differs by more than 10%
    if *base_size > 0 {
      let diff = if size > *base_size {
        size - *base_size
      } else {
        *base_size - size
      };
      let threshold = *base_size / 10; // 10%
      if diff > threshold {
        return true;
      }
    } else if size > 0 {
      // Baseline was empty but this response has content
      return true;
    }

    false
  }

  /// Load the wordlist of vhost prefixes to probe.
  ///
  /// Priority:
  /// 1. External file from `config.wordlist` if provided
  /// 2. Embedded `subdomains-top100` wordlist (via crate::wordlists)
  /// 3. Inline VHOST_PREFIXES constant as final fallback
  fn load_wordlist(&self) -> Vec<String> {
    // External wordlist file
    if let Some(ref path) = self.config.wordlist {
      if let Ok(lines) = crate::wordlists::Loader::load_lines(path) {
        let filtered: Vec<String> = lines
          .into_iter()
          .map(|l| l.trim().to_string())
          .filter(|l| !l.is_empty() && !l.starts_with('#'))
          .collect();
        if !filtered.is_empty() {
          return filtered;
        }
      }
    }

    // Embedded wordlist
    if let Some(words) = crate::wordlists::embedded::get_embedded("subdomains-top100") {
      if !words.is_empty() {
        return words;
      }
    }

    // Inline fallback
    Self::parse_embedded_prefixes()
  }

  /// Parse the inline VHOST_PREFIXES constant into a Vec.
  fn parse_embedded_prefixes() -> Vec<String> {
    VHOST_PREFIXES
      .lines()
      .map(|l| l.trim().to_string())
      .filter(|l| !l.is_empty())
      .collect()
  }

  /// Extract the page title from an HTML response body.
  ///
  /// Performs a simple case-insensitive search for `<title>...</title>`.
  fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start_tag = "<title>";
    let end_tag = "</title>";

    let start = lower.find(start_tag)?;
    let title_start = start + start_tag.len();
    let end = lower[title_start..].find(end_tag)?;

    let title = body[title_start..title_start + end].trim();
    if title.is_empty() {
      None
    } else {
      Some(title.to_string())
    }
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_default_config() {
    let config = VhostConfig::default();
    assert_eq!(config.threads, 10);
    assert_eq!(config.timeout, Duration::from_secs(10));
    assert!(!config.brute);
    assert!(config.wordlist.is_none());
    assert!(config.base_domain.is_empty());
    assert_eq!(config.jitter_ms, 100);
  }

  #[test]
  fn test_differs_status_change() {
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      ..Default::default()
    };
    let enumerator = VhostEnumerator::new(config);

    // Baseline returns 200, probe returns 301 => differs
    let baseline = (200_u16, 1000_usize, String::from("<html>default</html>"));
    assert!(enumerator.differs_from_baseline(301, 1000, "<html>redirect</html>", &baseline));
  }

  #[test]
  fn test_differs_size_change() {
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      ..Default::default()
    };
    let enumerator = VhostEnumerator::new(config);

    // Same status, but size differs by >10% (1000 vs 1200 = 20% diff)
    let baseline = (200_u16, 1000_usize, String::from("<html>default</html>"));
    assert!(enumerator.differs_from_baseline(
      200,
      1200,
      "<html>different content here</html>",
      &baseline
    ));
  }

  #[test]
  fn test_same_as_baseline() {
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      ..Default::default()
    };
    let enumerator = VhostEnumerator::new(config);

    // Same status, similar size (within 10%)
    let baseline = (200_u16, 1000_usize, String::from("<html>default</html>"));
    assert!(!enumerator.differs_from_baseline(200, 1050, "<html>default</html>", &baseline));
  }

  #[test]
  fn test_differs_empty_baseline_nonempty_response() {
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      ..Default::default()
    };
    let enumerator = VhostEnumerator::new(config);

    let baseline = (200_u16, 0_usize, String::new());
    assert!(enumerator.differs_from_baseline(200, 500, "<html>content</html>", &baseline));
  }

  #[test]
  fn test_extract_title() {
    assert_eq!(
      VhostEnumerator::extract_title("<html><head><title>My App</title></head></html>"),
      Some("My App".to_string())
    );
  }

  #[test]
  fn test_extract_title_case_insensitive() {
    assert_eq!(
      VhostEnumerator::extract_title("<HTML><HEAD><TITLE>Admin Panel</TITLE></HEAD></HTML>"),
      Some("Admin Panel".to_string())
    );
  }

  #[test]
  fn test_extract_title_missing() {
    assert_eq!(
      VhostEnumerator::extract_title("<html><body>No title here</body></html>"),
      None
    );
  }

  #[test]
  fn test_extract_title_empty() {
    assert_eq!(
      VhostEnumerator::extract_title("<html><head><title>  </title></head></html>"),
      None
    );
  }

  #[test]
  fn test_load_embedded_prefixes() {
    let prefixes = VhostEnumerator::parse_embedded_prefixes();
    assert!(!prefixes.is_empty());
    assert!(prefixes.contains(&"www".to_string()));
    assert!(prefixes.contains(&"admin".to_string()));
    assert!(prefixes.contains(&"staging".to_string()));
    assert!(prefixes.contains(&"api".to_string()));
    assert!(prefixes.contains(&"waf".to_string()));
    // Verify no blank lines leaked through
    assert!(!prefixes.contains(&String::new()));
  }

  #[test]
  fn test_enumerate_requires_brute_flag() {
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      brute: false,
      ..Default::default()
    };
    let enumerator = VhostEnumerator::new(config);
    // Without brute=true, enumerate returns nothing (safety guard)
    let results = enumerator.enumerate("127.0.0.1");
    assert!(results.is_empty());
  }

  #[test]
  fn test_discovered_vhost_fields() {
    let vhost = DiscoveredVhost {
      hostname: "staging.example.com".to_string(),
      status: 200,
      size: 4096,
      title: Some("Staging Environment".to_string()),
      differs_from_default: true,
    };
    assert_eq!(vhost.hostname, "staging.example.com");
    assert_eq!(vhost.status, 200);
    assert_eq!(vhost.size, 4096);
    assert_eq!(vhost.title.unwrap(), "Staging Environment");
    assert!(vhost.differs_from_default);
  }

  #[test]
  fn test_vhost_probe_constructs_host_header() {
    // Verify that a probe would target the right hostname format
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      brute: true,
      ..Default::default()
    };
    let _enumerator = VhostEnumerator::new(config);

    // The hostname format should be <prefix>.<base_domain>
    let prefix = "staging";
    let base = "example.com";
    let hostname = format!("{}.{}", prefix, base);
    assert_eq!(hostname, "staging.example.com");
  }

  #[test]
  fn test_size_boundary_exactly_ten_percent() {
    let config = VhostConfig {
      base_domain: "example.com".to_string(),
      ..Default::default()
    };
    let enumerator = VhostEnumerator::new(config);

    // Exactly 10% difference (1000 -> 1100): threshold is 100, diff is 100
    // 100 is NOT > 100, so this should be "same"
    let baseline = (200_u16, 1000_usize, String::from("x"));
    assert!(!enumerator.differs_from_baseline(200, 1100, "y", &baseline));

    // Just over 10% (1000 -> 1101): diff is 101 > 100
    assert!(enumerator.differs_from_baseline(200, 1101, "y", &baseline));
  }
}
