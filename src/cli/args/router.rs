/// Command router: resolves domain/resource/verb from positional tokens.
///
/// Builds a RouteTree from registry data and resolves a token stream into
/// one of several outcomes: fully resolved command, global command, magic
/// scan target, partial match, or unknown with suggestions.

use std::collections::{HashMap, HashSet};

use super::error::suggest;
use super::token::Token;
use super::types::CommandPath;

/// Global commands that bypass domain/resource/verb routing.
const GLOBAL_COMMANDS: &[&str] = &["help", "version", "commands", "shell"];

/// Result of route resolution.
#[derive(Debug)]
pub enum RouteResolution {
  /// Fully resolved: domain + resource + verb.
  Resolved {
    path: CommandPath,
    remaining_tokens: Vec<Token>,
  },
  /// Global command: help, version, commands, shell.
  GlobalCommand {
    name: String,
    remaining_tokens: Vec<Token>,
  },
  /// Magic scan: target is a URL/IP/domain, auto-detect scan type.
  MagicScan {
    target: String,
    remaining_tokens: Vec<Token>,
  },
  /// Partial: only domain found (no resource given).
  PartialDomain {
    domain: String,
    remaining_tokens: Vec<Token>,
  },
  /// Partial: domain + resource found but no verb.
  PartialResource {
    domain: String,
    resource: String,
    remaining_tokens: Vec<Token>,
  },
  /// Nothing matched.
  Unknown {
    tokens: Vec<String>,
    suggestions: Vec<String>,
  },
}

// ------------------------------------------------------------------
// Internal tree structures
// ------------------------------------------------------------------

struct ResourceEntry {
  verbs: HashSet<String>,
  verb_aliases: HashMap<String, String>,
}

struct DomainEntry {
  resources: HashMap<String, ResourceEntry>,
  aliases: HashMap<String, String>,
}

/// Domain/resource/verb tree built from Command trait implementations.
pub struct RouteTree {
  domains: HashMap<String, DomainEntry>,
  aliases: HashMap<String, String>,
}

impl RouteTree {
  /// Build from command registry data.
  ///
  /// * `domains`   - `(domain_name, domain_aliases)`
  /// * `resources` - `(domain, resource_name, resource_aliases)`
  /// * `verbs`     - `(domain, resource, verb_name, verb_aliases)`
  pub fn build(
    domains: &[(String, Vec<String>)],
    resources: &[(String, String, Vec<String>)],
    verbs: &[(String, String, String, Vec<String>)],
  ) -> Self {
    let mut tree_domains: HashMap<String, DomainEntry> = HashMap::new();
    let mut tree_aliases: HashMap<String, String> = HashMap::new();

    // Register domains and their aliases.
    for (name, aliases) in domains {
      for alias in aliases {
        tree_aliases.insert(alias.clone(), name.clone());
      }
      tree_domains.entry(name.clone()).or_insert_with(|| DomainEntry {
        resources: HashMap::new(),
        aliases: HashMap::new(),
      });
    }

    // Register resources and their aliases within their domain.
    for (domain, resource, aliases) in resources {
      let domain_entry = tree_domains.entry(domain.clone()).or_insert_with(|| DomainEntry {
        resources: HashMap::new(),
        aliases: HashMap::new(),
      });
      for alias in aliases {
        domain_entry.aliases.insert(alias.clone(), resource.clone());
      }
      domain_entry
        .resources
        .entry(resource.clone())
        .or_insert_with(|| ResourceEntry {
          verbs: HashSet::new(),
          verb_aliases: HashMap::new(),
        });
    }

    // Register verbs and their aliases within their domain/resource.
    for (domain, resource, verb, aliases) in verbs {
      let domain_entry = tree_domains.entry(domain.clone()).or_insert_with(|| DomainEntry {
        resources: HashMap::new(),
        aliases: HashMap::new(),
      });
      let resource_entry =
        domain_entry
          .resources
          .entry(resource.clone())
          .or_insert_with(|| ResourceEntry {
            verbs: HashSet::new(),
            verb_aliases: HashMap::new(),
          });
      resource_entry.verbs.insert(verb.clone());
      for alias in aliases {
        resource_entry.verb_aliases.insert(alias.clone(), verb.clone());
      }
    }

    Self {
      domains: tree_domains,
      aliases: tree_aliases,
    }
  }

  /// Resolve tokens into a route.
  pub fn resolve(&self, tokens: &[Token]) -> RouteResolution {
    // 1. Collect leading positionals (stop at first flag token).
    let mut positionals: Vec<&str> = Vec::new();
    let mut first_non_pos_idx: Option<usize> = None;

    for (i, token) in tokens.iter().enumerate() {
      match token {
        Token::Positional(val) => positionals.push(val.as_str()),
        _ => {
          first_non_pos_idx = Some(i);
          break;
        }
      }
    }

    // Remaining = everything after positionals consumed for routing.
    let build_remaining = |consumed: usize| -> Vec<Token> {
      let start = if consumed < positionals.len() {
        // Unconsumed positionals + all remaining tokens.
        consumed
      } else {
        positionals.len()
      };
      let mut remaining = Vec::new();
      // Re-emit unconsumed positionals.
      for &p in &positionals[start..] {
        remaining.push(Token::Positional(p.to_string()));
      }
      // Append everything from the first non-positional onward.
      let tail_start = first_non_pos_idx.unwrap_or(tokens.len());
      remaining.extend_from_slice(&tokens[tail_start..]);
      remaining
    };

    // 2. If empty: nothing to route.
    if positionals.is_empty() {
      return RouteResolution::Unknown {
        tokens: vec![],
        suggestions: self.domain_names(),
      };
    }

    let first = positionals[0];

    // 3. Check global commands.
    if GLOBAL_COMMANDS.contains(&first) {
      return RouteResolution::GlobalCommand {
        name: first.to_string(),
        remaining_tokens: build_remaining(1),
      };
    }

    // 4. Check magic scan targets.
    if is_magic_scan_target(first) {
      return RouteResolution::MagicScan {
        target: first.to_string(),
        remaining_tokens: build_remaining(1),
      };
    }

    // 5. Resolve domain (canonical or alias).
    let domain = if self.domains.contains_key(first) {
      first.to_string()
    } else if let Some(canonical) = self.aliases.get(first) {
      canonical.clone()
    } else {
      // Unknown domain -- generate suggestions.
      let candidates = self.domain_names();
      let candidate_refs: Vec<&str> = candidates.iter().map(|s| s.as_str()).collect();
      let suggestions = suggest(first, &candidate_refs, 3);
      return RouteResolution::Unknown {
        tokens: positionals.iter().map(|s| s.to_string()).collect(),
        suggestions,
      };
    };

    let domain_entry = self.domains.get(&domain).expect("domain just resolved");

    // 6. Only domain given.
    if positionals.len() == 1 {
      return RouteResolution::PartialDomain {
        domain,
        remaining_tokens: build_remaining(1),
      };
    }

    let second = positionals[1];

    // 7. Resolve resource (canonical or alias within domain).
    let resource = if domain_entry.resources.contains_key(second) {
      second.to_string()
    } else if let Some(canonical) = domain_entry.aliases.get(second) {
      canonical.clone()
    } else {
      // Before giving up, check compat translation (legacy: domain verb resource).
      if positionals.len() >= 3 {
        if let Some(resolution) =
          self.try_compat_swap(&domain, domain_entry, positionals[1], positionals[2], &build_remaining(3))
        {
          return resolution;
        }
      }
      // Resource not found.
      return RouteResolution::PartialDomain {
        domain,
        remaining_tokens: build_remaining(1),
      };
    };

    // 8. Only domain + resource given.
    if positionals.len() == 2 {
      return RouteResolution::PartialResource {
        domain,
        resource,
        remaining_tokens: build_remaining(2),
      };
    }

    let third = positionals[2];
    let resource_entry = domain_entry
      .resources
      .get(&resource)
      .expect("resource just resolved");

    // 9. Resolve verb (canonical or alias within resource).
    if resource_entry.verbs.contains(third) {
      return RouteResolution::Resolved {
        path: CommandPath {
          domain,
          resource: Some(resource),
          verb: Some(third.to_string()),
        },
        remaining_tokens: build_remaining(3),
      };
    }

    if let Some(canonical_verb) = resource_entry.verb_aliases.get(third) {
      return RouteResolution::Resolved {
        path: CommandPath {
          domain,
          resource: Some(resource),
          verb: Some(canonical_verb.clone()),
        },
        remaining_tokens: build_remaining(3),
      };
    }

    // 10. Compat translation: try swapping positional[1] and positional[2].
    if let Some(resolution) =
      self.try_compat_swap(&domain, domain_entry, positionals[1], positionals[2], &build_remaining(3))
    {
      return resolution;
    }

    // Verb not found but domain+resource valid.
    RouteResolution::PartialResource {
      domain,
      resource,
      remaining_tokens: build_remaining(2),
    }
  }

  /// Get all canonical domain names.
  pub fn domains(&self) -> Vec<&str> {
    let mut names: Vec<&str> = self.domains.keys().map(|s| s.as_str()).collect();
    names.sort();
    names
  }

  /// Get canonical resource names for a domain.
  pub fn resources(&self, domain: &str) -> Vec<&str> {
    self
      .domains
      .get(domain)
      .map(|entry| {
        let mut names: Vec<&str> = entry.resources.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
      })
      .unwrap_or_default()
  }

  /// Get canonical verb names for a domain/resource pair.
  pub fn verbs(&self, domain: &str, resource: &str) -> Vec<&str> {
    self
      .domains
      .get(domain)
      .and_then(|d| d.resources.get(resource))
      .map(|r| {
        let mut names: Vec<&str> = r.verbs.iter().map(|s| s.as_str()).collect();
        names.sort();
        names
      })
      .unwrap_or_default()
  }

  // ------------------------------------------------------------------
  // Private helpers
  // ------------------------------------------------------------------

  fn domain_names(&self) -> Vec<String> {
    let mut names: Vec<String> = self.domains.keys().cloned().collect();
    names.sort();
    names
  }

  /// Try the legacy order swap: `domain verb resource` -> `domain resource verb`.
  /// Returns `Some(Resolved)` if the swap produces a valid route.
  fn try_compat_swap(
    &self,
    domain: &str,
    domain_entry: &DomainEntry,
    first_token: &str,
    second_token: &str,
    remaining: &[Token],
  ) -> Option<RouteResolution> {
    // Interpret first_token as verb, second_token as resource.
    let swapped_resource = if domain_entry.resources.contains_key(second_token) {
      second_token.to_string()
    } else {
      domain_entry.aliases.get(second_token)?.clone()
    };

    let resource_entry = domain_entry.resources.get(&swapped_resource)?;

    let swapped_verb = if resource_entry.verbs.contains(first_token) {
      first_token.to_string()
    } else {
      resource_entry.verb_aliases.get(first_token)?.clone()
    };

    Some(RouteResolution::Resolved {
      path: CommandPath {
        domain: domain.to_string(),
        resource: Some(swapped_resource),
        verb: Some(swapped_verb),
      },
      remaining_tokens: remaining.to_vec(),
    })
  }
}

/// Detect whether a string looks like a scan target rather than a CLI command.
fn is_magic_scan_target(s: &str) -> bool {
  // URL schemes.
  if s.starts_with("http://") || s.starts_with("https://") || s.contains("://") {
    return true;
  }
  // Path-like URL (contains slash but no spaces).
  if s.contains('/') && !s.contains(' ') && !s.starts_with('-') {
    return true;
  }
  // IP address pattern: four dot-separated octets.
  let dot_parts: Vec<&str> = s.split('.').collect();
  if dot_parts.len() == 4 && dot_parts.iter().all(|p| p.parse::<u8>().is_ok()) {
    return true;
  }
  // host:port pattern.
  if s.contains(':') && !s.starts_with('-') {
    if let Some((_host, port)) = s.rsplit_once(':') {
      if port.parse::<u16>().is_ok() {
        return true;
      }
    }
  }
  // Domain-like: contains dot, starts with alphanumeric, only [a-z0-9.-:].
  if s.contains('.')
    && !s.starts_with('-')
    && s
      .chars()
      .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':')
  {
    return true;
  }
  false
}

// ==================================================================
// Tests
// ==================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::args::token::Token;

  /// Build a small tree for testing.
  fn test_tree() -> RouteTree {
    let domains = vec![
      ("dns".into(), vec![]),
      ("network".into(), vec!["n".into(), "net".into()]),
      ("web".into(), vec![]),
      ("recon".into(), vec!["r".into()]),
    ];
    let resources = vec![
      ("dns".into(), "record".into(), vec!["rec".into()]),
      ("network".into(), "ports".into(), vec!["p".into()]),
      ("network".into(), "host".into(), vec![]),
      ("web".into(), "asset".into(), vec![]),
      ("recon".into(), "domain".into(), vec!["dom".into()]),
    ];
    let verbs = vec![
      ("dns".into(), "record".into(), "lookup".into(), vec![]),
      ("dns".into(), "record".into(), "list".into(), vec![]),
      (
        "network".into(),
        "ports".into(),
        "scan".into(),
        vec!["s".into()],
      ),
      ("network".into(), "host".into(), "ping".into(), vec![]),
      ("web".into(), "asset".into(), "get".into(), vec![]),
      (
        "recon".into(),
        "domain".into(),
        "whois".into(),
        vec!["w".into()],
      ),
      ("recon".into(), "domain".into(), "subdomains".into(), vec![]),
    ];
    RouteTree::build(&domains, &resources, &verbs)
  }

  fn pos(s: &str) -> Token {
    Token::Positional(s.to_string())
  }

  fn long_flag(name: &str) -> Token {
    Token::LongFlag {
      name: name.to_string(),
      value: None,
    }
  }

  // ----------------------------------------------------------------
  // 1. Full command resolution
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_full_command() {
    let tree = test_tree();
    let tokens = vec![pos("dns"), pos("record"), pos("lookup")];
    match tree.resolve(&tokens) {
      RouteResolution::Resolved { path, remaining_tokens } => {
        assert_eq!(path.domain, "dns");
        assert_eq!(path.resource.as_deref(), Some("record"));
        assert_eq!(path.verb.as_deref(), Some("lookup"));
        assert!(remaining_tokens.is_empty());
      }
      other => panic!("expected Resolved, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 2. Alias resolution
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_with_aliases() {
    let tree = test_tree();
    let tokens = vec![pos("n"), pos("ports"), pos("s")];
    match tree.resolve(&tokens) {
      RouteResolution::Resolved { path, remaining_tokens } => {
        assert_eq!(path.domain, "network");
        assert_eq!(path.resource.as_deref(), Some("ports"));
        assert_eq!(path.verb.as_deref(), Some("scan"));
        assert!(remaining_tokens.is_empty());
      }
      other => panic!("expected Resolved, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 3. Global help
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_global_help() {
    let tree = test_tree();
    let tokens = vec![pos("help")];
    match tree.resolve(&tokens) {
      RouteResolution::GlobalCommand { name, remaining_tokens } => {
        assert_eq!(name, "help");
        assert!(remaining_tokens.is_empty());
      }
      other => panic!("expected GlobalCommand, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 4. Global version
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_global_version() {
    let tree = test_tree();
    let tokens = vec![pos("version")];
    match tree.resolve(&tokens) {
      RouteResolution::GlobalCommand { name, remaining_tokens } => {
        assert_eq!(name, "version");
        assert!(remaining_tokens.is_empty());
      }
      other => panic!("expected GlobalCommand, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 5. Magic scan: URL
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_magic_scan_url() {
    let tree = test_tree();
    let tokens = vec![pos("https://example.com"), long_flag("verbose")];
    match tree.resolve(&tokens) {
      RouteResolution::MagicScan { target, remaining_tokens } => {
        assert_eq!(target, "https://example.com");
        assert_eq!(remaining_tokens.len(), 1);
      }
      other => panic!("expected MagicScan, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 6. Magic scan: IP address
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_magic_scan_ip() {
    let tree = test_tree();
    let tokens = vec![pos("192.168.1.1")];
    match tree.resolve(&tokens) {
      RouteResolution::MagicScan { target, .. } => {
        assert_eq!(target, "192.168.1.1");
      }
      other => panic!("expected MagicScan, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 7. Partial domain
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_partial_domain() {
    let tree = test_tree();
    let tokens = vec![pos("dns")];
    match tree.resolve(&tokens) {
      RouteResolution::PartialDomain { domain, remaining_tokens } => {
        assert_eq!(domain, "dns");
        assert!(remaining_tokens.is_empty());
      }
      other => panic!("expected PartialDomain, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 8. Partial resource
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_partial_resource() {
    let tree = test_tree();
    let tokens = vec![pos("dns"), pos("record")];
    match tree.resolve(&tokens) {
      RouteResolution::PartialResource { domain, resource, remaining_tokens } => {
        assert_eq!(domain, "dns");
        assert_eq!(resource, "record");
        assert!(remaining_tokens.is_empty());
      }
      other => panic!("expected PartialResource, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 9. Unknown domain
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_unknown_domain() {
    let tree = test_tree();
    let tokens = vec![pos("dsn"), pos("record"), pos("lookup")];
    match tree.resolve(&tokens) {
      RouteResolution::Unknown { tokens: toks, suggestions } => {
        assert_eq!(toks, vec!["dsn", "record", "lookup"]);
        assert!(suggestions.contains(&"dns".to_string()));
      }
      other => panic!("expected Unknown, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 10. Compat translation (legacy order: domain verb resource)
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_compat_translation() {
    let tree = test_tree();
    // Legacy: rb dns lookup record -> canonical: rb dns record lookup
    let tokens = vec![pos("dns"), pos("lookup"), pos("record")];
    match tree.resolve(&tokens) {
      RouteResolution::Resolved { path, .. } => {
        assert_eq!(path.domain, "dns");
        assert_eq!(path.resource.as_deref(), Some("record"));
        assert_eq!(path.verb.as_deref(), Some("lookup"));
      }
      other => panic!("expected Resolved via compat swap, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 11. Remaining tokens pass-through
  // ----------------------------------------------------------------
  #[test]
  fn test_resolve_with_remaining_tokens() {
    let tree = test_tree();
    let tokens = vec![
      pos("network"),
      pos("ports"),
      pos("scan"),
      pos("192.168.1.1"),
      long_flag("preset"),
      pos("common"),
    ];
    match tree.resolve(&tokens) {
      RouteResolution::Resolved { path, remaining_tokens } => {
        assert_eq!(path.domain, "network");
        assert_eq!(path.resource.as_deref(), Some("ports"));
        assert_eq!(path.verb.as_deref(), Some("scan"));
        // remaining: "192.168.1.1" positional, --preset flag, "common" positional
        assert_eq!(remaining_tokens.len(), 3);
        assert_eq!(remaining_tokens[0], pos("192.168.1.1"));
      }
      other => panic!("expected Resolved, got {:?}", other),
    }
  }

  // ----------------------------------------------------------------
  // 12. domains() and resources() listing
  // ----------------------------------------------------------------
  #[test]
  fn test_domains_and_resources_listing() {
    let tree = test_tree();
    let domains = tree.domains();
    assert!(domains.contains(&"dns"));
    assert!(domains.contains(&"network"));
    assert!(domains.contains(&"web"));
    assert!(domains.contains(&"recon"));

    let resources = tree.resources("network");
    assert!(resources.contains(&"ports"));
    assert!(resources.contains(&"host"));

    let verbs = tree.verbs("dns", "record");
    assert!(verbs.contains(&"lookup"));
    assert!(verbs.contains(&"list"));

    // Non-existent domain returns empty.
    assert!(tree.resources("fake").is_empty());
    assert!(tree.verbs("fake", "foo").is_empty());
  }
}
