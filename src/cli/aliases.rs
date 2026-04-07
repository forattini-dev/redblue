/// CLI Aliases & Shortcuts
///
/// Provides a multi-tier alias system:
/// 1. Full names: rb intelligence fingerprint extract
/// 2. Short forms: rb intel fp extract
/// 3. Single-letter: rb i fp extract
/// 4. Compact aliases: rb ebr → rb evasion build rehash
///
/// Saves ~45% keystrokes while maintaining readability.
/// Compact aliases map a single token to a full (domain, resource, verb) triple.
/// They are intentionally short and inconspicuous for operational use.
use std::collections::HashMap;

const INTELLIGENCE_DOMAIN_ALIASES: &[&str] = &["i", "intel"];
const NETWORK_DOMAIN_ALIASES: &[&str] = &["n", "net", "ntwrk"];
const DATABASE_DOMAIN_ALIASES: &[&str] = &["d", "db"];
const ACCESS_DOMAIN_ALIASES: &[&str] = &["a", "acc"];
const EXPLOIT_DOMAIN_ALIASES: &[&str] = &["e", "exp"];
const RECON_DOMAIN_ALIASES: &[&str] = &["r"];
const SCREENSHOT_DOMAIN_ALIASES: &[&str] = &["s", "screen", "shot"];
const COLLECTION_DOMAIN_ALIASES: &[&str] = &["c", "collect"];
const BENCH_DOMAIN_ALIASES: &[&str] = &["b"];
const WORDLIST_DOMAIN_ALIASES: &[&str] = &["w", "wl"];
const CODE_DOMAIN_ALIASES: &[&str] = &["co"];
const CLOUD_DOMAIN_ALIASES: &[&str] = &["cl"];
const TAKEOVER_DOMAIN_ALIASES: &[&str] = &["to"];
const SYSTEM_DOMAIN_ALIASES: &[&str] = &["sys"];

const FINGERPRINT_RESOURCE_ALIASES: &[&str] = &["fp", "print"];
const RECORD_RESOURCE_ALIASES: &[&str] = &["rec", "records"];
const DOMAIN_RESOURCE_ALIASES: &[&str] = &["dom"];
const SECURITY_RESOURCE_ALIASES: &[&str] = &["sec"];
const CERTIFICATE_RESOURCE_ALIASES: &[&str] = &["cert", "crt"];
const PAYLOAD_RESOURCE_ALIASES: &[&str] = &["pl"];
const LISTENER_RESOURCE_ALIASES: &[&str] = &["listen", "ls"];
const SCREENSHOT_RESOURCE_ALIASES: &[&str] = &["screen", "shot", "ss"];
const DEPENDENCIES_RESOURCE_ALIASES: &[&str] = &["deps", "dep"];
const SUBDOMAINS_RESOURCE_ALIASES: &[&str] = &["subs", "sub"];
const HOST_RESOURCE_ALIASES: &[&str] = &["machine", "node"];

const DESCRIBE_VERB_ALIASES: &[&str] = &["desc"];
const ENUMERATE_VERB_ALIASES: &[&str] = &["enum"];
const BRUTEFORCE_VERB_ALIASES: &[&str] = &["brute", "bf"];
const TAKEOVER_VERB_ALIASES: &[&str] = &["to"];
const DISCOVER_VERB_ALIASES: &[&str] = &["disc"];
const FINGERPRINT_VERB_ALIASES: &[&str] = &["fp"];

fn resolve_alias<'a>(
  input: &'a str,
  catalog: &[(&'static str, &'static [&'static str])],
) -> &'a str {
  for (canonical, aliases) in catalog {
    if aliases.iter().any(|alias| *alias == input) {
      return canonical;
    }
  }

  input
}

pub fn resolve_domain_alias(input: &str) -> &str {
  resolve_alias(
    input,
    &[
      ("intelligence", INTELLIGENCE_DOMAIN_ALIASES),
      ("network", NETWORK_DOMAIN_ALIASES),
      ("database", DATABASE_DOMAIN_ALIASES),
      ("access", ACCESS_DOMAIN_ALIASES),
      ("exploit", EXPLOIT_DOMAIN_ALIASES),
      ("recon", RECON_DOMAIN_ALIASES),
      ("screenshot", SCREENSHOT_DOMAIN_ALIASES),
      ("collection", COLLECTION_DOMAIN_ALIASES),
      ("bench", BENCH_DOMAIN_ALIASES),
      ("wordlist", WORDLIST_DOMAIN_ALIASES),
      ("code", CODE_DOMAIN_ALIASES),
      ("cloud", CLOUD_DOMAIN_ALIASES),
      ("takeover", TAKEOVER_DOMAIN_ALIASES),
      ("system", SYSTEM_DOMAIN_ALIASES),
    ],
  )
}

pub fn resolve_resource_alias(input: &str) -> &str {
  resolve_alias(
    input,
    &[
      ("fingerprint", FINGERPRINT_RESOURCE_ALIASES),
      ("record", RECORD_RESOURCE_ALIASES),
      ("domain", DOMAIN_RESOURCE_ALIASES),
      ("security", SECURITY_RESOURCE_ALIASES),
      ("certificate", CERTIFICATE_RESOURCE_ALIASES),
      ("payload", PAYLOAD_RESOURCE_ALIASES),
      ("listener", LISTENER_RESOURCE_ALIASES),
      ("screenshot", SCREENSHOT_RESOURCE_ALIASES),
      ("dependencies", DEPENDENCIES_RESOURCE_ALIASES),
      ("subdomains", SUBDOMAINS_RESOURCE_ALIASES),
      ("host", HOST_RESOURCE_ALIASES),
    ],
  )
}

pub fn resolve_verb_alias(input: &str) -> &str {
  resolve_alias(
    input,
    &[
      ("describe", DESCRIBE_VERB_ALIASES),
      ("enumerate", ENUMERATE_VERB_ALIASES),
      ("bruteforce", BRUTEFORCE_VERB_ALIASES),
      ("takeover", TAKEOVER_VERB_ALIASES),
      ("discover", DISCOVER_VERB_ALIASES),
      ("fingerprint", FINGERPRINT_VERB_ALIASES),
    ],
  )
}

pub fn domain_aliases_for(domain: &str) -> &'static [&'static str] {
  match domain {
    "intelligence" => INTELLIGENCE_DOMAIN_ALIASES,
    "network" => NETWORK_DOMAIN_ALIASES,
    "database" => DATABASE_DOMAIN_ALIASES,
    "access" => ACCESS_DOMAIN_ALIASES,
    "exploit" => EXPLOIT_DOMAIN_ALIASES,
    "recon" => RECON_DOMAIN_ALIASES,
    "screenshot" => SCREENSHOT_DOMAIN_ALIASES,
    "collection" => COLLECTION_DOMAIN_ALIASES,
    "bench" => BENCH_DOMAIN_ALIASES,
    "wordlist" => WORDLIST_DOMAIN_ALIASES,
    "code" => CODE_DOMAIN_ALIASES,
    "cloud" => CLOUD_DOMAIN_ALIASES,
    "takeover" => TAKEOVER_DOMAIN_ALIASES,
    "system" => SYSTEM_DOMAIN_ALIASES,
    _ => &[],
  }
}

pub fn resource_aliases_for(resource: &str) -> &'static [&'static str] {
  match resource {
    "fingerprint" => FINGERPRINT_RESOURCE_ALIASES,
    "record" => RECORD_RESOURCE_ALIASES,
    "domain" => DOMAIN_RESOURCE_ALIASES,
    "security" => SECURITY_RESOURCE_ALIASES,
    "certificate" => CERTIFICATE_RESOURCE_ALIASES,
    "payload" => PAYLOAD_RESOURCE_ALIASES,
    "listener" => LISTENER_RESOURCE_ALIASES,
    "screenshot" => SCREENSHOT_RESOURCE_ALIASES,
    "dependencies" => DEPENDENCIES_RESOURCE_ALIASES,
    "subdomains" => SUBDOMAINS_RESOURCE_ALIASES,
    "host" => HOST_RESOURCE_ALIASES,
    _ => &[],
  }
}

pub fn verb_aliases_for(verb: &str) -> &'static [&'static str] {
  match verb {
    "describe" => DESCRIBE_VERB_ALIASES,
    "enumerate" => ENUMERATE_VERB_ALIASES,
    "bruteforce" => BRUTEFORCE_VERB_ALIASES,
    "takeover" => TAKEOVER_VERB_ALIASES,
    "discover" => DISCOVER_VERB_ALIASES,
    "fingerprint" => FINGERPRINT_VERB_ALIASES,
    _ => &[],
  }
}

pub struct AliasResolver {
  domain_aliases: HashMap<&'static str, &'static str>,
  resource_aliases: HashMap<&'static str, &'static str>,
  verb_aliases: HashMap<&'static str, &'static str>,
}

impl AliasResolver {
  pub fn new() -> Self {
    let mut domain_aliases = HashMap::new();
    for &alias in INTELLIGENCE_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "intelligence");
    }
    for &alias in NETWORK_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "network");
    }
    for &alias in DATABASE_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "database");
    }
    for &alias in ACCESS_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "access");
    }
    for &alias in EXPLOIT_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "exploit");
    }
    for &alias in RECON_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "recon");
    }
    for &alias in SCREENSHOT_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "screenshot");
    }
    for &alias in COLLECTION_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "collection");
    }
    for &alias in BENCH_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "bench");
    }
    for &alias in WORDLIST_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "wordlist");
    }
    for &alias in CODE_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "code");
    }
    for &alias in CLOUD_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "cloud");
    }
    for &alias in TAKEOVER_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "takeover");
    }
    for &alias in SYSTEM_DOMAIN_ALIASES {
      domain_aliases.insert(alias, "system");
    }

    let mut resource_aliases = HashMap::new();
    for &alias in FINGERPRINT_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "fingerprint");
    }
    for &alias in RECORD_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "record");
    }
    for &alias in DOMAIN_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "domain");
    }
    for &alias in SECURITY_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "security");
    }
    for &alias in CERTIFICATE_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "certificate");
    }
    for &alias in PAYLOAD_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "payload");
    }
    for &alias in LISTENER_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "listener");
    }
    for &alias in SCREENSHOT_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "screenshot");
    }
    for &alias in DEPENDENCIES_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "dependencies");
    }
    for &alias in SUBDOMAINS_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "subdomains");
    }
    for &alias in HOST_RESOURCE_ALIASES {
      resource_aliases.insert(alias, "host");
    }

    let mut verb_aliases = HashMap::new();
    for &alias in DESCRIBE_VERB_ALIASES {
      verb_aliases.insert(alias, "describe");
    }
    for &alias in ENUMERATE_VERB_ALIASES {
      verb_aliases.insert(alias, "enumerate");
    }
    for &alias in BRUTEFORCE_VERB_ALIASES {
      verb_aliases.insert(alias, "bruteforce");
    }
    for &alias in TAKEOVER_VERB_ALIASES {
      verb_aliases.insert(alias, "takeover");
    }
    for &alias in DISCOVER_VERB_ALIASES {
      verb_aliases.insert(alias, "discover");
    }
    for &alias in FINGERPRINT_VERB_ALIASES {
      verb_aliases.insert(alias, "fingerprint");
    }

    Self {
      domain_aliases,
      resource_aliases,
      verb_aliases,
    }
  }

  /// Resolve domain alias to canonical name
  pub fn resolve_domain<'a>(&'a self, input: &'a str) -> &'a str {
    let _ = &self.domain_aliases;
    resolve_domain_alias(input)
  }

  /// Resolve resource alias to canonical name
  pub fn resolve_resource<'a>(&'a self, input: &'a str) -> &'a str {
    let _ = &self.resource_aliases;
    resolve_resource_alias(input)
  }

  /// Resolve verb alias to canonical name
  pub fn resolve_verb<'a>(&'a self, input: &'a str) -> &'a str {
    let _ = &self.verb_aliases;
    resolve_verb_alias(input)
  }

  /// Resolve all parts of a command at once
  pub fn resolve_all(
    &self,
    domain: &str,
    resource: Option<&str>,
    verb: Option<&str>,
  ) -> (String, Option<String>, Option<String>) {
    let resolved_domain = self.resolve_domain(domain).to_string();
    let resolved_resource = resource.map(|r| self.resolve_resource(r).to_string());
    let resolved_verb = verb.map(|v| self.resolve_verb(v).to_string());

    (resolved_domain, resolved_resource, resolved_verb)
  }

  /// Get all aliases for a domain
  pub fn get_domain_aliases(&self, domain: &str) -> Vec<&str> {
    self
      .domain_aliases
      .iter()
      .filter(|(_, &canonical)| canonical == domain)
      .map(|(&alias, _)| alias)
      .collect()
  }

  /// Get all aliases for a resource
  pub fn get_resource_aliases(&self, resource: &str) -> Vec<&str> {
    self
      .resource_aliases
      .iter()
      .filter(|(_, &canonical)| canonical == resource)
      .map(|(&alias, _)| alias)
      .collect()
  }

  /// Get all aliases for a verb
  pub fn get_verb_aliases(&self, verb: &str) -> Vec<&str> {
    self
      .verb_aliases
      .iter()
      .filter(|(_, &canonical)| canonical == verb)
      .map(|(&alias, _)| alias)
      .collect()
  }

  /// Check if input is an alias
  pub fn is_alias(&self, input: &str) -> bool {
    self.domain_aliases.contains_key(input)
      || self.resource_aliases.contains_key(input)
      || self.verb_aliases.contains_key(input)
  }

  /// Get suggested command with aliases (for examples/help)
  pub fn suggest_shortest(
    &self,
    domain: &str,
    resource: Option<&str>,
    verb: Option<&str>,
  ) -> String {
    // Use shortest available alias
    let domain_aliases = self.get_domain_aliases(domain);
    let domain_short = domain_aliases
      .iter()
      .min_by_key(|a| a.len())
      .copied()
      .unwrap_or(domain);

    let mut parts = vec![domain_short.to_string()];

    if let Some(r) = resource {
      let resource_aliases = self.get_resource_aliases(r);
      let resource_short = resource_aliases
        .iter()
        .min_by_key(|a| a.len())
        .copied()
        .unwrap_or(r);
      parts.push(resource_short.to_string());
    }

    if let Some(v) = verb {
      let verb_aliases = self.get_verb_aliases(v);
      let verb_short = verb_aliases
        .iter()
        .min_by_key(|a| a.len())
        .copied()
        .unwrap_or(v);
      parts.push(verb_short.to_string());
    }

    parts.join(" ")
  }
}

impl Default for AliasResolver {
  fn default() -> Self {
    Self::new()
  }
}

/// Compact alias: a single token that expands to a full (domain, resource, verb) triple.
/// Used for operational shortcuts that should be inconspicuous in terminal history.
struct CompactAlias {
  alias: &'static str,
  domain: &'static str,
  resource: &'static str,
  verb: &'static str,
}

/// Registry of all compact aliases. Add new entries here.
const COMPACT_ALIASES: &[CompactAlias] = &[CompactAlias {
  alias: "ebr",
  domain: "evasion",
  resource: "build",
  verb: "rehash",
}];

/// Resolve a compact alias (single token → full domain/resource/verb triple).
/// Returns None if the token is not a registered compact alias.
pub fn resolve_compact_alias(input: &str) -> Option<(&'static str, &'static str, &'static str)> {
  COMPACT_ALIASES
    .iter()
    .find(|ca| ca.alias == input)
    .map(|ca| (ca.domain, ca.resource, ca.verb))
}

/// Return all registered compact aliases (for schema/manifest/help).
pub fn compact_alias_list() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
  COMPACT_ALIASES
    .iter()
    .map(|ca| (ca.alias, ca.domain, ca.resource, ca.verb))
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_domain_aliases() {
    let resolver = AliasResolver::new();

    assert_eq!(resolver.resolve_domain("i"), "intelligence");
    assert_eq!(resolver.resolve_domain("intel"), "intelligence");
    assert_eq!(resolver.resolve_domain("intelligence"), "intelligence");

    assert_eq!(resolver.resolve_domain("n"), "network");
    assert_eq!(resolver.resolve_domain("net"), "network");

    assert_eq!(resolver.resolve_domain("d"), "database");
    assert_eq!(resolver.resolve_domain("db"), "database");
    assert_eq!(resolver.resolve_domain("sys"), "system");
  }

  #[test]
  fn test_resource_aliases() {
    let resolver = AliasResolver::new();

    assert_eq!(resolver.resolve_resource("fp"), "fingerprint");
    assert_eq!(resolver.resolve_resource("print"), "fingerprint");

    assert_eq!(resolver.resolve_resource("rec"), "record");
    assert_eq!(resolver.resolve_resource("cert"), "certificate");
    assert_eq!(resolver.resolve_resource("machine"), "host");
  }

  #[test]
  fn test_verb_aliases() {
    let resolver = AliasResolver::new();

    assert_eq!(resolver.resolve_verb("desc"), "describe");
    assert_eq!(resolver.resolve_verb("enum"), "enumerate");
    assert_eq!(resolver.resolve_verb("brute"), "bruteforce");
  }

  #[test]
  fn test_resolve_all() {
    let resolver = AliasResolver::new();

    let (domain, resource, verb) = resolver.resolve_all("i", Some("fp"), Some("desc"));

    assert_eq!(domain, "intelligence");
    assert_eq!(resource, Some("fingerprint".to_string()));
    assert_eq!(verb, Some("describe".to_string()));
  }

  #[test]
  fn test_get_aliases() {
    let resolver = AliasResolver::new();

    let aliases = resolver.get_domain_aliases("intelligence");
    assert!(aliases.contains(&"i"));
    assert!(aliases.contains(&"intel"));
  }

  #[test]
  fn test_suggest_shortest() {
    let resolver = AliasResolver::new();

    let suggestion =
      resolver.suggest_shortest("intelligence", Some("fingerprint"), Some("describe"));

    // Should suggest shortest aliases
    assert!(suggestion.contains("i") || suggestion.contains("fp"));
  }

  #[test]
  fn test_is_alias() {
    let resolver = AliasResolver::new();

    assert!(resolver.is_alias("i"));
    assert!(resolver.is_alias("fp"));
    assert!(resolver.is_alias("desc"));
    assert!(!resolver.is_alias("notanalias"));
  }

  #[test]
  fn test_alias_catalog_helpers() {
    assert_eq!(domain_aliases_for("network"), &["n", "net", "ntwrk"]);
    assert_eq!(resource_aliases_for("record"), &["rec", "records"]);
    assert_eq!(verb_aliases_for("discover"), &["disc"]);
    assert_eq!(domain_aliases_for("system"), &["sys"]);
    assert_eq!(resource_aliases_for("host"), &["machine", "node"]);
  }

  #[test]
  fn test_compact_alias_ebr() {
    let result = resolve_compact_alias("ebr");
    assert_eq!(result, Some(("evasion", "build", "rehash")));
  }

  #[test]
  fn test_compact_alias_unknown() {
    assert_eq!(resolve_compact_alias("unknown"), None);
    assert_eq!(resolve_compact_alias("evasion"), None);
  }

  #[test]
  fn test_compact_alias_list() {
    let list = compact_alias_list();
    assert!(!list.is_empty());
    assert!(list.iter().any(|(alias, d, r, v)| *alias == "ebr"
      && *d == "evasion"
      && *r == "build"
      && *v == "rehash"));
  }
}
