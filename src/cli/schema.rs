use super::commands::{all_commands, Command, Flag, Route};
use crate::utils::json::JsonValue;
use std::collections::BTreeMap;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const CANONICAL_ORDER: &str = "domain-resource-verb";
pub const CANONICAL_GRAMMAR: &str = "rb <domain> <resource> <verb> [target] [args...] [flags]";
pub const GLOBAL_MACHINE_OUTPUT_FLAG: &str = "json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonSupport {
  Undeclared,
  BestEffort,
  Guaranteed,
}

impl JsonSupport {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Undeclared => "undeclared",
      Self::BestEffort => "best-effort",
      Self::Guaranteed => "guaranteed",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdoutPolicy {
  Mixed,
  JsonOnlyWhenRequested,
}

impl StdoutPolicy {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Mixed => "mixed",
      Self::JsonOnlyWhenRequested => "json-only-when-requested",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StderrPolicy {
  Mixed,
  DiagnosticsOnly,
}

impl StderrPolicy {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Mixed => "mixed",
      Self::DiagnosticsOnly => "diagnostics-only",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineOutputMetadata {
  pub global_flag: &'static str,
  pub preferred_flag: Option<&'static str>,
  pub preferred_value: Option<&'static str>,
  pub json_support: JsonSupport,
  pub stdout_policy: StdoutPolicy,
  pub stderr_policy: StderrPolicy,
}

impl Default for MachineOutputMetadata {
  fn default() -> Self {
    Self {
      global_flag: "json",
      preferred_flag: None,
      preferred_value: None,
      json_support: JsonSupport::BestEffort,
      stdout_policy: StdoutPolicy::JsonOnlyWhenRequested,
      stderr_policy: StderrPolicy::DiagnosticsOnly,
    }
  }
}

impl MachineOutputMetadata {
  pub const fn new() -> Self {
    Self {
      global_flag: "json",
      preferred_flag: None,
      preferred_value: None,
      json_support: JsonSupport::BestEffort,
      stdout_policy: StdoutPolicy::JsonOnlyWhenRequested,
      stderr_policy: StderrPolicy::DiagnosticsOnly,
    }
  }

  pub const fn with_preferred_flag(
    mut self,
    preferred_flag: &'static str,
    preferred_value: &'static str,
  ) -> Self {
    self.preferred_flag = Some(preferred_flag);
    self.preferred_value = Some(preferred_value);
    self
  }

  pub const fn with_json_support(mut self, json_support: JsonSupport) -> Self {
    self.json_support = json_support;
    self
  }

  pub const fn with_stdout_policy(mut self, stdout_policy: StdoutPolicy) -> Self {
    self.stdout_policy = stdout_policy;
    self
  }

  pub const fn with_stderr_policy(mut self, stderr_policy: StderrPolicy) -> Self {
    self.stderr_policy = stderr_policy;
    self
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandMetadata {
  pub canonical_order: &'static str,
  pub aliases: &'static [&'static str],
  pub machine_output: MachineOutputMetadata,
}

impl Default for CommandMetadata {
  fn default() -> Self {
    Self {
      canonical_order: CANONICAL_ORDER,
      aliases: &[],
      machine_output: MachineOutputMetadata::default(),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteMetadata {
  pub aliases: &'static [&'static str],
  pub machine_output: MachineOutputMetadata,
}

impl Default for RouteMetadata {
  fn default() -> Self {
    Self {
      aliases: &[],
      machine_output: MachineOutputMetadata::default(),
    }
  }
}

impl RouteMetadata {
  pub const fn new() -> Self {
    Self {
      aliases: &[],
      machine_output: MachineOutputMetadata::new(),
    }
  }

  pub const fn with_aliases(mut self, aliases: &'static [&'static str]) -> Self {
    self.aliases = aliases;
    self
  }

  pub const fn with_machine_output(mut self, machine_output: MachineOutputMetadata) -> Self {
    self.machine_output = machine_output;
    self
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSummary {
  pub resource: String,
  pub description: String,
  pub verbs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuggestionResult {
  pub stage: String,
  pub suggestions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerbNode {
  pub name: String,
  pub summary: String,
  pub aliases: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceNode {
  pub name: String,
  pub description: String,
  pub aliases: Vec<String>,
  pub verbs: Vec<VerbNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainNode {
  pub name: String,
  pub aliases: Vec<String>,
  pub resources: Vec<ResourceNode>,
}

impl CommandMetadata {
  pub const fn new() -> Self {
    Self {
      canonical_order: CANONICAL_ORDER,
      aliases: &[],
      machine_output: MachineOutputMetadata::new(),
    }
  }

  pub const fn with_aliases(mut self, aliases: &'static [&'static str]) -> Self {
    self.aliases = aliases;
    self
  }

  pub const fn with_machine_output(mut self, machine_output: MachineOutputMetadata) -> Self {
    self.machine_output = machine_output;
    self
  }
}

pub fn build_manifest(include_hidden: bool) -> JsonValue {
  let commands = all_commands()
    .iter()
    .filter(|command| include_hidden || !command.hidden())
    .map(|command| command_manifest(command.as_ref()))
    .collect();

  JsonValue::object(vec![
    (
      "schema_version".to_string(),
      JsonValue::Number(MANIFEST_SCHEMA_VERSION as f64),
    ),
    (
      "version".to_string(),
      JsonValue::from(crate::version::current_version()),
    ),
    ("binary".to_string(), JsonValue::from("redblue")),
    (
      "canonical_order".to_string(),
      JsonValue::from(CANONICAL_ORDER),
    ),
    (
      "canonical_grammar".to_string(),
      JsonValue::from(CANONICAL_GRAMMAR),
    ),
    (
      "machine_output".to_string(),
      JsonValue::object(vec![
        (
          "global_flag".to_string(),
          JsonValue::from(GLOBAL_MACHINE_OUTPUT_FLAG),
        ),
        (
          "description".to_string(),
          JsonValue::from("Global machine-readable output hint used by the JS SDK wrapper"),
        ),
      ]),
    ),
    (
      "global_options".to_string(),
      JsonValue::array(global_options_manifest()),
    ),
    (
      "domains".to_string(),
      JsonValue::array(
        domain_tree(include_hidden)
          .into_iter()
          .map(domain_node_manifest)
          .collect(),
      ),
    ),
    ("commands".to_string(), JsonValue::array(commands)),
  ])
}

pub fn domain_resource_summaries(domain: &str) -> Vec<ResourceSummary> {
  let mut summaries: Vec<ResourceSummary> = all_commands()
    .iter()
    .filter(|command| !command.hidden() && command.domain() == domain)
    .map(|command| ResourceSummary {
      resource: command.resource().to_string(),
      description: command.description().to_string(),
      verbs: command
        .routes()
        .iter()
        .map(|route| route.verb.to_string())
        .collect(),
    })
    .collect();

  summaries.sort_by(|a, b| a.resource.cmp(&b.resource));
  summaries
}

pub fn domain_summary(domain: &str) -> &'static str {
  match domain {
    "access" => "Remote access - reverse shells & listeners",
    "agent" => "C2 agent server and client operations",
    "assess" => "Assessment workflow automation",
    "attack" => "Attack workflow orchestration",
    "auth" | "auth_test" => "Credential testing and auth workflows",
    "bench" => "Load testing and performance benchmarking",
    "binary" => "Binary analysis, checksec, and exploit helpers",
    "cloud" => "Cloud storage and platform security",
    "code" => "Code security and secret scanning",
    "collection" => "Browser and endpoint collection",
    "config" => "Configuration management and initialization",
    "crypto" => "Hashing, codecs, ciphers, and recipes",
    "database" => "Database, graph, and vector operations",
    "dns" => "Records, zones, and resolvers",
    "dns_server" => "Authoritative DNS and hijacking flows",
    "docs" => "Documentation search and indexing",
    "evasion" => "AV/EDR evasion and stealth helpers",
    "exploit" => "Exploitation, persistence, and post-exploitation",
    "file" => "File operations, archives, and hashes",
    "fuzz" => "Fuzzing and input discovery",
    "health" => "Port health monitoring and diffs",
    "intel" => "Threat intelligence, CVEs, MITRE, and IOCs",
    "loot" => "Stored findings, credentials, and graphs",
    "mcp" => "Model Context Protocol bridge",
    "memory" => "Process memory inspection",
    "mitm" => "Man-in-the-middle orchestration",
    "nc" => "Netcat-compatible socket workflows",
    "network" => "Hosts, ports, and low-level telemetry",
    "password" => "Password cracking and analysis",
    "playbook" => "Playbook methodologies and execution",
    "proxy" => "HTTP CONNECT and SOCKS5 proxy servers",
    "recon" => "Asset intelligence and WHOIS insights",
    "report" => "Report generation",
    "scan" => "Compatibility scanning entrypoints",
    "search" => "Search across stored reconnaissance data",
    "service" => "Service installation and persistence helpers",
    "system" => "Local host inventory and runtime environment inference",
    "tls" => "TLS/SSL auditing and cipher intelligence",
    "web" => "Web assets and HTTP security audits",
    "wordlist" => "Wordlist generation and management",
    _ => "Security operations",
  }
}

pub fn resolve_command_tokens(
  domain: &str,
  resource: Option<&str>,
  verb: Option<&str>,
) -> (String, Option<String>, Option<String>) {
  (
    crate::cli::aliases::resolve_domain_alias(domain).to_string(),
    resource.map(|value| crate::cli::aliases::resolve_resource_alias(value).to_string()),
    verb.map(|value| crate::cli::aliases::resolve_verb_alias(value).to_string()),
  )
}

pub fn find_domain_node(domain: &str, include_hidden: bool) -> Option<DomainNode> {
  let normalized_domain = crate::cli::aliases::resolve_domain_alias(domain);
  domain_tree(include_hidden)
    .into_iter()
    .find(|node| node.name == normalized_domain)
}

pub fn route_exists(domain: &str, resource: &str, verb: &str) -> bool {
  let (domain, resource, verb) = resolve_command_tokens(domain, Some(resource), Some(verb));
  let Some(resource) = resource.as_deref() else {
    return false;
  };
  let Some(verb) = verb.as_deref() else {
    return false;
  };

  super::commands::command_for(&domain, resource)
    .map(|command| command.routes().iter().any(|route| route.verb == verb))
    .unwrap_or(false)
}

pub fn resource_exists(domain: &str, resource: &str) -> bool {
  let (domain, resource, _) = resolve_command_tokens(domain, Some(resource), None);
  let Some(resource) = resource.as_deref() else {
    return false;
  };

  super::commands::command_for(&domain, resource).is_some()
}

pub fn suggest_domains(domain: &str, limit: usize, include_hidden: bool) -> Vec<String> {
  let requested = crate::cli::aliases::resolve_domain_alias(domain).to_string();
  let mut candidates: Vec<(usize, String)> = domain_tree(include_hidden)
    .into_iter()
    .map(|node| {
      (
        levenshtein(&requested, &node.name),
        format!("rb {} help", node.name),
      )
    })
    .collect();

  candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
  candidates
    .into_iter()
    .filter(|(distance, _)| *distance <= 6)
    .take(limit)
    .map(|(_, suggestion)| suggestion)
    .collect()
}

pub fn suggest_resources(domain: &str, resource: &str, limit: usize) -> Vec<String> {
  let normalized_domain = crate::cli::aliases::resolve_domain_alias(domain);
  let normalized_resource = crate::cli::aliases::resolve_resource_alias(resource).to_string();
  let Some(domain) = find_domain_node(normalized_domain, false) else {
    return Vec::new();
  };

  let mut candidates: Vec<(usize, String)> = domain
    .resources
    .into_iter()
    .map(|node| {
      (
        levenshtein(&normalized_resource, &node.name),
        format!("rb {} {} help", normalized_domain, node.name),
      )
    })
    .collect();

  candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
  candidates
    .into_iter()
    .filter(|(distance, _)| *distance <= 8)
    .take(limit)
    .map(|(_, suggestion)| suggestion)
    .collect()
}

pub fn suggest_command_tokens(tokens: &[&str], include_hidden: bool) -> SuggestionResult {
  let cleaned = tokens
    .iter()
    .map(|token| token.trim())
    .filter(|token| !token.is_empty())
    .collect::<Vec<_>>();
  let domains = domain_tree(include_hidden);

  if cleaned.is_empty() {
    return SuggestionResult {
      stage: "domain".to_string(),
      suggestions: domains.into_iter().map(|domain| domain.name).collect(),
    };
  }

  if cleaned.len() == 1 {
    return SuggestionResult {
      stage: "domain".to_string(),
      suggestions: domains
        .into_iter()
        .filter(|domain| node_matches_token(&domain.name, &domain.aliases, cleaned[0]))
        .map(|domain| domain.name)
        .collect(),
    };
  }

  let Some(domain) = find_domain_node(cleaned[0], include_hidden) else {
    return SuggestionResult {
      stage: "domain".to_string(),
      suggestions: suggest_domains(cleaned[0], 5, include_hidden),
    };
  };

  if cleaned.len() == 2 {
    return SuggestionResult {
      stage: "resource".to_string(),
      suggestions: domain
        .resources
        .into_iter()
        .filter(|resource| node_matches_token(&resource.name, &resource.aliases, cleaned[1]))
        .map(|resource| resource.name)
        .collect(),
    };
  }

  let normalized_resource = crate::cli::aliases::resolve_resource_alias(cleaned[1]);
  let Some(resource) = domain
    .resources
    .into_iter()
    .find(|resource| resource.name == normalized_resource)
  else {
    return SuggestionResult {
      stage: "resource".to_string(),
      suggestions: suggest_resources(&domain.name, cleaned[1], 5),
    };
  };

  if cleaned.len() == 3 {
    return SuggestionResult {
      stage: "verb".to_string(),
      suggestions: resource
        .verbs
        .into_iter()
        .filter(|verb| node_matches_token(&verb.name, &verb.aliases, cleaned[2]))
        .map(|verb| verb.name)
        .collect(),
    };
  }

  SuggestionResult {
    stage: "command".to_string(),
    suggestions: vec![format!(
      "rb {} {} {}",
      domain.name,
      resource.name,
      crate::cli::aliases::resolve_verb_alias(cleaned[2])
    )],
  }
}

fn node_matches_token(name: &str, aliases: &[String], token: &str) -> bool {
  name.starts_with(token)
    || aliases
      .iter()
      .any(|alias| !alias.is_empty() && alias.starts_with(token))
}

pub fn suggest_route_commands(
  domain: &str,
  resource: &str,
  verb: &str,
  limit: usize,
) -> Vec<String> {
  let requested = format!("{}/{}/{}", domain, resource, verb);
  let mut candidates: Vec<(usize, String)> = all_commands()
    .iter()
    .filter(|command| !command.hidden())
    .flat_map(|command| {
      let domain = command.domain().to_string();
      let resource = command.resource().to_string();
      command.routes().into_iter().map(move |route| {
        let canonical_path = format!("{}/{}/{}", domain, resource, route.verb);
        let canonical_command = format!("rb {} {} {}", domain, resource, route.verb);
        (canonical_path, canonical_command)
      })
    })
    .map(|(canonical_path, canonical_command)| {
      (levenshtein(&requested, &canonical_path), canonical_command)
    })
    .collect();

  candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
  candidates
    .into_iter()
    .filter(|(distance, _)| *distance <= 8)
    .take(limit)
    .map(|(_, command)| command)
    .collect()
}

pub fn domain_tree(include_hidden: bool) -> Vec<DomainNode> {
  let mut domains: BTreeMap<String, BTreeMap<String, &dyn Command>> = BTreeMap::new();

  for command in all_commands()
    .iter()
    .filter(|command| include_hidden || !command.hidden())
  {
    domains
      .entry(command.domain().to_string())
      .or_default()
      .insert(command.resource().to_string(), command.as_ref());
  }

  domains
    .into_iter()
    .map(|(domain, resources)| DomainNode {
      name: domain.clone(),
      aliases: crate::cli::aliases::domain_aliases_for(&domain)
        .iter()
        .map(|alias| (*alias).to_string())
        .collect(),
      resources: resources
        .into_iter()
        .map(|(resource, command)| ResourceNode {
          name: resource.clone(),
          description: command.description().to_string(),
          aliases: crate::cli::aliases::resource_aliases_for(&resource)
            .iter()
            .map(|alias| (*alias).to_string())
            .collect(),
          verbs: command
            .routes()
            .iter()
            .map(|route| {
              let route_metadata = command.route_metadata(route.verb);
              VerbNode {
                name: route.verb.to_string(),
                summary: route.summary.to_string(),
                aliases: route_metadata
                  .aliases
                  .iter()
                  .map(|alias| (*alias).to_string())
                  .collect(),
              }
            })
            .collect(),
        })
        .collect(),
    })
    .collect()
}

pub fn total_route_count(include_hidden: bool) -> usize {
  domain_tree(include_hidden)
    .iter()
    .map(|domain| {
      domain
        .resources
        .iter()
        .map(|resource| resource.verbs.len())
        .sum::<usize>()
    })
    .sum()
}

fn domain_node_manifest(domain: DomainNode) -> JsonValue {
  JsonValue::object(vec![
    ("name".to_string(), JsonValue::from(domain.name)),
    (
      "aliases".to_string(),
      JsonValue::array(domain.aliases.into_iter().map(JsonValue::from).collect()),
    ),
    (
      "resources".to_string(),
      JsonValue::array(
        domain
          .resources
          .into_iter()
          .map(|resource| {
            JsonValue::object(vec![
              ("name".to_string(), JsonValue::from(resource.name)),
              (
                "description".to_string(),
                JsonValue::from(resource.description),
              ),
              (
                "aliases".to_string(),
                JsonValue::array(resource.aliases.into_iter().map(JsonValue::from).collect()),
              ),
              (
                "verbs".to_string(),
                JsonValue::array(
                  resource
                    .verbs
                    .into_iter()
                    .map(|verb| {
                      JsonValue::object(vec![
                        ("name".to_string(), JsonValue::from(verb.name)),
                        ("summary".to_string(), JsonValue::from(verb.summary)),
                        (
                          "aliases".to_string(),
                          JsonValue::array(verb.aliases.into_iter().map(JsonValue::from).collect()),
                        ),
                      ])
                    })
                    .collect(),
                ),
              ),
            ])
          })
          .collect(),
      ),
    ),
  ])
}

fn global_options_manifest() -> Vec<JsonValue> {
  vec![
    JsonValue::object(vec![
      ("long".to_string(), JsonValue::from("json")),
      ("short".to_string(), JsonValue::from("j")),
      (
        "description".to_string(),
        JsonValue::from("Force JSON output globally"),
      ),
      ("kind".to_string(), JsonValue::from("machine-output")),
      ("value".to_string(), JsonValue::from("json")),
    ]),
    JsonValue::object(vec![
      ("long".to_string(), JsonValue::from("output")),
      (
        "description".to_string(),
        JsonValue::from("Select output format globally"),
      ),
      ("kind".to_string(), JsonValue::from("output-format")),
      (
        "values".to_string(),
        JsonValue::array(vec![
          JsonValue::from("human"),
          JsonValue::from("json"),
          JsonValue::from("yaml"),
        ]),
      ),
    ]),
    JsonValue::object(vec![
      ("long".to_string(), JsonValue::from("format")),
      (
        "description".to_string(),
        JsonValue::from("Alias for --output"),
      ),
      ("kind".to_string(), JsonValue::from("output-format")),
      (
        "values".to_string(),
        JsonValue::array(vec![
          JsonValue::from("human"),
          JsonValue::from("json"),
          JsonValue::from("yaml"),
        ]),
      ),
    ]),
    JsonValue::object(vec![
      ("long".to_string(), JsonValue::from("stealth")),
      ("short".to_string(), JsonValue::from("S")),
      (
        "description".to_string(),
        JsonValue::from("Full evasion: heap jitter + rehash after execution"),
      ),
      ("kind".to_string(), JsonValue::from("evasion")),
    ]),
  ]
}

pub fn command_manifest(command: &dyn Command) -> JsonValue {
  let flags = command.flags();
  let routes = command.routes();
  let examples = command.examples();
  let metadata = command.metadata();
  let preferred_flag =
    machine_output_flag(&flags).or(metadata.machine_output.preferred_flag.map(str::to_string));

  JsonValue::object(vec![
    ("domain".to_string(), JsonValue::from(command.domain())),
    (
      "domain_aliases".to_string(),
      JsonValue::array(
        crate::cli::aliases::domain_aliases_for(command.domain())
          .iter()
          .map(|alias| JsonValue::from(*alias))
          .collect(),
      ),
    ),
    ("resource".to_string(), JsonValue::from(command.resource())),
    (
      "resource_aliases".to_string(),
      JsonValue::array(
        crate::cli::aliases::resource_aliases_for(command.resource())
          .iter()
          .map(|alias| JsonValue::from(*alias))
          .collect(),
      ),
    ),
    (
      "description".to_string(),
      JsonValue::from(command.description()),
    ),
    ("hidden".to_string(), JsonValue::from(command.hidden())),
    (
      "canonical_order".to_string(),
      JsonValue::from(metadata.canonical_order),
    ),
    (
      "canonical_prefix".to_string(),
      JsonValue::from(format!("rb {} {}", command.domain(), command.resource())),
    ),
    (
      "path".to_string(),
      JsonValue::object(vec![
        ("domain".to_string(), JsonValue::from(command.domain())),
        ("resource".to_string(), JsonValue::from(command.resource())),
      ]),
    ),
    (
      "aliases".to_string(),
      JsonValue::array(
        metadata
          .aliases
          .iter()
          .map(|alias| JsonValue::from(*alias))
          .collect(),
      ),
    ),
    (
      "machine_output".to_string(),
      machine_output_manifest(metadata.machine_output, preferred_flag.as_deref()),
    ),
    (
      "flags".to_string(),
      JsonValue::array(
        flags
          .iter()
          .map(|flag| flag_manifest(flag, preferred_flag.as_deref()))
          .collect(),
      ),
    ),
    (
      "examples".to_string(),
      JsonValue::array(
        examples
          .iter()
          .map(|(summary, command)| example_manifest(summary, command))
          .collect(),
      ),
    ),
    (
      "routes".to_string(),
      JsonValue::array(
        routes
          .iter()
          .map(|route| route_manifest(command, route, &examples))
          .collect(),
      ),
    ),
  ])
}

fn machine_output_manifest(
  machine_output: MachineOutputMetadata,
  preferred_flag: Option<&str>,
) -> JsonValue {
  JsonValue::object(vec![
    (
      "global_flag".to_string(),
      JsonValue::from(machine_output.global_flag),
    ),
    (
      "preferred_flag".to_string(),
      preferred_flag
        .map(JsonValue::from)
        .unwrap_or(JsonValue::Null),
    ),
    (
      "preferred_value".to_string(),
      machine_output
        .preferred_value
        .map(JsonValue::from)
        .unwrap_or(JsonValue::Null),
    ),
    (
      "json_support".to_string(),
      JsonValue::from(machine_output.json_support.as_str()),
    ),
    (
      "stdout_policy".to_string(),
      JsonValue::from(machine_output.stdout_policy.as_str()),
    ),
    (
      "stderr_policy".to_string(),
      JsonValue::from(machine_output.stderr_policy.as_str()),
    ),
  ])
}

fn flag_manifest(flag: &Flag, preferred_flag: Option<&str>) -> JsonValue {
  JsonValue::object(vec![
    ("long".to_string(), JsonValue::from(flag.long.clone())),
    (
      "short".to_string(),
      flag
        .short
        .map(|value| JsonValue::from(value.to_string()))
        .unwrap_or(JsonValue::Null),
    ),
    (
      "description".to_string(),
      JsonValue::from(flag.description.clone()),
    ),
    (
      "default".to_string(),
      flag
        .default
        .clone()
        .map(JsonValue::from)
        .unwrap_or(JsonValue::Null),
    ),
    (
      "arg".to_string(),
      flag
        .arg
        .clone()
        .map(JsonValue::from)
        .unwrap_or(JsonValue::Null),
    ),
    (
      "expects_value".to_string(),
      JsonValue::from(flag.arg.is_some()),
    ),
    (
      "camel_name".to_string(),
      JsonValue::from(kebab_to_camel(&flag.long)),
    ),
    (
      "machine_output_role".to_string(),
      if preferred_flag == Some(flag.long.as_str()) {
        JsonValue::from("preferred")
      } else {
        JsonValue::Null
      },
    ),
  ])
}

fn route_manifest(command: &dyn Command, route: &Route, examples: &[(&str, &str)]) -> JsonValue {
  let route_metadata = command.route_metadata(route.verb);
  let route_command = format!(
    "rb {} {} {}",
    command.domain(),
    command.resource(),
    route.verb
  );
  JsonValue::object(vec![
    ("verb".to_string(), JsonValue::from(route.verb)),
    ("summary".to_string(), JsonValue::from(route.summary)),
    ("usage".to_string(), JsonValue::from(route.usage)),
    (
      "aliases".to_string(),
      JsonValue::array(
        route_metadata
          .aliases
          .iter()
          .map(|alias| JsonValue::from(*alias))
          .collect(),
      ),
    ),
    (
      "canonical_path".to_string(),
      JsonValue::from(format!(
        "{}/{}/{}",
        command.domain(),
        command.resource(),
        route.verb
      )),
    ),
    (
      "command".to_string(),
      JsonValue::from(route_command.clone()),
    ),
    (
      "machine_output".to_string(),
      machine_output_manifest(
        route_metadata.machine_output,
        route_metadata.machine_output.preferred_flag,
      ),
    ),
    (
      "positionals".to_string(),
      JsonValue::array(parse_route_positionals(command, route)),
    ),
    (
      "examples".to_string(),
      JsonValue::array(
        examples
          .iter()
          .filter(|(_, example_command)| example_command.starts_with(&route_command))
          .map(|(summary, example_command)| example_manifest(summary, example_command))
          .collect(),
      ),
    ),
  ])
}

fn example_manifest(summary: &str, command: &str) -> JsonValue {
  JsonValue::object(vec![
    ("summary".to_string(), JsonValue::from(summary)),
    ("command".to_string(), JsonValue::from(command)),
  ])
}

pub fn machine_output_summary(machine_output: MachineOutputMetadata) -> String {
  let mut parts = vec![format!("json={}", machine_output.json_support.as_str())];

  if let Some(preferred_flag) = machine_output.preferred_flag {
    let preferred_value = machine_output.preferred_value.unwrap_or("json");
    parts.push(format!(
      "preferred=--{} {}",
      preferred_flag, preferred_value
    ));
  } else {
    parts.push(format!("global=--{}", machine_output.global_flag));
  }

  parts.push(format!("stdout={}", machine_output.stdout_policy.as_str()));
  parts.push(format!("stderr={}", machine_output.stderr_policy.as_str()));

  parts.join(", ")
}

fn levenshtein(a: &str, b: &str) -> usize {
  let a_len = a.len();
  let b_len = b.len();

  if a_len == 0 {
    return b_len;
  }
  if b_len == 0 {
    return a_len;
  }

  let mut prev_row: Vec<usize> = (0..=b_len).collect();
  let mut curr_row = vec![0; b_len + 1];

  for (i, a_char) in a.chars().enumerate() {
    curr_row[0] = i + 1;

    for (j, b_char) in b.chars().enumerate() {
      let cost = if a_char == b_char { 0 } else { 1 };
      curr_row[j + 1] = (curr_row[j] + 1)
        .min(prev_row[j + 1] + 1)
        .min(prev_row[j] + cost);
    }

    std::mem::swap(&mut prev_row, &mut curr_row);
  }

  prev_row[b_len]
}

fn parse_route_positionals(command: &dyn Command, route: &Route) -> Vec<JsonValue> {
  let prefix = format!(
    "rb {} {} {}",
    command.domain(),
    command.resource(),
    route.verb
  );
  let usage_tail = route
    .usage
    .strip_prefix(&prefix)
    .unwrap_or(route.usage)
    .trim();

  let mut positionals = Vec::new();
  let mut has_target = false;
  let mut arg_index = 0usize;
  // Track open `[…]` groups that start with a flag (e.g. `[--db <file>]`).
  // Tokens inside such a group must NOT be parsed as positionals — `<file>`
  // there is the flag's argument, not a command positional.
  let mut skip_until_close = false;

  for token in usage_tail.split_whitespace() {
    if skip_until_close {
      if token.ends_with(']') {
        skip_until_close = false;
      }
      continue;
    }
    // A token like `[--flag` opens a flag group. Skip it and every following
    // token up to and including the one that ends with `]`.
    if token.starts_with("[-") && !token.ends_with(']') {
      skip_until_close = true;
      continue;
    }
    let Some((name, required, repeated)) = parse_placeholder(token) else {
      continue;
    };

    let (slot, slot_index) = if !has_target {
      has_target = true;
      ("target", 0usize)
    } else {
      let index = arg_index;
      arg_index += 1;
      ("arg", index)
    };

    positionals.push(JsonValue::object(vec![
      ("name".to_string(), JsonValue::from(name)),
      ("required".to_string(), JsonValue::from(required)),
      ("repeated".to_string(), JsonValue::from(repeated)),
      ("slot".to_string(), JsonValue::from(slot)),
      ("index".to_string(), JsonValue::from(slot_index as f64)),
    ]));
  }

  positionals
}

fn parse_placeholder(token: &str) -> Option<(String, bool, bool)> {
  let trimmed = token.trim().trim_matches(',');
  if trimmed.is_empty() {
    return None;
  }

  let inner = trimmed.trim_matches(|ch| ch == '[' || ch == ']');
  if inner.is_empty()
    || inner == "FLAGS"
    || inner == "OPTIONS"
    || inner.starts_with("--")
    || inner.starts_with('-')
    || (inner.contains('=') && !inner.starts_with('<'))
  {
    return None;
  }

  let required = trimmed.starts_with('<') || inner.starts_with('<');
  let placeholder = inner.trim_matches(|ch| ch == '<' || ch == '>');
  let repeated = placeholder.ends_with("...");
  let name = placeholder
    .trim_end_matches("...")
    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_');

  if name.is_empty() {
    None
  } else {
    Some((name.to_string(), required, repeated))
  }
}

fn machine_output_flag(flags: &[Flag]) -> Option<String> {
  flags.iter().find_map(|flag| {
    let description = flag.description.to_ascii_lowercase();
    let mentions_output = description.contains("output");
    let mentions_json = description.contains("json");

    if mentions_output && mentions_json && (flag.long == "format" || flag.long == "output") {
      Some(flag.long.clone())
    } else {
      None
    }
  })
}

fn kebab_to_camel(value: &str) -> String {
  let mut out = String::new();
  let mut uppercase_next = false;

  for ch in value.chars() {
    if ch == '-' || ch == '_' {
      uppercase_next = true;
      continue;
    }

    if uppercase_next {
      out.push(ch.to_ascii_uppercase());
      uppercase_next = false;
    } else {
      out.push(ch);
    }
  }

  out
}

#[cfg(test)]
mod tests {
  use super::*;

  struct FixtureCommand;

  impl Command for FixtureCommand {
    fn domain(&self) -> &str {
      "dns"
    }

    fn resource(&self) -> &str {
      "record"
    }

    fn description(&self) -> &str {
      "fixture"
    }

    fn routes(&self) -> Vec<Route> {
      vec![Route {
        verb: "lookup",
        summary: "Lookup",
        usage: "rb dns record lookup <domain> [<type>...] [--type A]",
      }]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
      vec![]
    }

    fn execute(&self, _ctx: &crate::cli::CliContext) -> Result<(), String> {
      Ok(())
    }
  }

  // TODO: route_manifest_includes_canonical_path — needs JsonValue::as_object/get API
  // TODO: route_positionals_preserve_target_and_repeated_args — needs JsonValue::as_object/get API

  #[test]
  fn domain_resource_summaries_are_sorted() {
    let summaries = domain_resource_summaries("dns");
    assert!(!summaries.is_empty());

    let mut sorted = summaries.clone();
    sorted.sort_by(|a, b| a.resource.cmp(&b.resource));
    assert_eq!(summaries, sorted);
  }

  #[test]
  fn suggest_route_commands_prefers_canonical_match() {
    let suggestions = suggest_route_commands("tls", "audit", "security", 3);
    assert!(suggestions
      .iter()
      .any(|item| item == "rb tls security audit"));
  }

  #[test]
  fn suggest_route_commands_handles_typoed_verb() {
    let suggestions = suggest_route_commands("tls", "security", "audti", 3);
    assert!(suggestions
      .iter()
      .any(|item| item == "rb tls security audit"));
  }

  // TODO: manifest_includes_domain_tree — needs JsonValue::as_object/get API
  // TODO: manifest_includes_global_output_options — needs JsonValue::as_object/get API

  #[test]
  fn resolve_command_tokens_normalizes_aliases() {
    let (domain, resource, verb) = resolve_command_tokens("n", Some("sec"), Some("desc"));
    assert_eq!(domain, "network");
    assert_eq!(resource.as_deref(), Some("security"));
    assert_eq!(verb.as_deref(), Some("describe"));
  }

  #[test]
  fn find_domain_node_resolves_aliases() {
    let domain = find_domain_node("n", false).expect("network alias should resolve");
    assert_eq!(domain.name, "network");

    let system = find_domain_node("sys", false).expect("system alias should resolve");
    assert_eq!(system.name, "system");
  }

  #[test]
  fn resource_exists_resolves_aliases_and_known_resources() {
    assert!(resource_exists("web", "asset"));
    assert!(resource_exists("intelligence", "graph"));
    assert!(!resource_exists("web", "not-a-resource"));
  }

  #[test]
  fn suggest_domains_returns_canonical_help_routes() {
    let suggestions = suggest_domains("tlsx", 3, false);
    assert!(suggestions.iter().any(|item| item == "rb tls help"));
  }

  #[test]
  fn suggest_resources_returns_canonical_resource_help() {
    let suggestions = suggest_resources("dns", "records", 3);
    assert!(suggestions.iter().any(|item| item == "rb dns record help"));
  }

  #[test]
  fn suggest_command_tokens_tracks_domain_resource_and_verb_stages() {
    let empty = suggest_command_tokens(&[], false);
    assert_eq!(empty.stage, "domain");
    assert!(empty.suggestions.iter().any(|item| item == "dns"));

    let resource = suggest_command_tokens(&["dns", "rec"], false);
    assert_eq!(resource.stage, "resource");
    assert!(resource.suggestions.iter().any(|item| item == "record"));

    let verb = suggest_command_tokens(&["tls", "security", "aud"], false);
    assert_eq!(verb.stage, "verb");
    assert!(verb.suggestions.iter().any(|item| item == "audit"));

    let system_resource = suggest_command_tokens(&["sys", "mach"], false);
    assert_eq!(system_resource.stage, "resource");
    assert!(system_resource
      .suggestions
      .iter()
      .any(|item| item == "host"));

    let system_verb = suggest_command_tokens(&["system", "host", "inv"], false);
    assert_eq!(system_verb.stage, "verb");
    assert!(system_verb.suggestions.iter().any(|item| item == "inspect"));
  }
}
