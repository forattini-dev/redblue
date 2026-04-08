//! Schema-driven CLI argument parser
//!
//! Three-layer architecture ported from cli-args-parser (TypeScript):
//! - **token**: Pure lexer (argv -> typed tokens)
//! - **types**: Shared types (FlagSchema, FlagValue, ParsedCommand)
//! - **error**: Structured errors with Levenshtein suggestions
//! - **schema**: Schema-driven flag parsing + type coercion
//! - **router**: Command routing domain->resource->verb
//! - **help**: Help text generation
//! - **complete**: Shell completion generation

pub mod complete;
pub mod error;
pub mod help;
pub mod router;
pub mod schema;
pub mod token;
pub mod types;

pub use complete::{complete_partial, generate_completion_script, Shell};
pub use error::{suggest, ParseError};
pub use help::{format_command_help, format_domain_help, format_global_help, format_route_help};
pub use router::{RouteResolution, RouteTree};
pub use schema::{SchemaParser, SchemaResult};
pub use token::{tokenize, Token};
pub use types::{CommandPath, FlagSchema, FlagValue, ParsedCommand, ValueType};

use crate::cli::commands::{all_commands, command_for, Command, Flag};
use crate::cli::CliContext;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse command-line arguments and resolve the target command.
///
/// Returns the populated `CliContext` and a reference to the matched `Command`.
/// On failure (unknown command, invalid flags, help/version request, etc.)
/// returns a `ParseError`.
pub fn parse_and_route(args: &[String]) -> Result<(CliContext, &'static dyn Command), ParseError> {
  // 1. Tokenize raw argument strings.
  let tokens = tokenize(args);

  // 2. Build route tree from command registry + alias tables.
  let route_tree = build_route_tree_from_registry();

  // 3. Resolve route: consume leading positional tokens for domain/resource/verb.
  let resolution = route_tree.resolve(&tokens);

  // 4. Dispatch on the resolution variant.
  match resolution {
    RouteResolution::Resolved {
      path,
      remaining_tokens,
    } => {
      let command = find_command_by_path(&path)?;

      // Merge global flag schemas with command-specific flag schemas.
      let mut flag_schemas = types::global_flags();
      for flag in command.flags() {
        flag_schemas.push(flag_to_schema(&flag));
      }

      // Parse remaining tokens against the merged schema.
      let schema_parser = SchemaParser::new(flag_schemas);
      let result = schema_parser.parse(&remaining_tokens);

      // Report the first error if any occurred.
      if let Some(err) = result.errors.into_iter().next() {
        return Err(err);
      }

      // Build the CliContext.
      let mut ctx = CliContext::new();
      ctx.raw = args.to_vec();
      ctx.domain = Some(path.domain.clone());
      ctx.resource = path.resource.clone();
      ctx.verb = path.verb.clone();

      // First positional is the target; rest go into args.
      if let Some(target) = result.positionals.first() {
        ctx.target = Some(target.clone());
      }
      if result.positionals.len() > 1 {
        ctx.args = result.positionals[1..].to_vec();
      }

      // Convert FlagValue map into String map for CliContext compatibility.
      for (name, value) in &result.flags {
        ctx.flags.insert(name.clone(), value.as_str_value());
      }

      // Apply YAML config defaults (same logic as parser.rs).
      apply_config_defaults(&mut ctx);

      Ok((ctx, command))
    }

    RouteResolution::GlobalCommand { name, .. } => match name.as_str() {
      "help" => Err(ParseError::HelpRequested {
        text: "help".into(),
      }),
      "version" => Err(ParseError::VersionRequested {
        text: "version".into(),
      }),
      "commands" | "list" => Err(ParseError::Other("commands".into())),
      "shell" => Err(ParseError::Other("shell".into())),
      _ => Err(ParseError::Other(format!("Global command: {}", name))),
    },

    RouteResolution::MagicScan {
      target,
      remaining_tokens,
    } => {
      // Build a minimal context so main.rs can dispatch to magic scan.
      let mut ctx = CliContext::new();
      ctx.raw = args.to_vec();
      ctx.target = Some(target);

      // Parse remaining tokens for global flags only.
      let schema_parser = SchemaParser::new(types::global_flags());
      let result = schema_parser.parse(&remaining_tokens);
      for (name, value) in &result.flags {
        ctx.flags.insert(name.clone(), value.as_str_value());
      }
      ctx.args = result.positionals;

      apply_config_defaults(&mut ctx);

      Err(ParseError::Other("magic_scan".into()))
    }

    RouteResolution::PartialDomain {
      domain,
      remaining_tokens: _,
    } => {
      let available = route_tree
        .resources(&domain)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
      Err(ParseError::MissingResource {
        domain,
        available,
      })
    }

    RouteResolution::PartialResource {
      domain,
      resource,
      remaining_tokens: _,
    } => {
      let available = route_tree
        .verbs(&domain, &resource)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
      Err(ParseError::MissingVerb {
        domain,
        resource,
        available,
      })
    }

    RouteResolution::Unknown {
      tokens: toks,
      suggestions,
    } => Err(ParseError::UnknownCommand {
      tokens: toks,
      suggestions,
    }),
  }
}

// ---------------------------------------------------------------------------
// Route tree construction
// ---------------------------------------------------------------------------

/// Build a `RouteTree` from the live command registry plus the alias tables
/// defined in `crate::cli::aliases`.
fn build_route_tree_from_registry() -> RouteTree {
  use crate::cli::aliases;
  use std::collections::{HashMap, HashSet};

  let commands = all_commands();

  // Collect unique domains from the registry.
  let mut domain_set: HashSet<String> = HashSet::new();
  // Map: domain -> { resource -> set of verbs }
  let mut domain_resources: HashMap<String, HashMap<String, HashSet<String>>> = HashMap::new();

  for cmd in commands {
    let domain = cmd.domain().to_string();
    let resource = cmd.resource().to_string();

    domain_set.insert(domain.clone());

    let verbs: HashSet<String> = cmd
      .routes()
      .into_iter()
      .map(|route| route.verb.to_string())
      .collect();

    domain_resources
      .entry(domain)
      .or_default()
      .insert(resource, verbs);
  }

  // Build the domain list with aliases.
  let domains: Vec<(String, Vec<String>)> = domain_set
    .iter()
    .map(|d| {
      let domain_aliases: Vec<String> = aliases::domain_aliases_for(d)
        .iter()
        .map(|a| a.to_string())
        .collect();
      (d.clone(), domain_aliases)
    })
    .collect();

  // Build the resource list with aliases.
  let mut resources: Vec<(String, String, Vec<String>)> = Vec::new();
  for (domain, res_map) in &domain_resources {
    for resource in res_map.keys() {
      let resource_aliases: Vec<String> = aliases::resource_aliases_for(resource)
        .iter()
        .map(|a| a.to_string())
        .collect();
      resources.push((domain.clone(), resource.clone(), resource_aliases));
    }
  }

  // Build the verb list with aliases.
  let mut verbs: Vec<(String, String, String, Vec<String>)> = Vec::new();
  for (domain, res_map) in &domain_resources {
    for (resource, verb_set) in res_map {
      for verb in verb_set {
        let verb_aliases: Vec<String> = aliases::verb_aliases_for(verb)
          .iter()
          .map(|a| a.to_string())
          .collect();
        verbs.push((domain.clone(), resource.clone(), verb.clone(), verb_aliases));
      }
    }
  }

  RouteTree::build(&domains, &resources, &verbs)
}

// ---------------------------------------------------------------------------
// Command lookup
// ---------------------------------------------------------------------------

/// Find a `Command` reference by its resolved `CommandPath`.
///
/// Uses the registry's `command_for(domain, resource)` lookup which is
/// indexed by domain+resource.
fn find_command_by_path(path: &CommandPath) -> Result<&'static dyn Command, ParseError> {
  let resource = path.resource.as_deref().ok_or_else(|| {
    ParseError::MissingResource {
      domain: path.domain.clone(),
      available: vec![],
    }
  })?;

  command_for(&path.domain, resource).ok_or_else(|| ParseError::UnknownCommand {
    tokens: vec![path.domain.clone(), resource.to_string()],
    suggestions: vec![],
  })
}

// ---------------------------------------------------------------------------
// Flag conversion
// ---------------------------------------------------------------------------

/// Convert an existing `Flag` (from `Command::flags()`) into a `FlagSchema`
/// that the schema parser understands.
fn flag_to_schema(flag: &Flag) -> FlagSchema {
  // If the flag has an `arg` field, it expects a value (string).
  // Otherwise it is a boolean toggle.
  let mut schema = if flag.arg.is_some() {
    FlagSchema::new(&flag.long)
  } else {
    FlagSchema::boolean(&flag.long)
  };

  if let Some(short) = flag.short {
    schema = schema.with_short(short);
  }

  schema = schema.with_description(&flag.description);

  if let Some(ref default) = flag.default {
    schema = schema.with_default(default);
  }

  schema
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

/// Apply YAML configuration defaults to the context.
///
/// This replicates the logic from `crate::cli::parser::apply_config_defaults`
/// so that the new parser path produces identical results.
fn apply_config_defaults(ctx: &mut CliContext) {
  let config = crate::config::yaml::YamlConfig::load_from_cwd_cached();

  if let Some(ref preset) = config.preset {
    ctx
      .flags
      .entry("preset".to_string())
      .or_insert(preset.clone());
  }

  if let Some(threads) = config.threads {
    ctx
      .flags
      .entry("threads".to_string())
      .or_insert(threads.to_string());
  }

  if let Some(rate_limit) = config.rate_limit {
    ctx
      .flags
      .entry("rate-limit".to_string())
      .or_insert(rate_limit.to_string());
  }

  if let Some(ref output_format) = config.output_format {
    ctx
      .flags
      .entry("output".to_string())
      .or_insert(output_format.clone());
  }

  if let Some(ref output_file) = config.output_file {
    ctx
      .flags
      .entry("output-file".to_string())
      .or_insert(output_file.clone());
  }

  if config.auto_persist.unwrap_or(false) {
    ctx
      .flags
      .entry("persist".to_string())
      .or_insert("true".to_string());
  }

  if config.no_color.unwrap_or(false) {
    ctx
      .flags
      .entry("no-color".to_string())
      .or_insert("true".to_string());
  }

  if config.verbose.unwrap_or(false) {
    ctx
      .flags
      .entry("verbose".to_string())
      .or_insert("true".to_string());
  }

  // Merge command-specific flags from YAML config.
  if let Some(domain) = ctx.domain.as_deref() {
    let resource = ctx.resource.as_deref().unwrap_or("");
    let verb = ctx.verb.as_deref().unwrap_or("");
    let merged_flags = config.command_flags(domain, resource, verb);
    for (key, value) in merged_flags {
      ctx.flags.entry(key).or_insert(value);
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
  fn test_flag_to_schema_boolean() {
    let flag = Flag::new("verbose", "Show verbose output").with_short('v');
    let schema = flag_to_schema(&flag);

    assert_eq!(schema.long, "verbose");
    assert_eq!(schema.short, Some('v'));
    assert!(!schema.expects_value);
    assert_eq!(schema.value_type, ValueType::Bool);
    assert_eq!(schema.description, "Show verbose output");
  }

  #[test]
  fn test_flag_to_schema_with_value() {
    let flag = Flag::new("output", "Output format")
      .with_short('o')
      .with_arg("format")
      .with_default("text");
    let schema = flag_to_schema(&flag);

    assert_eq!(schema.long, "output");
    assert_eq!(schema.short, Some('o'));
    assert!(schema.expects_value);
    assert_eq!(schema.value_type, ValueType::String);
    assert_eq!(schema.default, Some("text".to_string()));
  }

  #[test]
  fn test_flag_to_schema_no_short() {
    let flag = Flag::new("threads", "Number of threads").with_arg("n");
    let schema = flag_to_schema(&flag);

    assert_eq!(schema.long, "threads");
    assert!(schema.short.is_none());
    assert!(schema.expects_value);
  }

  #[test]
  fn test_build_route_tree_has_domains() {
    let tree = build_route_tree_from_registry();
    let domains = tree.domains();

    // The registry should have at least some well-known domains.
    assert!(
      domains.contains(&"dns"),
      "route tree should contain 'dns' domain"
    );
    assert!(
      domains.contains(&"network"),
      "route tree should contain 'network' domain"
    );
    assert!(
      domains.contains(&"web"),
      "route tree should contain 'web' domain"
    );
  }

  #[test]
  fn test_build_route_tree_has_resources() {
    let tree = build_route_tree_from_registry();

    let dns_resources = tree.resources("dns");
    assert!(
      dns_resources.contains(&"record"),
      "dns domain should have 'record' resource"
    );
  }

  #[test]
  fn test_build_route_tree_has_verbs() {
    let tree = build_route_tree_from_registry();

    let dns_record_verbs = tree.verbs("dns", "record");
    assert!(
      dns_record_verbs.contains(&"lookup"),
      "dns/record should have 'lookup' verb"
    );
  }
}
