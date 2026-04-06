/// CLI Parser
///
/// Canonical pattern:
///   rb [domain] [resource] [verb] [target] [args...] [flags]
///
/// Compatibility pattern:
///   rb [domain] [verb] [resource] [target] [args...] [flags]
///
/// The parser prefers canonical `domain resource verb` order and only falls back
/// to compatibility order when that resolves to a known route.
use super::CliContext;

pub fn parse_args(args: &[String]) -> Result<CliContext, String> {
  if args.is_empty() {
    return Err("No command provided".to_string());
  }

  let mut ctx = CliContext::new();
  ctx.raw = args.to_vec();

  // Load YAML config from current directory (cached)
  let config = crate::config::yaml::YamlConfig::load_from_cwd_cached();

  let mut i = 0;
  let mut positionals: Vec<String> = Vec::new();

  // Parse flags
  while i < args.len() {
    let arg = &args[i];

    if arg == "--" {
      positionals.extend_from_slice(&args[i + 1..]);
      break;
    }

    if arg.starts_with("--") {
      let flag_name = arg.trim_start_matches("--");

      if let Some(eq_pos) = flag_name.find('=') {
        let (key, value) = flag_name.split_at(eq_pos);
        ctx.flags.insert(key.to_string(), value[1..].to_string());
      } else if i + 1 < args.len() && !args[i + 1].starts_with('-') {
        i += 1;
        ctx.flags.insert(flag_name.to_string(), args[i].clone());
      } else {
        ctx.flags.insert(flag_name.to_string(), "true".to_string());
      }
    } else if arg.starts_with('-') && arg.len() >= 2 {
      let flag_char = &arg[1..2];

      if i + 1 < args.len() && !args[i + 1].starts_with('-') {
        i += 1;
        ctx.flags.insert(flag_char.to_string(), args[i].clone());
      } else {
        ctx.flags.insert(flag_char.to_string(), "true".to_string());
      }
    } else {
      positionals.push(arg.clone());
    }

    i += 1;
  }

  if let Some(parsed) = parse_positionals(&positionals) {
    ctx.domain = parsed.domain;
    ctx.resource = parsed.resource;
    ctx.verb = parsed.verb;
    ctx.target = parsed.target;
    ctx.args = parsed.args;
  }

  apply_config_defaults(&mut ctx, config);

  Ok(ctx)
}

fn matches_resource_first_route(domain: &str, resource: &str, verb: &str) -> bool {
  crate::cli::schema::route_exists(domain, resource, verb)
}

fn matches_compat_route(domain: &str, verb: &str, resource: &str) -> bool {
  matches_resource_first_route(domain, resource, verb)
}

#[derive(Default)]
struct ParsedPositionals {
  domain: Option<String>,
  resource: Option<String>,
  verb: Option<String>,
  target: Option<String>,
  args: Vec<String>,
}

fn parse_positionals(positionals: &[String]) -> Option<ParsedPositionals> {
  let domain = positionals.first()?.clone();
  let mut parsed = ParsedPositionals {
    domain: Some(domain.clone()),
    ..ParsedPositionals::default()
  };

  if let Some(second) = positionals.get(1) {
    parsed.resource = Some(second.clone());
  }

  if let Some(third) = positionals.get(2) {
    parsed.verb = Some(third.clone());

    if let Some(second) = positionals.get(1) {
      if matches_resource_first_route(&domain, second, third) {
        parsed.resource = Some(second.clone());
        parsed.verb = Some(third.clone());
      } else if matches_compat_route(&domain, second, third) {
        parsed.resource = Some(third.clone());
        parsed.verb = Some(second.clone());
      }
    }
  }

  if let Some(target) = positionals.get(3) {
    parsed.target = Some(target.clone());
  }

  if positionals.len() > 4 {
    parsed.args = positionals[4..].to_vec();
  }

  Some(parsed)
}

fn apply_config_defaults(ctx: &mut CliContext, config: &crate::config::yaml::YamlConfig) {
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

  if let Some(domain) = ctx.domain.as_deref() {
    let resource = ctx.resource.as_deref().unwrap_or("");
    let verb = ctx.verb.as_deref().unwrap_or("");
    let merged_flags = config.command_flags(domain, resource, verb);
    for (key, value) in merged_flags {
      ctx.flags.entry(key).or_insert(value);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Compatibility pattern: rb [domain] [verb] [resource] [target]
  #[test]
  fn test_compat_pattern_network_scan() {
    // rb network scan ports 192.168.1.1
    let args = vec![
      "network".to_string(),
      "scan".to_string(),
      "ports".to_string(),
      "192.168.1.1".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("network".to_string()));
    assert_eq!(ctx.verb, Some("scan".to_string()));
    assert_eq!(ctx.resource, Some("ports".to_string()));
    assert_eq!(ctx.target, Some("192.168.1.1".to_string()));
  }

  #[test]
  fn test_compat_pattern_exploit_shell() {
    // rb exploit shell payload 10.10.10.10
    let args = vec![
      "exploit".to_string(),
      "shell".to_string(),
      "payload".to_string(),
      "10.10.10.10".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("exploit".to_string()));
    assert_eq!(ctx.verb, Some("shell".to_string()));
    assert_eq!(ctx.resource, Some("payload".to_string()));
    assert_eq!(ctx.target, Some("10.10.10.10".to_string()));
  }

  #[test]
  fn test_compat_pattern_dns_lookup() {
    // rb dns lookup record example.com
    let args = vec![
      "dns".to_string(),
      "lookup".to_string(),
      "record".to_string(),
      "example.com".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("dns".to_string()));
    assert_eq!(ctx.verb, Some("lookup".to_string()));
    assert_eq!(ctx.resource, Some("record".to_string()));
    assert_eq!(ctx.target, Some("example.com".to_string()));
  }

  #[test]
  fn test_compat_pattern_web_get() {
    // rb web get asset https://example.com
    let args = vec![
      "web".to_string(),
      "get".to_string(),
      "asset".to_string(),
      "https://example.com".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("web".to_string()));
    assert_eq!(ctx.verb, Some("get".to_string()));
    assert_eq!(ctx.resource, Some("asset".to_string()));
    assert_eq!(ctx.target, Some("https://example.com".to_string()));
  }

  #[test]
  fn test_prefers_resource_first_when_route_exists() {
    let args = vec![
      "tls".to_string(),
      "security".to_string(),
      "audit".to_string(),
      "example.com".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("tls".to_string()));
    assert_eq!(ctx.resource, Some("security".to_string()));
    assert_eq!(ctx.verb, Some("audit".to_string()));
    assert_eq!(ctx.target, Some("example.com".to_string()));
  }

  #[test]
  fn test_prefers_resource_first_for_crypto_hash_verify() {
    let args = vec![
      "crypto".to_string(),
      "hash".to_string(),
      "verify".to_string(),
      "rb-linux-x86_64".to_string(),
      "deadbeef".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("crypto".to_string()));
    assert_eq!(ctx.resource, Some("hash".to_string()));
    assert_eq!(ctx.verb, Some("verify".to_string()));
    assert_eq!(ctx.target, Some("rb-linux-x86_64".to_string()));
    assert_eq!(ctx.args, vec!["deadbeef".to_string()]);
  }

  // Canonical pattern tests: rb [domain] [resource] [verb] [target]
  #[test]
  fn test_canonical_pattern_network_ports_scan() {
    // rb network ports scan 192.168.1.1
    let args = vec![
      "network".to_string(),
      "ports".to_string(),
      "scan".to_string(),
      "192.168.1.1".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("network".to_string()));
    assert_eq!(ctx.resource, Some("ports".to_string()));
    assert_eq!(ctx.verb, Some("scan".to_string()));
    assert_eq!(ctx.target, Some("192.168.1.1".to_string()));
  }

  #[test]
  fn test_canonical_pattern_exploit_payload_shell() {
    // rb exploit payload shell 10.10.10.10
    let args = vec![
      "exploit".to_string(),
      "payload".to_string(),
      "shell".to_string(),
      "10.10.10.10".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("exploit".to_string()));
    assert_eq!(ctx.resource, Some("payload".to_string()));
    assert_eq!(ctx.verb, Some("shell".to_string()));
    assert_eq!(ctx.target, Some("10.10.10.10".to_string()));
  }

  #[test]
  fn test_canonical_pattern_with_aliases_prefers_resource_first() {
    let args = vec![
      "tls".to_string(),
      "sec".to_string(),
      "audit".to_string(),
      "example.com".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("tls".to_string()));
    assert_eq!(ctx.resource, Some("sec".to_string()));
    assert_eq!(ctx.verb, Some("audit".to_string()));
    assert_eq!(ctx.target, Some("example.com".to_string()));
  }

  #[test]
  fn test_with_flags() {
    // rb network scan ports 192.168.1.1 --threads 200
    let args = vec![
      "network".to_string(),
      "scan".to_string(),
      "ports".to_string(),
      "192.168.1.1".to_string(),
      "--threads".to_string(),
      "200".to_string(),
    ];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("network".to_string()));
    assert_eq!(ctx.verb, Some("scan".to_string()));
    assert_eq!(ctx.resource, Some("ports".to_string()));
    assert_eq!(ctx.target, Some("192.168.1.1".to_string()));
    assert_eq!(ctx.get_flag("threads"), Some("200".to_string()));
  }

  // Global/utility commands
  #[test]
  fn test_global_version() {
    let args = vec!["version".to_string()];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("version".to_string()));
    assert_eq!(ctx.resource, None);
    assert_eq!(ctx.verb, None);
  }

  #[test]
  fn test_global_help() {
    let args = vec!["help".to_string()];
    let ctx = parse_args(&args).unwrap();

    assert_eq!(ctx.domain, Some("help".to_string()));
    assert_eq!(ctx.resource, None);
    assert_eq!(ctx.verb, None);
  }
}
