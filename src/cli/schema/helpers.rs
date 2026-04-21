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

  for token in usage_tail.split_whitespace() {
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
