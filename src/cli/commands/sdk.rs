use super::{all_commands, print_help, Command, Flag, Route};
use crate::cli::CliContext;
use crate::utils::json::JsonValue;

/// Hidden SDK bridge for machine-readable CLI metadata.
pub struct SdkBridgeCommand;

impl Command for SdkBridgeCommand {
    fn domain(&self) -> &str {
        "sdk"
    }

    fn resource(&self) -> &str {
        "bridge"
    }

    fn description(&self) -> &str {
        "Internal SDK bridge metadata"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "manifest",
            summary: "Emit CLI metadata manifest as JSON",
            usage: "rb sdk bridge manifest [--pretty]",
        }]
    }

    fn hidden(&self) -> bool {
        true
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("pretty", "Pretty-print manifest JSON"),
            Flag::new(
                "include-hidden",
                "Include internal hidden commands in the manifest",
            ),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("manifest");
        match verb {
            "manifest" => {
                let manifest = build_manifest(ctx.has_flag("include-hidden"));
                if ctx.has_flag("pretty") {
                    println!("{}", to_pretty_json(&manifest, 0));
                } else {
                    println!("{}", manifest.to_json_string());
                }
                Ok(())
            }
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use `rb sdk bridge manifest`.",
                verb
            )),
        }
    }
}

fn build_manifest(include_hidden: bool) -> JsonValue {
    let commands = all_commands()
        .iter()
        .filter(|command| include_hidden || !command.hidden())
        .map(|command| command_manifest(command.as_ref()))
        .collect();

    JsonValue::object(vec![
        (
            "version".to_string(),
            JsonValue::from(env!("CARGO_PKG_VERSION")),
        ),
        ("binary".to_string(), JsonValue::from("redblue")),
        (
            "machine_output".to_string(),
            JsonValue::object(vec![
                ("global_flag".to_string(), JsonValue::from("json")),
                (
                    "description".to_string(),
                    JsonValue::from(
                        "Global machine-readable output hint used by the JS SDK wrapper",
                    ),
                ),
            ]),
        ),
        ("commands".to_string(), JsonValue::array(commands)),
    ])
}

fn command_manifest(command: &dyn Command) -> JsonValue {
    let flags = command.flags();
    let routes = command.routes();
    let preferred_flag = machine_output_flag(&flags);

    JsonValue::object(vec![
        ("domain".to_string(), JsonValue::from(command.domain())),
        ("resource".to_string(), JsonValue::from(command.resource())),
        (
            "description".to_string(),
            JsonValue::from(command.description()),
        ),
        ("hidden".to_string(), JsonValue::from(command.hidden())),
        (
            "machine_output".to_string(),
            JsonValue::object(vec![
                ("global_flag".to_string(), JsonValue::from("json")),
                (
                    "preferred_flag".to_string(),
                    preferred_flag
                        .clone()
                        .map(JsonValue::from)
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "preferred_value".to_string(),
                    if preferred_flag.is_some() {
                        JsonValue::from("json")
                    } else {
                        JsonValue::Null
                    },
                ),
            ]),
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
            "routes".to_string(),
            JsonValue::array(
                routes
                    .iter()
                    .map(|route| route_manifest(command, route))
                    .collect(),
            ),
        ),
    ])
}

fn flag_manifest(flag: &super::Flag, preferred_flag: Option<&str>) -> JsonValue {
    JsonValue::object(vec![
        ("long".to_string(), JsonValue::from(flag.long.clone())),
        (
            "short".to_string(),
            flag.short
                .map(|value| JsonValue::from(value.to_string()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "description".to_string(),
            JsonValue::from(flag.description.clone()),
        ),
        (
            "default".to_string(),
            flag.default
                .clone()
                .map(JsonValue::from)
                .unwrap_or(JsonValue::Null),
        ),
        (
            "arg".to_string(),
            flag.arg
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

fn route_manifest(command: &dyn Command, route: &Route) -> JsonValue {
    JsonValue::object(vec![
        ("verb".to_string(), JsonValue::from(route.verb)),
        ("summary".to_string(), JsonValue::from(route.summary)),
        ("usage".to_string(), JsonValue::from(route.usage)),
        (
            "positionals".to_string(),
            JsonValue::array(parse_route_positionals(command, route)),
        ),
    ])
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
            ("index".to_string(), JsonValue::from(slot_index)),
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

fn machine_output_flag(flags: &[super::Flag]) -> Option<String> {
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

fn to_pretty_json(value: &JsonValue, indent: usize) -> String {
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            value.to_json_string()
        }
        JsonValue::Array(items) => {
            if items.is_empty() {
                return "[]".to_string();
            }

            let mut out = String::from("[\n");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&"  ".repeat(indent + 1));
                out.push_str(&to_pretty_json(item, indent + 1));
            }
            out.push('\n');
            out.push_str(&"  ".repeat(indent));
            out.push(']');
            out
        }
        JsonValue::Object(entries) => {
            if entries.is_empty() {
                return "{}".to_string();
            }

            let mut out = String::from("{\n");
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&"  ".repeat(indent + 1));
                out.push_str(&JsonValue::from(key.clone()).to_json_string());
                out.push_str(": ");
                out.push_str(&to_pretty_json(item, indent + 1));
            }
            out.push('\n');
            out.push_str(&"  ".repeat(indent));
            out.push('}');
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_manifest, kebab_to_camel, parse_placeholder};

    #[test]
    fn parse_required_placeholder() {
        let parsed = parse_placeholder("<target>").unwrap();
        assert_eq!(parsed.0, "target");
        assert!(parsed.1);
        assert!(!parsed.2);
    }

    #[test]
    fn parse_optional_repeated_placeholder() {
        let parsed = parse_placeholder("[files...]").unwrap();
        assert_eq!(parsed.0, "files");
        assert!(!parsed.1);
        assert!(parsed.2);
    }

    #[test]
    fn skip_flag_placeholders() {
        assert!(parse_placeholder("[--format json]").is_none());
        assert!(parse_placeholder("[FLAGS]").is_none());
    }

    #[test]
    fn convert_kebab_case_to_camel_case() {
        assert_eq!(kebab_to_camel("rate-limit"), "rateLimit");
    }

    #[test]
    fn manifest_hides_internal_sdk_command_by_default() {
        let manifest = build_manifest(false);
        let commands = manifest
            .get("commands")
            .and_then(|value| value.as_array())
            .unwrap();

        assert!(commands
            .iter()
            .all(|value| { value.get("domain").and_then(|value| value.as_str()) != Some("sdk") }));
    }

    #[test]
    fn manifest_exposes_dns_tls_and_network_ports_namespaces() {
        let manifest = build_manifest(false);
        let commands = manifest
            .get("commands")
            .and_then(|value| value.as_array())
            .unwrap();

        let mut found_dns = false;
        let mut found_tls = false;
        let mut found_ports = false;

        for command in commands {
            let domain = command.get("domain").and_then(|value| value.as_str());
            let resource = command.get("resource").and_then(|value| value.as_str());

            if domain == Some("dns") && resource == Some("record") {
                found_dns = true;
                assert_eq!(
                    command
                        .get("machine_output")
                        .and_then(|value| value.get("global_flag"))
                        .and_then(|value| value.as_str()),
                    Some("json")
                );
            }

            if domain == Some("tls") && resource == Some("security") {
                found_tls = true;
            }

            if domain == Some("network") && resource == Some("ports") {
                found_ports = true;
            }
        }

        assert!(found_dns);
        assert!(found_tls);
        assert!(found_ports);
    }
}
