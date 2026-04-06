use super::{print_help, Command, Flag, Route};
use crate::cli::schema;
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

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    match verb {
      "manifest" => crate::cli::schema::RouteMetadata::new().with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      ),
      _ => {
        crate::cli::schema::RouteMetadata::new().with_machine_output(self.metadata().machine_output)
      }
    }
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
  schema::build_manifest(include_hidden)
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
  use super::build_manifest;

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
    let mut found_system = false;

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
        assert_eq!(
          command
            .get("canonical_order")
            .and_then(|value| value.as_str()),
          Some("domain-resource-verb")
        );
      }

      if domain == Some("tls") && resource == Some("security") {
        found_tls = true;
      }

      if domain == Some("network") && resource == Some("ports") {
        found_ports = true;
      }

      if domain == Some("system") && resource == Some("host") {
        found_system = true;
        assert_eq!(
          command
            .get("machine_output")
            .and_then(|value| value.get("json_support"))
            .and_then(|value| value.as_str()),
          Some("guaranteed")
        );
      }
    }

    assert!(found_dns);
    assert!(found_tls);
    assert!(found_ports);
    assert!(found_system);
  }
}
