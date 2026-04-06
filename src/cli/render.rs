use super::{format::OutputFormat, output::Output, CliContext};
use crate::serde_json::Value;

pub fn render_machine_output(
  ctx: &CliContext,
  route: &str,
  json_value: &Value,
) -> Result<bool, String> {
  match ctx.get_output_format() {
    OutputFormat::Human => Ok(false),
    OutputFormat::Json => {
      Output::json_value(json_value);
      Ok(true)
    }
    OutputFormat::Yaml => Err(yaml_not_supported(route)),
  }
}

pub fn render_machine_output_with_yaml<F>(
  ctx: &CliContext,
  route: &str,
  json_value: &Value,
  yaml_renderer: F,
) -> Result<bool, String>
where
  F: FnOnce() -> Result<(), String>,
{
  match ctx.get_output_format() {
    OutputFormat::Human => Ok(false),
    OutputFormat::Json => {
      Output::json_value(json_value);
      Ok(true)
    }
    OutputFormat::Yaml => {
      yaml_renderer()?;
      Ok(true)
    }
  }
}

fn yaml_not_supported(route: &str) -> String {
  format!(
    "YAML output is not supported for `{}` yet. Use `--json` or human output.",
    route
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn render_machine_output_allows_human_to_fall_through() {
    let ctx = CliContext::new();
    let rendered = render_machine_output(&ctx, "rb dns record lookup", &Value::Null).unwrap();
    assert!(!rendered);
  }

  #[test]
  fn render_machine_output_rejects_yaml_when_not_supported() {
    let mut ctx = CliContext::new();
    ctx.flags.insert("output".to_string(), "yaml".to_string());
    let error = render_machine_output(&ctx, "rb network host ping", &Value::Null).unwrap_err();
    assert!(error.contains("YAML output is not supported"));
  }

  #[test]
  fn render_machine_output_with_yaml_runs_yaml_renderer() {
    let mut ctx = CliContext::new();
    ctx.flags.insert("output".to_string(), "yaml".to_string());
    let mut rendered_yaml = false;
    let rendered =
      render_machine_output_with_yaml(&ctx, "rb dns record lookup", &Value::Null, || {
        rendered_yaml = true;
        Ok(())
      })
      .unwrap();
    assert!(rendered);
    assert!(rendered_yaml);
  }
}
