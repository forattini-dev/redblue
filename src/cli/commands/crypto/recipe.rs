//! Recipe command - CyberChef-style operation chains

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::crypto::recipe::RecipeExecutor;
use crate::json;
use std::fs;

use super::helpers::hex_encode;

/// Recipe command (CyberChef-style operation chains)
pub struct CryptoRecipeCommand;

impl Command for CryptoRecipeCommand {
  fn domain(&self) -> &str {
    "crypto"
  }

  fn resource(&self) -> &str {
    "recipe"
  }

  fn description(&self) -> &str {
    "Recipe system - CyberChef-style operation chains"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let json_support = match verb {
      "run" | "bake" => crate::cli::schema::JsonSupport::Guaranteed,
      _ => crate::cli::schema::JsonSupport::BestEffort,
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(json_support)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "run",
        summary: "Execute a recipe chain",
        usage: "rb crypto recipe run <chain> <input>",
      },
      Route {
        verb: "bake",
        summary: "Alias for run",
        usage: "rb crypto recipe bake 'base64_decode | hex_encode' <input>",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("file", "Read input from file")
        .with_short('f')
        .with_arg("FILE"),
      Flag::new("format", "Output format (text, json)").with_default("text"),
      Flag::new("verbose", "Show step-by-step execution").with_short('v'),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Decode base64 then rot13",
        "rb crypto recipe run 'base64_decode | rot13' 'U0dWc2JHOD0='",
      ),
      (
        "Hex encode then base64",
        "rb crypto recipe run 'hex_encode | base64_encode' 'Hello'",
      ),
      (
        "Caesar decrypt with shift",
        "rb crypto recipe run 'caesar_decrypt(shift=3)' 'KHOOR'",
      ),
      (
        "Chain from file",
        "rb crypto recipe run 'base64_decode | hex_decode' --file encoded.txt",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "run" | "bake" => self.execute_recipe(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!(
        "Unknown verb '{}'. Use: rb crypto recipe help",
        verb
      )),
    }
  }
}

impl CryptoRecipeCommand {
  fn execute_recipe(&self, ctx: &CliContext) -> Result<(), String> {
    let recipe_str = ctx
      .target
      .as_ref()
      .ok_or("Missing recipe. Usage: rb crypto recipe run '<chain>' <input>")?;

    let input = if let Some(file) = ctx.get_flag("file") {
      fs::read(&file).map_err(|e| format!("Failed to read file '{}': {}", file, e))?
    } else if let Some(arg) = ctx.args.first() {
      arg.as_bytes().to_vec()
    } else {
      return Err("No input provided.".to_string());
    };

    let executor = RecipeExecutor::new();
    let result = executor.execute_string(recipe_str, &input);
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let verbose = ctx.has_flag("verbose");

    if !result.success {
      return Err(result.error.unwrap_or_else(|| "Unknown error".to_string()));
    }

    if format == "json" {
      let steps: Vec<_> = result
        .steps
        .iter()
        .map(|step| {
          json!({
              "operation": step.operation.clone(),
              "mode": step.mode.clone(),
              "output_size": step.output.len()
          })
        })
        .collect();
      let output = String::from_utf8(result.output.clone()).ok();
      let output_hex = if output.is_none() {
        Some(hex_encode(&result.output))
      } else {
        None
      };
      let payload = json!({
        "success": true,
        "steps": steps,
        "output": output,
        "output_hex": output_hex
      });
      if render::render_machine_output(ctx, "rb crypto recipe run", &payload)? {
        return Ok(());
      }
    } else {
      if verbose {
        Output::header("Recipe Execution");
        Output::item("Recipe", recipe_str);
        println!();

        for (i, step) in result.steps.iter().enumerate() {
          println!("  Step {}: {} ({})", i + 1, step.operation, step.mode);
          if let Ok(s) = String::from_utf8(step.output.clone()) {
            let preview: String = s.chars().take(50).collect();
            if s.len() > 50 {
              println!("    -> {}...", preview);
            } else {
              println!("    -> {}", preview);
            }
          } else {
            println!("    -> <{} bytes>", step.output.len());
          }
        }

        println!();
        Output::subheader("Final Output");
      }

      if let Ok(s) = String::from_utf8(result.output.clone()) {
        println!("{}", s);
      } else {
        println!("{}", hex_encode(&result.output));
      }
    }

    Ok(())
  }
}
