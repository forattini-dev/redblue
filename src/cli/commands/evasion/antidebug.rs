//! Anti-debugging detection command

use super::{colored, GREEN, RED};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::antidebug;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionAntidebugCommand;

impl Command for EvasionAntidebugCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "antidebug"
  }

  fn description(&self) -> &str {
    "Anti-debugging detection and evasion techniques"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "check",
        summary: "Run all anti-debugging checks",
        usage: "rb evasion antidebug check",
      },
      Route {
        verb: "quick",
        summary: "Quick debugger detection (boolean)",
        usage: "rb evasion antidebug quick",
      },
      Route {
        verb: "paranoid",
        summary: "Maximum sensitivity detection",
        usage: "rb evasion antidebug paranoid",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("sensitivity", "Detection sensitivity (0-100)")
        .with_short('s')
        .with_default("50"),
      Flag::new("aggressive", "Use aggressive response techniques"),
      Flag::new("format", "Output format (text, json)").with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Run all checks", "rb evasion antidebug check"),
      ("Quick check", "rb evasion antidebug quick"),
      ("Paranoid mode", "rb evasion antidebug paranoid"),
      (
        "Custom sensitivity",
        "rb evasion antidebug check --sensitivity 80",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("check");

    match verb {
      "check" => execute_antidebug_check(ctx),
      "quick" => execute_antidebug_quick(),
      "paranoid" => execute_antidebug_paranoid(),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_antidebug_check(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";

  let sensitivity: u32 = ctx
    .flags
    .get("sensitivity")
    .and_then(|s| s.parse().ok())
    .unwrap_or(50);
  let aggressive = ctx.flags.contains_key("aggressive");

  if !is_json {
    Output::header("Anti-Debugging Checks");
    println!();
    Output::spinner_start("Running detection checks");
  }

  let ad = antidebug::AntiDebug::new(sensitivity, aggressive);
  let result = ad.check_all();

  if is_json {
    let checks: Vec<_> = result
      .checks
      .iter()
      .map(|(name, detected)| {
        json!({
            "name": name.clone(),
            "key": name.to_lowercase().replace(' ', "_"),
            "detected": *detected
        })
      })
      .collect();
    Output::json_value(&json!({
        "debugger_detected": result.debugger_detected,
        "score": result.score,
        "sensitivity": sensitivity,
        "aggressive": aggressive,
        "action": format!("{:?}", result.action),
        "checks": checks
    }));
    return Ok(());
  }

  Output::spinner_done();
  println!();

  // Show overall result
  if result.debugger_detected {
    Output::error(&format!("Debugger DETECTED (score: {}/100)", result.score));
  } else {
    Output::success(&format!(
      "No debugger detected (score: {}/100)",
      result.score
    ));
  }

  println!();
  Output::info("Individual Checks:");

  for (name, detected) in &result.checks {
    if *detected {
      println!("    {} {}", colored("[DETECTED]", RED), name);
    } else {
      println!("    {} {}", colored("[CLEAN]", GREEN), name);
    }
  }

  println!();
  Output::info(&format!("Recommended Action: {:?}", result.action));

  Ok(())
}

fn execute_antidebug_quick() -> Result<(), String> {
  Output::header("Quick Debugger Check");
  println!();

  let detected = antidebug::quick_check();

  if detected {
    Output::error("Debugger DETECTED");
    println!();
    Output::warning("Execution may be monitored");
  } else {
    Output::success("No debugger detected");
  }

  Ok(())
}

fn execute_antidebug_paranoid() -> Result<(), String> {
  Output::header("Paranoid Debugger Check");
  println!();

  Output::spinner_start("Running paranoid checks (max sensitivity)");

  let result = antidebug::paranoid_check();

  Output::spinner_done();
  println!();

  if result.debugger_detected {
    Output::error(&format!(
      "Debugger LIKELY PRESENT (score: {}/100)",
      result.score
    ));
    println!();
    for (name, detected) in &result.checks {
      if *detected {
        println!("    {} {}", colored("[!]", RED), name);
      }
    }
  } else {
    Output::success("Environment appears clean");
  }

  Ok(())
}
