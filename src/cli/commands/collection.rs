use crate::cli::commands::{Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::collection::browser_creds::BrowserCollector;
use crate::serde_json::Value;

pub struct CollectCommand;

impl Command for CollectCommand {
  fn domain(&self) -> &str {
    "collect"
  }

  fn resource(&self) -> &str {
    "browser"
  }

  fn description(&self) -> &str {
    "Data collection from local system (browsers, secrets, etc)"
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
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "chrome",
        summary: "Collect Chrome/Chromium credentials",
        usage: "rb collect browser chrome",
      },
      Route {
        verb: "firefox",
        summary: "Collect Firefox credentials",
        usage: "rb collect browser firefox",
      },
      Route {
        verb: "all",
        summary: "Collect all browser credentials",
        usage: "rb collect browser all",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![Flag::new("output", "Output format (text, json, yaml)")
      .with_short('o')
      .with_default("text")]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Collect Chrome passwords", "rb collect browser chrome"),
      ("Collect all browser data", "rb collect browser all"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().ok_or("Missing verb")?;
    let collector = BrowserCollector::new();

    let creds = match verb {
      "chrome" => collector.collect_chrome().unwrap_or_default(),
      "firefox" => collector.collect_firefox().unwrap_or_default(),
      "all" => collector.collect(),
      _ => return Err(format!("Unknown browser type: {}", verb)),
    };

    let payload = Self::collection_payload(verb, &creds);
    if render::render_machine_output(ctx, &format!("rb collect browser {}", verb), &payload)? {
      return Ok(());
    }

    if creds.is_empty() {
      Output::info("No credentials found.");
      return Ok(());
    }

    Output::success(&format!("Found {} credentials", creds.len()));
    println!();
    println!(
      "{:<15} {:<30} {:<30} {:<20}",
      "BROWSER", "URL", "USERNAME", "PASSWORD"
    );
    println!("{}", "-".repeat(100));

    for cred in creds {
      let pwd = cred.password.as_deref().unwrap_or("[EMPTY]");
      println!(
        "{:<15} {:<30} {:<30} {:<20}",
        cred.browser,
        cred.url.chars().take(28).collect::<String>(),
        cred.username.chars().take(28).collect::<String>(),
        pwd.chars().take(20).collect::<String>()
      );
    }

    Ok(())
  }
}

impl CollectCommand {
  fn collection_payload(
    browser: &str,
    creds: &[crate::modules::collection::browser_creds::BrowserCredential],
  ) -> Value {
    let credentials: Vec<_> = creds
      .iter()
      .map(|cred| {
        json!({
          "browser": cred.browser,
          "url": cred.url,
          "username": cred.username,
          "password": cred.password.as_deref().unwrap_or("")
        })
      })
      .collect();

    json!({
      "browser": browser,
      "total": creds.len(),
      "credentials": credentials
    })
  }
}
