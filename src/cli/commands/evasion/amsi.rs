//! AMSI bypass command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::evasion::amsi;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionAmsiCommand;

impl Command for EvasionAmsiCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "amsi"
  }

  fn description(&self) -> &str {
    "AMSI bypass techniques (Windows)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "powershell",
        summary: "Generate PowerShell AMSI bypass",
        usage: "rb evasion amsi powershell [--method <m>]",
      },
      Route {
        verb: "csharp",
        summary: "Generate C# AMSI bypass code",
        usage: "rb evasion amsi csharp",
      },
      Route {
        verb: "obfuscated",
        summary: "Generate obfuscated bypass",
        usage: "rb evasion amsi obfuscated",
      },
      Route {
        verb: "providers",
        summary: "List known AMSI provider CLSIDs",
        usage: "rb evasion amsi providers",
      },
    ]
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("method", "Bypass method (patch, initfailed, context)")
        .with_short('m')
        .with_default("patch"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("PowerShell bypass", "rb evasion amsi powershell"),
      (
        "Init failed method",
        "rb evasion amsi powershell --method initfailed",
      ),
      ("C# bypass", "rb evasion amsi csharp"),
      ("Obfuscated bypass", "rb evasion amsi obfuscated"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("powershell");

    match verb {
      "powershell" | "ps" => execute_amsi_powershell(ctx),
      "csharp" | "cs" => execute_amsi_csharp(),
      "obfuscated" | "obf" => execute_amsi_obfuscated(),
      "providers" => execute_amsi_providers(),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_amsi_powershell(ctx: &CliContext) -> Result<(), String> {
  let method = ctx
    .flags
    .get("method")
    .map(|s| s.as_str())
    .unwrap_or("patch");

  Output::header("PowerShell AMSI Bypass");
  println!();

  let bypass_method = match method {
    "patch" => amsi::AmsiBypassMethod::PatchAmsiScanBuffer,
    "initfailed" | "init" => amsi::AmsiBypassMethod::ForceInitFailed,
    "context" => amsi::AmsiBypassMethod::CorruptContext,
    _ => {
      return Err(format!(
        "Unknown method: {}. Use: patch, initfailed, context",
        method
      ))
    }
  };

  Output::item("Method", &format!("{:?}", bypass_method));
  Output::warning("For authorized penetration testing only!");
  println!();

  let script = amsi::generate_powershell_bypass(bypass_method);
  println!("{}", script);

  Ok(())
}

fn execute_amsi_csharp() -> Result<(), String> {
  Output::header("C# AMSI Bypass");
  println!();

  Output::warning("For authorized penetration testing only!");
  println!();

  let code = amsi::generate_csharp_bypass();
  println!("{}", code);

  Ok(())
}

fn execute_amsi_obfuscated() -> Result<(), String> {
  Output::header("Obfuscated AMSI Bypass");
  println!();

  Output::info("This bypass uses string concatenation to avoid signatures");
  Output::warning("For authorized penetration testing only!");
  println!();

  let script = amsi::generate_obfuscated_bypass();
  println!("{}", script);

  Ok(())
}

fn execute_amsi_providers() -> Result<(), String> {
  Output::header("AMSI Provider CLSIDs");
  println!();

  Output::info("Known AMSI providers:");
  println!();

  for clsid in amsi::amsi_provider_clsids() {
    println!("    {}", clsid);
  }

  println!();
  Output::info("These CLSIDs are registered in:");
  println!("    HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\");

  Ok(())
}
