//! Cyclic command - De Bruijn sequence generator for buffer overflow offset detection

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::crypto::analysis::CyclicGenerator;
use crate::json;

use super::helpers::hex_encode;

pub struct CryptoCyclicCommand;

impl Command for CryptoCyclicCommand {
  fn domain(&self) -> &str {
    "crypto"
  }

  fn resource(&self) -> &str {
    "cyclic"
  }

  fn description(&self) -> &str {
    "De Bruijn sequence generator for buffer overflow offset detection"
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
      "generate" | "find" | "offset" => crate::cli::schema::JsonSupport::Guaranteed,
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
        verb: "generate",
        summary: "Generate cyclic pattern of specified length",
        usage: "rb crypto cyclic generate <length> [-n PATTERN_SIZE]",
      },
      Route {
        verb: "find",
        summary: "Find offset of pattern in cyclic sequence",
        usage: "rb crypto cyclic find <pattern> [-n PATTERN_SIZE] [--max-length LEN]",
      },
      Route {
        verb: "offset",
        summary: "Get pattern at specific offset",
        usage: "rb crypto cyclic offset <offset> [--length LEN]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("n", "Pattern length (4 for 32-bit, 8 for 64-bit)")
        .with_arg("SIZE")
        .with_default("4"),
      Flag::new("max-length", "Maximum sequence length to search")
        .with_arg("LEN")
        .with_default("20000"),
      Flag::new("length", "Length of pattern to generate at offset")
        .with_short('l')
        .with_arg("LEN")
        .with_default("100"),
      Flag::new("format", "Output format (text, json, raw)")
        .with_short('o')
        .with_default("text"),
      Flag::new("hex", "Interpret pattern as hex string"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Generate 100-byte pattern", "rb crypto cyclic generate 100"),
      (
        "Generate 8-byte pattern size",
        "rb crypto cyclic generate 200 -n 8",
      ),
      ("Find offset from pattern", "rb crypto cyclic find 'caaa'"),
      (
        "Find offset from hex (EIP)",
        "rb crypto cyclic find 0x61616163 --hex",
      ),
      ("Get pattern at offset 100", "rb crypto cyclic offset 100"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "generate" | "gen" => self.generate_pattern(ctx),
      "find" | "lookup" => self.find_offset(ctx),
      "offset" | "at" => self.pattern_at_offset(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!(
        "Unknown verb '{}'. Use: rb crypto cyclic help",
        verb
      )),
    }
  }
}

impl CryptoCyclicCommand {
  fn generate_pattern(&self, ctx: &CliContext) -> Result<(), String> {
    let length: usize = ctx
      .target
      .as_ref()
      .or_else(|| ctx.args.first())
      .ok_or("Length required. Usage: rb crypto cyclic generate <length>")?
      .parse()
      .map_err(|_| "Invalid length value")?;

    let n: usize = ctx
      .get_flag("n")
      .map(|s| s.parse())
      .transpose()
      .map_err(|_| "Invalid pattern size")?
      .unwrap_or(4);

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    let gen = CyclicGenerator::new().pattern_length(n);
    let pattern = gen.generate(length);

    match format.as_str() {
      "json" => {
        let value = if let Ok(s) = String::from_utf8(pattern.clone()) {
          json!({
              "length": pattern.len(),
              "pattern_size": n,
              "pattern": s,
          })
        } else {
          json!({
              "length": pattern.len(),
              "pattern_size": n,
              "pattern_hex": hex_encode(&pattern),
          })
        };
        if render::render_machine_output(ctx, "rb crypto cyclic generate", &value)? {
          return Ok(());
        }
      }
      "raw" => {
        // Write raw bytes to stdout
        use std::io::Write;
        let mut stdout = std::io::stdout();
        stdout.write_all(&pattern).map_err(|e| e.to_string())?;
      }
      _ => {
        Output::header("Cyclic Pattern");
        Output::item("Length", &format!("{} bytes", pattern.len()));
        Output::item(
          "Pattern size",
          &format!(
            "{} bytes ({})",
            n,
            if n == 4 {
              "32-bit"
            } else if n == 8 {
              "64-bit"
            } else {
              "custom"
            }
          ),
        );
        println!();

        if let Ok(s) = String::from_utf8(pattern.clone()) {
          // For text output, show in chunks
          if s.len() <= 80 {
            println!("{}", s);
          } else {
            for chunk in s.as_bytes().chunks(80) {
              println!("{}", String::from_utf8_lossy(chunk));
            }
          }
        } else {
          println!("{}", hex_encode(&pattern));
        }
      }
    }

    Ok(())
  }

  fn find_offset(&self, ctx: &CliContext) -> Result<(), String> {
    let pattern_input = ctx
      .target
      .as_ref()
      .or_else(|| ctx.args.first())
      .ok_or("Pattern required. Usage: rb crypto cyclic find <pattern>")?;

    let n: usize = ctx
      .get_flag("n")
      .map(|s| s.parse())
      .transpose()
      .map_err(|_| "Invalid pattern size")?
      .unwrap_or(4);

    let max_length: usize = ctx
      .get_flag("max-length")
      .map(|s| s.parse())
      .transpose()
      .map_err(|_| "Invalid max-length value")?
      .unwrap_or(20000);

    let is_hex = ctx.has_flag("hex");
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    let gen = CyclicGenerator::new().pattern_length(n);

    // Try to find the offset
    let result = if is_hex {
      gen.find_offset_hex(pattern_input, max_length)
    } else {
      let pattern_bytes = pattern_input.as_bytes();
      if pattern_bytes.len() == n {
        gen.find_offset(pattern_bytes, max_length)
      } else {
        // Try as hex anyway if length is wrong
        gen.find_offset_hex(pattern_input, max_length).or_else(|| {
          // Maybe it's a hex number without 0x prefix
          if pattern_input.chars().all(|c| c.is_ascii_hexdigit()) {
            gen.find_offset_hex(pattern_input, max_length)
          } else {
            None
          }
        })
      }
    };

    match format.as_str() {
      "json" => {
        let payload = json!({
          "pattern": pattern_input,
          "pattern_size": n,
          "found": result.is_some(),
          "offset": result,
        });
        if render::render_machine_output(ctx, "rb crypto cyclic find", &payload)? {
          return Ok(());
        }
      }
      _ => {
        if let Some(offset) = result {
          Output::header("Cyclic Pattern Offset");
          Output::item("Pattern", pattern_input);
          Output::item("Pattern size", &format!("{} bytes", n));
          Output::item("Max search", &format!("{} bytes", max_length));
          println!();
          Output::success(&format!("Found at offset: {}", offset));
          println!();

          // Show useful info for exploit dev
          Output::subheader("Exploit Development Info");
          println!("  Buffer size needed:  {} bytes", offset);
          println!("  Padding before EIP:  {} bytes", offset);
          println!("  Python:              b'A' * {}", offset);
          println!("  Perl:                'A' x {}", offset);
        } else {
          Output::error(&format!(
            "Pattern '{}' not found in first {} bytes",
            pattern_input, max_length
          ));
          Output::info("Try increasing --max-length or check pattern size with -n");
        }
      }
    }

    Ok(())
  }

  fn pattern_at_offset(&self, ctx: &CliContext) -> Result<(), String> {
    let offset: usize = ctx
      .target
      .as_ref()
      .or_else(|| ctx.args.first())
      .ok_or("Offset required. Usage: rb crypto cyclic offset <offset>")?
      .parse()
      .map_err(|_| "Invalid offset value")?;

    let n: usize = ctx
      .get_flag("n")
      .map(|s| s.parse())
      .transpose()
      .map_err(|_| "Invalid pattern size")?
      .unwrap_or(4);

    let length: usize = ctx
      .get_flag("length")
      .map(|s| s.parse())
      .transpose()
      .map_err(|_| "Invalid length value")?
      .unwrap_or(100);

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    let gen = CyclicGenerator::new().pattern_length(n);
    let pattern = gen.pattern_at(offset, length);

    match format.as_str() {
      "json" => {
        let value = if let Ok(s) = String::from_utf8(pattern.clone()) {
          json!({
              "offset": offset,
              "length": pattern.len(),
              "pattern": s,
          })
        } else {
          json!({
              "offset": offset,
              "length": pattern.len(),
              "pattern_hex": hex_encode(&pattern),
          })
        };
        if render::render_machine_output(ctx, "rb crypto cyclic offset", &value)? {
          return Ok(());
        }
      }
      _ => {
        Output::header("Pattern at Offset");
        Output::item("Offset", &format!("{}", offset));
        Output::item("Length", &format!("{} bytes", pattern.len()));
        println!();

        if let Ok(s) = String::from_utf8(pattern.clone()) {
          println!("{}", s);
        } else {
          println!("{}", hex_encode(&pattern));
        }
      }
    }

    Ok(())
  }
}
