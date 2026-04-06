//! String and data obfuscation command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::obfuscate;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionObfuscateCommand;

impl Command for EvasionObfuscateCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "obfuscate"
  }

  fn description(&self) -> &str {
    "String and data obfuscation techniques"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "xor",
        summary: "XOR obfuscate a string",
        usage: "rb evasion obfuscate xor <string> [--key <n>]",
      },
      Route {
        verb: "base64",
        summary: "Base64 encode data",
        usage: "rb evasion obfuscate base64 <data>",
      },
      Route {
        verb: "rot",
        summary: "ROT-N encode string (Caesar cipher)",
        usage: "rb evasion obfuscate rot <string> [--shift <n>]",
      },
      Route {
        verb: "deobfuscate",
        summary: "Deobfuscate XOR data",
        usage: "rb evasion obfuscate deobfuscate <hex> --key <n>",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("key", "XOR key (0-255)")
        .with_short('k')
        .with_arg("N"),
      Flag::new("shift", "ROT shift amount (1-25)")
        .with_short('s')
        .with_default("13"),
      Flag::new("hex", "Output as hex string"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "XOR obfuscate",
        "rb evasion obfuscate xor \"secret command\"",
      ),
      (
        "XOR with custom key",
        "rb evasion obfuscate xor \"secret\" --key 66 --hex",
      ),
      (
        "Base64 encode",
        "rb evasion obfuscate base64 \"sensitive data\"",
      ),
      ("ROT13 encode", "rb evasion obfuscate rot \"hello world\""),
      (
        "Deobfuscate",
        "rb evasion obfuscate deobfuscate 31262d2521 --key 66",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("xor");

    match verb {
      "xor" => execute_obfuscate_xor(ctx),
      "base64" => execute_obfuscate_base64(ctx),
      "rot" => execute_obfuscate_rot(ctx),
      "deobfuscate" => execute_deobfuscate(ctx),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_obfuscate_xor(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";

  let data = ctx.target.as_ref().ok_or("Missing string to obfuscate")?;

  let key: u8 = ctx
    .flags
    .get("key")
    .and_then(|s| s.parse().ok())
    .unwrap_or_else(|| {
      // Auto-derive key from content
      let mut k: u8 = 0x5A;
      for b in data.bytes() {
        k = k.wrapping_add(b).rotate_left(3);
      }
      if k == 0 {
        0x42
      } else {
        k
      }
    });

  let show_hex = ctx.flags.contains_key("hex");
  let obfuscated = obfuscate::xor_obfuscate(data, key);
  let hex: String = obfuscated.iter().map(|b| format!("{:02x}", b)).collect();

  if is_json {
    Output::json_value(&json!({
        "original": data,
        "key": key,
        "key_hex": format!("0x{:02X}", key),
        "obfuscated_hex": hex,
        "obfuscated_bytes": obfuscated,
        "deobfuscate_command": format!(
            "rb evasion obfuscate deobfuscate {} --key {}",
            hex, key
        ),
    }));
    return Ok(());
  }

  Output::header("XOR Obfuscation");
  println!();

  Output::item("Original", data);
  Output::item("Key", &format!("0x{:02X} ({})", key, key));

  if show_hex {
    Output::item("Obfuscated (hex)", &hex);
  } else {
    Output::item("Obfuscated (bytes)", &format!("{:?}", obfuscated));
  }

  // Show deobfuscation command
  println!();
  Output::info("To deobfuscate:");
  println!("    rb evasion obfuscate deobfuscate {} --key {}", hex, key);

  Ok(())
}

fn execute_obfuscate_base64(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";

  let data = ctx.target.as_ref().ok_or("Missing data to encode")?;
  let encoded = obfuscate::base64_encode(data.as_bytes());

  if is_json {
    Output::json_value(&json!({
        "original": data,
        "encoded": encoded,
    }));
    return Ok(());
  }

  Output::header("Base64 Encoding");
  println!();

  Output::item("Original", data);
  Output::item("Encoded", &encoded);

  Ok(())
}

fn execute_obfuscate_rot(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";
  let data = ctx.target.as_ref().ok_or("Missing string to encode")?;

  let shift: u8 = ctx
    .flags
    .get("shift")
    .and_then(|s| s.parse().ok())
    .unwrap_or(13);

  Output::header(&format!("ROT-{} Encoding", shift));
  println!();

  let encoded = obfuscate::rot_encode(data, shift);
  let decode_shift = 26 - (shift % 26);

  if is_json {
    Output::json_value(&json!({
        "original": data,
        "shift": shift,
        "encoded": encoded,
        "decode_shift": decode_shift,
    }));
    return Ok(());
  }

  Output::item("Original", data);
  Output::item("Shift", &shift.to_string());
  Output::item("Encoded", &encoded);

  // Show decode command
  println!();
  Output::info("To decode:");
  println!(
    "    rb evasion obfuscate rot \"{}\" --shift {}",
    encoded, decode_shift
  );

  Ok(())
}

fn execute_deobfuscate(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";
  let hex_data = ctx
    .target
    .as_ref()
    .ok_or("Missing hex data to deobfuscate")?;
  let key: u8 = ctx
    .flags
    .get("key")
    .and_then(|s| s.parse().ok())
    .ok_or("Missing --key flag")?;

  if hex_data.len() % 2 != 0 {
    return Err("Invalid hex string".to_string());
  }

  Output::header("XOR Deobfuscation");
  println!();

  // Parse hex string to bytes
  let bytes: Result<Vec<u8>, _> = (0..hex_data.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&hex_data[i..i + 2], 16))
    .collect();

  let bytes = bytes.map_err(|_| "Invalid hex string")?;

  let deobfuscated = obfuscate::xor_deobfuscate(&bytes, key);

  if is_json {
    Output::json_value(&json!({
        "hex_input": hex_data,
        "key": key,
        "key_hex": format!("0x{:02X}", key),
        "deobfuscated": deobfuscated,
    }));
    return Ok(());
  }

  Output::item("Hex Input", hex_data);
  Output::item("Key", &format!("0x{:02X} ({})", key, key));
  Output::item("Deobfuscated", &deobfuscated);

  Ok(())
}
