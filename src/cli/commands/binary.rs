//! Binary analysis CLI commands
//!
//! Provides ELF/PE parsing, checksec, ROP gadgets, and pattern generation.

use super::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::binary::got_targets;
use crate::modules::binary::{Binary, GadgetClass, GadgetFinder, Pattern};

/// Binary analysis command
pub struct BinaryCommand;

impl Command for BinaryCommand {
  fn domain(&self) -> &str {
    "binary"
  }

  fn resource(&self) -> &str {
    "analysis"
  }

  fn description(&self) -> &str {
    "Binary analysis - ELF/PE parsing, checksec, ROP gadgets"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "info",
        summary: "Display binary information",
        usage: "rb binary analysis info ./target",
      },
      Route {
        verb: "sections",
        summary: "List binary sections",
        usage: "rb binary analysis sections ./target",
      },
      Route {
        verb: "symbols",
        summary: "List or search symbols",
        usage: "rb binary analysis symbols ./target --filter main",
      },
      Route {
        verb: "checksec",
        summary: "Check security features (RELRO, canary, NX, PIE)",
        usage: "rb binary analysis checksec ./target",
      },
      Route {
        verb: "rop",
        summary: "Find ROP gadgets",
        usage: "rb binary analysis rop ./target --filter \"pop rdi\"",
      },
      Route {
        verb: "plt",
        summary: "Resolve PLT address for function",
        usage: "rb binary analysis plt ./target printf",
      },
      Route {
        verb: "got",
        summary: "Resolve GOT address for function",
        usage: "rb binary analysis got ./target puts",
      },
      Route {
        verb: "got-targets",
        summary: "Analyze GOT entries and rank exploitation targets",
        usage: "rb binary analysis got-targets ./target",
      },
      Route {
        verb: "pattern",
        summary: "Generate De Bruijn pattern",
        usage: "rb binary analysis pattern 200",
      },
      Route {
        verb: "find",
        summary: "Find pattern offset",
        usage: "rb binary analysis find 0x41414141",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("filter", "Filter symbols or gadgets by pattern").with_short('f'),
      Flag::new("depth", "Maximum gadget depth (default: 10)")
        .with_short('d')
        .with_default("10"),
      Flag::new("class", "Filter gadgets by class (pop, mov, syscall, etc.)"),
      Flag::new("json", "Output in JSON format").with_short('j'),
      Flag::new("limit", "Limit number of results")
        .with_short('n')
        .with_default("100"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Show binary info", "rb binary analysis info /bin/ls"),
      ("List sections", "rb binary analysis sections /bin/ls"),
      (
        "Search symbols",
        "rb binary analysis symbols /bin/ls --filter main",
      ),
      (
        "Check security features",
        "rb binary analysis checksec /bin/ls",
      ),
      (
        "Check security (JSON)",
        "rb binary analysis checksec /bin/ls --json",
      ),
      ("Find ROP gadgets", "rb binary analysis rop /bin/ls"),
      (
        "Filter gadgets",
        "rb binary analysis rop /bin/ls --filter \"pop rdi\"",
      ),
      (
        "Find syscall gadgets",
        "rb binary analysis rop /bin/ls --class syscall",
      ),
      ("Resolve PLT address", "rb binary analysis plt /bin/ls puts"),
      ("Generate pattern", "rb binary analysis pattern 200"),
      ("Find offset (hex)", "rb binary analysis find 0x41414141"),
      ("Find offset (ASCII)", "rb binary analysis find aaab"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("info");
    let json_output = ctx.flags.contains_key("json");

    match verb {
      "info" => self.cmd_info(ctx, json_output),
      "sections" => self.cmd_sections(ctx, json_output),
      "symbols" => self.cmd_symbols(ctx, json_output),
      "checksec" => self.cmd_checksec(ctx, json_output),
      "rop" => self.cmd_rop(ctx, json_output),
      "plt" => self.cmd_plt(ctx, json_output),
      "got" => self.cmd_got(ctx, json_output),
      "got-targets" => self.cmd_got_targets(ctx, json_output),
      "pattern" => self.cmd_pattern(ctx),
      "find" => self.cmd_find(ctx, json_output),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

impl BinaryCommand {
  fn load_binary(&self, ctx: &CliContext) -> Result<Binary, String> {
    let path = ctx.target.as_deref().ok_or("Missing target binary path")?;
    Binary::from_file(path).map_err(|e| format!("Failed to load binary: {}", e))
  }

  fn cmd_info(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;

    if json {
      println!(
        r#"{{"path":"{}","format":"{}","arch":"{}","bits":{},"endian":"{}","entry":"0x{:x}","sections":{},"symbols":{}}}"#,
        binary.path.display(),
        binary.format,
        binary.arch,
        binary.bits,
        binary.endian,
        binary.entry_point,
        binary.sections.len(),
        binary.symbols.len()
      );
    } else {
      Output::header("Binary Information");
      println!("{}", binary.info());
    }

    Ok(())
  }

  fn cmd_sections(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;

    if json {
      let sections: Vec<String> = binary
        .sections
        .iter()
        .map(|s| {
          format!(
            r#"{{"name":"{}","vaddr":"0x{:x}","offset":"0x{:x}","size":{},"flags":"{}"}}"#,
            s.name, s.vaddr, s.offset, s.size, s.flags
          )
        })
        .collect();
      println!("[{}]", sections.join(","));
    } else {
      Output::header("Sections");
      println!(
        "{:<20} {:>16} {:>16} {:>12} {:>6}",
        "Name", "VAddr", "Offset", "Size", "Flags"
      );
      println!("{}", "-".repeat(74));
      for section in &binary.sections {
        println!(
          "{:<20} 0x{:014x} 0x{:014x} {:>12} {:>6}",
          section.name, section.vaddr, section.offset, section.size, section.flags
        );
      }
    }

    Ok(())
  }

  fn cmd_symbols(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;
    let filter = ctx.flags.get("filter").map(String::as_str);
    let limit: usize = ctx
      .flags
      .get("limit")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    let symbols: Vec<_> = if let Some(pattern) = filter {
      binary.search_symbols(pattern)
    } else {
      binary.symbols.iter().collect()
    };

    let symbols: Vec<_> = symbols.into_iter().take(limit).collect();

    if json {
      let items: Vec<String> = symbols
        .iter()
        .map(|s| {
          format!(
            r#"{{"name":"{}","value":"0x{:x}","size":{},"type":"{}","binding":"{}"}}"#,
            s.name, s.value, s.size, s.sym_type, s.binding
          )
        })
        .collect();
      println!("[{}]", items.join(","));
    } else {
      Output::header(&format!("Symbols ({})", symbols.len()));
      println!(
        "{:<40} {:>16} {:>8} {:>10} {:>8}",
        "Name", "Value", "Size", "Type", "Bind"
      );
      println!("{}", "-".repeat(86));
      for sym in symbols {
        println!(
          "{:<40} 0x{:014x} {:>8} {:>10} {:>8}",
          if sym.name.len() > 38 {
            &sym.name[..38]
          } else {
            &sym.name
          },
          sym.value,
          sym.size,
          sym.sym_type,
          sym.binding
        );
      }
    }

    Ok(())
  }

  fn cmd_checksec(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;

    if json {
      println!("{}", binary.security.to_json());
    } else {
      Output::header(&format!("Security Features: {}", binary.path.display()));
      println!();
      println!("{}", binary.security.display());
      println!();

      // Additional details
      if binary.security.rpath.is_some() || binary.security.runpath.is_some() {
        println!("\nPotential Hijacking Vectors:");
        if let Some(ref rpath) = binary.security.rpath {
          println!("  RPATH:   {}", rpath);
        }
        if let Some(ref runpath) = binary.security.runpath {
          println!("  RUNPATH: {}", runpath);
        }
      }

      if binary.security.fortify {
        println!("\nFORTIFY:  Enabled (some functions use *_chk variants)");
      }
    }

    Ok(())
  }

  fn cmd_rop(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;
    let filter = ctx.flags.get("filter").map(String::as_str);
    let class_filter = ctx.flags.get("class").map(String::as_str);
    let depth: usize = ctx
      .flags
      .get("depth")
      .and_then(|s| s.parse().ok())
      .unwrap_or(10);
    let limit: usize = ctx
      .flags
      .get("limit")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    let finder = GadgetFinder::new(binary.arch).with_depth(depth);

    let mut gadgets = if let Some(pattern) = filter {
      finder.find_matching(&binary, pattern)
    } else if let Some(class_str) = class_filter {
      let class = match class_str.to_lowercase().as_str() {
        "pop" => GadgetClass::PopReg,
        "mov" => GadgetClass::MovReg,
        "xchg" => GadgetClass::XchgReg,
        "syscall" => GadgetClass::Syscall,
        "call" => GadgetClass::Call,
        "jmp" => GadgetClass::Jmp,
        "arith" | "arithmetic" => GadgetClass::Arithmetic,
        "load" => GadgetClass::Load,
        "store" => GadgetClass::Store,
        "leave" => GadgetClass::Leave,
        _ => GadgetClass::Other,
      };
      finder.find_by_class(&binary, class)
    } else {
      finder.find_gadgets(&binary)
    };

    gadgets.truncate(limit);

    if json {
      let items: Vec<String> = gadgets
        .iter()
        .map(|g| {
          format!(
            r#"{{"address":"0x{:x}","instructions":"{}","class":"{}","bytes":"{}"}}"#,
            g.address,
            g.instructions,
            g.classification,
            g.hex_bytes()
          )
        })
        .collect();
      println!("[{}]", items.join(","));
    } else {
      Output::header(&format!("ROP Gadgets ({} found)", gadgets.len()));
      for gadget in &gadgets {
        println!("{}", gadget.display());
      }

      if gadgets.is_empty() {
        println!("No gadgets found matching criteria.");
      }
    }

    Ok(())
  }

  fn cmd_plt(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;

    // Get function name from extra args
    let func_name = ctx
      .args
      .first()
      .ok_or("Missing function name. Usage: rb binary analysis plt ./target <function>")?;

    match binary.plt_address(func_name) {
      Some(addr) => {
        if json {
          println!(r#"{{"function":"{}","plt":"0x{:x}"}}"#, func_name, addr);
        } else {
          println!("{}@plt: 0x{:x}", func_name, addr);
        }
      }
      None => {
        // Try searching symbols
        let matches = binary.search_symbols(func_name);
        if matches.is_empty() {
          return Err(format!("Symbol '{}' not found", func_name));
        }
        println!("PLT entry not found. Similar symbols:");
        for sym in matches.iter().take(5) {
          println!("  {} @ 0x{:x}", sym.name, sym.value);
        }
      }
    }

    Ok(())
  }

  fn cmd_got(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;

    let func_name = ctx
      .args
      .first()
      .ok_or("Missing function name. Usage: rb binary analysis got ./target <function>")?;

    match binary.got_address(func_name) {
      Some(addr) => {
        if json {
          println!(r#"{{"function":"{}","got":"0x{:x}"}}"#, func_name, addr);
        } else {
          println!("{}@got: 0x{:x}", func_name, addr);
        }
      }
      None => {
        return Err(format!("GOT entry for '{}' not found", func_name));
      }
    }

    Ok(())
  }

  fn cmd_got_targets(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let binary = self.load_binary(ctx)?;
    let analysis = got_targets::analyze_got_targets(&binary);

    if json {
      println!("{}", got_targets::format_analysis_json(&analysis));
    } else {
      print!("{}", got_targets::format_analysis(&analysis));
    }

    Ok(())
  }

  fn cmd_pattern(&self, ctx: &CliContext) -> Result<(), String> {
    let length: usize = ctx
      .target
      .as_deref()
      .ok_or("Missing pattern length. Usage: rb binary analysis pattern <length>")?
      .parse()
      .map_err(|_| "Invalid length: must be a number")?;

    if length > 50000 {
      return Err("Pattern length too large (max 50000)".into());
    }

    let pattern = Pattern::create_string(length);
    println!("{}", pattern);

    Ok(())
  }

  fn cmd_find(&self, ctx: &CliContext, json: bool) -> Result<(), String> {
    let query = ctx
      .target
      .as_deref()
      .ok_or("Missing search query. Usage: rb binary analysis find <pattern|0xHEX>")?;

    // Try hex first
    if query.starts_with("0x") || query.starts_with("0X") {
      if let Some((offset, endian)) = Pattern::find_offset_hex(query) {
        if json {
          println!(
            r#"{{"query":"{}","offset":{},"endian":"{}"}}"#,
            query, offset, endian
          );
        } else {
          println!("Offset: {} ({})", offset, endian);
        }
        return Ok(());
      }
    }

    // Try ASCII
    if let Some(offset) = Pattern::find_offset(query) {
      if json {
        println!(r#"{{"query":"{}","offset":{}}}"#, query, offset);
      } else {
        println!("Offset: {}", offset);
      }
    } else {
      return Err(format!("Pattern '{}' not found", query));
    }

    Ok(())
  }
}
