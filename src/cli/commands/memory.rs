//! Memory inspection command - Cheat Engine-style process memory analysis
//!
//! Provides functionality for:
//! - Process attachment via ptrace
//! - Memory region enumeration
//! - Value scanning (exact, range, changed/unchanged)
//! - Pattern/AOB signature scanning
//! - Memory reading and writing
//!
//! Requires CAP_SYS_PTRACE capability or root privileges.

#[cfg(target_os = "linux")]
use crate::cli::commands::{print_help, Command, Flag, Route};
#[cfg(target_os = "linux")]
use crate::cli::{output::Output, render, CliContext};
#[cfg(target_os = "linux")]
use crate::json;
#[cfg(target_os = "linux")]
use crate::modules::memory::{
  parse_maps, Pattern, PatternScanner, ProcessMemory, ScanType, Scanner, ValueType,
};
#[cfg(target_os = "linux")]
use crate::serde_json::Value;

/// Process information for listing
#[cfg(target_os = "linux")]
struct ProcessInfo {
  pid: i32,
  name: String,
  cmdline: String,
  uid: u32,
  state: char,
  vm_rss_kb: u64,
}

#[cfg(target_os = "linux")]
pub struct MemoryCommand;

#[cfg(target_os = "linux")]
impl Command for MemoryCommand {
  fn domain(&self) -> &str {
    "memory"
  }

  fn resource(&self) -> &str {
    "process"
  }

  fn description(&self) -> &str {
    "Process memory inspection and manipulation (Cheat Engine-style)"
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
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "list",
        summary: "List running processes (targets for memory inspection)",
        usage: "rb memory process list [--filter name] [--user] [--all]",
      },
      Route {
        verb: "maps",
        summary: "List memory regions of a process",
        usage: "rb memory process maps <pid>",
      },
      Route {
        verb: "read",
        summary: "Read bytes from a memory address",
        usage: "rb memory process read <pid> <addr> [--size 64]",
      },
      Route {
        verb: "write",
        summary: "Write bytes to a memory address",
        usage: "rb memory process write <pid> <addr> <hex-bytes>",
      },
      Route {
        verb: "scan",
        summary: "Scan for a value in process memory",
        usage: "rb memory process scan <pid> --value 100 --type i32",
      },
      Route {
        verb: "aob",
        summary: "Scan for a byte pattern (AOB/signature)",
        usage: "rb memory process aob <pid> \"48 8B ?? ?? 89\"",
      },
      Route {
        verb: "string",
        summary: "Scan for a string in process memory",
        usage: "rb memory process string <pid> \"search text\"",
      },
      Route {
        verb: "dump",
        summary: "Dump a memory region to file",
        usage: "rb memory process dump <pid> <addr> <size> -o output.bin",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("value", "Value to search for").with_short('v'),
      Flag::new("type", "Value type (i8|i16|i32|i64|u8|u16|u32|u64|f32|f64)")
        .with_short('t')
        .with_default("i32"),
      Flag::new("size", "Number of bytes to read")
        .with_short('s')
        .with_default("64"),
      Flag::new("output", "Output file for dump").with_short('o'),
      Flag::new("max", "Maximum results to show")
        .with_short('m')
        .with_default("100"),
      Flag::new("hex", "Display values in hexadecimal"),
      Flag::new("scannable", "Only scan heap/stack/anonymous regions"),
      Flag::new("filter", "Filter processes by name"),
      Flag::new("user", "Show only processes owned by current user"),
      Flag::new("all", "Show all processes (including system)"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("List all user processes", "rb memory process list"),
      ("Filter by name", "rb memory process list --filter firefox"),
      ("Show all processes", "rb memory process list --all"),
      ("List memory regions", "rb memory process maps 1234"),
      (
        "Read 64 bytes at address",
        "rb memory process read 1234 0x7ffc12345000 --size 64",
      ),
      (
        "Scan for i32 value 100",
        "rb memory process scan 1234 --value 100 --type i32",
      ),
      (
        "Scan for float value",
        "rb memory process scan 1234 --value 99.5 --type f32",
      ),
      (
        "AOB pattern scan",
        "rb memory process aob 1234 \"48 8B 05 ?? ?? ?? ??\"",
      ),
      (
        "Search for string",
        "rb memory process string 1234 \"password\"",
      ),
      (
        "Write bytes",
        "rb memory process write 1234 0x7ffc12345000 90909090",
      ),
      (
        "Dump region to file",
        "rb memory process dump 1234 0x400000 4096 -o code.bin",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "list" => self.cmd_list(ctx),
      "maps" => self.cmd_maps(ctx),
      "read" => self.cmd_read(ctx),
      "write" => self.cmd_write(ctx),
      "scan" => self.cmd_scan(ctx),
      "aob" => self.cmd_aob(ctx),
      "string" => self.cmd_string(ctx),
      "dump" => self.cmd_dump(ctx),
      _ => {
        print_help(self);
        Err(format!("Unknown verb: {}", verb))
      }
    }
  }
}

#[cfg(target_os = "linux")]
impl MemoryCommand {
  fn parse_pid(ctx: &CliContext) -> Result<i32, String> {
    let pid_str = ctx.target.as_ref().ok_or("Missing PID")?;
    pid_str
      .parse::<i32>()
      .map_err(|_| format!("Invalid PID: {}", pid_str))
  }

  fn parse_address(s: &str) -> Result<usize, String> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    usize::from_str_radix(s, 16).map_err(|_| format!("Invalid address: {}", s))
  }

  fn cmd_list(&self, ctx: &CliContext) -> Result<(), String> {
    let filter = ctx.flags.get("filter");
    let user_only = ctx.flags.contains_key("user") || !ctx.flags.contains_key("all");
    let current_uid = unsafe { libc::getuid() };

    if !ctx.wants_machine_output() {
      Output::header("Running Processes");
    }

    let mut processes = Vec::new();

    // Read /proc directory
    let proc_dir =
      std::fs::read_dir("/proc").map_err(|e| format!("Failed to read /proc: {}", e))?;

    for entry in proc_dir.flatten() {
      let name = entry.file_name();
      let name_str = name.to_string_lossy();

      // Only process numeric directories (PIDs)
      if let Ok(pid) = name_str.parse::<i32>() {
        if let Some(info) = Self::get_process_info(pid) {
          // Filter by user if requested
          if user_only && info.uid != current_uid {
            continue;
          }

          // Filter by name if requested
          if let Some(filter_str) = filter {
            let filter_lower = filter_str.to_lowercase();
            if !info.name.to_lowercase().contains(&filter_lower)
              && !info.cmdline.to_lowercase().contains(&filter_lower)
            {
              continue;
            }
          }

          processes.push(info);
        }
      }
    }

    // Sort by PID
    processes.sort_by_key(|p| p.pid);

    let attachable_count = processes
      .iter()
      .filter(|p| p.uid == current_uid || current_uid == 0)
      .count();

    let payload = process_list_payload(
      &processes,
      current_uid,
      user_only,
      filter.cloned(),
      attachable_count,
    );
    if render::render_machine_output(ctx, "rb memory process list", &payload)? {
      return Ok(());
    }

    Output::info(&format!("Found {} processes", processes.len()));
    if user_only {
      Output::info(&format!(
        "Showing processes for UID {} (use --all for all)",
        current_uid
      ));
    }

    println!();
    println!(
      "{:>8} {:>8} {:>10} {:>10} {:<20} CMDLINE",
      "PID", "UID", "MEM (MB)", "STATE", "NAME"
    );
    println!("{}", "-".repeat(100));

    for proc in &processes {
      let mem_str = format!("{:.1}", proc.vm_rss_kb as f64 / 1024.0);
      let state_str = match proc.state {
        'R' => "Running",
        'S' => "Sleeping",
        'D' => "Disk",
        'Z' => "Zombie",
        'T' => "Stopped",
        't' => "Traced",
        'X' => "Dead",
        _ => "Unknown",
      };

      // Truncate cmdline for display
      let cmdline_display = if proc.cmdline.len() > 50 {
        format!("{}...", &proc.cmdline[..47])
      } else {
        proc.cmdline.clone()
      };

      // Highlight attachable processes
      let attachable = proc.uid == current_uid || current_uid == 0;
      let pid_str = if attachable {
        format!("{:>8}", proc.pid)
      } else {
        format!("{:>8}", proc.pid)
      };

      println!(
        "{} {:>8} {:>10} {:>10} {:<20} {}",
        pid_str,
        proc.uid,
        mem_str,
        state_str,
        if proc.name.len() > 20 {
          format!("{}...", &proc.name[..17])
        } else {
          proc.name.clone()
        },
        cmdline_display
      );
    }

    println!();
    Output::success(&format!(
      "{} processes attachable (same UID or root)",
      attachable_count
    ));

    Ok(())
  }

  fn get_process_info(pid: i32) -> Option<ProcessInfo> {
    // Read /proc/pid/comm for name
    let name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
      .ok()?
      .trim()
      .to_string();

    // Read /proc/pid/cmdline
    let cmdline_raw = std::fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    let cmdline = cmdline_raw
      .split(|&b| b == 0)
      .filter(|s| !s.is_empty())
      .map(|s| String::from_utf8_lossy(s).to_string())
      .collect::<Vec<_>>()
      .join(" ");

    // Read /proc/pid/status for UID, state, memory
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;

    let mut uid = 0u32;
    let mut state = '?';
    let mut vm_rss_kb = 0u64;

    for line in status.lines() {
      if line.starts_with("State:") {
        state = line
          .chars()
          .skip(6)
          .find(|c| !c.is_whitespace())
          .unwrap_or('?');
      } else if line.starts_with("Uid:") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 1 {
          uid = parts[1].parse().unwrap_or(0);
        }
      } else if line.starts_with("VmRSS:") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 1 {
          vm_rss_kb = parts[1].parse().unwrap_or(0);
        }
      }
    }

    Some(ProcessInfo {
      pid,
      name,
      cmdline,
      uid,
      state,
      vm_rss_kb,
    })
  }

  fn cmd_maps(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    if !ctx.wants_machine_output() {
      Output::header(&format!("Memory Regions - PID {}", pid));
    }

    let regions = parse_maps(pid)?;
    let scannable_only = ctx.flags.contains_key("scannable");

    let filtered: Vec<_> = if scannable_only {
      regions.iter().filter(|r| r.is_scannable()).collect()
    } else {
      regions.iter().collect()
    };

    let total_size: usize = filtered.iter().map(|r| r.size()).sum();

    let payload = memory_maps_payload(pid, &regions, &filtered, scannable_only, total_size);
    if render::render_machine_output(ctx, "rb memory process maps", &payload)? {
      return Ok(());
    }

    Output::info(&format!("Total regions: {}", regions.len()));
    if scannable_only {
      Output::info(&format!("Showing scannable only: {}", filtered.len()));
    }

    println!();
    println!(
      "{:<18} {:<18} {:>12} {:>6} NAME",
      "START", "END", "SIZE", "PERMS"
    );
    println!("{}", "-".repeat(80));

    for region in &filtered {
      let size_str = if region.size() >= 1024 * 1024 {
        format!("{:.1} MB", region.size() as f64 / 1024.0 / 1024.0)
      } else if region.size() >= 1024 {
        format!("{:.1} KB", region.size() as f64 / 1024.0)
      } else {
        format!("{} B", region.size())
      };

      println!(
        "{:<18} {:<18} {:>12} {:>6} {}",
        format!("0x{:x}", region.start),
        format!("0x{:x}", region.end),
        size_str,
        region.perms.to_string(),
        region.name()
      );
    }

    println!();
    Output::success(&format!(
      "Total: {:.2} MB",
      total_size as f64 / 1024.0 / 1024.0
    ));

    Ok(())
  }

  fn cmd_read(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    // Get address from positional args
    let addr_str = ctx.args.get(0).ok_or("Missing address argument")?;
    let addr = Self::parse_address(addr_str)?;

    let size: usize = ctx
      .flags
      .get("size")
      .and_then(|s| s.parse().ok())
      .unwrap_or(64);

    if !ctx.wants_machine_output() {
      Output::header(&format!("Reading {} bytes at 0x{:x}", size, addr));
    }

    let mut proc = ProcessMemory::attach(pid)?;
    let data = proc.read_bytes(addr, size)?;
    proc.detach()?;

    let payload = memory_read_payload(pid, addr, &data);
    if render::render_machine_output(ctx, "rb memory process read", &payload)? {
      return Ok(());
    }

    // Hexdump format
    for (i, chunk) in data.chunks(16).enumerate() {
      let offset = i * 16;
      let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
      let ascii: String = chunk
        .iter()
        .map(|&b| {
          if b.is_ascii_graphic() || b == b' ' {
            b as char
          } else {
            '.'
          }
        })
        .collect();

      println!("{:08X}  {:48}  |{}|", addr + offset, hex.join(" "), ascii);
    }

    Ok(())
  }

  fn cmd_write(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    let addr_str = ctx.args.get(0).ok_or("Missing address argument")?;
    let addr = Self::parse_address(addr_str)?;

    let hex_bytes = ctx.args.get(1).ok_or("Missing hex bytes argument")?;

    // Parse hex string to bytes
    let bytes = Self::parse_hex_string(hex_bytes)?;

    if !ctx.wants_machine_output() {
      Output::header(&format!("Writing {} bytes at 0x{:x}", bytes.len(), addr));
    }

    let mut proc = ProcessMemory::attach(pid)?;

    // Show before
    let before = proc.read_bytes(addr, bytes.len())?;

    // Write
    proc.write_bytes(addr, &bytes)?;

    // Show after
    let after = proc.read_bytes(addr, bytes.len())?;
    proc.detach()?;

    let payload = memory_write_payload(pid, addr, bytes.len(), &before, &after);
    if render::render_machine_output(ctx, "rb memory process write", &payload)? {
      return Ok(());
    }

    Output::info(&format!(
      "Before: {}",
      before
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
    ));

    Output::success(&format!(
      "After:  {}",
      after
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
    ));

    Ok(())
  }

  fn cmd_scan(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    let value_str = ctx.flags.get("value").ok_or("Missing --value flag")?;
    let type_str = ctx.flags.get("type").map(|s| s.as_str()).unwrap_or("i32");
    let max_results: usize = ctx
      .flags
      .get("max")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    let value_type =
      ValueType::from_str(type_str).ok_or_else(|| format!("Invalid type: {}", type_str))?;

    // Parse value based on type
    let scan_type = if type_str.starts_with('f') {
      let val: f64 = value_str
        .parse()
        .map_err(|_| format!("Invalid float value: {}", value_str))?;
      ScanType::ExactFloat(val, 0.0001) // Small epsilon for float comparison
    } else {
      let val: i64 = value_str
        .parse()
        .map_err(|_| format!("Invalid integer value: {}", value_str))?;
      ScanType::Exact(val)
    };

    if !ctx.wants_machine_output() {
      Output::header(&format!(
        "Scanning PID {} for {} = {}",
        pid,
        value_type.name(),
        value_str
      ));
    }

    let mut proc = ProcessMemory::attach(pid)?;
    let regions = parse_maps(pid)?;
    let scannable: Vec<_> = regions
      .iter()
      .filter(|r| r.is_scannable())
      .cloned()
      .collect();

    let total_size: usize = scannable.iter().map(|r| r.size()).sum();

    if !ctx.wants_machine_output() {
      Output::info(&format!(
        "Scanning {} regions ({:.2} MB)",
        scannable.len(),
        total_size as f64 / 1024.0 / 1024.0
      ));
      Output::spinner_start("Scanning memory");
    }

    let mut scanner = Scanner::new(value_type);
    let count = scanner.first_scan(&mut proc, &scannable, scan_type)?;

    if !ctx.wants_machine_output() {
      Output::spinner_done();
      Output::success(&format!("Found {} results", count));
    }

    // Show results
    let results = scanner.results();
    let show_count = results.len().min(max_results);

    let payload = memory_scan_payload(
      pid,
      value_str,
      value_type.name(),
      scannable.len(),
      total_size,
      count,
      max_results,
      &results,
      show_count,
    );
    if render::render_machine_output(ctx, "rb memory process scan", &payload)? {
      proc.detach()?;
      return Ok(());
    }

    if show_count > 0 {
      println!();
      println!("{:<18} {:>20} {:>20}", "ADDRESS", "VALUE", "HEX");
      println!("{}", "-".repeat(60));

      for result in results.iter().take(show_count) {
        println!(
          "{:<18} {:>20} {:>20}",
          format!("0x{:x}", result.address),
          result.value.to_string(),
          format!("0x{:X}", result.value.as_i64())
        );
      }

      if count > max_results {
        println!("... and {} more results", count - max_results);
      }
    }

    proc.detach()?;
    Ok(())
  }

  fn cmd_aob(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    let pattern_str = ctx.args.get(0).ok_or("Missing pattern argument")?;
    let max_results: usize = ctx
      .flags
      .get("max")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    let pattern = Pattern::parse(pattern_str)?;

    if !ctx.wants_machine_output() {
      Output::header(&format!("AOB Scan PID {} for: {}", pid, pattern_str));
    }

    let mut proc = ProcessMemory::attach(pid)?;
    let regions = parse_maps(pid)?;

    // For AOB, scan all readable regions (including code)
    let readable: Vec<_> = regions
      .iter()
      .filter(|r| r.is_readable())
      .cloned()
      .collect();

    let total_size: usize = readable.iter().map(|r| r.size()).sum();

    if !ctx.wants_machine_output() {
      Output::info(&format!(
        "Scanning {} regions ({:.2} MB)",
        readable.len(),
        total_size as f64 / 1024.0 / 1024.0
      ));
      Output::spinner_start("Pattern scanning");
    }

    let results = PatternScanner::scan(&mut proc, &readable, &pattern, Some(max_results))?;

    if !ctx.wants_machine_output() {
      Output::spinner_done();
      Output::success(&format!("Found {} matches", results.len()));
    }

    let payload = memory_aob_payload(
      pid,
      pattern_str,
      readable.len(),
      total_size,
      max_results,
      &results,
    );
    if render::render_machine_output(ctx, "rb memory process aob", &payload)? {
      proc.detach()?;
      return Ok(());
    }

    if !results.is_empty() {
      println!();
      println!("{:<18} {:<40} REGION", "ADDRESS", "BYTES");
      println!("{}", "-".repeat(80));

      for result in &results {
        println!(
          "{:<18} {:<40} {}",
          format!("0x{:x}", result.address),
          result.bytes_hex(),
          result.region_name
        );
      }
    }

    proc.detach()?;
    Ok(())
  }

  fn cmd_string(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    let search_str = ctx.args.get(0).ok_or("Missing search string argument")?;
    let max_results: usize = ctx
      .flags
      .get("max")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    if !ctx.wants_machine_output() {
      Output::header(&format!("String Scan PID {} for: \"{}\"", pid, search_str));
    }

    let mut proc = ProcessMemory::attach(pid)?;
    let regions = parse_maps(pid)?;
    let readable: Vec<_> = regions
      .iter()
      .filter(|r| r.is_readable())
      .cloned()
      .collect();

    let total_size: usize = readable.iter().map(|r| r.size()).sum();
    let pattern = crate::modules::memory::pattern::string_pattern(search_str);

    if !ctx.wants_machine_output() {
      Output::spinner_start("Scanning for string");
    }

    let results = PatternScanner::scan(&mut proc, &readable, &pattern, Some(max_results))?;

    if !ctx.wants_machine_output() {
      Output::spinner_done();
      Output::success(&format!("Found {} matches", results.len()));
    }

    let payload = memory_string_payload(
      pid,
      search_str,
      readable.len(),
      total_size,
      max_results,
      &results,
    );
    if render::render_machine_output(ctx, "rb memory process string", &payload)? {
      proc.detach()?;
      return Ok(());
    }

    if !results.is_empty() {
      println!();
      println!("{:<18} REGION", "ADDRESS");
      println!("{}", "-".repeat(60));

      for result in &results {
        println!(
          "{:<18} {}",
          format!("0x{:x}", result.address),
          result.region_name
        );
      }
    }

    proc.detach()?;
    Ok(())
  }

  fn cmd_dump(&self, ctx: &CliContext) -> Result<(), String> {
    let pid = Self::parse_pid(ctx)?;

    let addr_str = ctx.args.get(0).ok_or("Missing address argument")?;
    let addr = Self::parse_address(addr_str)?;

    let size_str = ctx.args.get(1).ok_or("Missing size argument")?;
    let size: usize = size_str
      .parse()
      .map_err(|_| format!("Invalid size: {}", size_str))?;

    let output_file = ctx.flags.get("output").ok_or("Missing --output flag")?;

    if !ctx.wants_machine_output() {
      Output::header(&format!(
        "Dumping {} bytes from 0x{:x} to {}",
        size, addr, output_file
      ));
    }

    let mut proc = ProcessMemory::attach(pid)?;

    if !ctx.wants_machine_output() {
      Output::spinner_start("Reading memory");
    }

    let data = proc.read_bytes(addr, size)?;

    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    std::fs::write(output_file, &data).map_err(|e| format!("Failed to write file: {}", e))?;

    let payload = memory_dump_payload(pid, addr, size, data.len(), output_file);
    if render::render_machine_output(ctx, "rb memory process dump", &payload)? {
      proc.detach()?;
      return Ok(());
    }

    Output::success(&format!("Wrote {} bytes to {}", data.len(), output_file));

    proc.detach()?;
    Ok(())
  }

  fn parse_hex_string(s: &str) -> Result<Vec<u8>, String> {
    let s = s.replace(" ", "").replace("0x", "").replace("0X", "");

    if !s.len().is_multiple_of(2) {
      return Err("Hex string must have even number of characters".into());
    }

    let mut bytes = Vec::new();
    for i in (0..s.len()).step_by(2) {
      let byte = u8::from_str_radix(&s[i..i + 2], 16)
        .map_err(|_| format!("Invalid hex: {}", &s[i..i + 2]))?;
      bytes.push(byte);
    }

    Ok(bytes)
  }
}

#[cfg(target_os = "linux")]
fn process_state_label(state: char) -> &'static str {
  match state {
    'R' => "Running",
    'S' => "Sleeping",
    'D' => "Disk",
    'Z' => "Zombie",
    'T' => "Stopped",
    't' => "Traced",
    'X' => "Dead",
    _ => "Unknown",
  }
}

#[cfg(target_os = "linux")]
fn process_info_to_json(proc: &ProcessInfo, current_uid: u32) -> crate::serde_json::Value {
  json!({
      "pid": proc.pid,
      "uid": proc.uid,
      "name": proc.name.clone(),
      "cmdline": proc.cmdline.clone(),
      "state": process_state_label(proc.state),
      "vm_rss_kb": proc.vm_rss_kb,
      "attachable": proc.uid == current_uid || current_uid == 0
  })
}

#[cfg(target_os = "linux")]
fn memory_region_to_json(
  region: &crate::modules::memory::MemoryRegion,
) -> crate::serde_json::Value {
  json!({
      "start": format!("0x{:x}", region.start),
      "end": format!("0x{:x}", region.end),
      "size": region.size(),
      "perms": region.perms.to_string(),
      "name": region.name(),
      "readable": region.is_readable(),
      "writable": region.is_writable(),
      "executable": region.perms.execute,
      "scannable": region.is_scannable()
  })
}

#[cfg(target_os = "linux")]
fn scan_result_to_json(result: &crate::modules::memory::ScanResult) -> crate::serde_json::Value {
  json!({
      "address": format!("0x{:x}", result.address),
      "value": result.value.to_string(),
      "hex": format!("0x{:X}", result.value.as_i64())
  })
}

#[cfg(target_os = "linux")]
fn pattern_match_to_json(
  result: &crate::modules::memory::pattern::PatternMatch,
) -> crate::serde_json::Value {
  json!({
      "address": format!("0x{:x}", result.address),
      "bytes": result.bytes_hex(),
      "region": result.region_name.clone()
  })
}

#[cfg(target_os = "linux")]
fn process_list_payload(
  processes: &[ProcessInfo],
  current_uid: u32,
  user_only: bool,
  filter: Option<String>,
  attachable_count: usize,
) -> Value {
  let processes_json: Vec<Value> = processes
    .iter()
    .map(|proc| process_info_to_json(proc, current_uid))
    .collect();
  json!({
    "current_uid": current_uid,
    "user_only": user_only,
    "filter": filter,
    "total": processes.len(),
    "attachable": attachable_count,
    "processes": processes_json
  })
}

#[cfg(target_os = "linux")]
fn memory_maps_payload(
  pid: i32,
  regions: &[crate::modules::memory::MemoryRegion],
  filtered: &[&crate::modules::memory::MemoryRegion],
  scannable_only: bool,
  total_size: usize,
) -> Value {
  let regions_json: Vec<Value> = filtered
    .iter()
    .map(|region| memory_region_to_json(region))
    .collect();
  json!({
    "pid": pid,
    "total_regions": regions.len(),
    "filtered_regions": filtered.len(),
    "scannable_only": scannable_only,
    "total_size_bytes": total_size,
    "regions": regions_json
  })
}

#[cfg(target_os = "linux")]
fn memory_read_payload(pid: i32, addr: usize, data: &[u8]) -> Value {
  let hex_str: String = data.iter().map(|b| format!("{:02X}", b)).collect();
  let ascii_str: String = data
    .iter()
    .map(|&b| {
      if b.is_ascii_graphic() || b == b' ' {
        b as char
      } else {
        '.'
      }
    })
    .collect();
  let bytes_json: Vec<Value> = data
    .chunks(16)
    .enumerate()
    .map(|(i, chunk)| {
      let offset = i * 16;
      let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
      json!({
        "offset": format!("0x{:08x}", addr + offset),
        "hex": hex.join(" ")
      })
    })
    .collect();
  json!({
    "pid": pid,
    "address": format!("0x{:x}", addr),
    "size": data.len(),
    "hex": hex_str,
    "ascii": ascii_str,
    "bytes": bytes_json
  })
}

#[cfg(target_os = "linux")]
fn memory_write_payload(pid: i32, addr: usize, size: usize, before: &[u8], after: &[u8]) -> Value {
  let before_hex: String = before.iter().map(|b| format!("{:02X}", b)).collect();
  let after_hex: String = after.iter().map(|b| format!("{:02X}", b)).collect();
  json!({
    "pid": pid,
    "address": format!("0x{:x}", addr),
    "size": size,
    "before": before_hex,
    "after": after_hex,
    "success": true
  })
}

#[cfg(target_os = "linux")]
fn memory_scan_payload(
  pid: i32,
  search_value: &str,
  value_type: &str,
  regions_scanned: usize,
  total_size: usize,
  total_results: usize,
  max_results: usize,
  results: &[crate::modules::memory::ScanResult],
  show_count: usize,
) -> Value {
  let results_json: Vec<Value> = results
    .iter()
    .take(show_count)
    .map(scan_result_to_json)
    .collect();
  json!({
    "pid": pid,
    "search_value": search_value,
    "value_type": value_type,
    "regions_scanned": regions_scanned,
    "total_size_bytes": total_size,
    "total_results": total_results,
    "max_results": max_results,
    "results": results_json
  })
}

#[cfg(target_os = "linux")]
fn memory_aob_payload(
  pid: i32,
  pattern: &str,
  regions_scanned: usize,
  total_size: usize,
  max_results: usize,
  results: &[crate::modules::memory::pattern::PatternMatch],
) -> Value {
  let matches_json: Vec<Value> = results.iter().map(pattern_match_to_json).collect();
  json!({
    "pid": pid,
    "pattern": pattern,
    "regions_scanned": regions_scanned,
    "total_size_bytes": total_size,
    "max_results": max_results,
    "total_matches": results.len(),
    "matches": matches_json
  })
}

#[cfg(target_os = "linux")]
fn memory_string_payload(
  pid: i32,
  search_string: &str,
  regions_scanned: usize,
  total_size: usize,
  max_results: usize,
  results: &[crate::modules::memory::pattern::PatternMatch],
) -> Value {
  let matches_json: Vec<Value> = results
    .iter()
    .map(|result| {
      json!({
        "address": format!("0x{:x}", result.address),
        "region": result.region_name.clone()
      })
    })
    .collect();
  json!({
    "pid": pid,
    "search_string": search_string,
    "regions_scanned": regions_scanned,
    "total_size_bytes": total_size,
    "max_results": max_results,
    "total_matches": results.len(),
    "matches": matches_json
  })
}

#[cfg(target_os = "linux")]
fn memory_dump_payload(
  pid: i32,
  addr: usize,
  requested_size: usize,
  actual_size: usize,
  output_file: &str,
) -> Value {
  json!({
    "pid": pid,
    "address": format!("0x{:x}", addr),
    "requested_size": requested_size,
    "actual_size": actual_size,
    "output_file": output_file,
    "success": true
  })
}

// Empty implementation for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub struct MemoryCommand;

#[cfg(not(target_os = "linux"))]
impl crate::cli::commands::Command for MemoryCommand {
  fn domain(&self) -> &str {
    "memory"
  }

  fn resource(&self) -> &str {
    "process"
  }

  fn description(&self) -> &str {
    "Process memory inspection (Linux only)"
  }

  fn routes(&self) -> Vec<crate::cli::commands::Route> {
    vec![]
  }

  fn flags(&self) -> Vec<crate::cli::commands::Flag> {
    vec![]
  }

  fn execute(&self, _ctx: &crate::cli::CliContext) -> Result<(), String> {
    Err("Memory inspection is only available on Linux".into())
  }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use super::*;

  #[test]
  fn process_list_payload_includes_attachable_summary() {
    let processes = vec![ProcessInfo {
      pid: 42,
      name: "test".to_string(),
      cmdline: "/bin/test".to_string(),
      uid: 1000,
      state: 'S',
      vm_rss_kb: 2048,
    }];
    let payload = process_list_payload(&processes, 1000, true, Some("test".to_string()), 1);
    assert_eq!(payload["total"], json!(1));
    assert_eq!(payload["attachable"], json!(1));
    assert_eq!(
      payload["processes"].as_array().unwrap()[0]["name"],
      json!("test")
    );
  }

  #[test]
  fn memory_read_payload_serializes_ascii_and_chunks() {
    let payload = memory_read_payload(1234, 0x1000, b"AB\x00CD");
    assert_eq!(payload["pid"], json!(1234));
    assert_eq!(payload["address"], json!("0x1000"));
    assert_eq!(payload["ascii"], json!("AB.CD"));
    assert_eq!(
      payload["bytes"].as_array().unwrap()[0]["offset"],
      json!("0x00001000")
    );
  }

  #[test]
  fn memory_dump_payload_reports_output_file() {
    let payload = memory_dump_payload(77, 0x4000, 256, 256, "dump.bin");
    assert_eq!(payload["pid"], json!(77));
    assert_eq!(payload["output_file"], json!("dump.bin"));
    assert_eq!(payload["success"], json!(true));
  }
}
