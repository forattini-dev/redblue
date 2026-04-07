//! Track covering and history clearing command

use super::{colored, GREEN, RED, YELLOW};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::evasion::tracks;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionTracksCommand;

impl Command for EvasionTracksCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "tracks"
  }

  fn description(&self) -> &str {
    "Track covering and history clearing for operational security"
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
        verb: "scan",
        summary: "Scan for history files without clearing",
        usage: "rb evasion tracks scan",
      },
      Route {
        verb: "clear",
        summary: "Clear all shell history files",
        usage: "rb evasion tracks clear [--secure] [--shell <name>]",
      },
      Route {
        verb: "sessions",
        summary: "Clear redblue session files",
        usage: "rb evasion tracks sessions",
      },
      Route {
        verb: "command",
        summary: "Show shell command to clear current session",
        usage: "rb evasion tracks command [--shell <name>]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("secure", "Overwrite files before clearing (zeros + random)"),
      Flag::new("shell", "Target specific shell (bash, zsh, fish)")
        .with_short('s')
        .with_arg("NAME"),
      Flag::new("format", "Output format (text, json)")
        .with_short('f')
        .with_default("text"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Scan for history files", "rb evasion tracks scan"),
      ("Clear all history", "rb evasion tracks clear"),
      ("Secure wipe history", "rb evasion tracks clear --secure"),
      (
        "Clear only bash history",
        "rb evasion tracks clear --shell bash",
      ),
      ("Clear rb sessions", "rb evasion tracks sessions"),
      ("Get clear command", "rb evasion tracks command"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("scan");

    match verb {
      "scan" => execute_tracks_scan(ctx),
      "clear" => execute_tracks_clear(ctx),
      "sessions" => execute_tracks_sessions(ctx),
      "command" | "cmd" => execute_tracks_command(ctx),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_tracks_scan(ctx: &CliContext) -> Result<(), String> {
  let machine_output = ctx.wants_machine_output();

  if !machine_output {
    Output::header("Track Scanner");
    println!();
    Output::spinner_start("Scanning for history files");
  }

  let stats = tracks::ClearStats::gather();
  let files = tracks::HistoryFiles::detect();

  // Helper to collect file info
  fn collect_files(paths: &[std::path::PathBuf]) -> Vec<(String, u64)> {
    paths
      .iter()
      .map(|f| {
        let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
        (f.display().to_string(), size)
      })
      .collect()
  }

  let bash_files = collect_files(&files.bash);
  let zsh_files = collect_files(&files.zsh);
  let fish_files = collect_files(&files.fish);
  let other_files = collect_files(&files.other);
  let file_entries = |entries: Vec<(String, u64)>| {
    entries
      .into_iter()
      .map(|(path, size)| json!({ "path": path, "size": size }))
      .collect::<Vec<_>>()
  };
  let payload = json!({
      "summary": json!({
          "total_history_files": stats.history_files,
          "total_history_bytes": stats.history_bytes,
          "session_files": stats.session_files,
      }),
      "files": json!({
          "bash": file_entries(bash_files),
          "zsh": file_entries(zsh_files),
          "fish": file_entries(fish_files),
          "other": file_entries(other_files),
      }),
  });
  if render::render_machine_output(ctx, "rb evasion tracks scan", &payload)? {
    return Ok(());
  }

  Output::spinner_done();
  println!();

  Output::info("History Files Found:");

  if !files.bash.is_empty() {
    println!(
      "    {} Bash history files:",
      colored(&files.bash.len().to_string(), YELLOW)
    );
    for f in &files.bash {
      let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
      println!("        {} ({} bytes)", f.display(), size);
    }
  }

  if !files.zsh.is_empty() {
    println!(
      "    {} Zsh history files:",
      colored(&files.zsh.len().to_string(), YELLOW)
    );
    for f in &files.zsh {
      let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
      println!("        {} ({} bytes)", f.display(), size);
    }
  }

  if !files.fish.is_empty() {
    println!(
      "    {} Fish history files:",
      colored(&files.fish.len().to_string(), YELLOW)
    );
    for f in &files.fish {
      let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
      println!("        {} ({} bytes)", f.display(), size);
    }
  }

  if !files.other.is_empty() {
    println!(
      "    {} Other shell history files:",
      colored(&files.other.len().to_string(), YELLOW)
    );
    for f in &files.other {
      let size = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
      println!("        {} ({} bytes)", f.display(), size);
    }
  }

  println!();
  Output::info("Summary:");
  println!("    Total history files:  {}", stats.history_files);
  println!("    Total history bytes:  {} bytes", stats.history_bytes);
  println!("    Session files (.rb):  {}", stats.session_files);

  println!();
  Output::info("To clear:");
  println!("    rb evasion tracks clear           # Quick clear");
  println!("    rb evasion tracks clear --secure  # Secure wipe");

  Ok(())
}

fn execute_tracks_clear(ctx: &CliContext) -> Result<(), String> {
  let machine_output = ctx.wants_machine_output();

  let secure = ctx.flags.contains_key("secure");
  let shell_filter = ctx.flags.get("shell");

  let mode = if secure { "secure" } else { "quick" };

  if !machine_output {
    Output::header("Track Clearer");
    println!();
    Output::warning("This will PERMANENTLY clear shell history files!");
    Output::warning("For authorized penetration testing only.");
    println!();

    let mode_desc = if secure {
      "Secure wipe (overwrite + truncate)"
    } else {
      "Quick clear (truncate only)"
    };
    Output::item("Mode", mode_desc);

    if let Some(shell) = shell_filter {
      Output::item("Shell filter", shell);
    }

    println!();
    Output::spinner_start("Clearing history");
  }

  let results = if let Some(shell) = shell_filter {
    tracks::clear_shell_history(shell, secure)
  } else {
    tracks::clear_all_history(secure)
  };

  if !machine_output {
    Output::spinner_done();
    println!();
  }

  let mut success_count = 0;
  let mut failed_count = 0;
  let mut total_bytes = 0u64;

  for result in &results {
    if result.success {
      success_count += 1;
      total_bytes += result.bytes_cleared;
    } else {
      failed_count += 1;
    }
  }

  let shell = tracks::detect_shell();
  let files_json: Vec<_> = results
    .iter()
    .map(|result| {
      json!({
          "path": result.file.display().to_string(),
          "success": result.success,
          "bytes_cleared": result.bytes_cleared,
          "error": result.error,
      })
    })
    .collect();
  let payload = json!({
      "mode": mode,
      "secure": secure,
      "shell_filter": shell_filter,
      "success_count": success_count,
      "failed_count": failed_count,
      "total_bytes": total_bytes,
      "files": files_json,
      "detected_shell": shell,
      "clear_session_command": tracks::get_clear_session_command(&shell),
  });
  if render::render_machine_output(ctx, "rb evasion tracks clear", &payload)? {
    return Ok(());
  }

  for result in &results {
    if result.success {
      println!(
        "    {} {} ({} bytes)",
        colored("[CLEARED]", GREEN),
        result.file.display(),
        result.bytes_cleared
      );
    } else {
      let err = result.error.as_deref().unwrap_or("unknown");
      println!(
        "    {} {} ({})",
        colored("[FAILED]", RED),
        result.file.display(),
        err
      );
    }
  }

  println!();
  Output::info("Summary:");
  println!("    Files cleared:  {}", success_count);
  println!("    Bytes cleared:  {}", total_bytes);
  if failed_count > 0 {
    println!("    Failed:         {}", failed_count);
  }

  println!();
  let shell = tracks::detect_shell();
  Output::info(&format!("To clear current session ({}):", shell));
  println!("    {}", tracks::get_clear_session_command(&shell));

  Ok(())
}

fn execute_tracks_sessions(ctx: &CliContext) -> Result<(), String> {
  let machine_output = ctx.wants_machine_output();

  if !machine_output {
    Output::header("Session File Cleaner");
    println!();
    Output::warning("This will clear redblue session files!");
    println!();
    Output::spinner_start("Clearing session files");
  }

  let results = tracks::clear_redblue_sessions();

  if !machine_output {
    Output::spinner_done();
    println!();
  }

  if results.is_empty() {
    let payload = json!({
        "success": true,
        "total_cleared": 0,
        "total_bytes": 0,
        "files": [],
    });
    if render::render_machine_output(ctx, "rb evasion tracks sessions", &payload)? {
      return Ok(());
    }
    Output::info("No session files found");
    return Ok(());
  }

  let mut success_count = 0;
  let mut total_bytes = 0u64;

  for result in &results {
    if result.success {
      success_count += 1;
      total_bytes += result.bytes_cleared;
    }
  }

  let files_json: Vec<_> = results
    .iter()
    .map(|result| {
      json!({
          "path": result.file.display().to_string(),
          "bytes": result.bytes_cleared,
      })
    })
    .collect();
  let payload = json!({
      "success": true,
      "total_cleared": success_count,
      "total_bytes": total_bytes,
      "files": files_json,
  });
  if render::render_machine_output(ctx, "rb evasion tracks sessions", &payload)? {
    return Ok(());
  }

  for result in &results {
    if result.success {
      println!(
        "    {} {} ({} bytes)",
        colored("[CLEARED]", GREEN),
        result.file.display(),
        result.bytes_cleared
      );
    }
  }

  println!();
  Output::success(&format!(
    "Cleared {} session files ({} bytes)",
    success_count, total_bytes
  ));

  Ok(())
}

fn execute_tracks_command(ctx: &CliContext) -> Result<(), String> {
  let shell = ctx
    .flags
    .get("shell")
    .cloned()
    .unwrap_or_else(tracks::detect_shell);

  let detected_shell = tracks::detect_shell();
  let clear_command = tracks::get_clear_session_command(&shell);

  let payload = json!({
      "detected_shell": detected_shell,
      "target_shell": shell,
      "clear_command": clear_command,
      "all_commands": json!({
          "bash": "history -c && history -w",
          "zsh": "fc -p && history -p",
          "fish": "history clear",
          "sh": "unset HISTFILE",
      }),
  });
  if render::render_machine_output(ctx, "rb evasion tracks command", &payload)? {
    return Ok(());
  }

  Output::header("Session Clear Command");
  println!();

  Output::item("Detected shell", &detected_shell);
  Output::item("Target shell", &shell);
  println!();

  Output::info("Run this command to clear current session history:");
  println!();
  println!("    {}", colored(&clear_command, GREEN));
  println!();

  Output::info("All shells:");
  println!("    bash:  history -c && history -w");
  println!("    zsh:   fc -p && history -p");
  println!("    fish:  history clear");
  println!("    sh:    unset HISTFILE");

  Ok(())
}
