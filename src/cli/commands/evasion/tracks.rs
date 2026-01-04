//! Track covering and history clearing command

use super::{colored, GREEN, RED, YELLOW};
use crate::cli::output::Output;
use crate::cli::CliContext;
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
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if !is_json {
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

    if is_json {
        println!("{{");
        println!("  \"summary\": {{");
        println!("    \"total_history_files\": {},", stats.history_files);
        println!("    \"total_history_bytes\": {},", stats.history_bytes);
        println!("    \"session_files\": {}", stats.session_files);
        println!("  }},");
        println!("  \"files\": {{");

        // Bash
        let bash_files = collect_files(&files.bash);
        println!("    \"bash\": [");
        for (i, (path, size)) in bash_files.iter().enumerate() {
            let comma = if i < bash_files.len() - 1 { "," } else { "" };
            println!(
                "      {{ \"path\": \"{}\", \"size\": {} }}{}",
                path.replace('"', "\\\""),
                size,
                comma
            );
        }
        println!("    ],");

        // Zsh
        let zsh_files = collect_files(&files.zsh);
        println!("    \"zsh\": [");
        for (i, (path, size)) in zsh_files.iter().enumerate() {
            let comma = if i < zsh_files.len() - 1 { "," } else { "" };
            println!(
                "      {{ \"path\": \"{}\", \"size\": {} }}{}",
                path.replace('"', "\\\""),
                size,
                comma
            );
        }
        println!("    ],");

        // Fish
        let fish_files = collect_files(&files.fish);
        println!("    \"fish\": [");
        for (i, (path, size)) in fish_files.iter().enumerate() {
            let comma = if i < fish_files.len() - 1 { "," } else { "" };
            println!(
                "      {{ \"path\": \"{}\", \"size\": {} }}{}",
                path.replace('"', "\\\""),
                size,
                comma
            );
        }
        println!("    ],");

        // Other
        let other_files = collect_files(&files.other);
        println!("    \"other\": [");
        for (i, (path, size)) in other_files.iter().enumerate() {
            let comma = if i < other_files.len() - 1 { "," } else { "" };
            println!(
                "      {{ \"path\": \"{}\", \"size\": {} }}{}",
                path.replace('"', "\\\""),
                size,
                comma
            );
        }
        println!("    ]");

        println!("  }}");
        println!("}}");
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
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    let secure = ctx.flags.contains_key("secure");
    let shell_filter = ctx.flags.get("shell");

    let mode = if secure { "secure" } else { "quick" };

    if !is_json {
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

    if !is_json {
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

    if is_json {
        println!("{{");
        println!("  \"mode\": \"{}\",", mode);
        println!("  \"secure\": {},", secure);
        if let Some(shell) = shell_filter {
            println!("  \"shell_filter\": \"{}\",", shell);
        } else {
            println!("  \"shell_filter\": null,");
        }
        println!("  \"success_count\": {},", success_count);
        println!("  \"failed_count\": {},", failed_count);
        println!("  \"total_bytes\": {},", total_bytes);
        println!("  \"files\": [");
        for (i, result) in results.iter().enumerate() {
            let comma = if i < results.len() - 1 { "," } else { "" };
            let path = result
                .file
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            println!("    {{");
            println!("      \"path\": \"{}\",", path);
            println!("      \"success\": {},", result.success);
            println!("      \"bytes_cleared\": {},", result.bytes_cleared);
            if let Some(err) = &result.error {
                println!("      \"error\": \"{}\"", err.replace('"', "\\\""));
            } else {
                println!("      \"error\": null");
            }
            println!("    }}{}", comma);
        }
        println!("  ],");
        let shell = tracks::detect_shell();
        println!("  \"detected_shell\": \"{}\",", shell);
        println!(
            "  \"clear_session_command\": \"{}\"",
            tracks::get_clear_session_command(&shell).replace('"', "\\\"")
        );
        println!("}}");
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
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if !is_json {
        Output::header("Session File Cleaner");
        println!();
        Output::warning("This will clear redblue session files!");
        println!();
        Output::spinner_start("Clearing session files");
    }

    let results = tracks::clear_redblue_sessions();

    if !is_json {
        Output::spinner_done();
        println!();
    }

    if results.is_empty() {
        if is_json {
            println!("{{");
            println!("  \"success\": true,");
            println!("  \"total_cleared\": 0,");
            println!("  \"total_bytes\": 0,");
            println!("  \"files\": []");
            println!("}}");
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

    if is_json {
        println!("{{");
        println!("  \"success\": true,");
        println!("  \"total_cleared\": {},", success_count);
        println!("  \"total_bytes\": {},", total_bytes);
        println!("  \"files\": [");
        for (i, result) in results.iter().enumerate() {
            let comma = if i < results.len() - 1 { "," } else { "" };
            let path = result
                .file
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            println!(
                "    {{ \"path\": \"{}\", \"bytes\": {} }}{}",
                path, result.bytes_cleared, comma
            );
        }
        println!("  ]");
        println!("}}");
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
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    let shell = ctx
        .flags
        .get("shell")
        .cloned()
        .unwrap_or_else(tracks::detect_shell);

    let detected_shell = tracks::detect_shell();
    let clear_command = tracks::get_clear_session_command(&shell);

    if is_json {
        println!("{{");
        println!("  \"detected_shell\": \"{}\",", detected_shell);
        println!("  \"target_shell\": \"{}\",", shell);
        println!(
            "  \"clear_command\": \"{}\",",
            clear_command.replace('"', "\\\"")
        );
        println!("  \"all_commands\": {{");
        println!("    \"bash\": \"history -c && history -w\",");
        println!("    \"zsh\": \"fc -p && history -p\",");
        println!("    \"fish\": \"history clear\",");
        println!("    \"sh\": \"unset HISTFILE\"");
        println!("  }}");
        println!("}}");
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
