//! Build-time binary mutation command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::evasion::mutations;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionBuildCommand;

impl Command for EvasionBuildCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "build"
    }

    fn description(&self) -> &str {
        "Build-time binary mutation information"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "info",
                summary: "Show build mutation fingerprint and keys",
                usage: "rb evasion build info",
            },
            Route {
                verb: "obfuscate",
                summary: "Obfuscate string using build-specific key",
                usage: "rb evasion build obfuscate <string>",
            },
            Route {
                verb: "deobfuscate",
                summary: "Deobfuscate hex data using build-specific key",
                usage: "rb evasion build deobfuscate <hex>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("hex", "Output as hex string"),
            Flag::new("format", "Output format (text, json)").with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Show build info", "rb evasion build info"),
            (
                "Build-key obfuscate",
                "rb evasion build obfuscate \"secret\"",
            ),
            (
                "Build-key deobfuscate",
                "rb evasion build deobfuscate a1b2c3",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("info");

        match verb {
            "info" => execute_build_info(),
            "obfuscate" => execute_build_obfuscate(ctx),
            "deobfuscate" => execute_build_deobfuscate(ctx),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_build_info() -> Result<(), String> {
    Output::header("Build-Time Mutation Info");
    println!();

    Output::info("This binary was compiled with unique mutation values.");
    Output::info("Each `cargo build` produces a different binary hash.");
    println!();

    // Show build fingerprint
    let fingerprint = mutations::get_build_fingerprint();
    Output::item("Build Fingerprint", fingerprint);

    // Show build timestamp
    let timestamp = mutations::get_build_timestamp();
    let datetime = format_timestamp(timestamp);
    Output::item("Build Timestamp", &format!("{} ({})", timestamp, datetime));

    // Show XOR key
    let xor_key = mutations::get_xor_key();
    Output::item("XOR Key", &format!("0x{:02X} ({})", xor_key, xor_key));

    println!();
    Output::info("How it works:");
    println!("    1. build.rs runs before each compilation");
    println!("    2. Generates random values using timestamp + entropy");
    println!("    3. Values are embedded in binary at compile time");
    println!("    4. Result: Different SHA256 hash each build");

    println!();
    Output::info("To verify hash changes:");
    println!("    touch build.rs && cargo build --release");
    println!("    sha256sum target/release/redblue");
    println!("    touch build.rs && cargo build --release");
    println!("    sha256sum target/release/redblue");

    Ok(())
}

fn execute_build_obfuscate(ctx: &CliContext) -> Result<(), String> {
    let data = ctx.target.as_ref().ok_or("Missing string to obfuscate")?;
    let show_hex = ctx.flags.contains_key("hex");

    Output::header("Build-Key Obfuscation");
    println!();

    let obfuscated = mutations::obfuscate_string(data);

    Output::item("Original", data);
    Output::item(
        "Build XOR Key",
        &format!("0x{:02X}", mutations::get_xor_key()),
    );

    if show_hex {
        let hex: String = obfuscated.iter().map(|b| format!("{:02x}", b)).collect();
        Output::item("Obfuscated (hex)", &hex);
    } else {
        Output::item("Obfuscated (bytes)", &format!("{:?}", obfuscated));
    }

    // Show deobfuscation command
    let hex: String = obfuscated.iter().map(|b| format!("{:02x}", b)).collect();
    println!();
    Output::info("To deobfuscate with THIS build:");
    println!("    rb evasion build deobfuscate {}", hex);
    println!();
    Output::warning("Note: Only this exact binary can deobfuscate!");
    Output::warning("A rebuild will generate new keys.");

    Ok(())
}

fn execute_build_deobfuscate(ctx: &CliContext) -> Result<(), String> {
    let hex_data = ctx
        .target
        .as_ref()
        .ok_or("Missing hex data to deobfuscate")?;

    Output::header("Build-Key Deobfuscation");
    println!();

    // Parse hex string to bytes
    if hex_data.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    let mut bytes = Vec::with_capacity(hex_data.len() / 2);
    for i in (0..hex_data.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex_data[i..i + 2], 16)
            .map_err(|_| format!("Invalid hex at position {}", i))?;
        bytes.push(byte);
    }

    let deobfuscated = mutations::deobfuscate_string(&bytes);

    Output::item("Hex Input", hex_data);
    Output::item(
        "Build XOR Key",
        &format!("0x{:02X}", mutations::get_xor_key()),
    );
    Output::item("Deobfuscated", &deobfuscated);

    Ok(())
}

/// Format Unix timestamp to human-readable string
fn format_timestamp(unix_secs: u64) -> String {
    // Simple formatting - Unix epoch + seconds
    let secs_per_minute = 60;
    let secs_per_hour = 3600;
    let secs_per_day = 86400;
    let days_per_year = 365;

    let days_since_epoch = unix_secs / secs_per_day;
    let years_since_1970 = days_since_epoch / days_per_year;
    let year = 1970 + years_since_1970;

    let remaining_secs = unix_secs % secs_per_day;
    let hours = remaining_secs / secs_per_hour;
    let minutes = (remaining_secs % secs_per_hour) / secs_per_minute;
    let seconds = remaining_secs % secs_per_minute;

    format!("~{} {:02}:{:02}:{:02} UTC", year, hours, minutes, seconds)
}
