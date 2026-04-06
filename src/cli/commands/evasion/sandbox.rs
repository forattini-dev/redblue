//! Sandbox detection command

use super::{colored, GREEN, RED};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::sandbox;

use crate::cli::commands::{Command, Flag, Route};

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
        vec![Flag::new("format", "Output format (text, json)")
            .with_short('f')
            .with_default("text")]
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
            "check" => execute_sandbox_check(ctx),
            "score" => execute_sandbox_score(ctx),
            "delay" => execute_sandbox_delay(ctx),
            _ => Err(format!("Unknown verb: {}", verb)),
        }
    }
}

fn execute_sandbox_check(ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if !is_json {
        Output::header("Sandbox Detection");
        println!();
        Output::spinner_start("Running sandbox checks");
    }

    let is_sandbox = sandbox::detect_sandbox();

    let checks = [
        ("VM Files", sandbox::check_vm_files()),
        ("Sandbox Processes", sandbox::check_sandbox_processes()),
        ("Timing Anomaly", sandbox::check_timing_anomaly()),
        ("Low Resources", sandbox::check_low_resources()),
        ("Suspicious Username", sandbox::check_suspicious_username()),
        ("Debugger Present", sandbox::check_debugger()),
    ];

    if is_json {
        let checks_json: Vec<_> = checks
            .iter()
            .map(|(name, detected)| {
                json!({
                    "name": name,
                    "key": name.to_lowercase().replace(' ', "_"),
                    "detected": detected,
                })
            })
            .collect();
        Output::json_value(&json!({
            "sandbox_detected": is_sandbox,
            "checks": checks_json,
        }));
        return Ok(());
    }

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

    for (name, detected) in &checks {
        if *detected {
            println!("    {} {}", colored("[DETECTED]", RED), name);
        } else {
            println!("    {} {}", colored("[CLEAN]", GREEN), name);
        }
    }

    Ok(())
}

fn execute_sandbox_score(ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if !is_json {
        Output::header("Sandbox Detection Score");
        println!();
        Output::spinner_start("Calculating score");
    }

    let score = sandbox::sandbox_score();

    let vm_files = sandbox::check_vm_files();
    let sandbox_procs = sandbox::check_sandbox_processes();
    let timing = sandbox::check_timing_anomaly();
    let low_res = sandbox::check_low_resources();
    let susp_user = sandbox::check_suspicious_username();
    let debugger = sandbox::check_debugger();

    if is_json {
        let risk = if score >= 50 {
            "high"
        } else if score >= 25 {
            "medium"
        } else {
            "low"
        };
        let breakdown = json!({
            "vm_files": json!({
                "detected": vm_files,
                "points": if vm_files { 20 } else { 0 }
            }),
            "sandbox_processes": json!({
                "detected": sandbox_procs,
                "points": if sandbox_procs { 20 } else { 0 }
            }),
            "timing_anomaly": json!({
                "detected": timing,
                "points": if timing { 25 } else { 0 }
            }),
            "low_resources": json!({
                "detected": low_res,
                "points": if low_res { 15 } else { 0 }
            }),
            "suspicious_user": json!({
                "detected": susp_user,
                "points": if susp_user { 10 } else { 0 }
            }),
            "debugger_present": json!({
                "detected": debugger,
                "points": if debugger { 10 } else { 0 }
            })
        });
        Output::json_value(&json!({
            "score": score,
            "risk": risk,
            "breakdown": breakdown,
        }));
        return Ok(());
    }

    Output::spinner_done();
    println!();

    // Display score with color based on value
    let score_color = if score >= 50 {
        colored(&format!("{}/100", score), RED)
    } else if score >= 25 {
        colored(&format!("{}/100", score), super::YELLOW)
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
        if vm_files { "+20" } else { "  0" }
    );
    println!(
        "    Sandbox Processes:  {} pts",
        if sandbox_procs { "+20" } else { "  0" }
    );
    println!(
        "    Timing Anomaly:     {} pts",
        if timing { "+25" } else { "  0" }
    );
    println!(
        "    Low Resources:      {} pts",
        if low_res { "+15" } else { "  0" }
    );
    println!(
        "    Suspicious User:    {} pts",
        if susp_user { "+10" } else { "  0" }
    );
    println!(
        "    Debugger Present:   {} pts",
        if debugger { "+10" } else { "  0" }
    );

    Ok(())
}

fn execute_sandbox_delay(ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";
    let delay_ms: u64 = ctx
        .target
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000);

    if !is_json {
        Output::header("Sandbox-Aware Delay");
        println!();
    }

    let is_sandbox = sandbox::detect_sandbox();

    if is_sandbox {
        sandbox::delay_execution(delay_ms);
    }

    if is_json {
        Output::json_value(&json!({
            "sandbox_detected": is_sandbox,
            "delay_ms": delay_ms,
            "delayed": is_sandbox,
        }));
        return Ok(());
    }

    if is_sandbox {
        Output::warning(&format!(
            "Sandbox detected - delaying {} ms ({} seconds)",
            delay_ms,
            delay_ms / 1000
        ));
        Output::success("Delay complete");
    } else {
        Output::info("No sandbox detected - no delay needed");
    }

    Ok(())
}
