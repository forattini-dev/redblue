//! Network evasion command (jitter, timing)

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::json;
use crate::modules::evasion::network;

use crate::cli::commands::{Command, Flag, Route};

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
            Flag::new("format", "Output format (text, json)").with_default("text"),
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
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

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

    let min = base_ms.saturating_sub((base_ms * jitter_percent as u64) / 100);
    let max = base_ms + (base_ms * jitter_percent as u64) / 100;

    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let delay = network::jittered_duration(base_ms, jitter_percent);
        samples.push(delay.as_millis() as u64);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    if is_json {
        Output::json_value(&json!({
            "base_ms": base_ms,
            "jitter_percent": jitter_percent,
            "min_ms": min,
            "max_ms": max,
            "samples": samples
        }));
        return Ok(());
    }

    Output::header("Jittered Delay Calculator");
    println!();

    Output::item("Base Delay", &format!("{} ms", base_ms));
    Output::item("Jitter", &format!("{}%", jitter_percent));
    Output::item("Range", &format!("{} - {} ms", min, max));

    println!();
    Output::info(&format!("Sample delays ({} iterations):", count));

    for (i, sample) in samples.iter().enumerate() {
        println!("    #{}: {} ms", i + 1, sample);
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
