//! Evasion configuration presets command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::evasion::EvasionConfig;

use crate::cli::commands::{Command, Flag, Route};

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
        vec![Flag::new("format", "Output format (text, json)").with_default("text")]
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
