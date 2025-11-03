/// Network/ping command - ICMP Echo Request/Reply
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::network::ping::{ping_system, PingConfig};
use std::time::Duration;

pub struct PingCommand;

impl Command for PingCommand {
    fn domain(&self) -> &str {
        "network"
    }

    fn resource(&self) -> &str {
        "host"
    }

    fn description(&self) -> &str {
        "ICMP Echo Request/Reply (ping) and host reachability"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "ping",
            summary: "Send ICMP echo requests to test host reachability",
            usage: "rb network host ping <host>",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("count", "Number of ping packets to send")
                .with_short('c')
                .with_default("4"),
            Flag::new("interval", "Time between pings in milliseconds")
                .with_short('i')
                .with_default("1000"),
            Flag::new("timeout", "Timeout for each ping in milliseconds")
                .with_short('t')
                .with_default("1000"),
            Flag::new("size", "Packet payload size in bytes")
                .with_short('s')
                .with_default("56"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Ping Google DNS", "rb network host ping 8.8.8.8"),
            (
                "Ping 10 times with 500ms interval",
                "rb network host ping example.com --count 10 --interval 500",
            ),
            (
                "Fast ping with 200ms timeout",
                "rb network host ping 192.168.1.1 --timeout 200",
            ),
            (
                "Large packet size (jumbo frames test)",
                "rb network host ping 10.0.0.1 --size 1400",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "Missing verb. Use 'ping'".to_string()
        })?;

        match verb.as_str() {
            "ping" => self.ping(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb '{}'. Use 'ping'", verb))
            }
        }
    }
}

impl PingCommand {
    fn ping(&self, ctx: &CliContext) -> Result<(), String> {
        // Get target host
        let host = ctx
            .target
            .as_ref()
            .ok_or("Missing target. Usage: rb network host ping <host>")?;

        // Parse flags
        let count = ctx
            .flags
            .get("count")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4);

        let interval = ctx
            .flags
            .get("interval")
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(1));

        let timeout = ctx
            .flags
            .get("timeout")
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(1));

        let packet_size = ctx
            .flags
            .get("size")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(56);

        let config = PingConfig {
            count,
            interval,
            timeout,
            packet_size,
        };

        // Display header
        Output::header(&format!("Ping {}", host));
        Output::item("Packets", &count.to_string());
        Output::item("Packet size", &format!("{} bytes", packet_size));
        Output::item("Timeout", &format!("{}ms", timeout.as_millis()));
        println!();

        Output::spinner_start("Pinging");

        // Execute ping
        let result = ping_system(host, &config)?;

        Output::spinner_done();
        println!();

        // Display results
        Output::section("Ping Statistics");

        // Color-code packet loss
        let loss_color = if result.packet_loss_percent == 0.0 {
            "\x1b[32m" // Green - no loss
        } else if result.packet_loss_percent < 10.0 {
            "\x1b[33m" // Yellow - acceptable loss
        } else {
            "\x1b[31m" // Red - high loss
        };

        Output::item("Packets sent", &result.packets_sent.to_string());
        Output::item("Packets received", &result.packets_received.to_string());
        Output::item(
            "Packet loss",
            &format!("{}{}%\x1b[0m", loss_color, result.packet_loss_percent),
        );

        println!();

        // RTT statistics (only if we received packets)
        if result.packets_received > 0 {
            Output::section("Round-Trip Time (RTT)");
            Output::item("Minimum", &format!("{:.3} ms", result.min_rtt_ms));
            Output::item("Average", &format!("{:.3} ms", result.avg_rtt_ms));
            Output::item("Maximum", &format!("{:.3} ms", result.max_rtt_ms));

            // Quality assessment
            let quality = if result.avg_rtt_ms < 50.0 {
                "\x1b[32mExcellent\x1b[0m"
            } else if result.avg_rtt_ms < 100.0 {
                "\x1b[32mGood\x1b[0m"
            } else if result.avg_rtt_ms < 200.0 {
                "\x1b[33mAcceptable\x1b[0m"
            } else if result.avg_rtt_ms < 500.0 {
                "\x1b[33mPoor\x1b[0m"
            } else {
                "\x1b[31mVery poor\x1b[0m"
            };

            Output::item("Connection quality", quality);
        } else {
            Output::warning("No packets received - host may be down or unreachable");
        }

        Ok(())
    }
}
