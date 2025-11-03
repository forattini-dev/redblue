/// ICMP Ping Module
///
/// Provides ping functionality with fallback to system ping command
/// - ICMP protocol implementation (for when we have raw socket access)
/// - System ping wrapper (for unprivileged use)
/// - RTT statistics
/// - Packet loss tracking
use std::process::Command;
use std::time::Duration;

/// Ping configuration
#[derive(Debug, Clone)]
pub struct PingConfig {
    pub count: usize,
    pub interval: Duration,
    pub timeout: Duration,
    pub packet_size: usize,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            count: 4,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            packet_size: 56,
        }
    }
}

/// Ping using system ping command (fallback)
pub fn ping_system(host: &str, config: &PingConfig) -> Result<PingSystemResult, String> {
    // Try to use system ping command
    #[cfg(target_os = "linux")]
    {
        ping_linux(host, config)
    }

    #[cfg(target_os = "macos")]
    {
        ping_macos(host, config)
    }

    #[cfg(target_os = "windows")]
    {
        ping_windows(host, config)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("Ping not supported on this platform".to_string())
    }
}

/// System ping result
#[derive(Debug, Clone)]
pub struct PingSystemResult {
    pub host: String,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub packet_loss_percent: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub output: String,
}

#[cfg(target_os = "linux")]
fn ping_linux(host: &str, config: &PingConfig) -> Result<PingSystemResult, String> {
    let output = Command::new("ping")
        .arg("-c")
        .arg(config.count.to_string())
        .arg("-W")
        .arg(config.timeout.as_secs().to_string())
        .arg("-s")
        .arg(config.packet_size.to_string())
        .arg(host)
        .output()
        .map_err(|e| format!("Failed to execute ping: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if !output.status.success() {
        return Err(format!("Ping failed: {}", stdout));
    }

    parse_linux_ping_output(host, &stdout)
}

#[cfg(target_os = "macos")]
fn ping_macos(host: &str, config: &PingConfig) -> Result<PingSystemResult, String> {
    let output = Command::new("ping")
        .arg("-c")
        .arg(config.count.to_string())
        .arg("-W")
        .arg((config.timeout.as_millis()).to_string())
        .arg("-s")
        .arg(config.packet_size.to_string())
        .arg(host)
        .output()
        .map_err(|e| format!("Failed to execute ping: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if !output.status.success() {
        return Err(format!("Ping failed: {}", stdout));
    }

    parse_macos_ping_output(host, &stdout)
}

#[cfg(target_os = "windows")]
fn ping_windows(host: &str, config: &PingConfig) -> Result<PingSystemResult, String> {
    let output = Command::new("ping")
        .arg("-n")
        .arg(config.count.to_string())
        .arg("-w")
        .arg(config.timeout.as_millis().to_string())
        .arg("-l")
        .arg(config.packet_size.to_string())
        .arg(host)
        .output()
        .map_err(|e| format!("Failed to execute ping: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if !output.status.success() {
        return Err(format!("Ping failed: {}", stdout));
    }

    parse_windows_ping_output(host, &stdout)
}

#[cfg(target_os = "linux")]
fn parse_linux_ping_output(host: &str, output: &str) -> Result<PingSystemResult, String> {
    let mut packets_sent = 0;
    let mut packets_received = 0;
    let mut packet_loss_percent = 0.0;
    let mut min_rtt_ms = 0.0;
    let mut max_rtt_ms = 0.0;
    let mut avg_rtt_ms = 0.0;

    for line in output.lines() {
        // Parse statistics line: "4 packets transmitted, 4 received, 0% packet loss, time 3005ms"
        if line.contains("packets transmitted") {
            let parts: Vec<&str> = line.split(',').collect();

            if let Some(transmitted) = parts.first() {
                if let Some(num_str) = transmitted.split_whitespace().next() {
                    packets_sent = num_str.parse().unwrap_or(0);
                }
            }

            if parts.len() > 1 {
                let received_part = parts[1].trim();
                if let Some(num_str) = received_part.split_whitespace().next() {
                    packets_received = num_str.parse().unwrap_or(0);
                }
            }

            if parts.len() > 2 {
                let loss_part = parts[2].trim();
                if let Some(percent_str) = loss_part.split('%').next() {
                    packet_loss_percent = percent_str.trim().parse().unwrap_or(0.0);
                }
            }
        }

        // Parse RTT line: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms"
        if line.starts_with("rtt min/avg/max") {
            if let Some(rtt_part) = line.split('=').nth(1) {
                let values: Vec<&str> = rtt_part.trim().split('/').collect();
                if values.len() >= 3 {
                    min_rtt_ms = values[0].trim().parse().unwrap_or(0.0);
                    avg_rtt_ms = values[1].trim().parse().unwrap_or(0.0);
                    max_rtt_ms = values[2].trim().parse().unwrap_or(0.0);
                }
            }
        }
    }

    Ok(PingSystemResult {
        host: host.to_string(),
        packets_sent,
        packets_received,
        packet_loss_percent,
        min_rtt_ms,
        max_rtt_ms,
        avg_rtt_ms,
        output: output.to_string(),
    })
}

#[cfg(target_os = "macos")]
fn parse_macos_ping_output(host: &str, output: &str) -> Result<PingSystemResult, String> {
    // macOS ping output is similar to Linux
    parse_linux_ping_output(host, output)
}

#[cfg(target_os = "windows")]
fn parse_windows_ping_output(host: &str, output: &str) -> Result<PingSystemResult, String> {
    let mut packets_sent = 0;
    let mut packets_received = 0;
    let mut packet_loss_percent = 0.0;
    let mut min_rtt_ms = 0.0;
    let mut max_rtt_ms = 0.0;
    let mut avg_rtt_ms = 0.0;

    for line in output.lines() {
        // Parse statistics: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        if line.contains("Sent =") {
            let parts: Vec<&str> = line.split(',').collect();

            if let Some(sent_part) = parts.first() {
                if let Some(num_str) = sent_part.split('=').nth(1) {
                    packets_sent = num_str.trim().parse().unwrap_or(0);
                }
            }

            if parts.len() > 1 {
                let received_part = parts[1].trim();
                if let Some(num_str) = received_part.split('=').nth(1) {
                    packets_received = num_str.trim().parse().unwrap_or(0);
                }
            }

            if parts.len() > 2 {
                let loss_part = parts[2].trim();
                if let Some(percent) = loss_part.split('(').nth(1) {
                    if let Some(num_str) = percent.split('%').next() {
                        packet_loss_percent = num_str.trim().parse().unwrap_or(0.0);
                    }
                }
            }
        }

        // Parse RTT: "Minimum = 0ms, Maximum = 1ms, Average = 0ms"
        if line.contains("Minimum =") {
            let parts: Vec<&str> = line.split(',').collect();

            if let Some(min_part) = parts.first() {
                if let Some(num_str) = min_part.split('=').nth(1) {
                    let val_str = num_str.trim().trim_end_matches("ms");
                    min_rtt_ms = val_str.parse().unwrap_or(0.0);
                }
            }

            if parts.len() > 1 {
                let max_part = parts[1].trim();
                if let Some(num_str) = max_part.split('=').nth(1) {
                    let val_str = num_str.trim().trim_end_matches("ms");
                    max_rtt_ms = val_str.parse().unwrap_or(0.0);
                }
            }

            if parts.len() > 2 {
                let avg_part = parts[2].trim();
                if let Some(num_str) = avg_part.split('=').nth(1) {
                    let val_str = num_str.trim().trim_end_matches("ms");
                    avg_rtt_ms = val_str.parse().unwrap_or(0.0);
                }
            }
        }
    }

    Ok(PingSystemResult {
        host: host.to_string(),
        packets_sent,
        packets_received,
        packet_loss_percent,
        min_rtt_ms,
        max_rtt_ms,
        avg_rtt_ms,
        output: output.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_config_default() {
        let config = PingConfig::default();
        assert_eq!(config.count, 4);
        assert_eq!(config.interval, Duration::from_secs(1));
        assert_eq!(config.timeout, Duration::from_secs(1));
        assert_eq!(config.packet_size, 56);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_linux_ping() {
        let output = r#"PING google.com (142.250.185.46) 56(84) bytes of data.
64 bytes from fra16s13-in-f14.1e100.net (142.250.185.46): icmp_seq=1 ttl=118 time=10.2 ms
64 bytes from fra16s13-in-f14.1e100.net (142.250.185.46): icmp_seq=2 ttl=118 time=11.3 ms

--- google.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 10.234/10.789/11.345/0.555 ms"#;

        let result = parse_linux_ping_output("google.com", output).unwrap();

        assert_eq!(result.packets_sent, 2);
        assert_eq!(result.packets_received, 2);
        assert_eq!(result.packet_loss_percent, 0.0);
        assert!((result.min_rtt_ms - 10.234).abs() < 0.001);
        assert!((result.avg_rtt_ms - 10.789).abs() < 0.001);
        assert!((result.max_rtt_ms - 11.345).abs() < 0.001);
    }
}
