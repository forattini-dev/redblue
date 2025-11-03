use std::io::{Read, Write};
use std::net::TcpStream;
/// Timing Analysis for OS and Service Fingerprinting
///
/// Different operating systems and service implementations have distinct timing
/// behaviors that can be used for fingerprinting:
///
/// - Connection timeout values
/// - SYN/ACK response times
/// - Keep-alive intervals
/// - Retransmission patterns
/// - Protocol-specific delays
///
/// Examples:
/// - Linux Telnet: ~75 seconds timeout
/// - Windows Telnet: ~21 seconds timeout
/// - Unix/BSD Telnet: ~60 seconds timeout
/// - SSH: Different key exchange timing per implementation
use std::time::{Duration, Instant};

/// Timing signature for OS/service fingerprinting
#[derive(Debug, Clone)]
pub struct TimingSignature {
    pub connection_time: Duration,
    pub first_response_time: Option<Duration>,
    pub timeout_behavior: TimeoutBehavior,
    pub keep_alive_interval: Option<Duration>,
}

/// Timeout behavior patterns
#[derive(Debug, Clone, PartialEq)]
pub enum TimeoutBehavior {
    /// Connection times out after specified duration
    Timeout(Duration),
    /// Connection accepted but no response
    Silent,
    /// Connection actively refused
    Refused,
    /// Connection reset by peer
    Reset,
}

/// OS fingerprint result based on timing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OsFamily {
    Linux,
    Windows,
    UnixBsd,
    MacOS,
    Solaris,
    Unknown,
}

impl OsFamily {
    pub fn name(&self) -> &'static str {
        match self {
            OsFamily::Linux => "Linux",
            OsFamily::Windows => "Windows",
            OsFamily::UnixBsd => "Unix/BSD",
            OsFamily::MacOS => "macOS",
            OsFamily::Solaris => "Solaris",
            OsFamily::Unknown => "Unknown",
        }
    }
}

/// Telnet timeout fingerprinting
///
/// Different OS have different default telnet timeouts:
/// - Linux: ~75 seconds
/// - Windows: ~21 seconds
/// - Unix/BSD: ~60 seconds
/// - Solaris: ~180 seconds
pub fn fingerprint_telnet_timeout(host: &str, port: u16) -> Result<(OsFamily, Duration), String> {
    let start = Instant::now();

    // Try to connect with a very long timeout
    let address = format!("{}:{}", host, port);
    let stream = TcpStream::connect_timeout(
        &address
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?,
        Duration::from_secs(200),
    );

    let elapsed = start.elapsed();

    match stream {
        Ok(mut s) => {
            // Connected successfully - now measure time to first byte
            s.set_read_timeout(Some(Duration::from_secs(180)))
                .map_err(|e| format!("Failed to set timeout: {}", e))?;

            let mut buf = [0u8; 1024];
            let response_start = Instant::now();
            let _ = s.read(&mut buf); // Ignore errors, just measure timing
            let response_time = response_start.elapsed();

            // Analyze timeout characteristics
            let os = classify_telnet_timeout(elapsed);
            Ok((os, response_time))
        }
        Err(_) => {
            // Connection failed - analyze the timeout duration
            let os = classify_telnet_timeout(elapsed);
            Ok((os, elapsed))
        }
    }
}

/// Classify OS based on Telnet timeout duration
fn classify_telnet_timeout(timeout: Duration) -> OsFamily {
    let secs = timeout.as_secs();

    // Known timeout patterns (with tolerance)
    match secs {
        0..=25 => OsFamily::Windows,   // Windows: ~21s
        26..=65 => OsFamily::UnixBsd,  // BSD/Unix: ~60s
        66..=90 => OsFamily::Linux,    // Linux: ~75s
        91..=200 => OsFamily::Solaris, // Solaris: ~180s
        _ => OsFamily::Unknown,
    }
}

/// SSH key exchange timing fingerprinting
///
/// Different SSH implementations have different timing characteristics:
/// - OpenSSH: Fast key exchange (~50-150ms)
/// - Dropbear: Very fast (~20-80ms)
/// - Commercial SSH: Slower (~200-500ms)
pub fn fingerprint_ssh_timing(host: &str, port: u16) -> Result<TimingSignature, String> {
    let address = format!("{}:{}", host, port);
    let conn_start = Instant::now();

    let mut stream =
        TcpStream::connect(&address).map_err(|e| format!("Connection failed: {}", e))?;

    let connection_time = conn_start.elapsed();

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    // Read SSH banner
    let response_start = Instant::now();
    let mut banner = vec![0u8; 256];
    let n = stream
        .read(&mut banner)
        .map_err(|e| format!("Read failed: {}", e))?;
    let first_response_time = response_start.elapsed();

    banner.truncate(n);

    Ok(TimingSignature {
        connection_time,
        first_response_time: Some(first_response_time),
        timeout_behavior: TimeoutBehavior::Silent,
        keep_alive_interval: None,
    })
}

/// FTP banner timing analysis
///
/// FTP servers respond with different timing based on implementation:
/// - ProFTPD: Immediate banner (~10-50ms)
/// - vsftpd: Very fast (~5-30ms)
/// - IIS FTP: Slower (~100-300ms)
/// - FileZilla Server: Medium (~50-150ms)
pub fn fingerprint_ftp_timing(host: &str, port: u16) -> Result<(String, Duration), String> {
    let address = format!("{}:{}", host, port);
    let start = Instant::now();

    let mut stream =
        TcpStream::connect(&address).map_err(|e| format!("Connection failed: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    // Measure time to receive banner
    let mut banner = vec![0u8; 512];
    let n = stream
        .read(&mut banner)
        .map_err(|e| format!("Read failed: {}", e))?;

    let banner_time = start.elapsed();
    banner.truncate(n);

    let banner_str = String::from_utf8_lossy(&banner).to_string();

    Ok((banner_str, banner_time))
}

/// HTTP timing fingerprinting
///
/// Web servers have distinct timing patterns:
/// - nginx: Very fast response (~5-20ms)
/// - Apache: Fast (~10-50ms)
/// - IIS: Variable (~20-100ms)
/// - Tomcat: Slower (~50-200ms)
pub fn fingerprint_http_timing(host: &str, port: u16) -> Result<TimingSignature, String> {
    let address = format!("{}:{}", host, port);
    let conn_start = Instant::now();

    let mut stream =
        TcpStream::connect(&address).map_err(|e| format!("Connection failed: {}", e))?;

    let connection_time = conn_start.elapsed();

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    // Send minimal HTTP request
    let request = b"GET / HTTP/1.0\r\n\r\n";
    let write_start = Instant::now();
    stream
        .write_all(request)
        .map_err(|e| format!("Write failed: {}", e))?;

    // Measure response time
    let mut response = vec![0u8; 1024];
    let _ = stream
        .read(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    let response_time = write_start.elapsed();

    Ok(TimingSignature {
        connection_time,
        first_response_time: Some(response_time),
        timeout_behavior: TimeoutBehavior::Silent,
        keep_alive_interval: None,
    })
}

/// Database timing fingerprinting
///
/// Different databases have different handshake timing:
/// - MySQL: Fast handshake (~10-50ms)
/// - PostgreSQL: Medium (~20-80ms)
/// - MSSQL: Slower (~50-150ms)
/// - MongoDB: Fast (~15-60ms)
pub fn fingerprint_database_timing(host: &str, port: u16) -> Result<TimingSignature, String> {
    let address = format!("{}:{}", host, port);
    let conn_start = Instant::now();

    let mut stream =
        TcpStream::connect(&address).map_err(|e| format!("Connection failed: {}", e))?;

    let connection_time = conn_start.elapsed();

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    // Measure time to receive server handshake
    let response_start = Instant::now();
    let mut handshake = vec![0u8; 512];
    let _ = stream.read(&mut handshake); // Ignore errors
    let handshake_time = response_start.elapsed();

    Ok(TimingSignature {
        connection_time,
        first_response_time: Some(handshake_time),
        timeout_behavior: TimeoutBehavior::Silent,
        keep_alive_interval: None,
    })
}

/// TCP retransmission pattern analysis
///
/// Different OS have different TCP retransmission patterns:
/// - Linux: Exponential backoff starting at 3s (3, 6, 12, 24...)
/// - Windows: Exponential backoff starting at 3s (3, 6, 12, 24...)
/// - BSD: Different initial value (1s, 2, 4, 8...)
/// - Solaris: Aggressive retries (0.5, 1, 2, 4...)
pub fn analyze_tcp_retransmission(_host: &str, _port: u16) -> Result<Vec<Duration>, String> {
    // This would require raw socket access to observe retransmissions
    // For now, return empty vector - full implementation requires elevated privileges
    Ok(vec![])
}

/// Combined timing analysis for comprehensive fingerprinting
pub fn comprehensive_timing_analysis(
    host: &str,
    port: u16,
    service: &str,
) -> Result<(OsFamily, TimingSignature), String> {
    let signature = match service.to_lowercase().as_str() {
        "telnet" => {
            let (os, timeout) = fingerprint_telnet_timeout(host, port)?;
            return Ok((
                os,
                TimingSignature {
                    connection_time: timeout,
                    first_response_time: None,
                    timeout_behavior: TimeoutBehavior::Timeout(timeout),
                    keep_alive_interval: None,
                },
            ));
        }
        "ssh" => fingerprint_ssh_timing(host, port)?,
        "ftp" => {
            let (_, timing) = fingerprint_ftp_timing(host, port)?;
            TimingSignature {
                connection_time: timing,
                first_response_time: Some(timing),
                timeout_behavior: TimeoutBehavior::Silent,
                keep_alive_interval: None,
            }
        }
        "http" | "https" => fingerprint_http_timing(host, port)?,
        "mysql" | "postgres" | "mssql" | "mongodb" => fingerprint_database_timing(host, port)?,
        _ => {
            return Err(format!("Unknown service: {}", service));
        }
    };

    // Infer OS from timing characteristics
    let os = infer_os_from_signature(&signature);

    Ok((os, signature))
}

/// Infer OS from timing signature patterns
fn infer_os_from_signature(sig: &TimingSignature) -> OsFamily {
    // Analyze connection time patterns
    let conn_ms = sig.connection_time.as_millis();

    // Fast connections typically indicate Linux/Unix
    if conn_ms < 10 {
        return OsFamily::Linux;
    }

    // Slower connections might indicate Windows
    if conn_ms > 50 {
        return OsFamily::Windows;
    }

    // Default to unknown if pattern unclear
    OsFamily::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_telnet_timeout() {
        assert_eq!(
            classify_telnet_timeout(Duration::from_secs(21)),
            OsFamily::Windows
        );
        assert_eq!(
            classify_telnet_timeout(Duration::from_secs(60)),
            OsFamily::UnixBsd
        );
        assert_eq!(
            classify_telnet_timeout(Duration::from_secs(75)),
            OsFamily::Linux
        );
        assert_eq!(
            classify_telnet_timeout(Duration::from_secs(180)),
            OsFamily::Solaris
        );
    }

    #[test]
    fn test_os_family_names() {
        assert_eq!(OsFamily::Linux.name(), "Linux");
        assert_eq!(OsFamily::Windows.name(), "Windows");
        assert_eq!(OsFamily::UnixBsd.name(), "Unix/BSD");
    }

    #[test]
    fn test_timing_signature() {
        let sig = TimingSignature {
            connection_time: Duration::from_millis(5),
            first_response_time: Some(Duration::from_millis(15)),
            timeout_behavior: TimeoutBehavior::Silent,
            keep_alive_interval: None,
        };

        assert_eq!(sig.connection_time.as_millis(), 5);
    }
}
