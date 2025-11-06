/// TCP/IP Stack Fingerprinting
///
/// Extract OS and system information from TCP/IP stack behavior.
/// This module implements PASSIVE fingerprinting - we analyze what we receive
/// without sending any malicious or unusual packets.
///
/// Techniques:
/// - TCP options analysis (MSS, Window Scale, SACK, Timestamps)
/// - Initial TTL detection
/// - Window size patterns
/// - IP ID sequence analysis
/// - TCP timestamp clock skew
/// - Retransmission behavior
use std::time::{Duration, SystemTime};

/// TCP Option types from RFC 793, 1323, 2018
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    EndOfOptions,                        // 0
    NoOp,                                // 1
    MaxSegmentSize(u16),                 // 2
    WindowScale(u8),                     // 3
    SackPermitted,                       // 4
    Sack(Vec<(u32, u32)>),               // 5
    Timestamp { value: u32, echo: u32 }, // 8
    Unknown(u8, Vec<u8>),
}

/// IP ID sequence behavior
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpIdBehavior {
    Random,        // Modern Linux, BSD, OpenBSD (RFC 6864)
    Sequential,    // Old Linux 2.4, Windows per-connection
    GlobalCounter, // Very old systems
    Zero,          // Some embedded devices
    Unknown,
}

/// Operating System guess with confidence
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsGuess {
    Linux {
        version: Option<String>,
        confidence: u8,
    },
    Windows {
        version: Option<String>,
        confidence: u8,
    },
    MacOS {
        version: Option<String>,
        confidence: u8,
    },
    FreeBSD {
        version: Option<String>,
        confidence: u8,
    },
    OpenBSD {
        version: Option<String>,
        confidence: u8,
    },
    Solaris {
        version: Option<String>,
        confidence: u8,
    },
    CiscoIOS {
        confidence: u8,
    },
    Embedded {
        device_type: Option<String>,
        confidence: u8,
    },
    Unknown,
}

impl OsGuess {
    pub fn confidence(&self) -> u8 {
        match self {
            OsGuess::Linux { confidence, .. } => *confidence,
            OsGuess::Windows { confidence, .. } => *confidence,
            OsGuess::MacOS { confidence, .. } => *confidence,
            OsGuess::FreeBSD { confidence, .. } => *confidence,
            OsGuess::OpenBSD { confidence, .. } => *confidence,
            OsGuess::Solaris { confidence, .. } => *confidence,
            OsGuess::CiscoIOS { confidence } => *confidence,
            OsGuess::Embedded { confidence, .. } => *confidence,
            OsGuess::Unknown => 0,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            OsGuess::Linux { .. } => "Linux",
            OsGuess::Windows { .. } => "Windows",
            OsGuess::MacOS { .. } => "macOS",
            OsGuess::FreeBSD { .. } => "FreeBSD",
            OsGuess::OpenBSD { .. } => "OpenBSD",
            OsGuess::Solaris { .. } => "Solaris",
            OsGuess::CiscoIOS { .. } => "Cisco IOS",
            OsGuess::Embedded { .. } => "Embedded",
            OsGuess::Unknown => "Unknown",
        }
    }
}

/// TCP Fingerprint - the core data structure
#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub window_size: u16,
    pub ttl: u8,
    pub options: Vec<TcpOption>,
    pub ip_id: Option<u16>,
    pub dont_fragment: bool,

    // Derived fields
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub has_timestamp: bool,
    pub has_sack: bool,
}

impl TcpFingerprint {
    pub fn new() -> Self {
        Self {
            window_size: 0,
            ttl: 0,
            options: Vec::new(),
            ip_id: None,
            dont_fragment: false,
            mss: None,
            window_scale: None,
            has_timestamp: false,
            has_sack: false,
        }
    }

    /// Extract options and populate derived fields
    pub fn extract_options(&mut self) {
        for opt in &self.options {
            match opt {
                TcpOption::MaxSegmentSize(mss) => self.mss = Some(*mss),
                TcpOption::WindowScale(ws) => self.window_scale = Some(*ws),
                TcpOption::Timestamp { .. } => self.has_timestamp = true,
                TcpOption::SackPermitted | TcpOption::Sack(_) => self.has_sack = true,
                _ => {}
            }
        }
    }

    /// Detect OS from TCP/IP fingerprint
    ///
    /// This uses multiple heuristics:
    /// 1. TTL (most reliable)
    /// 2. Window size patterns
    /// 3. TCP option order and values
    /// 4. MSS values
    /// 5. Window scaling
    pub fn detect_os(&self) -> OsGuess {
        let mut confidence = 0u8;

        // === Linux Detection ===
        // TTL=64, MSS=1460, WS=7, SACK+TS common
        if self.ttl == 64 && self.window_scale == Some(7) {
            confidence = 70;

            // Linux 2.6+ has MSS=1460 typically
            if self.mss == Some(1460) {
                confidence += 10;
            }

            // Modern Linux always has SACK and Timestamps
            if self.has_sack && self.has_timestamp {
                confidence += 10;
            }

            // Check option order (Linux-specific pattern)
            if self.has_linux_option_pattern() {
                confidence += 10;
            }

            return OsGuess::Linux {
                version: self.guess_linux_version(),
                confidence,
            };
        }

        // === Windows Detection ===
        // TTL=128, WS=8 (Vista+), large window
        if self.ttl == 128 {
            confidence = 70;

            // Windows Vista+ uses WS=8
            if self.window_scale == Some(8) {
                confidence += 10;
                return OsGuess::Windows {
                    version: Some("Vista or newer".to_string()),
                    confidence,
                };
            }

            // Windows XP used WS=2
            if self.window_scale == Some(2) {
                confidence += 10;
                return OsGuess::Windows {
                    version: Some("XP".to_string()),
                    confidence,
                };
            }

            return OsGuess::Windows {
                version: None,
                confidence,
            };
        }

        // === macOS Detection ===
        // TTL=64, Window=65535, EOL padding, specific option order
        if self.ttl == 64 && self.window_size == 65535 {
            confidence = 60;

            // macOS has distinctive EOL padding
            if self.has_eol_padding() {
                confidence += 20;
            }

            return OsGuess::MacOS {
                version: None,
                confidence,
            };
        }

        // === Solaris/AIX Detection ===
        // TTL=255, many NOPs
        if self.ttl == 255 {
            confidence = 60;

            let nop_count = self.count_nops();
            if nop_count > 4 {
                confidence += 20;
                return OsGuess::Solaris {
                    version: None,
                    confidence,
                };
            }

            // Cisco IOS also uses TTL=255 but minimal options
            if self.options.len() <= 2 && self.mss == Some(4128) {
                return OsGuess::CiscoIOS { confidence: 80 };
            }
        }

        // === FreeBSD Detection ===
        // TTL=64, Window=65535, distinct option order
        if self.ttl == 64 && self.window_size == 65535 {
            confidence = 50;

            if self.has_freebsd_option_pattern() {
                confidence += 30;
            }

            return OsGuess::FreeBSD {
                version: None,
                confidence,
            };
        }

        // === OpenBSD Detection ===
        // TTL=64, random IP ID
        if self.ttl == 64 {
            // OpenBSD implements RFC 6864 (random IP ID)
            return OsGuess::OpenBSD {
                version: None,
                confidence: 40,
            };
        }

        OsGuess::Unknown
    }

    /// Guess Linux kernel version from TCP behavior
    fn guess_linux_version(&self) -> Option<String> {
        // Linux 2.6+ uses WS=7
        if self.window_scale == Some(7) {
            return Some("2.6 or newer".to_string());
        }

        // Linux 2.4 uses WS=0-2
        if let Some(ws) = self.window_scale {
            if ws <= 2 {
                return Some("2.4".to_string());
            }
        }

        None
    }

    /// Check for Linux-specific TCP option pattern
    /// Typical: MSS, SACK, TS, NOP, WS
    fn has_linux_option_pattern(&self) -> bool {
        if self.options.len() < 3 {
            return false;
        }

        // Check first few options
        matches!(self.options.first(), Some(TcpOption::MaxSegmentSize(_)))
    }

    /// Check for macOS EOL padding
    /// macOS adds EOL at the end of TCP options
    fn has_eol_padding(&self) -> bool {
        matches!(self.options.last(), Some(TcpOption::EndOfOptions))
    }

    /// Count NOP options (Solaris uses many)
    fn count_nops(&self) -> usize {
        self.options
            .iter()
            .filter(|opt| matches!(opt, TcpOption::NoOp))
            .count()
    }

    /// Check for FreeBSD option pattern
    /// FreeBSD: MSS, NOP, WS, SACK, TS
    fn has_freebsd_option_pattern(&self) -> bool {
        if self.options.len() < 4 {
            return false;
        }

        // FreeBSD has specific option order
        matches!(self.options.first(), Some(TcpOption::MaxSegmentSize(_)))
            && self.has_sack
            && self.has_timestamp
    }

    /// Calculate effective window size (window × 2^scale)
    pub fn effective_window_size(&self) -> u32 {
        let scale = self.window_scale.unwrap_or(0);
        (self.window_size as u32) << scale
    }

    /// Infer likely MTU from MSS
    pub fn infer_mtu(&self) -> Option<u16> {
        self.mss.map(|mss| mss + 40) // MSS + TCP(20) + IP(20)
    }

    /// Calculate distance in hops from TTL
    pub fn calculate_hops(&self) -> Option<u8> {
        let initial_ttls = [30, 32, 64, 128, 255];

        for &initial in &initial_ttls {
            if self.ttl <= initial {
                return Some(initial - self.ttl);
            }
        }

        None
    }

    /// Generate a signature string for database storage
    pub fn signature(&self) -> String {
        format!(
            "TTL:{} Win:{} MSS:{} WS:{} SACK:{} TS:{}",
            self.ttl,
            self.window_size,
            self.mss.unwrap_or(0),
            self.window_scale.unwrap_or(0),
            self.has_sack as u8,
            self.has_timestamp as u8,
        )
    }
}

/// IP ID sequence analyzer
pub struct IpIdAnalyzer {
    samples: Vec<u16>,
}

impl IpIdAnalyzer {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, ip_id: u16) {
        self.samples.push(ip_id);
    }

    /// Analyze IP ID sequence behavior
    pub fn analyze(&self) -> IpIdBehavior {
        if self.samples.len() < 3 {
            return IpIdBehavior::Unknown;
        }

        // Check if all zeros
        if self.samples.iter().all(|&id| id == 0) {
            return IpIdBehavior::Zero;
        }

        // Calculate differences between consecutive samples
        let diffs: Vec<i32> = self
            .samples
            .windows(2)
            .map(|w| w[1] as i32 - w[0] as i32)
            .collect();

        let avg_diff = diffs.iter().sum::<i32>() / diffs.len() as i32;
        let variance = self.calculate_variance(&diffs);

        // Random: high variance, no pattern
        if variance > 10000.0 {
            return IpIdBehavior::Random; // Modern Linux, BSD
        }

        // Sequential: low variance, positive increment
        if avg_diff > 0 && avg_diff < 100 && variance < 100.0 {
            return IpIdBehavior::Sequential; // Windows, old Linux
        }

        // Global counter: large jumps (other connections incrementing)
        if avg_diff > 100 {
            return IpIdBehavior::GlobalCounter;
        }

        IpIdBehavior::Unknown
    }

    fn calculate_variance(&self, diffs: &[i32]) -> f64 {
        if diffs.is_empty() {
            return 0.0;
        }

        let mean = diffs.iter().sum::<i32>() as f64 / diffs.len() as f64;
        let variance = diffs
            .iter()
            .map(|&d| {
                let diff = d as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / diffs.len() as f64;

        variance
    }
}

/// TCP Timestamp analyzer for clock skew detection
pub struct TcpTimestampAnalyzer {
    samples: Vec<TcpTimestampSample>,
}

#[derive(Debug, Clone)]
pub struct TcpTimestampSample {
    pub ts_value: u32,
    pub ts_echo_reply: u32,
    pub received_at: SystemTime,
}

impl TcpTimestampAnalyzer {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, sample: TcpTimestampSample) {
        self.samples.push(sample);
    }

    /// Detect clock frequency (Hz)
    /// Linux: 250Hz or 1000Hz
    /// Windows: 100Hz
    /// BSD: 100Hz
    pub fn detect_clock_frequency(&self) -> Option<u32> {
        if self.samples.len() < 5 {
            return None;
        }

        // Calculate timestamp increments per second
        let first = &self.samples[0];
        let last = self.samples.last()?;

        let ts_diff = last.ts_value.wrapping_sub(first.ts_value);
        let time_diff = last
            .received_at
            .duration_since(first.received_at)
            .ok()?
            .as_secs_f64();

        if time_diff < 0.1 {
            return None; // Too short interval
        }

        let hz = (ts_diff as f64 / time_diff) as u32;

        // Round to known frequencies
        if (90..=110).contains(&hz) {
            Some(100) // Windows, BSD
        } else if (240..=260).contains(&hz) {
            Some(250) // Linux
        } else if (900..=1100).contains(&hz) {
            Some(1000) // Linux with CONFIG_HZ=1000
        } else {
            Some(hz)
        }
    }

    /// Estimate system uptime from initial timestamp
    pub fn estimate_uptime(&self) -> Option<Duration> {
        let hz = self.detect_clock_frequency()?;
        let first_ts = self.samples.first()?.ts_value;

        Some(Duration::from_secs((first_ts / hz) as u64))
    }

    /// Detect clock skew (virtualization, time drift)
    pub fn detect_clock_skew(&self) -> f64 {
        if self.samples.len() < 10 {
            return 0.0;
        }

        // Compare expected vs actual timestamp increments
        let mut skews = Vec::new();

        for i in 1..self.samples.len() {
            let prev = &self.samples[i - 1];
            let curr = &self.samples[i];

            let actual_ts_diff = curr.ts_value.wrapping_sub(prev.ts_value);
            let time_diff = curr
                .received_at
                .duration_since(prev.received_at)
                .unwrap_or(Duration::from_secs(0))
                .as_secs_f64();

            if time_diff > 0.0 {
                let expected_ts_diff = time_diff * 1000.0; // Assume 1000 Hz
                let skew = (actual_ts_diff as f64 - expected_ts_diff).abs();
                skews.push(skew);
            }
        }

        if skews.is_empty() {
            return 0.0;
        }

        skews.iter().sum::<f64>() / skews.len() as f64
    }
}

/// Retransmission pattern analyzer
#[derive(Debug, Clone)]
pub struct RetransmissionProfile {
    pub initial_rto: Duration,
    pub retries: Vec<Duration>,
    pub max_retries: u8,
}

impl RetransmissionProfile {
    /// Detect OS from retransmission behavior
    pub fn detect_os(&self) -> OsGuess {
        let initial_sec = self.initial_rto.as_secs();

        // Linux: initial RTO=3s, max 15 retries
        if initial_sec == 3 && self.max_retries >= 15 {
            return OsGuess::Linux {
                version: None,
                confidence: 80,
            };
        }

        // Windows: initial RTO=3s, max 5 retries
        if initial_sec == 3 && self.max_retries == 5 {
            return OsGuess::Windows {
                version: None,
                confidence: 80,
            };
        }

        // FreeBSD: initial RTO=1.5s
        if self.initial_rto.as_millis() == 1500 {
            return OsGuess::FreeBSD {
                version: None,
                confidence: 70,
            };
        }

        // macOS: initial RTO=1s
        if initial_sec == 1 {
            return OsGuess::MacOS {
                version: None,
                confidence: 70,
            };
        }

        OsGuess::Unknown
    }

    /// Check if backoff is exponential
    pub fn is_exponential_backoff(&self) -> bool {
        if self.retries.len() < 2 {
            return false;
        }

        for i in 1..self.retries.len() {
            let prev = self.retries[i - 1].as_secs_f64();
            let curr = self.retries[i].as_secs_f64();

            // Check if roughly doubled
            let ratio = curr / prev;
            if !(1.8..=2.2).contains(&ratio) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_detection() {
        let mut fp = TcpFingerprint {
            ttl: 64,
            window_size: 5840,
            window_scale: Some(7),
            mss: Some(1460),
            has_sack: true,
            has_timestamp: true,
            ..TcpFingerprint::new()
        };

        fp.extract_options();
        let os = fp.detect_os();

        assert_eq!(os.name(), "Linux");
        assert!(os.confidence() >= 90);
    }

    #[test]
    fn test_windows_detection() {
        let fp = TcpFingerprint {
            ttl: 128,
            window_size: 8192,
            window_scale: Some(8),
            mss: Some(1460),
            ..TcpFingerprint::new()
        };

        let os = fp.detect_os();
        assert_eq!(os.name(), "Windows");
    }

    #[test]
    fn test_hop_calculation() {
        let fp = TcpFingerprint {
            ttl: 60,
            ..TcpFingerprint::new()
        };

        assert_eq!(fp.calculate_hops(), Some(4)); // 64 - 60 = 4 hops
    }

    #[test]
    fn test_ip_id_analysis() {
        let mut analyzer = IpIdAnalyzer::new();

        // Sequential pattern
        analyzer.add_sample(1000);
        analyzer.add_sample(1001);
        analyzer.add_sample(1002);
        analyzer.add_sample(1003);

        assert_eq!(analyzer.analyze(), IpIdBehavior::Sequential);
    }
}
