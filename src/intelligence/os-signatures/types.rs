/// OS Fingerprint Signature Types
///
/// Shared types for OS fingerprinting signatures.
use std::fmt;

/// OS Signature entry
#[derive(Debug, Clone)]
pub struct OsSignature {
    pub id: u32,
    pub name: String,
    pub vendor: String,
    pub os_family: String,
    pub os_generation: Option<String>,
    pub device_type: DeviceType,
    pub cpe: Option<String>, // Common Platform Enumeration

    // TCP/IP characteristics
    pub ttl: TtlMatch,
    pub window_size: WindowMatch,
    pub mss: MssMatch,
    pub window_scale: Option<u8>,
    pub tcp_options: TcpOptionsPattern,
    pub df_bit: Option<bool>, // Don't Fragment
    pub ip_id: IpIdPattern,

    // Additional probes
    pub icmp_response: Option<IcmpPattern>,
    pub ecn_support: Option<bool>, // Explicit Congestion Notification

    pub confidence_weight: f32, // How reliable this signature is
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeviceType {
    GeneralPurpose,
    Router,
    Switch,
    Firewall,
    LoadBalancer,
    Printer,
    Phone,
    Storage,
    Webcam,
    IoT,
    WAP, // Wireless Access Point
    PLC, // Programmable Logic Controller
    MediaDevice,
    VoIP,
    GameConsole,
    Container,
    VirtualMachine,
    Unknown,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceType::GeneralPurpose => write!(f, "general purpose"),
            DeviceType::Router => write!(f, "router"),
            DeviceType::Switch => write!(f, "switch"),
            DeviceType::Firewall => write!(f, "firewall"),
            DeviceType::LoadBalancer => write!(f, "load balancer"),
            DeviceType::Printer => write!(f, "printer"),
            DeviceType::Phone => write!(f, "phone"),
            DeviceType::Storage => write!(f, "storage"),
            DeviceType::Webcam => write!(f, "webcam"),
            DeviceType::IoT => write!(f, "IoT device"),
            DeviceType::WAP => write!(f, "WAP"),
            DeviceType::PLC => write!(f, "PLC"),
            DeviceType::MediaDevice => write!(f, "media device"),
            DeviceType::VoIP => write!(f, "VoIP device"),
            DeviceType::GameConsole => write!(f, "game console"),
            DeviceType::Container => write!(f, "container"),
            DeviceType::VirtualMachine => write!(f, "virtual machine"),
            DeviceType::Unknown => write!(f, "unknown"),
        }
    }
}

/// TTL matching criteria
#[derive(Debug, Clone)]
pub enum TtlMatch {
    Exact(u8),
    Range(u8, u8),
    Initial(u8), // Initial TTL (we calculate hops)
    Any,
}

impl TtlMatch {
    pub fn matches(&self, observed_ttl: u8) -> bool {
        match self {
            TtlMatch::Exact(v) => observed_ttl == *v,
            TtlMatch::Range(min, max) => observed_ttl >= *min && observed_ttl <= *max,
            TtlMatch::Initial(initial) => {
                // Account for up to 30 hops
                observed_ttl <= *initial && observed_ttl > initial.saturating_sub(30)
            }
            TtlMatch::Any => true,
        }
    }

    pub fn get_initial_ttl(&self) -> Option<u8> {
        match self {
            TtlMatch::Exact(v) | TtlMatch::Initial(v) => Some(*v),
            _ => None,
        }
    }
}

/// Window size matching
#[derive(Debug, Clone)]
pub enum WindowMatch {
    Exact(u16),
    Range(u16, u16),
    Multiple(u16), // Must be multiple of this value
    Any,
}

impl WindowMatch {
    pub fn matches(&self, observed: u16) -> bool {
        match self {
            WindowMatch::Exact(v) => observed == *v,
            WindowMatch::Range(min, max) => observed >= *min && observed <= *max,
            WindowMatch::Multiple(m) => *m > 0 && observed % m == 0,
            WindowMatch::Any => true,
        }
    }
}

/// MSS matching
#[derive(Debug, Clone)]
pub enum MssMatch {
    Exact(u16),
    Range(u16, u16),
    Any,
    None, // No MSS option present
}

impl MssMatch {
    pub fn matches(&self, observed: Option<u16>) -> bool {
        match (self, observed) {
            (MssMatch::Exact(v), Some(o)) => o == *v,
            (MssMatch::Range(min, max), Some(o)) => o >= *min && o <= *max,
            (MssMatch::Any, Some(_)) => true,
            (MssMatch::None, None) => true,
            _ => false,
        }
    }
}

/// TCP Options order pattern
#[derive(Debug, Clone)]
pub struct TcpOptionsPattern {
    pub pattern: String, // M=MSS, W=WS, N=NOP, S=SACK, T=TS, E=EOL
    pub strict_order: bool,
}

impl TcpOptionsPattern {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            strict_order: true,
        }
    }

    pub fn flexible(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            strict_order: false,
        }
    }

    pub fn matches(&self, observed: &str) -> bool {
        if self.strict_order {
            observed == self.pattern
        } else {
            // Check all required options are present (order-independent)
            for c in self.pattern.chars() {
                if !observed.contains(c) {
                    return false;
                }
            }
            true
        }
    }
}

/// IP ID behavior pattern
#[derive(Debug, Clone)]
pub enum IpIdPattern {
    Zero,
    Random,
    Sequential,
    GlobalIncrement,
    PerHostIncrement,
    Any,
}

/// ICMP response characteristics
#[derive(Debug, Clone)]
pub struct IcmpPattern {
    pub responds_to_echo: bool,
    pub echo_df_bit: Option<bool>,
    pub ttl_match: TtlMatch,
}

/// Signature builder helper for cleaner code
pub struct SignatureBuilder {
    sig: OsSignature,
}

impl SignatureBuilder {
    pub fn new(id: u32, name: &str) -> Self {
        Self {
            sig: OsSignature {
                id,
                name: name.to_string(),
                vendor: String::new(),
                os_family: String::new(),
                os_generation: None,
                device_type: DeviceType::GeneralPurpose,
                cpe: None,
                ttl: TtlMatch::Any,
                window_size: WindowMatch::Any,
                mss: MssMatch::Any,
                window_scale: None,
                tcp_options: TcpOptionsPattern::flexible(""),
                df_bit: None,
                ip_id: IpIdPattern::Any,
                icmp_response: None,
                ecn_support: None,
                confidence_weight: 0.8,
            },
        }
    }

    pub fn vendor(mut self, vendor: &str) -> Self {
        self.sig.vendor = vendor.to_string();
        self
    }

    pub fn family(mut self, family: &str) -> Self {
        self.sig.os_family = family.to_string();
        self
    }

    pub fn generation(mut self, gen: &str) -> Self {
        self.sig.os_generation = Some(gen.to_string());
        self
    }

    pub fn device(mut self, device_type: DeviceType) -> Self {
        self.sig.device_type = device_type;
        self
    }

    pub fn cpe(mut self, cpe: &str) -> Self {
        self.sig.cpe = Some(cpe.to_string());
        self
    }

    pub fn ttl(mut self, ttl: TtlMatch) -> Self {
        self.sig.ttl = ttl;
        self
    }

    pub fn ttl_initial(mut self, ttl: u8) -> Self {
        self.sig.ttl = TtlMatch::Initial(ttl);
        self
    }

    pub fn window(mut self, win: WindowMatch) -> Self {
        self.sig.window_size = win;
        self
    }

    pub fn window_exact(mut self, win: u16) -> Self {
        self.sig.window_size = WindowMatch::Exact(win);
        self
    }

    pub fn window_range(mut self, min: u16, max: u16) -> Self {
        self.sig.window_size = WindowMatch::Range(min, max);
        self
    }

    pub fn mss(mut self, mss: MssMatch) -> Self {
        self.sig.mss = mss;
        self
    }

    pub fn mss_exact(mut self, mss: u16) -> Self {
        self.sig.mss = MssMatch::Exact(mss);
        self
    }

    pub fn ws(mut self, ws: u8) -> Self {
        self.sig.window_scale = Some(ws);
        self
    }

    pub fn options(mut self, pattern: &str) -> Self {
        self.sig.tcp_options = TcpOptionsPattern::new(pattern);
        self
    }

    pub fn options_flex(mut self, pattern: &str) -> Self {
        self.sig.tcp_options = TcpOptionsPattern::flexible(pattern);
        self
    }

    pub fn df(mut self, df: bool) -> Self {
        self.sig.df_bit = Some(df);
        self
    }

    pub fn ip_id(mut self, pattern: IpIdPattern) -> Self {
        self.sig.ip_id = pattern;
        self
    }

    pub fn ecn(mut self, support: bool) -> Self {
        self.sig.ecn_support = Some(support);
        self
    }

    pub fn confidence(mut self, weight: f32) -> Self {
        self.sig.confidence_weight = weight;
        self
    }

    pub fn build(self) -> OsSignature {
        self.sig
    }
}
