# Passive Network Fingerprinting - Intelligence Extraction Guide

## TL;DR
Reference playbook for every passive signal we harvest (TCP options, TLS JA3, HTTP headers) and how to turn them into OS, infra, or service intel.

**redblue** can extract massive amounts of intelligence from network protocols WITHOUT active scanning. This document catalogs ALL fingerprinting techniques we can implement.

---

## 🎯 Philosophy: Every Byte Tells a Story

Network protocols leak information through:
- **What they send** (headers, options, defaults)
- **How they send it** (order, timing, structure)
- **What they DON'T send** (missing fields, unsupported features)
- **When they respond** (timing patterns, delays)
- **How they fail** (error messages, timeout behavior)

---

## 1. TCP/IP Stack Fingerprinting (PASSIVE)

### A. TCP Options Analysis

**What we observe:**
```
TCP Options in SYN/SYN-ACK packets reveal OS implementation details
```

**Fingerprinting vectors:**

| OS Family | Typical TCP Options | Window Size | TTL | Notes |
|-----------|-------------------|-------------|-----|-------|
| **Linux** | MSS, SACK, TS, NOP, WS | 5840-29200 | 64 | Modern: WS=7 (128×WS) |
| **Windows** | MSS, NOP, WS, NOP, NOP, SACK | 8192-65535 | 128 | Vista+: WS=8 (256×WS) |
| **macOS** | MSS, NOP, WS, NOP, NOP, TS, SACK, EOL | 65535 | 64 | Unique EOL padding |
| **FreeBSD** | MSS, NOP, WS, SACK, TS | 65535 | 64 | Distinct option order |
| **Solaris** | MSS, NOP, NOP, SACK, NOP, NOP, TS, NOP, WS, EOL | 32768-49152 | 255 | Lots of NOPs |
| **Cisco IOS** | MSS | 4128 | 255 | Minimal options |

**Implementation:**
```rust
// src/intelligence/tcp-fingerprint.rs
pub struct TcpFingerprint {
    pub window_size: u16,
    pub ttl: u8,
    pub options: Vec<TcpOption>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub timestamp: bool,
    pub sack_permitted: bool,
}

impl TcpFingerprint {
    pub fn detect_os(&self) -> OsGuess {
        // Linux: TTL=64, WS=7, specific option order
        if self.ttl == 64 && self.window_scale == Some(7) {
            return OsGuess::Linux;
        }

        // Windows: TTL=128, WS=8, large window
        if self.ttl == 128 && self.window_scale == Some(8) {
            return OsGuess::Windows;
        }

        // macOS: EOL padding, TTL=64
        if self.ttl == 64 && self.has_eol_padding() {
            return OsGuess::MacOS;
        }

        // Solaris: TTL=255, many NOPs
        if self.ttl == 255 && self.count_nops() > 4 {
            return OsGuess::Solaris;
        }

        OsGuess::Unknown
    }
}
```

### B. IP TTL (Time-to-Live) Patterns

**Default TTL by OS:**
- Linux/Unix: **64**
- Windows: **128**
- Solaris/AIX: **255**
- Cisco: **255**
- Old systems: **30, 32, 60**

**Distance calculation:**
```rust
// If we receive TTL=60, and default is 64 → 4 hops away
pub fn calculate_hops(received_ttl: u8) -> Option<u8> {
    let defaults = [255, 128, 64, 32];

    for &default in &defaults {
        if received_ttl <= default {
            return Some(default - received_ttl);
        }
    }
    None
}
```

### C. IP ID Field Behavior

**Implementation differences:**

| OS | IP ID Behavior | Pattern |
|----|---------------|---------|
| **Linux 2.6+** | Random | Non-sequential |
| **Linux 2.4** | Global counter | Sequential across all connections |
| **Windows** | Per-connection | Sequential per connection |
| **FreeBSD** | Random | Non-sequential |
| **OpenBSD** | Random | Non-sequential with RFC 6864 |

**Use case:** Detect load balancers, NAT, connection persistence

```rust
pub fn analyze_ip_id_sequence(samples: &[u16]) -> IpIdBehavior {
    let diffs: Vec<i32> = samples.windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();

    let avg_diff = diffs.iter().sum::<i32>() / diffs.len() as i32;

    if avg_diff.abs() < 10 {
        IpIdBehavior::Random  // Modern Linux, BSD
    } else if avg_diff > 0 && avg_diff < 100 {
        IpIdBehavior::Sequential  // Windows, old Linux
    } else {
        IpIdBehavior::PerConnection
    }
}
```

### D. TCP Timestamp Analysis

**Clock skew detection:**
```rust
// Detect virtualization, clock drift, uptime
pub struct TcpTimestamp {
    pub value: u32,      // TSval
    pub echo_reply: u32, // TSecr
    pub received_at: SystemTime,
}

pub fn detect_clock_skew(samples: &[TcpTimestamp]) -> ClockSkew {
    // Calculate timestamp Hz (usually 100Hz, 250Hz, 1000Hz)
    // Linux: 250Hz or 1000Hz
    // Windows: 100Hz
    // BSD: 100Hz
}

pub fn estimate_uptime(first_ts: u32, hz: u32) -> Duration {
    Duration::from_secs((first_ts / hz) as u64)
}
```

### E. TCP Retransmission Behavior

**You mentioned this! Retransmission patterns reveal OS:**

| OS | Initial RTO | Backoff | Max Retries |
|----|------------|---------|-------------|
| **Linux** | 3s | Exponential (3s → 6s → 12s) | 15 |
| **Windows** | 3s | Exponential | 5 |
| **FreeBSD** | 1.5s | Exponential | 12 |
| **macOS** | 1s | Exponential | 8 |

```rust
pub struct RetransmissionProfile {
    pub initial_rto: Duration,
    pub retries: Vec<Duration>,
    pub max_retries: u8,
}

impl RetransmissionProfile {
    pub fn detect_os(&self) -> OsGuess {
        if self.initial_rto.as_secs() == 3 && self.max_retries == 15 {
            OsGuess::Linux
        } else if self.initial_rto.as_secs() == 3 && self.max_retries == 5 {
            OsGuess::Windows
        } else if self.initial_rto.as_millis() == 1500 {
            OsGuess::FreeBSD
        } else {
            OsGuess::Unknown
        }
    }
}
```

---

## 2. TLS/SSL Fingerprinting (JA3/JA4)

### A. JA3 Fingerprinting

**What we capture:**
```
TLS ClientHello fields → Unique hash identifying client application
```

**JA3 string format:**
```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```

**Example:**
```
Firefox 120:  771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0

Chrome 120:   771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24,0

curl 8.4:     771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0
```

**Implementation:**
```rust
// src/intelligence/tls-fingerprint.rs
pub struct JA3Fingerprint {
    pub ssl_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

impl JA3Fingerprint {
    pub fn from_client_hello(data: &[u8]) -> Self {
        // Parse TLS ClientHello
        // Extract fields
    }

    pub fn to_string(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.ssl_version,
            self.ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
            self.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
            self.elliptic_curves.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
            self.ec_point_formats.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("-"),
        )
    }

    pub fn hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let ja3_string = self.to_string();
        let mut hasher = DefaultHasher::new();
        ja3_string.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub fn identify_client(&self) -> ClientIdentity {
        // Match against known JA3 hashes
        match self.hash().as_str() {
            "cd08e31764fd6e75eac4650d2024231b" => ClientIdentity::Firefox,
            "579ccef312d18482fc42e2b822ca2430" => ClientIdentity::Chrome,
            "51c64c77e60f3980eea90869b68c58a8" => ClientIdentity::Curl,
            "e7d705a3286e19ea42f587b344ee6865" => ClientIdentity::Python,
            _ => ClientIdentity::Unknown,
        }
    }
}
```

### B. JA4+ (Newer, More Robust)

**JA4 improvements over JA3:**
- Not vulnerable to cipher order changes
- Includes ALPN (Application-Layer Protocol Negotiation)
- Better at detecting bots vs browsers

```rust
pub struct JA4Fingerprint {
    pub protocol_version: String,  // "q" for QUIC, "t" for TCP
    pub sni_status: char,           // "d" for domain, "i" for IP
    pub cipher_count: u8,
    pub extension_count: u8,
    pub alpn_first: String,         // First ALPN value
    // ... more fields
}
```

### C. Certificate Chain Analysis

**Intelligence from certificates:**

```rust
pub struct CertificateIntelligence {
    pub issuer: String,              // CA identity
    pub subject_alt_names: Vec<String>, // All SANs = all domains
    pub validity_period: Duration,   // Short = automation, long = manual
    pub serial_number: Vec<u8>,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_size: u16,

    // Intelligence
    pub is_wildcard: bool,           // *.example.com
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub is_free_ca: bool,            // Let's Encrypt, ZeroSSL
    pub is_enterprise_ca: bool,      // DigiCert, Entrust
}

impl CertificateIntelligence {
    pub fn infer_organization_size(&self) -> OrgSize {
        if self.is_free_ca {
            OrgSize::Small  // Startups, hobbyists
        } else if self.is_enterprise_ca && self.validity_period.as_secs() > 31536000 {
            OrgSize::Large  // 1+ year certs = $$$ = enterprise
        } else {
            OrgSize::Medium
        }
    }

    pub fn infer_automation(&self) -> bool {
        // Let's Encrypt = 90 days = automated renewal
        self.is_free_ca && self.validity_period.as_secs() < 7776000
    }

    pub fn extract_all_domains(&self) -> Vec<String> {
        self.subject_alt_names.clone()
    }
}
```

---

## 3. HTTP Fingerprinting

### A. Server Header Analysis

**Common patterns:**

| Server Header | Technology | Version Leaks |
|--------------|------------|---------------|
| `Apache/2.4.41 (Ubuntu)` | Web server + OS | Yes, full version |
| `nginx/1.18.0` | Web server | Yes, version only |
| `Microsoft-IIS/10.0` | IIS + Windows | Version hints at Windows version |
| `cloudflare` | CDN/WAF | Hides origin |
| `AmazonS3` | Cloud storage | AWS presence |

```rust
pub fn analyze_server_header(server: &str) -> ServerIntelligence {
    if server.contains("Apache") {
        // Extract version, OS
        if let Some(os) = extract_os_from_apache(server) {
            return ServerIntelligence {
                server_type: ServerType::Apache,
                os_hint: Some(os),
                version: extract_version(server),
            };
        }
    }

    if server.contains("nginx") {
        ServerIntelligence {
            server_type: ServerType::Nginx,
            version: extract_version(server),
            os_hint: None,  // Nginx doesn't leak OS
        }
    }

    // ... etc
}
```

### B. Header Order Fingerprinting

**Different servers send headers in different orders:**

```rust
pub struct HttpHeaderOrder {
    pub headers: Vec<String>,  // Order matters!
}

impl HttpHeaderOrder {
    pub fn fingerprint(&self) -> ServerGuess {
        let order_signature = self.headers.join("|");

        // Apache: Date|Server|Last-Modified|ETag|Accept-Ranges|Content-Length|Content-Type
        if order_signature.starts_with("Date|Server|Last-Modified") {
            return ServerGuess::Apache;
        }

        // nginx: Server|Date|Content-Type|Content-Length|Connection
        if order_signature.starts_with("Server|Date|Content-Type") {
            return ServerGuess::Nginx;
        }

        // IIS: Content-Length|Content-Type|Server|X-Powered-By|Date
        if order_signature.starts_with("Content-Length|Content-Type|Server") {
            return ServerGuess::IIS;
        }

        ServerGuess::Unknown
    }
}
```

### C. Cookie Fingerprinting

**Framework detection via cookie names:**

```rust
pub fn detect_framework_from_cookies(cookies: &HashMap<String, String>) -> Vec<Framework> {
    let mut frameworks = Vec::new();

    if cookies.contains_key("PHPSESSID") {
        frameworks.push(Framework::PHP);
    }

    if cookies.contains_key("JSESSIONID") {
        frameworks.push(Framework::Java);
    }

    if cookies.contains_key("ASP.NET_SessionId") {
        frameworks.push(Framework::AspNet);
    }

    if cookies.contains_key("__cfduid") {
        frameworks.push(Framework::Cloudflare);
    }

    if cookies.contains_key("_ga") || cookies.contains_key("_gid") {
        frameworks.push(Framework::GoogleAnalytics);
    }

    frameworks
}
```

### D. HTTP Status Code Behavior

**Error pages reveal technology:**

```rust
pub struct HttpErrorIntelligence {
    pub status_code: u16,
    pub error_page_content: String,
    pub headers: HashMap<String, String>,
}

impl HttpErrorIntelligence {
    pub fn detect_technology(&self) -> Vec<Technology> {
        let mut tech = Vec::new();

        // 404 pages often leak framework
        if self.status_code == 404 {
            if self.error_page_content.contains("Django") {
                tech.push(Technology::Django);
            }
            if self.error_page_content.contains("Laravel") {
                tech.push(Technology::Laravel);
            }
            if self.error_page_content.contains("WordPress") {
                tech.push(Technology::WordPress);
            }
        }

        // 403 Forbidden styles differ
        if self.status_code == 403 {
            if self.error_page_content.contains("nginx") {
                tech.push(Technology::Nginx);
            }
        }

        tech
    }
}
```

---

## 4. DNS Fingerprinting

### A. DNS Response Analysis

**BIND version detection:**
```rust
// Query: dig @target version.bind chaos txt
pub fn detect_dns_server(response: &DnsResponse) -> DnsServer {
    if let Some(version) = response.get_txt_record("version.bind") {
        if version.contains("BIND") {
            return DnsServer::Bind { version };
        }
    }

    // Cloudflare always returns specific IPs
    if response.answers.iter().any(|a| a.data == "104.16.132.229") {
        return DnsServer::Cloudflare;
    }

    DnsServer::Unknown
}
```

### B. DNS TTL Patterns

**CDN detection via low TTL:**
```rust
pub fn detect_cdn_from_ttl(ttl: u32) -> Option<Cdn> {
    match ttl {
        0..=60 => Some(Cdn::Cloudflare),    // Very low TTL
        61..=300 => Some(Cdn::Fastly),      // Low TTL
        301..=3600 => Some(Cdn::Akamai),    // Medium TTL
        _ => None,
    }
}
```

---

## 5. ICMP Fingerprinting

### A. ICMP Code Field

**Different OS, different ICMP codes:**

| OS | Port Unreachable | TTL Exceeded |
|----|-----------------|--------------|
| Linux | Code 3 | Code 0 |
| Windows | Code 3 | Code 0 |
| Solaris | Code 2 | Code 1 |

### B. ICMP Payload Echo

**Some OS echo back different payload sizes:**

```rust
pub fn detect_os_from_icmp_echo(sent_size: usize, received_size: usize) -> OsGuess {
    if received_size == sent_size {
        OsGuess::LinuxOrWindows
    } else if received_size < sent_size {
        OsGuess::BSDVariant
    } else {
        OsGuess::Unknown
    }
}
```

---

## 6. Banner Analysis

### A. SSH Banners

**Format: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`**

```rust
pub struct SshBanner {
    pub protocol_version: String,  // SSH-2.0
    pub software: String,           // OpenSSH_8.2p1
    pub os_hint: Option<String>,    // Ubuntu-4ubuntu0.5
}

impl SshBanner {
    pub fn parse(banner: &str) -> Self {
        // Extract OS from banner
        let os_hint = if banner.contains("Ubuntu") {
            Some("Ubuntu".to_string())
        } else if banner.contains("Debian") {
            Some("Debian".to_string())
        } else if banner.contains("FreeBSD") {
            Some("FreeBSD".to_string())
        } else {
            None
        };

        Self { /* ... */ }
    }
}
```

### B. FTP Banners

**Examples:**
- `220 ProFTPD 1.3.5 Server (Debian)`
- `220 Microsoft FTP Service`
- `220 (vsFTPd 3.0.3)`

### C. SMTP Banners

**Example: `220 mail.example.com ESMTP Postfix (Ubuntu)`**

---

## 7. WebSocket Fingerprinting

### A. Upgrade Handshake Analysis

```rust
pub struct WebSocketHandshake {
    pub sec_websocket_key: String,
    pub sec_websocket_version: String,
    pub sec_websocket_extensions: Vec<String>,
    pub user_agent: String,
}

impl WebSocketHandshake {
    pub fn detect_client(&self) -> WsClient {
        // Browser WebSocket API always uses specific version
        if self.sec_websocket_version == "13" && self.user_agent.contains("Chrome") {
            WsClient::ChromeBrowser
        } else if self.sec_websocket_extensions.contains(&"ws".to_string()) {
            WsClient::NodeWs  // Node.js ws library
        } else {
            WsClient::Unknown
        }
    }
}
```

---

## 8. Timing Analysis

### A. Response Time Distribution

**Detect:**
- Load balancers (multi-modal response times)
- Geographic distance (consistent delay)
- Rate limiting (sudden slowdowns)
- Caching (bimodal: fast cache hits vs slow misses)

```rust
pub struct TimingProfile {
    pub samples: Vec<Duration>,
}

impl TimingProfile {
    pub fn detect_caching(&self) -> bool {
        // Bimodal distribution = caching
        let fast = self.samples.iter().filter(|&&d| d < Duration::from_millis(50)).count();
        let slow = self.samples.iter().filter(|&&d| d > Duration::from_millis(200)).count();

        fast > 0 && slow > 0 && (fast + slow) > self.samples.len() / 2
    }

    pub fn detect_load_balancer(&self) -> bool {
        // Multiple distinct peaks = multiple backend servers
        let variance = self.calculate_variance();
        variance > 100.0  // High variance = load balancer
    }
}
```

---

## 9. WAF/CDN Detection

### A. WAF Fingerprinting

**Detection methods:**

```rust
pub fn detect_waf(response: &HttpResponse) -> Option<Waf> {
    // 1. Check headers
    if response.headers.contains_key("cf-ray") {
        return Some(Waf::Cloudflare);
    }

    if response.headers.contains_key("x-sucuri-id") {
        return Some(Waf::Sucuri);
    }

    // 2. Check cookies
    if response.cookies.contains_key("__cfduid") {
        return Some(Waf::Cloudflare);
    }

    // 3. Send malicious payload, analyze block page
    let test_response = send_xss_payload();
    if test_response.status == 403 && test_response.body.contains("ModSecurity") {
        return Some(Waf::ModSecurity);
    }

    None
}
```

---

## 10. Infrastructure Inference

### A. Cloud Provider Detection

```rust
pub fn detect_cloud_provider(ip: &str, headers: &HashMap<String, String>) -> Option<CloudProvider> {
    // AWS IP ranges
    if is_aws_ip(ip) {
        return Some(CloudProvider::AWS);
    }

    // Azure headers
    if headers.contains_key("x-ms-request-id") {
        return Some(CloudProvider::Azure);
    }

    // GCP headers
    if headers.contains_key("x-goog-generation") {
        return Some(CloudProvider::GCP);
    }

    // DigitalOcean IP ranges
    if is_digitalocean_ip(ip) {
        return Some(CloudProvider::DigitalOcean);
    }

    None
}
```

---

## 11. Protocol Implementation Quirks

### A. HTTP/2 SETTINGS Frame

**Different servers send different SETTINGS:**

```rust
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Http2Settings {
    pub fn fingerprint_server(&self) -> ServerGuess {
        // nginx typical settings
        if self.max_concurrent_streams == 128 && self.initial_window_size == 65535 {
            return ServerGuess::Nginx;
        }

        // Apache typical settings
        if self.max_concurrent_streams == 100 {
            return ServerGuess::Apache;
        }

        ServerGuess::Unknown
    }
}
```

---

## 12. Behavioral Fingerprinting

### A. Rate Limiting Patterns

```rust
pub struct RateLimitProfile {
    pub threshold: u32,      // Requests before limit
    pub window: Duration,    // Time window
    pub reset_type: ResetType, // Rolling vs Fixed window
}

pub enum ResetType {
    Rolling,    // Cloudflare, nginx
    Fixed,      // Traditional WAF
}
```

### B. Connection Persistence

**Detect load balancer session affinity:**

```rust
pub fn detect_session_affinity() -> bool {
    // Make multiple requests, check if we hit same backend
    let mut backends = HashSet::new();

    for _ in 0..10 {
        let response = make_request();
        let backend_id = extract_backend_id(&response);
        backends.insert(backend_id);
    }

    backends.len() == 1  // All requests → same backend = sticky sessions
}
```

---

## 📊 Data Organization Strategy

### Storage Schema

```rust
// src/storage/segments/fingerprints.rs
pub struct FingerprintRecord {
    pub target: String,
    pub timestamp: SystemTime,

    // TCP/IP Layer
    pub tcp_fingerprint: Option<TcpFingerprint>,
    pub ip_ttl: Option<u8>,
    pub ip_id_behavior: Option<IpIdBehavior>,

    // TLS Layer
    pub ja3_hash: Option<String>,
    pub ja4_hash: Option<String>,
    pub cert_intelligence: Option<CertificateIntelligence>,

    // HTTP Layer
    pub http_server: Option<String>,
    pub http_headers_order: Option<Vec<String>>,
    pub cookies: Option<HashMap<String, String>>,

    // Application Layer
    pub ssh_banner: Option<String>,
    pub smtp_banner: Option<String>,

    // Intelligence
    pub os_guess: Option<OsGuess>,
    pub waf_detected: Option<Waf>,
    pub cdn_detected: Option<Cdn>,
    pub cloud_provider: Option<CloudProvider>,

    // Timing
    pub response_time_profile: Option<TimingProfile>,
}
```

### CLI Command Structure

```bash
# Extract fingerprints from target
rb intelligence fingerprint extract google.com

# Compare fingerprints
rb intelligence fingerprint compare target1.com target2.com

# List all fingerprints for a target
rb intelligence fingerprint list google.com

# Export fingerprint database
rb intelligence fingerprint export fingerprints.json
```

---

## 🎓 Learning Resources

### RFCs to Study
- **RFC 793**: TCP
- **RFC 791**: IP
- **RFC 1323**: TCP Extensions
- **RFC 8446**: TLS 1.3
- **RFC 2616**: HTTP/1.1
- **RFC 7540**: HTTP/2

### Tools to Learn From
- **nmap** - OS detection (--osscan-guess)
- **p0f** - Passive OS fingerprinting
- **Wireshark** - Protocol dissection
- **tshark** - CLI packet analysis

---

## 🚀 Implementation Priority

**Phase 1 (High Value):**
1. ✅ TCP options fingerprinting
2. ✅ TTL-based OS detection
3. ✅ JA3 TLS fingerprinting
4. ✅ HTTP header analysis
5. ✅ Banner extraction

**Phase 2 (Medium Value):**
6. IP ID sequence analysis
7. TCP timestamp clock skew
8. Certificate chain intelligence
9. WAF/CDN detection
10. Timing analysis

**Phase 3 (Advanced):**
11. JA4+ fingerprinting
12. HTTP/2 SETTINGS fingerprinting
13. Behavioral rate limit profiling
14. Load balancer detection
15. Retransmission pattern analysis

---

## 💡 Key Insight

**Every protocol interaction is a reconnaissance opportunity.**

Instead of just "making a connection," we should ask:
- What does the TCP handshake tell us?
- How does the server respond to edge cases?
- What defaults are being used?
- What's missing that should be there?
- What patterns emerge over time?

This mindset transforms redblue from a "tool that scans" into an "intelligence gathering platform."
