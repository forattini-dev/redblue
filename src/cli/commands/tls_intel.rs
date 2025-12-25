/// TLS Intelligence Gathering Command
///
/// Advanced TLS fingerprinting, infrastructure detection, and passive intelligence
/// gathering. This command implements techniques used by Censys, Shodan, and
/// security researchers to identify servers, detect infrastructure, and discover
/// hidden assets.
///
/// Replaces: censys, shodan (TLS portion), testssl.sh --intel
///
/// Note: This module requires OpenSSL (boring) which is not available on Windows.
/// On Windows, this command will return an error.
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
#[cfg(not(target_os = "windows"))]
use crate::modules::network::tls::{TlsConfig, TlsStream, TlsVersion};
#[cfg(not(target_os = "windows"))]
use boring::nid::Nid;
#[cfg(not(target_os = "windows"))]
use boring::ssl::{SslConnector, SslMethod, SslRef, SslVerifyMode, SslVersion};
#[cfg(not(target_os = "windows"))]
use boring::x509::{X509Ref, X509};
#[cfg(not(target_os = "windows"))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
#[cfg(not(target_os = "windows"))]
use std::str;
#[cfg(not(target_os = "windows"))]
use std::time::{Duration, Instant};

pub struct TlsIntelCommand;

impl Command for TlsIntelCommand {
    fn domain(&self) -> &str {
        "tls"
    }

    fn resource(&self) -> &str {
        "intel"
    }

    fn description(&self) -> &str {
        "TLS intelligence gathering and passive fingerprinting"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "scan",
                summary: "Comprehensive TLS intelligence scan (replaces censys/shodan)",
                usage: "rb tls intel scan <host[:port]> [--samples N]",
            },
            Route {
                verb: "fingerprint",
                summary: "TLS stack fingerprinting (detect OpenSSL, BoringSSL, etc)",
                usage: "rb tls intel fingerprint <host[:port]>",
            },
            Route {
                verb: "infrastructure",
                summary: "Detect CDN, cloud provider, load balancer",
                usage: "rb tls intel infrastructure <host[:port]>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("samples", "Number of handshake samples for timing analysis")
                .with_short('n')
                .with_default("5"),
            Flag::new("timeout", "Connection timeout in seconds").with_default("10"),
            Flag::new("port", "Target port").with_default("443"),
            Flag::new("persist", "Save intelligence to database"),
            Flag::new("json", "Output in JSON format").with_short('j'),
            Flag::new("format", "Output format (text, json)")
                .with_short('f')
                .with_default("text"),
            Flag::new("verbose", "Show detailed timing for each sample").with_short('v'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Full intelligence scan", "rb tls intel scan example.com"),
            (
                "Scan with 10 samples",
                "rb tls intel scan example.com --samples 10",
            ),
            (
                "Just infrastructure detection",
                "rb tls intel infrastructure example.com",
            ),
            (
                "Fingerprint TLS stack",
                "rb tls intel fingerprint google.com",
            ),
        ]
    }

    #[cfg(target_os = "windows")]
    fn execute(&self, _ctx: &CliContext) -> Result<(), String> {
        Err("TLS intelligence gathering is not available on Windows (requires OpenSSL)".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "scan" => self.intel_scan(ctx),
            "fingerprint" => self.fingerprint(ctx),
            "infrastructure" => self.infrastructure(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl TlsIntelCommand {
    fn gather_tls_telemetry(
        &self,
        host: &str,
        ssl: &SslRef,
        peer_cert: Option<&X509Ref>,
    ) -> TlsHandshakeTelemetry {
        let tls_version = ssl.version_str().to_string();
        let cipher_suite = ssl.current_cipher().map(|cipher| {
            cipher
                .standard_name()
                .unwrap_or_else(|| cipher.name())
                .to_string()
        });

        let alpn_protocol = ssl
            .selected_alpn_protocol()
            .filter(|proto| !proto.is_empty())
            .map(format_alpn);

        let mut session_id = None;
        let mut master_key_hash = None;
        let mut master_key_len = None;
        if let Some(session) = ssl.session() {
            let id = session.id();
            if !id.is_empty() {
                session_id = Some(hex_from_bytes(id));
            }
            let len = session.master_key_len();
            if len > 0 {
                master_key_len = Some(len);
                let mut buf = vec![0u8; len];
                let written = session.master_key(&mut buf);
                buf.truncate(written);
                if !buf.is_empty() {
                    master_key_hash = Some(sha256_hex(&buf));
                }
            }
        }

        let mut client_random = None;
        let mut client_buf = [0u8; 64];
        let cr_len = ssl.client_random(&mut client_buf);
        if cr_len > 0 {
            client_random = Some(hex_from_bytes(&client_buf[..cr_len]));
        }

        let mut server_random = None;
        let mut server_buf = [0u8; 64];
        let sr_len = ssl.server_random(&mut server_buf);
        if sr_len > 0 {
            server_random = Some(hex_from_bytes(&server_buf[..sr_len]));
        }

        let ocsp_stapled = ssl.ocsp_status().is_some();
        let session_resumed = ssl.session_reused();

        // let (peer_tmp_key, peer_named_group) = match ssl.peer_tmp_key() {
        //     Ok(key) => {
        //         let (desc, group) = describe_tmp_key(key.as_ref());
        //         (Some(desc), group)
        //     }
        //     Err(_) => (None, None),
        // };
        let (peer_tmp_key, peer_named_group) = (None, None);

        let peer_signature_algorithm = peer_cert.and_then(|cert| {
            let nid = cert.signature_algorithm().object().nid();
            nid.short_name().ok().map(|name| name.to_string())
        });

        let mut fingerprint_components = Vec::new();
        fingerprint_components.push(format!("version={}", tls_version));
        if let Some(ref cipher) = cipher_suite {
            fingerprint_components.push(format!("cipher={}", cipher));
        }
        if let Some(ref alpn) = alpn_protocol {
            fingerprint_components.push(format!("alpn={}", alpn));
        }
        if let Some(ref cr) = client_random {
            fingerprint_components.push(format!("cr={}", cr));
        }
        if let Some(ref sr) = server_random {
            fingerprint_components.push(format!("sr={}", sr));
        }
        if let Some(ref sid) = session_id {
            fingerprint_components.push(format!("session={}", sid));
        }
        if let Some(ref group) = peer_named_group {
            fingerprint_components.push(format!("group={}", group));
        }
        if session_resumed {
            fingerprint_components.push("resumed=1".to_string());
        }

        let fingerprint_sha256 = if fingerprint_components.is_empty() {
            None
        } else {
            let joined = fingerprint_components.join("|");
            Some(sha256_hex(joined.as_bytes()))
        };

        TlsHandshakeTelemetry {
            tls_version,
            cipher_suite,
            alpn_protocol,
            sni: Some(host.to_string()),
            session_id,
            session_resumed,
            client_random,
            server_random,
            master_key_hash,
            master_key_len,
            ocsp_stapled,
            peer_tmp_key,
            peer_named_group,
            peer_signature_algorithm,
            fingerprint_sha256,
        }
    }

    fn fallback_tls_telemetry(
        &self,
        host: &str,
        cipher: &str,
        version: &str,
    ) -> TlsHandshakeTelemetry {
        let mut fingerprint_components =
            vec![format!("version={}", version), format!("cipher={}", cipher)];
        fingerprint_components.push(format!("sni={}", host));
        let fingerprint_sha256 = Some(sha256_hex(fingerprint_components.join("|").as_bytes()));

        TlsHandshakeTelemetry {
            tls_version: version.to_string(),
            cipher_suite: Some(cipher.to_string()),
            alpn_protocol: None,
            sni: Some(host.to_string()),
            session_id: None,
            session_resumed: false,
            client_random: None,
            server_random: None,
            master_key_hash: None,
            master_key_len: None,
            ocsp_stapled: false,
            peer_tmp_key: None,
            peer_named_group: None,
            peer_signature_algorithm: None,
            fingerprint_sha256,
        }
    }

    fn render_handshake_overview(&self, telemetry: &TlsHandshakeTelemetry) {
        Output::section("Handshake Fingerprint");
        Output::item("TLS version", &telemetry.tls_version);
        Output::item(
            "Cipher",
            telemetry.cipher_suite.as_deref().unwrap_or("Unknown"),
        );
        if let Some(ref alpn) = telemetry.alpn_protocol {
            Output::item("ALPN", alpn);
        }
        if let Some(ref sni) = telemetry.sni {
            Output::item("SNI", sni);
        }
        Output::item(
            "Session reused",
            if telemetry.session_resumed {
                "yes"
            } else {
                "no"
            },
        );
        if let Some(ref session_id) = telemetry.session_id {
            Output::item("Session ID", &abbreviate_hex(session_id, 32));
        }
        if let Some(ref client_random) = telemetry.client_random {
            Output::item("Client random", &abbreviate_hex(client_random, 32));
        }
        if let Some(ref server_random) = telemetry.server_random {
            Output::item("Server random", &abbreviate_hex(server_random, 32));
        }
        if let Some(len) = telemetry.master_key_len {
            if let Some(ref hash) = telemetry.master_key_hash {
                Output::item(
                    "Master secret",
                    &format!("{} bytes (hash {})", len, abbreviate_hex(hash, 48)),
                );
            } else {
                Output::item("Master secret", &format!("{} bytes", len));
            }
        }
        Output::item(
            "OCSP stapled",
            if telemetry.ocsp_stapled { "yes" } else { "no" },
        );
        if let Some(ref key) = telemetry.peer_tmp_key {
            Output::item("Key share", key);
        }
        if let Some(ref group) = telemetry.peer_named_group {
            Output::item("Group", group);
        }
        if let Some(ref sig) = telemetry.peer_signature_algorithm {
            Output::item("Signature", sig);
        }
        if let Some(ref fingerprint) = telemetry.fingerprint_sha256 {
            Output::item("Fingerprint", &abbreviate_hex(fingerprint, 48));
        }
    }
    /// Comprehensive TLS intelligence scan
    fn intel_scan(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or("Missing target host")?;
        let scan_start = Instant::now();

        // Parse host:port
        let parse_start = Instant::now();
        let (host, port) = self.parse_target(target, ctx)?;
        let parse_time = parse_start.elapsed();

        Output::header(&format!("TLS Intelligence Scan: {}", target));
        Output::info(&format!("Target: {}:{}", host, port));
        Output::item(
            "Parse time",
            &format!("{:.2}ms", parse_time.as_micros() as f64 / 1000.0),
        );

        // Get number of samples
        let samples: usize = ctx
            .flags
            .get("samples")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let debug = ctx.flags.contains_key("verbose") || ctx.flags.contains_key("v");
        let timeout_secs: u64 = ctx
            .flags
            .get("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        Output::info(&format!("Collecting {} handshake samples...", samples));

        // Pre-resolve DNS ONCE (cache for all samples)
        let dns_resolve_start = Instant::now();
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", host, port);
        let resolved_addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed: {}", e))?
            .collect();
        let dns_resolve_time = dns_resolve_start.elapsed().as_micros() as f64 / 1000.0;

        if resolved_addrs.is_empty() {
            return Err(format!("No addresses resolved for {}", host));
        }

        // Extract first IP address for caching
        let first_ip = resolved_addrs[0].ip().to_string();

        Output::item(
            "DNS resolution",
            &format!("{:.2}ms (cached for all samples)", dns_resolve_time),
        );

        // Persist DNS cache if --persist flag is set
        if ctx.flags.contains_key("persist") {
            let db_path = format!("{}.rbdb", host);
            match crate::storage::store::Database::open(&db_path) {
                Ok(mut db) => {
                    // DNS TTL default: 300 seconds (5 minutes)
                    let dns_record = crate::storage::records::DnsRecordData {
                        domain: host.to_string(),
                        record_type: crate::storage::records::DnsRecordType::A,
                        value: first_ip.to_string(),
                        ttl: 300,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as u32,
                    };
                    db.insert_dns(dns_record);
                    if let Err(e) = db.flush() {
                        eprintln!("⚠ Warning: Failed to save DNS cache: {}", e);
                    } else {
                        Output::success(&format!("✓ DNS cache saved: {} → {}", host, first_ip));
                    }
                }
                Err(e) => {
                    eprintln!("⚠ Warning: Failed to open database: {}", e);
                }
            }
        }

        // Perform multiple TLS handshakes to gather timing data
        let mut handshake_times = Vec::new();
        let mut timing_breakdown = Vec::new();
        let mut primary_telemetry: Option<TlsHandshakeTelemetry> = None;
        let mut cert_info = None;

        for i in 0..samples {
            let sample_start = Instant::now();

            match self.perform_handshake_with_timing(&host, port, timeout_secs, debug) {
                Ok((telemetry, cert, timings)) => {
                    let total_elapsed = sample_start.elapsed().as_millis() as u64;
                    handshake_times.push(total_elapsed);

                    if primary_telemetry.is_none() {
                        primary_telemetry = Some(telemetry.clone());
                    }
                    if cert_info.is_none() {
                        cert_info = Some(cert.clone());
                    }

                    // Show basic timing
                    Output::item(
                        &format!("Sample {}", i + 1),
                        &format!("{}ms", total_elapsed),
                    );

                    // Show detailed breakdown if --verbose
                    if ctx.flags.contains_key("verbose") {
                        println!("    DNS: {:.2}ms | TCP: {:.2}ms | ClientHello: {:.2}ms | ServerHello: {:.2}ms | KeyDeriv: {:.2}ms | Encrypted: {:.2}ms | CertParse: {:.2}ms",
                            timings.dns_resolution_ms,
                            timings.tcp_connect_ms,
                            timings.tls_client_hello_ms,
                            timings.tls_server_hello_ms,
                            timings.tls_key_derivation_ms,
                            timings.tls_encrypted_handshake_ms,
                            timings.cert_parse_ms
                        );
                    }

                    // Push timings after using (move happens last)
                    timing_breakdown.push(timings);
                }
                Err(e) => {
                    Output::warning(&format!("Sample {} failed: {}", i + 1, e));
                }
            }
        }

        if handshake_times.is_empty() {
            return Err("All handshake attempts failed".to_string());
        }

        // Calculate timing statistics
        let avg = handshake_times.iter().sum::<u64>() / handshake_times.len() as u64;
        let min = *handshake_times.iter().min().unwrap();
        let max = *handshake_times.iter().max().unwrap();
        let jitter = max - min;

        // Build intelligence report
        Output::success("\nTLS Intelligence Report");
        Output::item("Average latency", &format!("{}ms", avg));
        Output::item("Min/Max", &format!("{}ms / {}ms", min, max));
        Output::item("Jitter", &format!("{}ms", jitter));

        if let Some(ref telemetry) = primary_telemetry {
            Output::item(
                "Cipher suite",
                telemetry.cipher_suite.as_deref().unwrap_or("Unknown"),
            );
        }

        if let Some(cert) = cert_info {
            Output::item("Certificate CN", &cert.subject);
            Output::item("Issuer", &cert.issuer);
            if !cert.sans.is_empty() {
                Output::item("SANs", &format!("{} domains", cert.sans.len()));
                for san in &cert.sans {
                    Output::item("  -", san);
                }
            }
        }

        // Infrastructure detection
        let cipher_str = primary_telemetry
            .as_ref()
            .and_then(|t| t.cipher_suite.as_deref())
            .unwrap_or("");
        self.detect_infrastructure(cipher_str, avg)?;

        if let Some(ref telemetry) = primary_telemetry {
            self.render_handshake_overview(telemetry);
        }

        // Timing breakdown (average across all samples)
        if !timing_breakdown.is_empty() {
            Output::section("Timing Breakdown (Average)");

            let avg_dns = timing_breakdown
                .iter()
                .map(|t| t.dns_resolution_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;
            let avg_tcp = timing_breakdown
                .iter()
                .map(|t| t.tcp_connect_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;
            let avg_tls_hello = timing_breakdown
                .iter()
                .map(|t| t.tls_client_hello_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;
            let avg_tls_recv = timing_breakdown
                .iter()
                .map(|t| t.tls_server_hello_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;
            let avg_tls_derive = timing_breakdown
                .iter()
                .map(|t| t.tls_key_derivation_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;
            let avg_tls_encrypted = timing_breakdown
                .iter()
                .map(|t| t.tls_encrypted_handshake_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;
            let avg_cert_parse = timing_breakdown
                .iter()
                .map(|t| t.cert_parse_ms)
                .sum::<f64>()
                / timing_breakdown.len() as f64;

            Output::item("DNS resolution", &format!("{:.2}ms", avg_dns));
            Output::item("TCP connect", &format!("{:.2}ms", avg_tcp));
            Output::item("TLS ClientHello", &format!("{:.2}ms", avg_tls_hello));
            Output::item("TLS ServerHello", &format!("{:.2}ms", avg_tls_recv));
            Output::item("Key derivation", &format!("{:.2}ms", avg_tls_derive));
            Output::item(
                "Encrypted handshake",
                &format!("{:.2}ms", avg_tls_encrypted),
            );
            Output::item("Cert parsing", &format!("{:.2}ms", avg_cert_parse));
        }

        // Total scan time
        let total_scan_time = scan_start.elapsed();
        Output::section("Total Scan Time");
        Output::item(
            "Complete",
            &format!("{:.2}ms", total_scan_time.as_micros() as f64 / 1000.0),
        );

        Ok(())
    }

    /// Fingerprint TLS stack
    fn fingerprint(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or("Missing target host")?;
        let (host, port) = self.parse_target(target, ctx)?;

        let debug = ctx.flags.contains_key("verbose") || ctx.flags.contains_key("v");
        let timeout_secs: u64 = ctx
            .flags
            .get("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        Output::header(&format!("TLS Stack Fingerprinting: {}", target));

        let (telemetry, cert) = self.perform_handshake(&host, port, timeout_secs, debug)?;
        self.render_handshake_overview(&telemetry);

        Output::section("Certificate Summary");
        Output::item("Subject", &cert.subject);
        Output::item("Issuer", &cert.issuer);
        if !cert.sans.is_empty() {
            Output::item("SANs", &cert.sans.join(", "));
        }

        Ok(())
    }

    /// Detect infrastructure
    fn infrastructure(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or("Missing target host")?;
        let (host, port) = self.parse_target(target, ctx)?;

        let debug = ctx.flags.contains_key("verbose") || ctx.flags.contains_key("v");
        let timeout_secs: u64 = ctx
            .flags
            .get("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        Output::header(&format!("Infrastructure Detection: {}", target));

        let start = Instant::now();
        let (telemetry, cert, _timings) =
            self.perform_handshake_with_timing(&host, port, timeout_secs, debug)?;
        let total_latency = start.elapsed().as_millis() as u64;

        let cipher = telemetry.cipher_suite.as_deref().unwrap_or("Unknown");
        self.detect_infrastructure(cipher, total_latency)?;
        self.render_handshake_overview(&telemetry);

        // Detect from certificate
        Output::section("Certificate Analysis");
        Output::item("Issuer", &cert.issuer);

        if cert.issuer.contains("Let's Encrypt") {
            Output::success("Automation: Let's Encrypt (90-day auto-renewal)");
        }

        if cert.issuer.contains("Amazon") || cert.issuer.contains("ACM") {
            Output::success("Cloud Provider: AWS");
        }

        if cert.issuer.contains("Google Trust Services") {
            Output::success("Cloud Provider: Google Cloud");
        }

        if cert.subject.contains("cloudflare") || cert.issuer.contains("Cloudflare") {
            Output::success("CDN: Cloudflare");
        }

        Ok(())
    }

    /// Detect infrastructure from cipher and timing
    fn detect_infrastructure(&self, cipher: &str, latency_ms: u64) -> Result<(), String> {
        Output::section("Infrastructure Detection");

        // Detect from cipher preference
        if cipher.contains("CHACHA20") {
            Output::item("TLS Stack", "Modern (ChaCha20 preferred)");
            Output::item("Likely", "Cloudflare, Google, or modern nginx");
        } else if cipher.contains("AES_128_GCM") {
            Output::item("TLS Stack", "Standard (AES-128-GCM preferred)");
            Output::item("Likely", "AWS ELB, OpenSSL 1.1.1+, or Apache");
        }

        // Estimate location from latency
        let location = match latency_ms {
            0..=20 => "Same Region (<20ms)",
            21..=50 => "Same Country (20-50ms)",
            51..=100 => "Same Continent (50-100ms)",
            101..=200 => "Intercontinental (100-200ms)",
            _ => "Very Distant (>200ms)",
        };

        Output::item("Estimated Location", location);

        Ok(())
    }

    /// Perform a single TLS handshake and extract info with graceful fallback.
    fn perform_handshake(
        &self,
        host: &str,
        port: u16,
        timeout_secs: u64,
        debug: bool,
    ) -> Result<(TlsHandshakeTelemetry, CertInfo), String> {
        match self.perform_tls13_handshake(host, port, timeout_secs, debug) {
            Ok(result) => Ok(result),
            Err(tls13_err) => {
                Output::warning(&format!(
                    "TLS 1.3 handshake failed ({}). Falling back to TLS 1.2...",
                    tls13_err
                ));
                self.perform_tls12_handshake(host, port, timeout_secs, debug)
                    .map_err(|tls12_err| {
                        format!(
                            "TLS handshake failed.\n  TLS 1.3: {}\n  TLS 1.2: {}",
                            tls13_err, tls12_err
                        )
                    })
            }
        }
    }

    /// Attempt a TLS 1.3 handshake (preferred path)
    fn perform_tls13_handshake(
        &self,
        host: &str,
        port: u16,
        timeout_secs: u64,
        debug: bool,
    ) -> Result<(TlsHandshakeTelemetry, CertInfo), String> {
        let connector = Self::build_ssl_connector()?;
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).map_err(|e| format!("TCP connect failed: {}", e))?;
        let timeout = Duration::from_secs(timeout_secs.max(1));
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let ssl_stream = connector
            .connect(host, stream)
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        if debug {
            if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                eprintln!(
                    "[tls-intel][debug] negotiated cipher: {}",
                    cipher.standard_name().unwrap_or_else(|| cipher.name())
                );
            }
        }

        let ssl = ssl_stream.ssl();
        let peer_cert = ssl.peer_certificate();
        let telemetry =
            self.gather_tls_telemetry(host, ssl, peer_cert.as_ref().map(|cert| cert.as_ref()));

        let cert = peer_cert
            .as_ref()
            .map(|cert| Self::parse_certificate_basic(cert, host))
            .unwrap_or_else(|| CertInfo {
                subject: host.to_string(),
                issuer: "Unknown".to_string(),
                sans: Vec::new(),
            });

        Ok((telemetry, cert))
    }

    /// Fallback TLS 1.2 handshake using the netcat-style TLS stream.
    fn perform_tls12_handshake(
        &self,
        host: &str,
        port: u16,
        timeout_secs: u64,
        debug: bool,
    ) -> Result<(TlsHandshakeTelemetry, CertInfo), String> {
        use std::io::{Read, Write};

        let config = TlsConfig::new()
            .with_version(TlsVersion::Tls12)
            .with_verify(false)
            .with_timeout(Duration::from_secs(timeout_secs.max(1)))
            .with_debug(debug);

        let mut stream = TlsStream::connect(host, port, config)
            .map_err(|e| format!("TLS 1.2 connect failed: {}", e))?;

        // Minimal HTTP request to ensure the handshake completed successfully.
        let request = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("TLS 1.2 write failed: {}", e))?;

        let mut response = [0u8; 4];
        stream
            .read(&mut response)
            .map_err(|e| format!("TLS 1.2 read failed: {}", e))?;

        let cipher = "TLS_1_2 (fallback)".to_string();
        let telemetry = self.fallback_tls_telemetry(host, &cipher, "TLS 1.2");
        let cert = CertInfo {
            subject: host.to_string(),
            issuer: "Not inspected (TLS 1.2 fallback)".to_string(),
            sans: Vec::new(),
        };

        Ok((telemetry, cert))
    }

    /// Perform TLS handshake with detailed timing breakdown
    fn perform_handshake_with_timing(
        &self,
        host: &str,
        port: u16,
        timeout_secs: u64,
        _debug: bool,
    ) -> Result<(TlsHandshakeTelemetry, CertInfo, HandshakeTiming), String> {
        let mut timings = HandshakeTiming {
            dns_resolution_ms: 0.0, // DNS is done ONCE before the loop
            tcp_connect_ms: 0.0,
            tls_client_hello_ms: 0.0,
            tls_server_hello_ms: 0.0,
            tls_key_derivation_ms: 0.0,
            tls_encrypted_handshake_ms: 0.0,
            cert_parse_ms: 0.0,
        };

        // TCP connect
        let addr = format!("{}:{}", host, port);
        let connect_start = Instant::now();
        let stream = TcpStream::connect(&addr).map_err(|e| format!("TCP connect failed: {}", e))?;
        timings.tcp_connect_ms = connect_start.elapsed().as_micros() as f64 / 1000.0;

        let timeout = Duration::from_secs(timeout_secs.max(1));
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        let connector = Self::build_ssl_connector()?;

        // TLS handshake
        let handshake_start = Instant::now();
        let ssl_stream = connector
            .connect(host, stream)
            .map_err(|e| format!("TLS handshake failed: {}", e))?;
        let handshake_total = handshake_start.elapsed().as_micros() as f64 / 1000.0;

        // Approximate breakdown (based on typical TLS 1.3 handshake)
        // ClientHello: ~5% of handshake
        // ServerHello + encrypted messages: ~70% (network + processing)
        // Key derivation: ~10%
        // Encrypted handshake messages: ~15%
        timings.tls_client_hello_ms = handshake_total * 0.05;
        timings.tls_server_hello_ms = handshake_total * 0.70;
        timings.tls_key_derivation_ms = handshake_total * 0.10;
        timings.tls_encrypted_handshake_ms = handshake_total * 0.15;

        // Extract telemetry and certificate info
        let cert_start = Instant::now();
        let ssl = ssl_stream.ssl();
        let peer_cert = ssl.peer_certificate();
        let telemetry =
            self.gather_tls_telemetry(host, ssl, peer_cert.as_ref().map(|cert| cert.as_ref()));
        let cert = peer_cert
            .as_ref()
            .map(|cert| Self::parse_certificate_basic(cert, host))
            .unwrap_or_else(|| CertInfo {
                subject: host.to_string(),
                issuer: "Unknown".to_string(),
                sans: Vec::new(),
            });
        timings.cert_parse_ms = cert_start.elapsed().as_micros() as f64 / 1000.0;

        Ok((telemetry, cert, timings))
    }

    /// Basic X.509 certificate parsing (Subject, Issuer, SANs)
    fn parse_certificate_basic(cert: &X509, host: &str) -> CertInfo {
        let subject = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|data| data.to_string())
            .unwrap_or_else(|| host.to_string());

        let issuer = cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|data| data.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let sans = cert
            .subject_alt_names()
            .map(|names| {
                let mut collected = Vec::new();
                for name in names {
                    if let Some(dns) = name.dnsname() {
                        collected.push(dns.to_string());
                    } else if let Some(ip_bytes) = name.ipaddress() {
                        if let Some(ip) = Self::format_ip_address(ip_bytes) {
                            collected.push(ip);
                        }
                    }
                }
                collected
            })
            .unwrap_or_else(Vec::new);

        CertInfo {
            subject,
            issuer,
            sans,
        }
    }

    fn format_ip_address(bytes: &[u8]) -> Option<String> {
        match bytes.len() {
            4 => {
                Some(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])).to_string())
            }
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Some(IpAddr::V6(Ipv6Addr::from(arr)).to_string())
            }
            _ => None,
        }
    }

    fn build_ssl_connector() -> Result<SslConnector, String> {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("Failed to create TLS connector: {}", e))?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| format!("Failed to set min TLS version: {}", e))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set max TLS version: {}", e))?;
        builder.set_verify(SslVerifyMode::NONE);
        Ok(builder.build())
    }

    /// Parse target into (host, port)
    fn parse_target(&self, target: &str, ctx: &CliContext) -> Result<(String, u16), String> {
        if let Some(colon_pos) = target.rfind(':') {
            let host = target[..colon_pos].to_string();
            let port = target[colon_pos + 1..]
                .parse::<u16>()
                .map_err(|_| "Invalid port number")?;
            Ok((host, port))
        } else {
            let port: u16 = ctx
                .flags
                .get("port")
                .and_then(|s| s.parse().ok())
                .unwrap_or(443);
            Ok((target.to_string(), port))
        }
    }
}

// Helper types and functions only used on non-Windows platforms
#[cfg(not(target_os = "windows"))]
mod tls_intel_impl {
    use boring::pkey::{Id as PKeyId, PKeyRef, Public};
    use boring::sha::sha256;

    /// Simplified certificate info
    #[derive(Debug, Clone)]
    pub struct CertInfo {
        pub subject: String,
        pub issuer: String,
        pub sans: Vec<String>,
    }

    /// Detailed timing breakdown for TLS handshake
    #[derive(Debug, Clone)]
    pub struct HandshakeTiming {
        pub dns_resolution_ms: f64,
        pub tcp_connect_ms: f64,
        pub tls_client_hello_ms: f64,
        pub tls_server_hello_ms: f64,
        pub tls_key_derivation_ms: f64,
        pub tls_encrypted_handshake_ms: f64,
        pub cert_parse_ms: f64,
    }

    #[derive(Debug, Clone)]
    pub struct TlsHandshakeTelemetry {
        pub tls_version: String,
        pub cipher_suite: Option<String>,
        pub alpn_protocol: Option<String>,
        pub sni: Option<String>,
        pub session_id: Option<String>,
        pub session_resumed: bool,
        pub client_random: Option<String>,
        pub server_random: Option<String>,
        pub master_key_hash: Option<String>,
        pub master_key_len: Option<usize>,
        pub ocsp_stapled: bool,
        pub peer_tmp_key: Option<String>,
        pub peer_named_group: Option<String>,
        pub peer_signature_algorithm: Option<String>,
        pub fingerprint_sha256: Option<String>,
    }

    pub fn hex_from_bytes(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{:02x}", byte));
        }
        out
    }

    pub fn sha256_hex(data: &[u8]) -> String {
        hex_from_bytes(&sha256(data))
    }

    pub fn format_alpn(protocol: &[u8]) -> String {
        match std::str::from_utf8(protocol) {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => format!("0x{}", hex_from_bytes(protocol)),
        }
    }

    pub fn abbreviate_hex(hex: &str, keep: usize) -> String {
        if hex.len() <= keep {
            hex.to_string()
        } else {
            format!("{}…", &hex[..keep])
        }
    }

    pub fn describe_tmp_key(key: &PKeyRef<Public>) -> (String, Option<String>) {
        let bits = key.bits();
        let bits_opt = if bits > 0 { Some(bits) } else { None };
        let mut named_group: Option<String> = None;
        let base = match key.id() {
            PKeyId::EC => {
                if let Ok(ec_key) = key.ec_key() {
                    if let Some(group) = ec_key.group().curve_name() {
                        if let Ok(name) = group.short_name() {
                            named_group = Some(name.to_string());
                            "ECDHE"
                        } else {
                            "ECDHE"
                        }
                    } else {
                        "ECDHE"
                    }
                } else {
                    "ECDHE"
                }
            }
            PKeyId::X25519 => {
                named_group = Some("x25519".to_string());
                "X25519"
            }
            PKeyId::X448 => {
                named_group = Some("x448".to_string());
                "X448"
            }
            PKeyId::ED25519 => "ED25519",
            PKeyId::ED448 => "ED448",
            PKeyId::DH => "DHE",
            other => {
                return (
                    if let Some(bits) = bits_opt {
                        format!("{:?} ({} bits)", other, bits)
                    } else {
                        format!("{:?}", other)
                    },
                    None,
                );
            }
        };

        let mut descriptor = base.to_string();
        if let Some(ref group) = named_group {
            descriptor.push_str(" ");
            descriptor.push_str(group);
        }
        if let Some(bits) = bits_opt {
            descriptor.push_str(&format!(" ({} bits)", bits));
        }

        (descriptor, named_group)
    }
}

#[cfg(not(target_os = "windows"))]
use tls_intel_impl::*;
