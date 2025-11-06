/// Host and service fingerprinting aggregator.
///
/// Builds on the existing port scanner, banner grabber, and timing-analysis
/// helpers to produce a consolidated view of a target host:
/// - Open TCP ports (from the connect scanner)
/// - Service banners (for version / OS hints)
/// - Timing signatures (for coarse OS attribution)
/// - Combined OS guess with supporting evidence
///
/// All implementation relies exclusively on the Rust standard library.
use crate::intelligence::os_fingerprint::{
    combine_fingerprints, fingerprint_from_timing, FingerprintEvidence, FingerprintMethod,
    OsFingerprint,
};
use crate::intelligence::timing_analysis::{
    comprehensive_timing_analysis, OsFamily, TimingSignature,
};
use crate::modules::network::banner::ServiceBanner;
use crate::modules::network::scanner::{PortScanResult, PortScanner};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};

/// Fingerprint for a single TCP service.
#[derive(Debug, Clone)]
pub struct ServiceFingerprint {
    pub port: u16,
    pub service_label: Option<String>,
    pub banner: Option<ServiceBanner>,
    pub timing: Option<ServiceTiming>,
}

/// Timing insight captured during service probing.
#[derive(Debug, Clone)]
pub struct ServiceTiming {
    pub signature: TimingSignature,
    pub inferred_os: OsFamily,
}

/// Aggregated host fingerprint.
#[derive(Debug, Clone)]
pub struct HostFingerprint {
    pub host: String,
    pub ip: IpAddr,
    pub open_ports: Vec<u16>,
    pub services: Vec<ServiceFingerprint>,
    pub os_guess: Option<OsFingerprint>,
}

impl HostFingerprint {
    /// Run a fingerprint against the target host. If `ports` is empty, the
    /// common port set from the port scanner is used.
    pub fn run(host: &str, ports: &[u16]) -> Result<Self, String> {
        let ip = resolve_host(host)?;
        let scanner = PortScanner::new(ip);

        let scan_results = if ports.is_empty() {
            scanner.scan_common()
        } else {
            scanner.scan_ports(ports)
        };

        let mut services = Vec::new();
        let mut fingerprints = Vec::new();
        let mut open_ports = Vec::new();

        for result in scan_results.into_iter().filter(|r| r.is_open) {
            open_ports.push(result.port);

            let banner = ServiceBanner::grab(host, result.port).ok();
            if let Some(ref banner_ref) = banner {
                if let Some(fp) = fingerprint_from_banner(banner_ref) {
                    fingerprints.push(fp);
                }
            }

            let timing = service_timing(host, &result).ok().flatten();
            if let Some(ref timing_ref) = timing {
                fingerprints.push(fingerprint_from_timing(&timing_ref.signature));
            }

            services.push(ServiceFingerprint {
                port: result.port,
                service_label: result.service.clone(),
                banner,
                timing,
            });
        }

        let os_guess = if fingerprints.is_empty() {
            None
        } else {
            Some(combine_fingerprints(fingerprints))
        };

        Ok(Self {
            host: host.to_string(),
            ip,
            open_ports,
            services,
            os_guess,
        })
    }
}

fn resolve_host(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }

    let mut addresses = (host, 443)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}: {}", host, e))?;
    addresses
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| format!("No addresses resolved for {}", host))
}

fn service_timing(host: &str, result: &PortScanResult) -> Result<Option<ServiceTiming>, String> {
    let service = match result
        .service
        .as_ref()
        .map(|s| s.trim().to_ascii_lowercase())
    {
        Some(label) if !label.is_empty() => label,
        _ => return Ok(None),
    };

    let (os_guess, signature) = comprehensive_timing_analysis(host, result.port, &service)?;

    Ok(Some(ServiceTiming {
        signature,
        inferred_os: os_guess,
    }))
}

fn fingerprint_from_banner(banner: &ServiceBanner) -> Option<OsFingerprint> {
    if banner.os_hints.is_empty() {
        return None;
    }

    let mut votes: HashMap<OsFamily, f32> = HashMap::new();
    let mut evidence = Vec::new();

    for hint in &banner.os_hints {
        if let Some(family) = os_family_from_hint(hint) {
            *votes.entry(family.clone()).or_insert(0.0) += 0.3;
            evidence.push(FingerprintEvidence {
                method: FingerprintMethod::BannerAnalysis,
                observation: format!(
                    "Service {}:{} banner exposed hint '{}'",
                    banner.host, banner.port, hint
                ),
                weight: 0.3,
            });
        }
    }

    let (os_family, confidence) = votes
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(family, score)| (family, score.min(0.9)))?;

    Some(OsFingerprint {
        os_family,
        specific_version: banner.version.clone(),
        confidence,
        evidence,
    })
}

fn os_family_from_hint(hint: &str) -> Option<OsFamily> {
    let lower = hint.to_ascii_lowercase();

    if lower.contains("windows") || lower.contains("microsoft") {
        return Some(OsFamily::Windows);
    }
    if lower.contains("ubuntu")
        || lower.contains("debian")
        || lower.contains("centos")
        || lower.contains("redhat")
        || lower.contains("rhel")
        || lower.contains("linux")
    {
        return Some(OsFamily::Linux);
    }
    if lower.contains("freebsd") || lower.contains("openbsd") || lower.contains("netbsd") {
        return Some(OsFamily::UnixBsd);
    }
    if lower.contains("solaris") {
        return Some(OsFamily::Solaris);
    }
    if lower.contains("darwin") || lower.contains("macos") || lower.contains("os x") {
        return Some(OsFamily::MacOS);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::network::banner::{ServiceBanner, ServiceType};

    #[test]
    fn test_os_family_from_hint() {
        assert_eq!(
            os_family_from_hint("Ubuntu").unwrap().name(),
            OsFamily::Linux.name()
        );
        assert_eq!(
            os_family_from_hint("Microsoft-IIS").unwrap().name(),
            OsFamily::Windows.name()
        );
        assert_eq!(
            os_family_from_hint("FreeBSD").unwrap().name(),
            OsFamily::UnixBsd.name()
        );
        assert!(os_family_from_hint("UnknownOSHint").is_none());
    }

    #[test]
    fn test_banner_fingerprint_combines_hints() {
        let banner = ServiceBanner {
            host: "example.com".to_string(),
            port: 22,
            service: ServiceType::SSH,
            banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3".to_string(),
            version: Some("OpenSSH_8.2p1".to_string()),
            os_hints: vec!["Ubuntu".to_string(), "Linux".to_string()],
            security_notes: vec!["Weak cipher".to_string()],
        };

        let fingerprint = fingerprint_from_banner(&banner).expect("fingerprint");
        assert_eq!(fingerprint.os_family, OsFamily::Linux);
        assert!(fingerprint.confidence > 0.0);
        assert!(!fingerprint.evidence.is_empty());
        assert!(fingerprint
            .evidence
            .iter()
            .any(|ev| ev.observation.contains("example.com")));
    }
}
