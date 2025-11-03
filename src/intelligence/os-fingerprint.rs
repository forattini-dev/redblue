/// OS Fingerprinting Module
///
/// Combines multiple fingerprinting techniques to identify the target operating system:
///
/// - TCP/IP stack fingerprinting (TTL, window size, TCP options)
/// - Timing analysis (from timing_analysis module)
/// - Banner analysis (from banner_analysis module)
/// - Protocol-specific behaviors
/// - ICMP responses
/// - HTTP header ordering
///
/// This module aggregates all OS detection methods to provide high-confidence OS identification.
use crate::intelligence::timing_analysis::{OsFamily, TimingSignature};
use std::collections::HashMap;

/// OS fingerprint result with confidence score
#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub os_family: OsFamily,
    pub specific_version: Option<String>,
    pub confidence: f32, // 0.0 to 1.0
    pub evidence: Vec<FingerprintEvidence>,
}

/// Evidence supporting OS detection
#[derive(Debug, Clone)]
pub struct FingerprintEvidence {
    pub method: FingerprintMethod,
    pub observation: String,
    pub weight: f32, // Contribution to confidence
}

/// Fingerprinting method used
#[derive(Debug, Clone, PartialEq)]
pub enum FingerprintMethod {
    TcpIpStack,
    TimingBehavior,
    BannerAnalysis,
    ServiceBehavior,
    IcmpResponse,
    HttpHeaders,
}

/// TCP/IP stack fingerprinting based on packet characteristics
pub fn fingerprint_tcp_stack(
    ttl: u8,
    window_size: u16,
    _tcp_options: &[u8],
) -> Option<OsFingerprint> {
    let mut evidence = Vec::new();
    let mut os_votes: HashMap<OsFamily, f32> = HashMap::new();

    // TTL-based detection
    match ttl {
        64 => {
            os_votes.insert(OsFamily::Linux, 0.5);
            os_votes.insert(OsFamily::MacOS, 0.3);
            evidence.push(FingerprintEvidence {
                method: FingerprintMethod::TcpIpStack,
                observation: "TTL=64 (Linux/Unix default)".to_string(),
                weight: 0.3,
            });
        }
        128 => {
            os_votes.insert(OsFamily::Windows, 0.6);
            evidence.push(FingerprintEvidence {
                method: FingerprintMethod::TcpIpStack,
                observation: "TTL=128 (Windows default)".to_string(),
                weight: 0.4,
            });
        }
        255 => {
            os_votes.insert(OsFamily::Solaris, 0.5);
            evidence.push(FingerprintEvidence {
                method: FingerprintMethod::TcpIpStack,
                observation: "TTL=255 (Solaris/Cisco)".to_string(),
                weight: 0.4,
            });
        }
        _ => {}
    }

    // Window size analysis
    match window_size {
        8192 => {
            *os_votes.entry(OsFamily::Windows).or_insert(0.0) += 0.2;
            evidence.push(FingerprintEvidence {
                method: FingerprintMethod::TcpIpStack,
                observation: "Window size 8192 (older Windows)".to_string(),
                weight: 0.2,
            });
        }
        65535 => {
            *os_votes.entry(OsFamily::Linux).or_insert(0.0) += 0.2;
            evidence.push(FingerprintEvidence {
                method: FingerprintMethod::TcpIpStack,
                observation: "Window size 65535 (common Linux)".to_string(),
                weight: 0.2,
            });
        }
        _ => {}
    }

    // Find OS with highest vote
    let (os_family, confidence) = os_votes
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())?;

    Some(OsFingerprint {
        os_family,
        specific_version: None,
        confidence,
        evidence,
    })
}

/// Combine multiple fingerprinting sources for final determination
pub fn combine_fingerprints(fingerprints: Vec<OsFingerprint>) -> OsFingerprint {
    let mut combined_evidence = Vec::new();
    let mut os_scores: HashMap<OsFamily, f32> = HashMap::new();

    for fp in &fingerprints {
        *os_scores.entry(fp.os_family.clone()).or_insert(0.0) += fp.confidence;
        combined_evidence.extend(fp.evidence.clone());
    }

    let (os_family, total_score) = os_scores
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .unwrap_or((OsFamily::Unknown, 0.0));

    let confidence = (total_score / fingerprints.len() as f32).min(1.0);

    OsFingerprint {
        os_family,
        specific_version: None,
        confidence,
        evidence: combined_evidence,
    }
}

/// Add timing-based fingerprint to the mix
pub fn fingerprint_from_timing(timing: &TimingSignature) -> OsFingerprint {
    let conn_ms = timing.connection_time.as_millis();

    let (os_family, confidence, observation) = if conn_ms < 5 {
        (OsFamily::Linux, 0.6, "Very fast connection time (< 5ms)")
    } else if conn_ms < 15 {
        (OsFamily::Linux, 0.4, "Fast connection time (5-15ms)")
    } else if conn_ms < 30 {
        (OsFamily::UnixBsd, 0.3, "Medium connection time (15-30ms)")
    } else {
        (OsFamily::Windows, 0.3, "Slower connection time (> 30ms)")
    };

    OsFingerprint {
        os_family,
        specific_version: None,
        confidence,
        evidence: vec![FingerprintEvidence {
            method: FingerprintMethod::TimingBehavior,
            observation: observation.to_string(),
            weight: confidence,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_fingerprinting() {
        let fp = fingerprint_tcp_stack(64, 65535, &[]);
        assert!(fp.is_some());
        let fp = fp.unwrap();
        assert_eq!(fp.os_family, OsFamily::Linux);
    }

    #[test]
    fn test_windows_ttl() {
        let fp = fingerprint_tcp_stack(128, 8192, &[]);
        assert!(fp.is_some());
        let fp = fp.unwrap();
        assert_eq!(fp.os_family, OsFamily::Windows);
    }

    #[test]
    fn test_combine_fingerprints() {
        let fp1 = OsFingerprint {
            os_family: OsFamily::Linux,
            specific_version: None,
            confidence: 0.6,
            evidence: vec![],
        };
        let fp2 = OsFingerprint {
            os_family: OsFamily::Linux,
            specific_version: None,
            confidence: 0.7,
            evidence: vec![],
        };

        let combined = combine_fingerprints(vec![fp1, fp2]);
        assert_eq!(combined.os_family, OsFamily::Linux);
        assert!(combined.confidence > 0.5);
    }
}
