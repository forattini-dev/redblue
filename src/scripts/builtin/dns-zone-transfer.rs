/// DNS Zone Transfer Script
///
/// Checks for misconfigured DNS servers that allow zone transfers.
/// This is a common misconfiguration that can expose all DNS records.

use crate::scripts::types::*;
use crate::scripts::Script;

/// DNS Zone Transfer Detection Script
pub struct DnsZoneTransferScript {
    meta: ScriptMetadata,
}

impl DnsZoneTransferScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "dns-zone-transfer".to_string(),
                name: "DNS Zone Transfer Check".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Checks if DNS server allows unauthorized zone transfers (AXFR)".to_string(),
                categories: vec![ScriptCategory::Vuln, ScriptCategory::Safe],
                protocols: vec!["dns".to_string()],
                ports: vec![53],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec![
                    "https://tools.ietf.org/html/rfc5936".to_string(),
                    "https://digi.ninja/projects/zonetransferme.php".to_string(),
                ],
            },
        }
    }
}

impl Default for DnsZoneTransferScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for DnsZoneTransferScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        // Check for zone transfer results in context
        let axfr_result = ctx.get_data("axfr_result").unwrap_or("");
        let axfr_records = ctx.get_data("axfr_records").unwrap_or("");

        if axfr_result.is_empty() {
            result.add_output("No AXFR test data available in context");
            return Ok(result);
        }

        result.success = true;

        let result_lower = axfr_result.to_lowercase();

        // Check if zone transfer succeeded
        if result_lower.contains("transfer successful")
            || result_lower.contains("records received")
            || !axfr_records.is_empty()
        {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "DNS Zone Transfer Allowed")
                    .with_description(
                        "DNS server allows zone transfers to unauthorized clients. \
                         This exposes all DNS records including internal hostnames."
                    )
                    .with_severity(FindingSeverity::High)
                    .with_remediation(
                        "Restrict zone transfers to authorized secondary DNS servers only. \
                         Configure 'allow-transfer' in BIND or equivalent in other DNS software."
                    ),
            );

            // Count transferred records
            let record_count = axfr_records.lines().count();
            if record_count > 0 {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "DNS Records Exposed")
                        .with_description(&format!("{} DNS records exposed via zone transfer", record_count))
                        .with_severity(FindingSeverity::Medium),
                );
                result.extract("axfr_record_count", &record_count.to_string());
            }

            // Check for interesting records
            let records_lower = axfr_records.to_lowercase();

            if records_lower.contains("_dmarc") || records_lower.contains("_domainkey") {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Email Security Records Found")
                        .with_description("DMARC/DKIM records found in zone transfer")
                        .with_severity(FindingSeverity::Info),
                );
            }

            if records_lower.contains("internal") || records_lower.contains("intranet") || records_lower.contains("private") {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "Internal Hostnames Exposed")
                        .with_description("Zone transfer reveals internal/private hostnames")
                        .with_severity(FindingSeverity::Medium),
                );
            }

            if records_lower.contains("admin") || records_lower.contains("management") || records_lower.contains("vpn") {
                result.add_finding(
                    Finding::new(FindingType::InfoLeak, "Sensitive Hostnames Exposed")
                        .with_description("Zone transfer reveals admin/management/VPN hostnames")
                        .with_severity(FindingSeverity::Medium),
                );
            }

        } else if result_lower.contains("refused") || result_lower.contains("denied") || result_lower.contains("not authorized") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "Zone Transfer Properly Restricted")
                    .with_description("DNS server correctly refuses zone transfers")
                    .with_severity(FindingSeverity::Info),
            );
        } else if result_lower.contains("timeout") || result_lower.contains("no response") {
            result.add_finding(
                Finding::new(FindingType::Discovery, "Zone Transfer Test Inconclusive")
                    .with_description("Could not determine zone transfer status (timeout/no response)")
                    .with_severity(FindingSeverity::Info),
            );
        }

        result.add_output(&format!("DNS zone transfer check complete for {}:{}", ctx.host, ctx.port));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_zone_transfer_script() {
        let script = DnsZoneTransferScript::new();
        assert_eq!(script.id(), "dns-zone-transfer");
        assert!(script.has_category(ScriptCategory::Vuln));
    }

    #[test]
    fn test_zone_transfer_allowed() {
        let script = DnsZoneTransferScript::new();
        let mut ctx = ScriptContext::new("ns1.example.com", 53);
        ctx.set_data("axfr_result", "Transfer successful");
        ctx.set_data("axfr_records", "example.com. IN A 1.2.3.4\nadmin.example.com. IN A 1.2.3.5");

        let result = script.run(&ctx).unwrap();
        assert!(result.success);
        let has_vuln = result.findings.iter().any(|f| f.title.contains("Zone Transfer Allowed"));
        assert!(has_vuln);
    }

    #[test]
    fn test_zone_transfer_refused() {
        let script = DnsZoneTransferScript::new();
        let mut ctx = ScriptContext::new("ns1.example.com", 53);
        ctx.set_data("axfr_result", "Transfer refused");

        let result = script.run(&ctx).unwrap();
        let has_restricted = result.findings.iter().any(|f| f.title.contains("Properly Restricted"));
        assert!(has_restricted);
    }
}
