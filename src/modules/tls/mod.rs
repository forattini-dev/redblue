pub mod audit;
pub mod auditor; // ✅ Re-enabled after TLS 1.2 + ECDHE completion!
pub mod cipher;
#[path = "comprehensive-audit.rs"]
pub mod comprehensive_audit; // 🎯 ULTIMATE TLS audit - combines ALL security tests!
#[path = "ct-logs.rs"]
pub mod ct_logs; // Certificate Transparency logs (subdomain enumeration via crt.sh)
pub mod heartbleed; // Heartbleed vulnerability tester (CVE-2014-0160)
pub mod ocsp; // OCSP certificate revocation checking (RFC 6960)
pub mod scanner; // TLS cipher/protocol scanner (sslscan replacement)
