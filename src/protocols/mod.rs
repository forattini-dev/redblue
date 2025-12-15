/// Raw protocol implementations from scratch
///
/// NOTE: Crypto primitives (AES, RSA, HMAC, etc) moved to crate::crypto
/// NOTE: TLS/HTTPS implementation at modules::network::tls
pub mod asn1; // ASN.1/DER parser (RFC 2459)
pub mod har; // HAR 1.2 (HTTP Archive) recording/replay
pub mod selector; // CSS Selector engine (Cheerio-like)
pub mod crypto; // Shared protocol crypto helpers (SHA-384, HKDF)
pub mod dns; // DNS (RFC 1035)
pub mod doh; // DNS-over-HTTPS (RFC 8484)
pub mod rdap; // RDAP - Registration Data Access Protocol (RFC 7480-7484)
pub mod ftp; // FTP/FTPS (RFC 959)
pub mod gcm; // AES-128-GCM implementation
pub mod http; // HTTP/1.1 (RFC 2616)
pub mod http2; // HTTP/2 (RFC 7540) - Binary framing, HPACK, multiplexing ✅ COMPLETE
pub mod https; // HTTPS (HTTP over TLS)
pub mod icmp; // ICMP (RFC 792)
pub mod raw; // Raw socket packet crafting (SYN/UDP/stealth scans)
pub mod ldap; // LDAP (RFC 4511)
pub mod mongodb; // MongoDB Wire Protocol
pub mod mssql; // MSSQL TDS Protocol
pub mod mysql; // MySQL Protocol
pub mod p256; // NIST P-256 elliptic curve primitives
pub mod ecdh; // ECDH key exchange
pub mod rsa; // RSA encryption/signatures
pub mod postgresql; // PostgreSQL Protocol
pub mod redis; // Redis RESP Protocol
pub mod smb; // SMB/CIFS Protocol
pub mod smtp; // SMTP (RFC 5321)
pub mod snmp; // SNMP (RFC 1157)
pub mod ssh; // SSH (RFC 4253)
pub mod tcp; // Raw TCP
pub mod telnet; // Telnet (RFC 854)
pub mod udp; // Raw UDP
pub mod whois; // WHOIS (RFC 3912)
pub mod x509; // Rich X.509 certificate parser
pub mod tls; // TLS handshake for certificate extraction
pub mod tls12; // TLS 1.2 full implementation
pub mod tls_cert; // TLS certificate display structures
pub mod tls_impersonator; // TLS impersonation profiles
#[path = "x509-parser.rs"]
pub mod x509_parser; // X.509 certificate parser
