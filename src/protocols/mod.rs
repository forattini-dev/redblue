/// Raw protocol implementations from scratch
///
/// NOTE: Crypto primitives (AES, RSA, HMAC, etc) moved to crate::crypto
/// NOTE: TLS/HTTPS implementation at modules::network::tls
pub mod asn1; // ASN.1/DER parser (RFC 2459)
pub mod dns; // DNS (RFC 1035)
pub mod ftp; // FTP/FTPS (RFC 959)
pub mod http; // HTTP/1.1 (RFC 2616)
pub mod http2; // HTTP/2 (RFC 7540) - Binary framing, HPACK, multiplexing
pub mod icmp; // ICMP (RFC 792)
pub mod ldap; // LDAP (RFC 4511)
pub mod mongodb; // MongoDB Wire Protocol
pub mod mssql; // MSSQL TDS Protocol
pub mod mysql; // MySQL Protocol
pub mod postgresql; // PostgreSQL Protocol
pub mod redis; // Redis RESP Protocol
pub mod smb; // SMB/CIFS Protocol
pub mod smtp; // SMTP (RFC 5321)
pub mod snmp; // SNMP (RFC 1157)
pub mod ssh; // SSH (RFC 4253)
pub mod tcp; // Raw TCP
pub mod telnet; // Telnet (RFC 854)
pub mod tls13; // TLS 1.3 (RFC 8446)
pub mod udp; // Raw UDP
pub mod whois; // WHOIS (RFC 3912)
#[path = "x509-parser.rs"]
pub mod x509_parser; // X.509 certificate parser
