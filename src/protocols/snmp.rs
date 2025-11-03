/// SNMP Protocol Implementation (RFC 1157)
///
/// Implements Simple Network Management Protocol for:
/// - SNMPv1/v2c (community-based)
/// - GET/GETNEXT/GETBULK requests
/// - Community string enumeration
/// - OID walking
/// - System information retrieval
///
/// Reference: https://tools.ietf.org/html/rfc1157
use std::net::UdpSocket;
use std::time::Duration;

/// SNMP version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SnmpVersion {
    V1 = 0,  // SNMPv1
    V2c = 1, // SNMPv2c (community-based)
}

/// SNMP PDU types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PduType {
    GetRequest = 0xa0,
    GetNextRequest = 0xa1,
    GetResponse = 0xa2,
    SetRequest = 0xa3,
    Trap = 0xa4,
    GetBulkRequest = 0xa5, // SNMPv2c only
}

/// Common SNMP OIDs
pub mod oids {
    pub const SYSTEM_DESCR: &str = "1.3.6.1.2.1.1.1.0"; // sysDescr
    pub const SYSTEM_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0"; // sysObjectID
    pub const SYSTEM_UPTIME: &str = "1.3.6.1.2.1.1.3.0"; // sysUpTime
    pub const SYSTEM_CONTACT: &str = "1.3.6.1.2.1.1.4.0"; // sysContact
    pub const SYSTEM_NAME: &str = "1.3.6.1.2.1.1.5.0"; // sysName
    pub const SYSTEM_LOCATION: &str = "1.3.6.1.2.1.1.6.0"; // sysLocation
    pub const SYSTEM_SERVICES: &str = "1.3.6.1.2.1.1.7.0"; // sysServices
    pub const IF_NUMBER: &str = "1.3.6.1.2.1.2.1.0"; // ifNumber
    pub const IF_TABLE: &str = "1.3.6.1.2.1.2.2"; // ifTable
}

/// SNMP client for basic operations
pub struct SnmpClient {
    socket: UdpSocket,
    timeout: Duration,
    pub community: String,
    pub version: SnmpVersion,
}

impl SnmpClient {
    /// Create a new SNMP client
    pub fn new(community: &str) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        Ok(Self {
            socket,
            timeout: Duration::from_secs(5),
            community: community.to_string(),
            version: SnmpVersion::V2c,
        })
    }

    /// Create SNMPv1 client
    pub fn v1(community: &str) -> Result<Self, String> {
        let mut client = Self::new(community)?;
        client.version = SnmpVersion::V1;
        Ok(client)
    }

    /// Create SNMPv2c client
    pub fn v2c(community: &str) -> Result<Self, String> {
        Self::new(community)
    }

    /// Set timeout
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;
        self.timeout = timeout;
        Ok(())
    }

    /// Send SNMP GET request
    pub fn get(&self, host: &str, port: u16, oid: &str) -> Result<Vec<u8>, String> {
        let request = self.build_get_request(oid)?;
        self.send_request(host, port, &request)
    }

    /// Send SNMP GETNEXT request
    pub fn get_next(&self, host: &str, port: u16, oid: &str) -> Result<Vec<u8>, String> {
        let request = self.build_get_next_request(oid)?;
        self.send_request(host, port, &request)
    }

    /// Build SNMP GET request packet
    fn build_get_request(&self, oid: &str) -> Result<Vec<u8>, String> {
        // Simplified ASN.1 BER encoding for SNMP GET
        let mut packet = Vec::new();

        // SEQUENCE
        packet.push(0x30);
        let length_pos = packet.len();
        packet.push(0x00); // Placeholder for length

        // Version (INTEGER)
        packet.push(0x02); // INTEGER tag
        packet.push(0x01); // Length
        packet.push(self.version as u8);

        // Community (OCTET STRING)
        packet.push(0x04); // OCTET STRING tag
        packet.push(self.community.len() as u8);
        packet.extend_from_slice(self.community.as_bytes());

        // PDU (GetRequest)
        packet.push(PduType::GetRequest as u8);
        let pdu_length_pos = packet.len();
        packet.push(0x00); // Placeholder for PDU length

        // Request ID (INTEGER) - using 1234
        packet.push(0x02); // INTEGER tag
        packet.push(0x02); // Length (2 bytes)
        packet.push(0x04); // 1234 high byte
        packet.push(0xd2); // 1234 low byte

        // Error status (INTEGER) - 0 = no error
        packet.push(0x02);
        packet.push(0x01);
        packet.push(0x00);

        // Error index (INTEGER) - 0
        packet.push(0x02);
        packet.push(0x01);
        packet.push(0x00);

        // Variable bindings (SEQUENCE)
        packet.push(0x30);
        let varbind_seq_pos = packet.len();
        packet.push(0x00); // Placeholder

        // Single variable binding (SEQUENCE)
        packet.push(0x30);
        let varbind_pos = packet.len();
        packet.push(0x00); // Placeholder

        // OID (OBJECT IDENTIFIER)
        let oid_bytes = self.encode_oid(oid)?;
        packet.push(0x06); // OID tag
        packet.push(oid_bytes.len() as u8);
        packet.extend_from_slice(&oid_bytes);

        // NULL value
        packet.push(0x05);
        packet.push(0x00);

        // Update variable binding length
        let varbind_len = packet.len() - varbind_pos - 1;
        packet[varbind_pos] = varbind_len as u8;

        // Update variable bindings sequence length
        let varbind_seq_len = packet.len() - varbind_seq_pos - 1;
        packet[varbind_seq_pos] = varbind_seq_len as u8;

        // Update PDU length
        let pdu_len = packet.len() - pdu_length_pos - 1;
        packet[pdu_length_pos] = pdu_len as u8;

        // Update total length
        let total_len = packet.len() - length_pos - 1;
        packet[length_pos] = total_len as u8;

        Ok(packet)
    }

    /// Build SNMP GETNEXT request
    fn build_get_next_request(&self, oid: &str) -> Result<Vec<u8>, String> {
        let mut request = self.build_get_request(oid)?;

        // Find and replace GetRequest PDU type with GetNextRequest
        for i in 0..request.len() {
            if request[i] == PduType::GetRequest as u8 {
                request[i] = PduType::GetNextRequest as u8;
                break;
            }
        }

        Ok(request)
    }

    /// Encode OID string to bytes
    fn encode_oid(&self, oid: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = oid.split('.').collect();
        let mut bytes = Vec::new();

        if parts.len() < 2 {
            return Err("Invalid OID format".to_string());
        }

        // First byte encodes first two numbers: (first * 40) + second
        let first: u8 = parts[0].parse().map_err(|_| "Invalid OID number")?;
        let second: u8 = parts[1].parse().map_err(|_| "Invalid OID number")?;
        bytes.push(first * 40 + second);

        // Encode remaining numbers
        for i in 2..parts.len() {
            let num: u32 = parts[i].parse().map_err(|_| "Invalid OID number")?;

            if num < 128 {
                bytes.push(num as u8);
            } else {
                // Multi-byte encoding (variable length)
                let mut encoded = Vec::new();
                let mut n = num;

                encoded.push((n & 0x7f) as u8);
                n >>= 7;

                while n > 0 {
                    encoded.push(((n & 0x7f) | 0x80) as u8);
                    n >>= 7;
                }

                encoded.reverse();
                bytes.extend_from_slice(&encoded);
            }
        }

        Ok(bytes)
    }

    /// Send SNMP request and receive response
    fn send_request(&self, host: &str, port: u16, request: &[u8]) -> Result<Vec<u8>, String> {
        let addr = format!("{}:{}", host, port);

        self.socket
            .send_to(request, &addr)
            .map_err(|e| format!("Failed to send SNMP request: {}", e))?;

        let mut buffer = vec![0u8; 1500]; // Max UDP packet size
        let (size, _src) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|e| format!("Failed to receive SNMP response: {}", e))?;

        buffer.truncate(size);
        Ok(buffer)
    }

    /// Parse basic SNMP response to extract value
    pub fn parse_response(&self, response: &[u8]) -> Result<String, String> {
        // Very simplified parser - just extract the value portion
        // In a full implementation, we'd properly parse the entire ASN.1 structure

        if response.len() < 10 {
            return Err("Response too short".to_string());
        }

        // Find the value after the OID
        // This is a simplified heuristic approach
        let mut i = 0;
        while i < response.len() - 2 {
            // Look for OCTET STRING (0x04) or INTEGER (0x02) after OID (0x06)
            if response[i] == 0x04 || response[i] == 0x02 {
                if i + 1 < response.len() {
                    let len = response[i + 1] as usize;
                    if i + 2 + len <= response.len() {
                        let value_bytes = &response[i + 2..i + 2 + len];

                        // Try to convert to string
                        if let Ok(s) = String::from_utf8(value_bytes.to_vec()) {
                            if s.chars().all(|c| c.is_ascii_graphic() || c.is_whitespace()) {
                                return Ok(s);
                            }
                        }

                        // Return as hex if not valid UTF-8
                        return Ok(format!("{:02x?}", value_bytes));
                    }
                }
            }
            i += 1;
        }

        Err("Could not parse value from response".to_string())
    }
}

/// Test if SNMP is accessible with a community string
pub fn test_snmp_community(host: &str, port: u16, community: &str) -> Result<bool, String> {
    let client = SnmpClient::v2c(community)?;

    match client.get(host, port, oids::SYSTEM_DESCR) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Get system description via SNMP
pub fn get_system_info(host: &str, port: u16, community: &str) -> Result<String, String> {
    let client = SnmpClient::v2c(community)?;
    let response = client.get(host, port, oids::SYSTEM_DESCR)?;
    client.parse_response(&response)
}

/// Common community strings for brute force
pub fn common_communities() -> Vec<&'static str> {
    vec![
        "public",
        "private",
        "community",
        "snmp",
        "admin",
        "manager",
        "cisco",
        "default",
        "secret",
        "read",
        "write",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple_oid() {
        let client = SnmpClient::v2c("public").unwrap();
        let encoded = client.encode_oid("1.3.6.1.2.1.1.1.0").unwrap();

        // First byte should be (1 * 40) + 3 = 43
        assert_eq!(encoded[0], 43);
    }

    #[test]
    fn test_snmp_versions() {
        assert_eq!(SnmpVersion::V1 as u8, 0);
        assert_eq!(SnmpVersion::V2c as u8, 1);
    }

    #[test]
    fn test_common_communities() {
        let communities = common_communities();
        assert!(communities.contains(&"public"));
        assert!(communities.contains(&"private"));
    }
}
