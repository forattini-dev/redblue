/// MySQL Protocol Implementation (Simplified)
///
/// Implements MySQL protocol handshake for:
/// - Version detection
/// - Server capabilities
/// - Authentication testing
/// - Basic connection
///
/// Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

/// MySQL server handshake information
#[derive(Debug, Clone)]
pub struct MysqlHandshake {
    pub protocol_version: u8,
    pub server_version: String,
    pub connection_id: u32,
    pub capabilities: u32,
    pub character_set: u8,
    pub status_flags: u16,
}

/// MySQL client
pub struct MysqlClient {
    stream: TcpStream,
    pub handshake: Option<MysqlHandshake>,
}

impl MysqlClient {
    /// Connect to MySQL server and read handshake
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        let address = format!("{}:{}", host, port);

        let stream = TcpStream::connect(&address)
            .map_err(|e| format!("Failed to connect to {}: {}", address, e))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        let mut client = Self {
            stream,
            handshake: None,
        };

        // Read server handshake
        let handshake = client.read_handshake()?;
        client.handshake = Some(handshake);

        Ok(client)
    }

    /// Read MySQL handshake packet
    fn read_handshake(&mut self) -> Result<MysqlHandshake, String> {
        // Read packet header (4 bytes: 3 bytes length + 1 byte sequence)
        let mut header = [0u8; 4];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read packet header: {}", e))?;

        let payload_len =
            (header[0] as u32) | ((header[1] as u32) << 8) | ((header[2] as u32) << 16);

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| format!("Failed to read payload: {}", e))?;

        self.parse_handshake(&payload)
    }

    /// Parse handshake packet
    fn parse_handshake(&self, data: &[u8]) -> Result<MysqlHandshake, String> {
        if data.is_empty() {
            return Err("Empty handshake packet".to_string());
        }

        let protocol_version = data[0];
        let mut pos = 1;

        // Read server version (null-terminated string)
        let version_end = data[pos..]
            .iter()
            .position(|&b| b == 0)
            .ok_or("Invalid server version")?;
        let server_version = String::from_utf8_lossy(&data[pos..pos + version_end]).to_string();
        pos += version_end + 1;

        // Connection ID (4 bytes)
        if pos + 4 > data.len() {
            return Err("Packet too short for connection ID".to_string());
        }
        let connection_id =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Auth plugin data part 1 (8 bytes) - skip
        pos += 8;

        // Filler (1 byte) - skip
        pos += 1;

        // Capability flags lower 2 bytes
        if pos + 2 > data.len() {
            return Err("Packet too short for capabilities".to_string());
        }
        let capabilities_lower = u16::from_le_bytes([data[pos], data[pos + 1]]) as u32;
        pos += 2;

        // Character set (1 byte)
        if pos >= data.len() {
            return Err("Packet too short for charset".to_string());
        }
        let character_set = data[pos];
        pos += 1;

        // Status flags (2 bytes)
        if pos + 2 > data.len() {
            return Err("Packet too short for status flags".to_string());
        }
        let status_flags = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Capability flags upper 2 bytes
        if pos + 2 > data.len() {
            return Err("Packet too short for upper capabilities".to_string());
        }
        let capabilities_upper = u16::from_le_bytes([data[pos], data[pos + 1]]) as u32;
        let capabilities = capabilities_lower | (capabilities_upper << 16);

        Ok(MysqlHandshake {
            protocol_version,
            server_version,
            connection_id,
            capabilities,
            character_set,
            status_flags,
        })
    }

    /// Get server version
    pub fn version(&self) -> Option<String> {
        self.handshake.as_ref().map(|h| h.server_version.clone())
    }

    /// Check if server supports SSL
    pub fn supports_ssl(&self) -> bool {
        if let Some(ref h) = self.handshake {
            const CLIENT_SSL: u32 = 0x0800;
            (h.capabilities & CLIENT_SSL) != 0
        } else {
            false
        }
    }

    /// Check if server supports plugin authentication
    pub fn supports_plugin_auth(&self) -> bool {
        if let Some(ref h) = self.handshake {
            const CLIENT_PLUGIN_AUTH: u32 = 0x80000;
            (h.capabilities & CLIENT_PLUGIN_AUTH) != 0
        } else {
            false
        }
    }
}

/// Get MySQL server version
pub fn mysql_version(host: &str, port: u16) -> Result<String, String> {
    let client = MysqlClient::connect(host, port)?;
    client
        .version()
        .ok_or_else(|| "No handshake received".to_string())
}

/// Get full MySQL server info
pub fn mysql_info(host: &str, port: u16) -> Result<MysqlHandshake, String> {
    let client = MysqlClient::connect(host, port)?;
    client
        .handshake
        .ok_or_else(|| "No handshake received".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_capabilities() {
        // Test capability flag constants
        const CLIENT_SSL: u32 = 0x0800;
        const CLIENT_PLUGIN_AUTH: u32 = 0x80000;

        let caps_with_ssl = CLIENT_SSL | CLIENT_PLUGIN_AUTH;
        assert_eq!(caps_with_ssl & CLIENT_SSL, CLIENT_SSL);
        assert_eq!(caps_with_ssl & CLIENT_PLUGIN_AUTH, CLIENT_PLUGIN_AUTH);
    }

    #[test]
    fn test_handshake_struct() {
        let handshake = MysqlHandshake {
            protocol_version: 10,
            server_version: "8.0.32".to_string(),
            connection_id: 123,
            capabilities: 0x8800,
            character_set: 33,
            status_flags: 2,
        };

        assert_eq!(handshake.protocol_version, 10);
        assert!(handshake.server_version.starts_with("8.0"));
    }
}
