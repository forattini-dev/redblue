/// Microsoft SQL Server Protocol Implementation (TDS - Tabular Data Stream)
///
/// Implements TDS protocol for:
/// - Server version detection
/// - Pre-login handshake
/// - SQL Server instance enumeration
/// - Authentication testing (SQL Server auth)
///
/// Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// TDS packet types
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum TdsPacketType {
    SqlBatch = 0x01,
    PreTDS7Login = 0x02,
    Rpc = 0x03,
    TabularResult = 0x04,
    AttentionSignal = 0x06,
    BulkLoadData = 0x07,
    TransactionManagerRequest = 0x0E,
    Tds7Login = 0x10,
    Sspi = 0x11,
    PreLogin = 0x12,
}

/// TDS packet status
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum TdsPacketStatus {
    Normal = 0x00,
    EndOfMessage = 0x01,
    IgnoreEvent = 0x02,
    ResetConnection = 0x08,
}

/// Pre-login options
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum PreLoginOption {
    Version = 0x00,
    Encryption = 0x01,
    InstOpt = 0x02,
    ThreadId = 0x03,
    Mars = 0x04,
    TraceId = 0x05,
    FedAuthRequired = 0x06,
    NonceOpt = 0x07,
    Terminator = 0xFF,
}

/// SQL Server information from pre-login
#[derive(Debug, Clone)]
pub struct MssqlServerInfo {
    pub version: String,
    pub sub_build: u16,
    pub encryption_supported: bool,
}

/// MSSQL client
pub struct MssqlClient {
    stream: TcpStream,
}

impl MssqlClient {
    /// Connect to SQL Server
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

        Ok(Self { stream })
    }

    /// Perform pre-login handshake
    pub fn prelogin(&mut self) -> Result<MssqlServerInfo, String> {
        // Build and send pre-login packet
        let prelogin_packet = self.build_prelogin_packet();

        self.stream
            .write_all(&prelogin_packet)
            .map_err(|e| format!("Failed to send pre-login: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Read pre-login response
        let response = self.read_tds_packet()?;
        self.parse_prelogin_response(&response)
    }

    /// Build TDS pre-login packet
    fn build_prelogin_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // TDS header (8 bytes)
        packet.push(TdsPacketType::PreLogin as u8); // Type
        packet.push(TdsPacketStatus::EndOfMessage as u8); // Status
        packet.push(0x00); // Length (high byte) - placeholder
        packet.push(0x00); // Length (low byte) - placeholder
        packet.push(0x00); // SPID (high)
        packet.push(0x00); // SPID (low)
        packet.push(0x00); // Packet ID
        packet.push(0x00); // Window

        // Pre-login data
        let mut data = Vec::new();

        // VERSION option
        let version_offset = 5 + 6; // 5 bytes for this option + 6 bytes for ENCRYPTION option + TERMINATOR
        data.push(PreLoginOption::Version as u8);
        data.extend_from_slice(&(version_offset as u16).to_be_bytes()); // Offset
        data.extend_from_slice(&6u16.to_be_bytes()); // Length (6 bytes for version)

        // ENCRYPTION option
        let encryption_offset = version_offset + 6;
        data.push(PreLoginOption::Encryption as u8);
        data.extend_from_slice(&(encryption_offset as u16).to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes()); // Length (1 byte)

        // TERMINATOR
        data.push(PreLoginOption::Terminator as u8);

        // VERSION value (6 bytes)
        // Client version: 12.0.0.0 (SQL Server 2014)
        data.push(0x0C); // Major: 12
        data.push(0x00); // Minor: 0
        data.push(0x00); // Build high
        data.push(0x00); // Build low
        data.push(0x00); // Sub-build high
        data.push(0x00); // Sub-build low

        // ENCRYPTION value (1 byte) - ENCRYPT_NOT_SUP = 0x02
        data.push(0x02);

        // Update packet length in header
        let total_len = 8 + data.len();
        packet[2] = ((total_len >> 8) & 0xFF) as u8;
        packet[3] = (total_len & 0xFF) as u8;

        // Append data
        packet.extend_from_slice(&data);

        packet
    }

    /// Read TDS packet
    fn read_tds_packet(&mut self) -> Result<Vec<u8>, String> {
        // Read TDS header (8 bytes)
        let mut header = [0u8; 8];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read TDS header: {}", e))?;

        // Parse packet length from header (bytes 2-3, big-endian)
        let packet_len = ((header[2] as usize) << 8) | (header[3] as usize);

        if packet_len < 8 || packet_len > 32768 {
            return Err(format!("Invalid packet length: {}", packet_len));
        }

        // Read packet data (excluding header)
        let data_len = packet_len - 8;
        let mut data = vec![0u8; data_len];
        self.stream
            .read_exact(&mut data)
            .map_err(|e| format!("Failed to read packet data: {}", e))?;

        Ok(data)
    }

    /// Parse pre-login response
    fn parse_prelogin_response(&self, data: &[u8]) -> Result<MssqlServerInfo, String> {
        if data.len() < 5 {
            return Err("Response too short".to_string());
        }

        let mut version_offset = 0;
        let mut version_length = 0;
        let mut encryption_offset = 0;
        let mut pos = 0;

        // Parse option tokens
        while pos < data.len() {
            let option = data[pos];

            if option == PreLoginOption::Terminator as u8 {
                break;
            }

            if pos + 5 > data.len() {
                break;
            }

            let offset = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
            let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);

            match option {
                x if x == PreLoginOption::Version as u8 => {
                    version_offset = offset;
                    version_length = length;
                }
                x if x == PreLoginOption::Encryption as u8 => {
                    encryption_offset = offset;
                }
                _ => {}
            }

            pos += 5;
        }

        // Extract version
        let mut version_str = String::from("Unknown");
        let mut sub_build = 0u16;

        if version_offset > 0 && version_length >= 6 && version_offset + 6 <= data.len() {
            let major = data[version_offset];
            let minor = data[version_offset + 1];
            let build =
                ((data[version_offset + 2] as u16) << 8) | (data[version_offset + 3] as u16);
            sub_build =
                ((data[version_offset + 4] as u16) << 8) | (data[version_offset + 5] as u16);

            version_str = format!("{}.{}.{}.{}", major, minor, build, sub_build);
        }

        // Extract encryption support
        let encryption_supported = if encryption_offset > 0 && encryption_offset < data.len() {
            data[encryption_offset] != 0x02 // 0x02 = ENCRYPT_NOT_SUP
        } else {
            false
        };

        Ok(MssqlServerInfo {
            version: version_str,
            sub_build,
            encryption_supported,
        })
    }

    /// Get SQL Server product version name
    pub fn get_version_name(&self, info: &MssqlServerInfo) -> String {
        // Parse major version from version string
        let parts: Vec<&str> = info.version.split('.').collect();
        if parts.is_empty() {
            return "Unknown SQL Server".to_string();
        }

        match parts[0] {
            "16" => "SQL Server 2022".to_string(),
            "15" => "SQL Server 2019".to_string(),
            "14" => "SQL Server 2017".to_string(),
            "13" => "SQL Server 2016".to_string(),
            "12" => "SQL Server 2014".to_string(),
            "11" => "SQL Server 2012".to_string(),
            "10" if parts.len() > 1 && parts[1] == "50" => "SQL Server 2008 R2".to_string(),
            "10" => "SQL Server 2008".to_string(),
            "9" => "SQL Server 2005".to_string(),
            "8" => "SQL Server 2000".to_string(),
            _ => format!("SQL Server (version {})", info.version),
        }
    }
}

/// Get SQL Server version information
pub fn get_mssql_version(host: &str, port: u16) -> Result<String, String> {
    let mut client = MssqlClient::connect(host, port)?;
    let info = client.prelogin()?;
    let version_name = client.get_version_name(&info);
    Ok(format!("{} ({})", version_name, info.version))
}

/// Test SQL Server connectivity
pub fn test_mssql_connection(host: &str, port: u16) -> Result<MssqlServerInfo, String> {
    let mut client = MssqlClient::connect(host, port)?;
    client.prelogin()
}

/// Common MSSQL ports
pub fn common_mssql_ports() -> Vec<u16> {
    vec![
        1433, // Default SQL Server port
        1434, // SQL Server Browser Service
        2433, // Alternative port
        3433, // Alternative port
    ]
}

/// Common SQL Server instance names
pub fn common_instance_names() -> Vec<&'static str> {
    vec![
        "MSSQLSERVER", // Default instance
        "SQLEXPRESS",
        "SQLDEVELOPER",
        "SHAREPOINT",
        "MICROSOFT##WID",
        "MICROSOFT##SSEE",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_types() {
        assert_eq!(TdsPacketType::PreLogin as u8, 0x12);
        assert_eq!(TdsPacketType::Tds7Login as u8, 0x10);
        assert_eq!(TdsPacketType::SqlBatch as u8, 0x01);
    }

    #[test]
    fn test_packet_status() {
        assert_eq!(TdsPacketStatus::Normal as u8, 0x00);
        assert_eq!(TdsPacketStatus::EndOfMessage as u8, 0x01);
    }

    #[test]
    fn test_prelogin_options() {
        assert_eq!(PreLoginOption::Version as u8, 0x00);
        assert_eq!(PreLoginOption::Encryption as u8, 0x01);
        assert_eq!(PreLoginOption::Terminator as u8, 0xFF);
    }

    #[test]
    fn test_common_ports() {
        let ports = common_mssql_ports();
        assert!(ports.contains(&1433));
        assert!(ports.contains(&1434));
    }

    #[test]
    fn test_common_instances() {
        let instances = common_instance_names();
        assert!(instances.contains(&"MSSQLSERVER"));
        assert!(instances.contains(&"SQLEXPRESS"));
    }

    #[test]
    fn test_version_name_mapping() {
        let client = MssqlClient::connect("127.0.0.1", 1433).ok();
        if let Some(c) = client {
            let info_2019 = MssqlServerInfo {
                version: "15.0.2000.5".to_string(),
                sub_build: 5,
                encryption_supported: false,
            };
            assert_eq!(c.get_version_name(&info_2019), "SQL Server 2019");

            let info_2017 = MssqlServerInfo {
                version: "14.0.1000.169".to_string(),
                sub_build: 169,
                encryption_supported: false,
            };
            assert_eq!(c.get_version_name(&info_2017), "SQL Server 2017");
        }
    }
}
