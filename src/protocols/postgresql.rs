/// PostgreSQL Protocol Implementation
///
/// Implements PostgreSQL frontend/backend protocol for:
/// - Server version detection
/// - Authentication testing
/// - Database enumeration
/// - Connection parameter parsing
///
/// Reference: https://www.postgresql.org/docs/current/protocol.html
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// PostgreSQL message types
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum MessageType {
    AuthenticationRequest = b'R' as isize,
    BackendKeyData = b'K' as isize,
    ParameterStatus = b'S' as isize,
    ReadyForQuery = b'Z' as isize,
    ErrorResponse = b'E' as isize,
    NoticeResponse = b'N' as isize,
    RowDescription = b'T' as isize,
    DataRow = b'D' as isize,
    CommandComplete = b'C' as isize,
}

/// PostgreSQL authentication methods
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum AuthMethod {
    Ok = 0,
    KerberosV5 = 2,
    CleartextPassword = 3,
    MD5Password = 5,
    SCMCredential = 6,
    GSS = 7,
    SSPI = 9,
    SASL = 10,
}

/// PostgreSQL server parameters
#[derive(Debug, Clone, Default)]
pub struct PgServerParams {
    pub server_version: String,
    pub server_encoding: String,
    pub client_encoding: String,
    pub application_name: String,
    pub timezone: String,
    pub integer_datetimes: String,
}

/// PostgreSQL connection result
#[derive(Debug, Clone)]
pub struct PgConnectionResult {
    pub success: bool,
    pub auth_method: i32,
    pub params: PgServerParams,
    pub error_message: Option<String>,
}

/// PostgreSQL client
pub struct PgClient {
    stream: TcpStream,
}

impl PgClient {
    /// Connect to PostgreSQL server
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

    /// Perform startup handshake
    pub fn startup(&mut self, user: &str, database: &str) -> Result<PgConnectionResult, String> {
        // Send startup message
        let startup = self.build_startup_message(user, database);
        self.stream
            .write_all(&startup)
            .map_err(|e| format!("Failed to send startup: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Read server responses
        self.read_startup_responses()
    }

    /// Build PostgreSQL startup message (protocol version 3.0)
    fn build_startup_message(&self, user: &str, database: &str) -> Vec<u8> {
        let mut msg = Vec::new();

        // Protocol version 3.0 (major=3, minor=0)
        let protocol_version: i32 = (3 << 16) | 0;

        // Calculate message length
        let params = format!("user\0{}\0database\0{}\0\0", user, database);
        let length = 4 + 4 + params.len(); // length field + protocol + params

        // Message length (including itself)
        msg.extend_from_slice(&(length as i32).to_be_bytes());

        // Protocol version
        msg.extend_from_slice(&protocol_version.to_be_bytes());

        // Parameters (key-value pairs, null-terminated, double-null at end)
        msg.extend_from_slice(params.as_bytes());

        msg
    }

    /// Read startup responses from server
    fn read_startup_responses(&mut self) -> Result<PgConnectionResult, String> {
        let mut result = PgConnectionResult {
            success: false,
            auth_method: -1,
            params: PgServerParams::default(),
            error_message: None,
        };

        loop {
            // Read message type (1 byte)
            let mut msg_type = [0u8; 1];
            if self.stream.read_exact(&mut msg_type).is_err() {
                break;
            }

            // Read message length (4 bytes, big-endian, includes itself)
            let mut len_bytes = [0u8; 4];
            self.stream
                .read_exact(&mut len_bytes)
                .map_err(|e| format!("Failed to read length: {}", e))?;

            let msg_len = i32::from_be_bytes(len_bytes) as usize;
            if msg_len < 4 {
                return Err("Invalid message length".to_string());
            }

            // Read message body
            let body_len = msg_len - 4;
            let mut body = vec![0u8; body_len];
            if body_len > 0 {
                self.stream
                    .read_exact(&mut body)
                    .map_err(|e| format!("Failed to read body: {}", e))?;
            }

            match msg_type[0] {
                b'R' => {
                    // Authentication request
                    if body.len() >= 4 {
                        let auth_type = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        result.auth_method = auth_type;

                        if auth_type == AuthMethod::Ok as i32 {
                            result.success = true;
                        }
                    }
                }
                b'S' => {
                    // ParameterStatus
                    self.parse_parameter_status(&body, &mut result.params);
                }
                b'K' => {
                    // BackendKeyData (ignore for now)
                }
                b'Z' => {
                    // ReadyForQuery - connection established
                    break;
                }
                b'E' => {
                    // ErrorResponse
                    result.error_message = Some(self.parse_error_response(&body));
                    break;
                }
                _ => {
                    // Unknown message type, ignore
                }
            }
        }

        Ok(result)
    }

    /// Parse ParameterStatus message
    fn parse_parameter_status(&self, body: &[u8], params: &mut PgServerParams) {
        if let Some((key, value)) = parse_null_terminated_pair(body) {
            match key.as_str() {
                "server_version" => params.server_version = value,
                "server_encoding" => params.server_encoding = value,
                "client_encoding" => params.client_encoding = value,
                "application_name" => params.application_name = value,
                "TimeZone" => params.timezone = value,
                "integer_datetimes" => params.integer_datetimes = value,
                _ => {} // Ignore other parameters
            }
        }
    }

    /// Parse ErrorResponse message
    fn parse_error_response(&self, body: &[u8]) -> String {
        let mut error_parts = Vec::new();

        let mut pos = 0;
        while pos < body.len() {
            let field_type = body[pos];
            if field_type == 0 {
                break; // End of error fields
            }

            pos += 1;

            // Read null-terminated string
            let start = pos;
            while pos < body.len() && body[pos] != 0 {
                pos += 1;
            }

            if pos < body.len() {
                if let Ok(value) = String::from_utf8(body[start..pos].to_vec()) {
                    match field_type {
                        b'S' => error_parts.push(format!("Severity: {}", value)),
                        b'C' => error_parts.push(format!("Code: {}", value)),
                        b'M' => error_parts.push(format!("Message: {}", value)),
                        b'D' => error_parts.push(format!("Detail: {}", value)),
                        _ => {}
                    }
                }
                pos += 1; // Skip null terminator
            }
        }

        error_parts.join(", ")
    }

    /// Authenticate with password (cleartext)
    pub fn auth_password(&mut self, password: &str) -> Result<bool, String> {
        let mut msg = Vec::new();

        // Message type 'p' (password message)
        msg.push(b'p');

        // Message length (including length field + password + null terminator)
        let msg_len = 4 + password.len() + 1;
        msg.extend_from_slice(&(msg_len as i32).to_be_bytes());

        // Password (null-terminated)
        msg.extend_from_slice(password.as_bytes());
        msg.push(0);

        self.stream
            .write_all(&msg)
            .map_err(|e| format!("Failed to send password: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Read authentication response
        let response = self.read_startup_responses()?;
        Ok(response.success)
    }
}

/// Parse null-terminated key-value pair
fn parse_null_terminated_pair(data: &[u8]) -> Option<(String, String)> {
    let mut parts = data.split(|&b| b == 0);

    let key = parts.next()?.to_vec();
    let value = parts.next()?.to_vec();

    let key_str = String::from_utf8(key).ok()?;
    let value_str = String::from_utf8(value).ok()?;

    Some((key_str, value_str))
}

/// Test PostgreSQL connection
pub fn test_postgres_connection(
    host: &str,
    port: u16,
    user: &str,
    database: &str,
) -> Result<PgConnectionResult, String> {
    let mut client = PgClient::connect(host, port)?;
    client.startup(user, database)
}

/// Get PostgreSQL server version
pub fn get_postgres_version(host: &str, port: u16) -> Result<String, String> {
    let mut client = PgClient::connect(host, port)?;
    let result = client.startup("postgres", "postgres")?;

    if !result.params.server_version.is_empty() {
        Ok(result.params.server_version.clone())
    } else {
        Err("Version not available".to_string())
    }
}

/// Try PostgreSQL authentication
pub fn try_postgres_auth(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    database: &str,
) -> Result<bool, String> {
    let mut client = PgClient::connect(host, port)?;
    let startup_result = client.startup(user, database)?;

    if startup_result.success {
        return Ok(true);
    }

    if startup_result.auth_method == AuthMethod::CleartextPassword as i32 {
        client.auth_password(password)
    } else {
        Ok(false) // Other auth methods not implemented yet
    }
}

/// Common PostgreSQL usernames for testing
pub fn common_postgres_users() -> Vec<&'static str> {
    vec!["postgres", "admin", "root", "user", "test"]
}

/// Common PostgreSQL databases
pub fn common_postgres_databases() -> Vec<&'static str> {
    vec!["postgres", "template1", "template0", "test", "admin"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_methods() {
        assert_eq!(AuthMethod::Ok as i32, 0);
        assert_eq!(AuthMethod::CleartextPassword as i32, 3);
        assert_eq!(AuthMethod::MD5Password as i32, 5);
    }

    #[test]
    fn test_message_types() {
        assert_eq!(MessageType::AuthenticationRequest as u8, b'R');
        assert_eq!(MessageType::ParameterStatus as u8, b'S');
        assert_eq!(MessageType::ReadyForQuery as u8, b'Z');
        assert_eq!(MessageType::ErrorResponse as u8, b'E');
    }

    #[test]
    fn test_parse_null_terminated_pair() {
        let data = b"key\0value\0";
        let result = parse_null_terminated_pair(data);
        assert!(result.is_some());
        let (key, value) = result.unwrap();
        assert_eq!(key, "key");
        assert_eq!(value, "value");
    }

    #[test]
    fn test_startup_message_structure() {
        let client = PgClient::connect("127.0.0.1", 5432).ok();
        if let Some(mut c) = client {
            let msg = c.build_startup_message("testuser", "testdb");
            assert!(msg.len() > 8); // Should have at least length + protocol version
            assert_eq!(&msg[0..4], &(msg.len() as i32).to_be_bytes()); // Check length field
        }
    }

    #[test]
    fn test_common_users() {
        let users = common_postgres_users();
        assert!(users.contains(&"postgres"));
        assert!(users.contains(&"admin"));
    }

    #[test]
    fn test_common_databases() {
        let dbs = common_postgres_databases();
        assert!(dbs.contains(&"postgres"));
        assert!(dbs.contains(&"template1"));
    }
}
