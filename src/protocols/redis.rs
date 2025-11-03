/// Redis Protocol Implementation (RESP - REdis Serialization Protocol)
///
/// Implements Redis protocol for:
/// - RESP protocol encoding/decoding
/// - Basic Redis commands (PING, INFO, GET, SET, KEYS, etc.)
/// - Authentication (AUTH command)
/// - No-auth detection
/// - Database enumeration
///
/// Reference: https://redis.io/docs/reference/protocol-spec/
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// RESP data types
#[derive(Debug, Clone, PartialEq)]
pub enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),   // None = null bulk string
    Array(Option<Vec<RespValue>>), // None = null array
}

impl RespValue {
    /// Encode RESP value to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RespValue::SimpleString(s) => format!("+{}\r\n", s).into_bytes(),
            RespValue::Error(e) => format!("-{}\r\n", e).into_bytes(),
            RespValue::Integer(i) => format!(":{}\r\n", i).into_bytes(),
            RespValue::BulkString(None) => b"$-1\r\n".to_vec(),
            RespValue::BulkString(Some(data)) => {
                let mut bytes = format!("${}\r\n", data.len()).into_bytes();
                bytes.extend_from_slice(data);
                bytes.extend_from_slice(b"\r\n");
                bytes
            }
            RespValue::Array(None) => b"*-1\r\n".to_vec(),
            RespValue::Array(Some(arr)) => {
                let mut bytes = format!("*{}\r\n", arr.len()).into_bytes();
                for val in arr {
                    bytes.extend_from_slice(&val.encode());
                }
                bytes
            }
        }
    }

    /// Check if this is an error response
    pub fn is_error(&self) -> bool {
        matches!(self, RespValue::Error(_))
    }

    /// Extract string value
    pub fn as_string(&self) -> Option<String> {
        match self {
            RespValue::SimpleString(s) => Some(s.clone()),
            RespValue::BulkString(Some(data)) => String::from_utf8(data.clone()).ok(),
            _ => None,
        }
    }

    /// Extract integer value
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            RespValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Extract array
    pub fn as_array(&self) -> Option<&Vec<RespValue>> {
        match self {
            RespValue::Array(Some(arr)) => Some(arr),
            _ => None,
        }
    }
}

/// Redis client
pub struct RedisClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    pub authenticated: bool,
}

impl RedisClient {
    /// Connect to Redis server
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        let address = format!("{}:{}", host, port);

        let stream = TcpStream::connect(&address)
            .map_err(|e| format!("Failed to connect to {}: {}", address, e))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        let reader_stream = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;

        let reader = BufReader::new(reader_stream);

        Ok(Self {
            stream,
            reader,
            authenticated: false,
        })
    }

    /// Send PING command
    pub fn ping(&mut self) -> Result<RespValue, String> {
        self.send_command(&["PING"])
    }

    /// Send INFO command
    pub fn info(&mut self, section: Option<&str>) -> Result<RespValue, String> {
        if let Some(s) = section {
            self.send_command(&["INFO", s])
        } else {
            self.send_command(&["INFO"])
        }
    }

    /// Send AUTH command
    pub fn auth(&mut self, password: &str) -> Result<RespValue, String> {
        let resp = self.send_command(&["AUTH", password])?;

        if !resp.is_error() {
            self.authenticated = true;
        }

        Ok(resp)
    }

    /// Send GET command
    pub fn get(&mut self, key: &str) -> Result<RespValue, String> {
        self.send_command(&["GET", key])
    }

    /// Send SET command
    pub fn set(&mut self, key: &str, value: &str) -> Result<RespValue, String> {
        self.send_command(&["SET", key, value])
    }

    /// Send KEYS command
    pub fn keys(&mut self, pattern: &str) -> Result<RespValue, String> {
        self.send_command(&["KEYS", pattern])
    }

    /// Send DBSIZE command
    pub fn dbsize(&mut self) -> Result<RespValue, String> {
        self.send_command(&["DBSIZE"])
    }

    /// Send CONFIG GET command
    pub fn config_get(&mut self, parameter: &str) -> Result<RespValue, String> {
        self.send_command(&["CONFIG", "GET", parameter])
    }

    /// Send SELECT command (change database)
    pub fn select(&mut self, db: usize) -> Result<RespValue, String> {
        self.send_command(&["SELECT", &db.to_string()])
    }

    /// Send CLIENT LIST command
    pub fn client_list(&mut self) -> Result<RespValue, String> {
        self.send_command(&["CLIENT", "LIST"])
    }

    /// Send arbitrary command
    pub fn send_command(&mut self, args: &[&str]) -> Result<RespValue, String> {
        // Build RESP array
        let command = RespValue::Array(Some(
            args.iter()
                .map(|arg| RespValue::BulkString(Some(arg.as_bytes().to_vec())))
                .collect(),
        ));

        // Send command
        let bytes = command.encode();
        self.stream
            .write_all(&bytes)
            .map_err(|e| format!("Failed to send command: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        // Read response
        self.read_response()
    }

    /// Read RESP response
    fn read_response(&mut self) -> Result<RespValue, String> {
        let mut first_byte = [0u8; 1];
        self.stream
            .read_exact(&mut first_byte)
            .map_err(|e| format!("Failed to read response type: {}", e))?;

        match first_byte[0] {
            b'+' => self.read_simple_string(),
            b'-' => self.read_error(),
            b':' => self.read_integer(),
            b'$' => self.read_bulk_string(),
            b'*' => self.read_array(),
            _ => Err(format!("Unknown RESP type: {}", first_byte[0] as char)),
        }
    }

    /// Read simple string
    fn read_simple_string(&mut self) -> Result<RespValue, String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read line: {}", e))?;

        Ok(RespValue::SimpleString(line.trim_end().to_string()))
    }

    /// Read error
    fn read_error(&mut self) -> Result<RespValue, String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read line: {}", e))?;

        Ok(RespValue::Error(line.trim_end().to_string()))
    }

    /// Read integer
    fn read_integer(&mut self) -> Result<RespValue, String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read line: {}", e))?;

        let num = line
            .trim()
            .parse::<i64>()
            .map_err(|e| format!("Invalid integer: {}", e))?;

        Ok(RespValue::Integer(num))
    }

    /// Read bulk string
    fn read_bulk_string(&mut self) -> Result<RespValue, String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read length: {}", e))?;

        let len = line
            .trim()
            .parse::<i64>()
            .map_err(|e| format!("Invalid bulk string length: {}", e))?;

        if len == -1 {
            return Ok(RespValue::BulkString(None)); // Null bulk string
        }

        let mut data = vec![0u8; len as usize];
        std::io::Read::read_exact(&mut self.reader, &mut data)
            .map_err(|e| format!("Failed to read bulk data: {}", e))?;

        // Read trailing \r\n
        let mut crlf = [0u8; 2];
        std::io::Read::read_exact(&mut self.reader, &mut crlf)
            .map_err(|e| format!("Failed to read CRLF: {}", e))?;

        Ok(RespValue::BulkString(Some(data)))
    }

    /// Read array
    fn read_array(&mut self) -> Result<RespValue, String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read array length: {}", e))?;

        let len = line
            .trim()
            .parse::<i64>()
            .map_err(|e| format!("Invalid array length: {}", e))?;

        if len == -1 {
            return Ok(RespValue::Array(None)); // Null array
        }

        let mut elements = Vec::new();
        for _ in 0..len {
            elements.push(self.read_response()?);
        }

        Ok(RespValue::Array(Some(elements)))
    }
}

/// Test if Redis is accessible without authentication
pub fn test_no_auth(host: &str, port: u16) -> Result<bool, String> {
    let mut client = RedisClient::connect(host, port)?;

    match client.ping() {
        Ok(resp) => Ok(!resp.is_error()),
        Err(_) => Ok(false),
    }
}

/// Get Redis server info
pub fn get_server_info(host: &str, port: u16) -> Result<String, String> {
    let mut client = RedisClient::connect(host, port)?;
    let info = client.info(Some("server"))?;

    info.as_string()
        .ok_or_else(|| "Failed to get server info".to_string())
}

/// Try to authenticate with a password
pub fn try_auth(host: &str, port: u16, password: &str) -> Result<bool, String> {
    let mut client = RedisClient::connect(host, port)?;
    let result = client.auth(password);

    match result {
        Ok(resp) => Ok(!resp.is_error()),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple_string() {
        let val = RespValue::SimpleString("OK".to_string());
        assert_eq!(val.encode(), b"+OK\r\n");
    }

    #[test]
    fn test_encode_integer() {
        let val = RespValue::Integer(42);
        assert_eq!(val.encode(), b":42\r\n");
    }

    #[test]
    fn test_encode_bulk_string() {
        let val = RespValue::BulkString(Some(b"hello".to_vec()));
        assert_eq!(val.encode(), b"$5\r\nhello\r\n");
    }

    #[test]
    fn test_encode_null_bulk_string() {
        let val = RespValue::BulkString(None);
        assert_eq!(val.encode(), b"$-1\r\n");
    }

    #[test]
    fn test_encode_array() {
        let val = RespValue::Array(Some(vec![RespValue::BulkString(Some(b"PING".to_vec()))]));
        assert_eq!(val.encode(), b"*1\r\n$4\r\nPING\r\n");
    }

    #[test]
    fn test_is_error() {
        let err = RespValue::Error("ERR invalid command".to_string());
        assert!(err.is_error());

        let ok = RespValue::SimpleString("OK".to_string());
        assert!(!ok.is_error());
    }
}
