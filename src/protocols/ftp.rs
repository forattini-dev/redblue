/// FTP Protocol Implementation (RFC 959)
///
/// Implements File Transfer Protocol for:
/// - FTP client (connect, login, commands)
/// - Anonymous FTP detection
/// - PASV/PORT mode support
/// - Directory listing
/// - File transfer (RETR, STOR)
/// - FTPS detection (AUTH TLS)
///
/// Reference: https://tools.ietf.org/html/rfc959
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// FTP response codes
pub mod codes {
    pub const READY: u16 = 220;
    pub const USER_OK: u16 = 331;
    pub const LOGIN_OK: u16 = 230;
    pub const COMMAND_OK: u16 = 200;
    pub const SYSTEM_TYPE: u16 = 215;
    pub const DIRECTORY_STATUS: u16 = 212;
    pub const FILE_STATUS: u16 = 213;
    pub const HELP_MESSAGE: u16 = 214;
    pub const NAME_SYSTEM_TYPE: u16 = 215;
    pub const SERVICE_READY: u16 = 120;
    pub const SERVICE_CLOSING: u16 = 221;
    pub const DATA_CONNECTION_OPEN: u16 = 125;
    pub const DATA_CONNECTION_CLOSING: u16 = 226;
    pub const ENTERING_PASSIVE: u16 = 227;
    pub const USER_LOGGED_IN: u16 = 230;
    pub const FILE_ACTION_OK: u16 = 250;
    pub const PATHNAME_CREATED: u16 = 257;
    pub const NEED_PASSWORD: u16 = 331;
    pub const NEED_ACCOUNT: u16 = 332;
    pub const FILE_ACTION_PENDING: u16 = 350;
    pub const SERVICE_NOT_AVAILABLE: u16 = 421;
    pub const CANNOT_OPEN_DATA_CONN: u16 = 425;
    pub const CONNECTION_CLOSED: u16 = 426;
    pub const FILE_ACTION_NOT_TAKEN: u16 = 450;
    pub const ACTION_ABORTED: u16 = 451;
    pub const INSUFFICIENT_STORAGE: u16 = 452;
    pub const SYNTAX_ERROR: u16 = 500;
    pub const SYNTAX_ERROR_PARAMS: u16 = 501;
    pub const COMMAND_NOT_IMPLEMENTED: u16 = 502;
    pub const BAD_SEQUENCE: u16 = 503;
    pub const PARAMETER_NOT_IMPLEMENTED: u16 = 504;
    pub const NOT_LOGGED_IN: u16 = 530;
    pub const NEED_ACCOUNT_FOR_STORING: u16 = 532;
    pub const FILE_UNAVAILABLE: u16 = 550;
    pub const PAGE_TYPE_UNKNOWN: u16 = 551;
    pub const EXCEEDED_STORAGE: u16 = 552;
    pub const FILENAME_NOT_ALLOWED: u16 = 553;
}

/// FTP response
#[derive(Debug, Clone)]
pub struct FtpResponse {
    pub code: u16,
    pub message: String,
    pub is_multiline: bool,
}

impl FtpResponse {
    pub fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    pub fn is_intermediate(&self) -> bool {
        self.code >= 100 && self.code < 200
    }

    pub fn is_error(&self) -> bool {
        self.code >= 400
    }

    pub fn needs_password(&self) -> bool {
        self.code == codes::NEED_PASSWORD
    }

    pub fn is_logged_in(&self) -> bool {
        self.code == codes::LOGIN_OK || self.code == codes::USER_LOGGED_IN
    }
}

/// FTP transfer mode
#[derive(Debug, Clone, PartialEq)]
pub enum TransferMode {
    Passive, // PASV - server tells client where to connect
    Active,  // PORT - client tells server where to connect
}

/// FTP client
pub struct FtpClient {
    control_stream: TcpStream,
    reader: BufReader<TcpStream>,
    pub transfer_mode: TransferMode,
    pub supports_tls: bool,
}

impl FtpClient {
    /// Connect to FTP server
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

        let reader_stream = stream
            .try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;

        let reader = BufReader::new(reader_stream);

        let mut client = Self {
            control_stream: stream,
            reader,
            transfer_mode: TransferMode::Passive,
            supports_tls: false,
        };

        // Read welcome message (220)
        let _welcome = client.read_response()?;

        Ok(client)
    }

    /// Send USER command
    pub fn user(&mut self, username: &str) -> Result<FtpResponse, String> {
        self.send_command(&format!("USER {}\r\n", username))?;
        self.read_response()
    }

    /// Send PASS command
    pub fn pass(&mut self, password: &str) -> Result<FtpResponse, String> {
        self.send_command(&format!("PASS {}\r\n", password))?;
        self.read_response()
    }

    /// Login with username and password
    pub fn login(&mut self, username: &str, password: &str) -> Result<FtpResponse, String> {
        let user_resp = self.user(username)?;

        if user_resp.needs_password() {
            self.pass(password)
        } else if user_resp.is_logged_in() {
            Ok(user_resp)
        } else {
            Err(format!("Unexpected response: {}", user_resp.message))
        }
    }

    /// Try anonymous login
    pub fn login_anonymous(&mut self) -> Result<FtpResponse, String> {
        self.login("anonymous", "anonymous@example.com")
    }

    /// Send SYST command (get system type)
    pub fn syst(&mut self) -> Result<FtpResponse, String> {
        self.send_command("SYST\r\n")?;
        self.read_response()
    }

    /// Send PWD command (print working directory)
    pub fn pwd(&mut self) -> Result<FtpResponse, String> {
        self.send_command("PWD\r\n")?;
        self.read_response()
    }

    /// Send CWD command (change working directory)
    pub fn cwd(&mut self, path: &str) -> Result<FtpResponse, String> {
        self.send_command(&format!("CWD {}\r\n", path))?;
        self.read_response()
    }

    /// Send LIST command (list directory)
    pub fn list(&mut self, path: Option<&str>) -> Result<String, String> {
        // Enter passive mode
        let data_addr = self.pasv()?;

        // Connect to data connection
        let mut data_stream = TcpStream::connect(&data_addr)
            .map_err(|e| format!("Failed to connect to data port: {}", e))?;

        // Send LIST command
        let cmd = if let Some(p) = path {
            format!("LIST {}\r\n", p)
        } else {
            "LIST\r\n".to_string()
        };
        self.send_command(&cmd)?;
        let _resp = self.read_response()?;

        // Read data from data connection
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut data_stream, &mut data)
            .map_err(|e| format!("Failed to read data: {}", e))?;

        // Read final response
        let _final_resp = self.read_response()?;

        String::from_utf8(data).map_err(|e| format!("Invalid UTF-8: {}", e))
    }

    /// Send PASV command (enter passive mode)
    pub fn pasv(&mut self) -> Result<String, String> {
        self.send_command("PASV\r\n")?;
        let resp = self.read_response()?;

        if !resp.is_success() {
            return Err(format!("PASV failed: {}", resp.message));
        }

        // Parse PASV response: "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
        Self::parse_pasv_response(&resp.message)
    }

    /// Parse PASV response to extract IP:PORT
    fn parse_pasv_response(message: &str) -> Result<String, String> {
        // Find the part inside parentheses
        let start = message
            .find('(')
            .ok_or("Invalid PASV response: no opening paren")?;
        let end = message
            .find(')')
            .ok_or("Invalid PASV response: no closing paren")?;

        let numbers_str = &message[start + 1..end];
        let numbers: Vec<&str> = numbers_str.split(',').collect();

        if numbers.len() != 6 {
            return Err("Invalid PASV response: expected 6 numbers".to_string());
        }

        let h1: u8 = numbers[0].parse().map_err(|_| "Invalid IP octet")?;
        let h2: u8 = numbers[1].parse().map_err(|_| "Invalid IP octet")?;
        let h3: u8 = numbers[2].parse().map_err(|_| "Invalid IP octet")?;
        let h4: u8 = numbers[3].parse().map_err(|_| "Invalid IP octet")?;
        let p1: u8 = numbers[4].parse().map_err(|_| "Invalid port byte")?;
        let p2: u8 = numbers[5].parse().map_err(|_| "Invalid port byte")?;

        let port = (p1 as u16) * 256 + (p2 as u16);
        Ok(format!("{}.{}.{}.{}:{}", h1, h2, h3, h4, port))
    }

    /// Send QUIT command
    pub fn quit(&mut self) -> Result<FtpResponse, String> {
        self.send_command("QUIT\r\n")?;
        self.read_response()
    }

    /// Send FEAT command (feature list)
    pub fn feat(&mut self) -> Result<FtpResponse, String> {
        self.send_command("FEAT\r\n")?;
        let resp = self.read_response()?;

        // Check if AUTH TLS is supported
        if resp.message.contains("AUTH TLS") || resp.message.contains("AUTH SSL") {
            self.supports_tls = true;
        }

        Ok(resp)
    }

    /// Send NOOP command (keep-alive)
    pub fn noop(&mut self) -> Result<FtpResponse, String> {
        self.send_command("NOOP\r\n")?;
        self.read_response()
    }

    /// Send TYPE command (set transfer type)
    pub fn type_(&mut self, type_code: &str) -> Result<FtpResponse, String> {
        self.send_command(&format!("TYPE {}\r\n", type_code))?;
        self.read_response()
    }

    /// Send raw command
    fn send_command(&mut self, command: &str) -> Result<(), String> {
        self.control_stream
            .write_all(command.as_bytes())
            .map_err(|e| format!("Failed to send command: {}", e))?;
        self.control_stream
            .flush()
            .map_err(|e| format!("Failed to flush stream: {}", e))?;
        Ok(())
    }

    /// Read FTP response
    fn read_response(&mut self) -> Result<FtpResponse, String> {
        let mut lines = Vec::new();
        let mut is_multiline = false;

        loop {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .map_err(|e| format!("Failed to read response: {}", e))?;

            if line.is_empty() {
                return Err("Connection closed by server".to_string());
            }

            lines.push(line.clone());

            // Check if this is a continuation line (has '-' after code)
            if line.len() >= 4 && line.chars().nth(3) == Some('-') {
                is_multiline = true;
                continue;
            } else {
                // Last line (has space after code)
                break;
            }
        }

        // Parse response code from first line
        let first_line = &lines[0];
        if first_line.len() < 3 {
            return Err("Invalid FTP response".to_string());
        }

        let code_str = &first_line[0..3];
        let code = code_str
            .parse::<u16>()
            .map_err(|_| "Invalid response code".to_string())?;

        // Combine all lines into message
        let message = lines.join("");

        Ok(FtpResponse {
            code,
            message,
            is_multiline,
        })
    }
}

/// Quick FTP banner grab
pub fn ftp_banner(host: &str, port: u16) -> Result<String, String> {
    let client = FtpClient::connect(host, port)?;
    // The banner is already read in connect(), so we can't get it directly
    // Instead, return system type
    let mut client = client;
    let syst = client.syst()?;
    Ok(syst.message)
}

/// Test anonymous FTP access
pub fn test_anonymous_ftp(host: &str, port: u16) -> Result<bool, String> {
    let mut client = FtpClient::connect(host, port)?;
    let login_result = client.login_anonymous();

    match login_result {
        Ok(resp) if resp.is_logged_in() => Ok(true),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pasv_response() {
        let response = "227 Entering Passive Mode (192,168,1,1,19,136)";
        let addr = FtpClient::parse_pasv_response(response).unwrap();
        assert_eq!(addr, "192.168.1.1:5000"); // (19 * 256) + 136 = 5000
    }

    #[test]
    fn test_response_codes() {
        let resp = FtpResponse {
            code: 220,
            message: "Welcome".to_string(),
            is_multiline: false,
        };
        assert!(resp.is_success());
        assert!(!resp.is_error());
    }

    #[test]
    fn test_password_needed() {
        let resp = FtpResponse {
            code: codes::NEED_PASSWORD,
            message: "Password required".to_string(),
            is_multiline: false,
        };
        assert!(resp.needs_password());
    }
}
