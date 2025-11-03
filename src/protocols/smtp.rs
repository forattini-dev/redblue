/// SMTP Protocol Implementation (RFC 5321)
///
/// Implements Simple Mail Transfer Protocol for email transmission
/// - SMTP handshake (EHLO, HELO)
/// - SMTP commands (MAIL FROM, RCPT TO, DATA, QUIT)
/// - STARTTLS detection
/// - Server capability detection
///
/// Reference: https://tools.ietf.org/html/rfc5321
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// SMTP response codes
pub mod codes {
    pub const SERVICE_READY: u16 = 220;
    pub const SERVICE_CLOSING: u16 = 221;
    pub const ACTION_OK: u16 = 250;
    pub const USER_NOT_LOCAL_FORWARD: u16 = 251;
    pub const START_MAIL_INPUT: u16 = 354;
    pub const SERVICE_NOT_AVAILABLE: u16 = 421;
    pub const MAILBOX_UNAVAILABLE: u16 = 450;
    pub const LOCAL_ERROR: u16 = 451;
    pub const INSUFFICIENT_STORAGE: u16 = 452;
    pub const COMMAND_UNRECOGNIZED: u16 = 500;
    pub const SYNTAX_ERROR_PARAMS: u16 = 501;
    pub const COMMAND_NOT_IMPLEMENTED: u16 = 502;
    pub const BAD_SEQUENCE: u16 = 503;
    pub const PARAMETER_NOT_IMPLEMENTED: u16 = 504;
    pub const MAILBOX_NOT_FOUND: u16 = 550;
    pub const USER_NOT_LOCAL: u16 = 551;
    pub const EXCEEDED_STORAGE: u16 = 552;
    pub const MAILBOX_NAME_INVALID: u16 = 553;
    pub const TRANSACTION_FAILED: u16 = 554;
}

/// SMTP response
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub message: String,
    pub is_multiline: bool,
}

impl SmtpResponse {
    pub fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 400
    }

    pub fn is_intermediate(&self) -> bool {
        self.code >= 300 && self.code < 400
    }

    pub fn is_error(&self) -> bool {
        self.code >= 400
    }
}

/// SMTP client
pub struct SmtpClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    pub capabilities: Vec<String>,
    pub supports_starttls: bool,
}

impl SmtpClient {
    /// Connect to SMTP server
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
            stream,
            reader,
            capabilities: Vec::new(),
            supports_starttls: false,
        };

        // Read server greeting (220 Service ready)
        let _greeting = client.read_response()?;

        Ok(client)
    }

    /// Send EHLO command
    pub fn ehlo(&mut self, domain: &str) -> Result<SmtpResponse, String> {
        self.send_command(&format!("EHLO {}\r\n", domain))?;
        let response = self.read_response()?;

        // Parse EHLO response for capabilities
        if response.is_success() {
            self.parse_capabilities(&response.message);
        }

        Ok(response)
    }

    /// Send HELO command (fallback for old servers)
    pub fn helo(&mut self, domain: &str) -> Result<SmtpResponse, String> {
        self.send_command(&format!("HELO {}\r\n", domain))?;
        self.read_response()
    }

    /// Send MAIL FROM command
    pub fn mail_from(&mut self, from: &str) -> Result<SmtpResponse, String> {
        self.send_command(&format!("MAIL FROM:<{}>\r\n", from))?;
        self.read_response()
    }

    /// Send RCPT TO command
    pub fn rcpt_to(&mut self, to: &str) -> Result<SmtpResponse, String> {
        self.send_command(&format!("RCPT TO:<{}>\r\n", to))?;
        self.read_response()
    }

    /// Send DATA command
    pub fn data(&mut self) -> Result<SmtpResponse, String> {
        self.send_command("DATA\r\n")?;
        self.read_response()
    }

    /// Send email content (after DATA command)
    pub fn send_content(&mut self, content: &str) -> Result<SmtpResponse, String> {
        self.send_command(content)?;
        self.send_command("\r\n.\r\n")?; // End of data marker
        self.read_response()
    }

    /// Send QUIT command
    pub fn quit(&mut self) -> Result<SmtpResponse, String> {
        self.send_command("QUIT\r\n")?;
        self.read_response()
    }

    /// Send STARTTLS command
    pub fn starttls(&mut self) -> Result<SmtpResponse, String> {
        if !self.supports_starttls {
            return Err("Server does not support STARTTLS".to_string());
        }
        self.send_command("STARTTLS\r\n")?;
        self.read_response()
    }

    /// Send NOOP command (keep-alive)
    pub fn noop(&mut self) -> Result<SmtpResponse, String> {
        self.send_command("NOOP\r\n")?;
        self.read_response()
    }

    /// Send RSET command (reset)
    pub fn rset(&mut self) -> Result<SmtpResponse, String> {
        self.send_command("RSET\r\n")?;
        self.read_response()
    }

    /// Send VRFY command (verify email address)
    pub fn vrfy(&mut self, address: &str) -> Result<SmtpResponse, String> {
        self.send_command(&format!("VRFY {}\r\n", address))?;
        self.read_response()
    }

    /// Send raw command
    fn send_command(&mut self, command: &str) -> Result<(), String> {
        self.stream
            .write_all(command.as_bytes())
            .map_err(|e| format!("Failed to send command: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("Failed to flush stream: {}", e))?;
        Ok(())
    }

    /// Read SMTP response
    fn read_response(&mut self) -> Result<SmtpResponse, String> {
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
            return Err("Invalid SMTP response".to_string());
        }

        let code_str = &first_line[0..3];
        let code = code_str
            .parse::<u16>()
            .map_err(|_| "Invalid response code".to_string())?;

        // Combine all lines into message
        let message = lines.join("");

        Ok(SmtpResponse {
            code,
            message,
            is_multiline,
        })
    }

    /// Parse EHLO capabilities
    fn parse_capabilities(&mut self, response: &str) {
        self.capabilities.clear();
        self.supports_starttls = false;

        for line in response.lines() {
            // Skip the first line (usually "250-hostname")
            // Capabilities are in format "250-CAPABILITY" or "250 CAPABILITY"
            if line.len() > 4 {
                let capability = line[4..].trim().to_uppercase();
                if !capability.is_empty() {
                    if capability == "STARTTLS" {
                        self.supports_starttls = true;
                    }
                    self.capabilities.push(capability);
                }
            }
        }
    }
}

/// Simple email structure
pub struct Email {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

impl Email {
    pub fn new(from: &str, to: Vec<String>, subject: &str, body: &str) -> Self {
        Self {
            from: from.to_string(),
            to,
            subject: subject.to_string(),
            body: body.to_string(),
        }
    }

    /// Convert email to SMTP DATA format
    pub fn to_data(&self) -> String {
        let mut data = String::new();

        // Headers
        data.push_str(&format!("From: {}\r\n", self.from));
        data.push_str(&format!("To: {}\r\n", self.to.join(", ")));
        data.push_str(&format!("Subject: {}\r\n", self.subject));
        data.push_str("\r\n"); // Empty line between headers and body

        // Body
        data.push_str(&self.body);

        data
    }
}

/// Send email via SMTP
pub fn send_email(
    host: &str,
    port: u16,
    from: &str,
    to: Vec<String>,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let mut client = SmtpClient::connect(host, port)?;

    // Send EHLO
    client.ehlo("localhost")?;

    // Send MAIL FROM
    client.mail_from(from)?;

    // Send RCPT TO for each recipient
    for recipient in &to {
        client.rcpt_to(recipient)?;
    }

    // Send DATA command
    let data_response = client.data()?;
    if !data_response.is_intermediate() {
        return Err(format!("DATA command failed: {}", data_response.message));
    }

    // Send email content
    let email = Email::new(from, to, subject, body);
    let content = email.to_data();
    client.send_content(&content)?;

    // Send QUIT
    client.quit()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_to_data() {
        let email = Email::new(
            "alice@example.com",
            vec!["bob@example.com".to_string()],
            "Test Subject",
            "Test Body",
        );

        let data = email.to_data();

        assert!(data.contains("From: alice@example.com"));
        assert!(data.contains("To: bob@example.com"));
        assert!(data.contains("Subject: Test Subject"));
        assert!(data.contains("Test Body"));
    }
}
