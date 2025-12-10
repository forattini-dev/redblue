use std::io::{self, BufReader, BufRead, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct SmtpClient {
    server_addr: String,
    timeout: Duration,
}

impl SmtpClient {
    pub fn new(server_addr: &str) -> Self {
        Self {
            server_addr: server_addr.to_string(),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Verifies if an email address exists by interacting with the SMTP server.
    /// Does not actually send an email.
    pub fn verify_email(&self, email: &str) -> Result<bool, String> {
        let stream = TcpStream::connect(&self.server_addr)
            .map_err(|e| format!("Failed to connect to SMTP server {}: {}", self.server_addr, e))?;
        stream.set_read_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(self.timeout)).map_err(|e| e.to_string())?;

        // Clone stream for separate read/write handles
        let read_stream = stream.try_clone()
            .map_err(|e| format!("Failed to clone stream: {}", e))?;
        let mut writer = stream;
        let mut reader = BufReader::new(read_stream);
        let mut line = String::new();

        // 1. Read initial greeting (220)
        self.read_line(&mut reader, &mut line)?;
        if !line.starts_with("220") {
            return Err(format!("Unexpected SMTP greeting: {}", line.trim()));
        }

        // 2. Send HELO/EHLO
        self.write_line(&mut writer, b"EHLO redblue.local")?;
        self.read_line(&mut reader, &mut line)?;
        if !line.starts_with("250") {
            return Err(format!("Unexpected EHLO response: {}", line.trim()));
        }

        // 3. Set sender (MAIL FROM)
        self.write_line(&mut writer, b"MAIL FROM:<test@redblue.local>")?;
        self.read_line(&mut reader, &mut line)?;
        if !line.starts_with("250") {
            return Err(format!("Unexpected MAIL FROM response: {}", line.trim()));
        }

        // 4. Verify recipient (RCPT TO)
        let rcpt_cmd = format!("RCPT TO:<{}>", email);
        self.write_line(&mut writer, rcpt_cmd.as_bytes())?;
        self.read_line(&mut reader, &mut line)?;

        // Common successful responses: 250 (OK), 251 (User not local; will forward)
        // Common failure responses: 550 (No such user), 553 (Mailbox name not allowed)
        let exists = line.starts_with("250") || line.starts_with("251");

        // 5. Quit
        self.write_line(&mut writer, b"QUIT")?;
        self.read_line(&mut reader, &mut line)?;

        Ok(exists)
    }

    fn read_line(&self, reader: &mut BufReader<TcpStream>, line: &mut String) -> Result<(), String> {
        line.clear();
        reader.read_line(line).map_err(|e| format!("Failed to read from SMTP stream: {}", e))?;
        Ok(())
    }

    fn write_line(&self, stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
        stream.write_all(data).map_err(|e| format!("Failed to write to SMTP stream: {}", e))?;
        stream.write_all(b"\r\n").map_err(|e| format!("Failed to write to SMTP stream: {}", e))?;
        Ok(())
    }
}