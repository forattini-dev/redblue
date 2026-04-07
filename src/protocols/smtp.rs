use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::encoding::base64::base64_encode;

pub struct SmtpClient {
  server_addr: String,
  timeout: Duration,
}

/// Email message configuration
pub struct EmailConfig {
  pub from: String,
  pub to: Vec<String>,
  pub subject: String,
  pub body_text: Option<String>,
  pub body_html: Option<String>,
  pub reply_to: Option<String>,
  pub auth: Option<SmtpAuth>,
  pub headers: HashMap<String, String>,
}

impl EmailConfig {
  pub fn new(from: &str, to: &str, subject: &str) -> Self {
    Self {
      from: from.to_string(),
      to: vec![to.to_string()],
      subject: subject.to_string(),
      body_text: None,
      body_html: None,
      reply_to: None,
      auth: None,
      headers: HashMap::new(),
    }
  }

  pub fn with_text(mut self, text: &str) -> Self {
    self.body_text = Some(text.to_string());
    self
  }

  pub fn with_html(mut self, html: &str) -> Self {
    self.body_html = Some(html.to_string());
    self
  }

  pub fn with_auth(mut self, auth: SmtpAuth) -> Self {
    self.auth = Some(auth);
    self
  }

  pub fn with_reply_to(mut self, reply_to: &str) -> Self {
    self.reply_to = Some(reply_to.to_string());
    self
  }

  pub fn add_recipient(mut self, to: &str) -> Self {
    self.to.push(to.to_string());
    self
  }
}

/// SMTP authentication credentials
pub struct SmtpAuth {
  pub username: String,
  pub password: String,
  pub method: AuthMethod,
}

impl SmtpAuth {
  pub fn plain(username: &str, password: &str) -> Self {
    Self {
      username: username.to_string(),
      password: password.to_string(),
      method: AuthMethod::Plain,
    }
  }

  pub fn login(username: &str, password: &str) -> Self {
    Self {
      username: username.to_string(),
      password: password.to_string(),
      method: AuthMethod::Login,
    }
  }
}

/// SMTP authentication method
pub enum AuthMethod {
  Plain,
  Login,
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

  /// Send an email through the SMTP server.
  ///
  /// Full SMTP transaction: EHLO -> AUTH (optional) -> MAIL FROM -> RCPT TO -> DATA -> QUIT
  pub fn send_email(&self, config: &EmailConfig) -> Result<(), String> {
    if config.to.is_empty() {
      return Err("No recipients specified".to_string());
    }

    let stream = TcpStream::connect(&self.server_addr).map_err(|e| {
      format!(
        "Failed to connect to SMTP server {}: {}",
        self.server_addr, e
      )
    })?;
    stream
      .set_read_timeout(Some(self.timeout))
      .map_err(|e| e.to_string())?;
    stream
      .set_write_timeout(Some(self.timeout))
      .map_err(|e| e.to_string())?;

    let read_stream = stream
      .try_clone()
      .map_err(|e| format!("Failed to clone stream: {}", e))?;
    let mut writer = stream;
    let mut reader = BufReader::new(read_stream);
    let mut line = String::new();

    // 1. Read greeting (220)
    self.read_line(&mut reader, &mut line)?;
    if !line.starts_with("220") {
      return Err(format!("Unexpected SMTP greeting: {}", line.trim()));
    }

    // 2. EHLO - read multiline response to get capabilities
    self.write_line(&mut writer, b"EHLO redblue.local")?;
    let _caps = self.read_multiline(&mut reader, &mut line)?;

    // 3. AUTH if credentials provided
    if let Some(auth) = &config.auth {
      match auth.method {
        AuthMethod::Plain => {
          self.auth_plain(&mut reader, &mut writer, &mut line, auth)?;
        }
        AuthMethod::Login => {
          self.auth_login(&mut reader, &mut writer, &mut line, auth)?;
        }
      }
    }

    // 4. MAIL FROM
    let mail_from = format!("MAIL FROM:<{}>", config.from);
    self.write_line(&mut writer, mail_from.as_bytes())?;
    self.read_line(&mut reader, &mut line)?;
    if !line.starts_with("250") {
      return Err(format!("MAIL FROM rejected: {}", line.trim()));
    }

    // 5. RCPT TO for each recipient
    for recipient in &config.to {
      let rcpt_to = format!("RCPT TO:<{}>", recipient);
      self.write_line(&mut writer, rcpt_to.as_bytes())?;
      self.read_line(&mut reader, &mut line)?;
      if !line.starts_with("250") && !line.starts_with("251") {
        return Err(format!("RCPT TO <{}> rejected: {}", recipient, line.trim()));
      }
    }

    // 6. DATA
    self.write_line(&mut writer, b"DATA")?;
    self.read_line(&mut reader, &mut line)?;
    if !line.starts_with("354") {
      return Err(format!("DATA command rejected: {}", line.trim()));
    }

    // 7. Send message body
    let message = Self::build_mime_message(config);
    writer
      .write_all(message.as_bytes())
      .map_err(|e| format!("Failed to write message body: {}", e))?;

    // End with <CRLF>.<CRLF>
    writer
      .write_all(b"\r\n.\r\n")
      .map_err(|e| format!("Failed to write message terminator: {}", e))?;

    self.read_line(&mut reader, &mut line)?;
    if !line.starts_with("250") {
      return Err(format!("Message rejected: {}", line.trim()));
    }

    // 8. QUIT
    self.write_line(&mut writer, b"QUIT")?;
    let _ = self.read_line(&mut reader, &mut line);

    Ok(())
  }

  /// Verifies if an email address exists by interacting with the SMTP server.
  /// Does not actually send an email.
  pub fn verify_email(&self, email: &str) -> Result<bool, String> {
    let stream = TcpStream::connect(&self.server_addr).map_err(|e| {
      format!(
        "Failed to connect to SMTP server {}: {}",
        self.server_addr, e
      )
    })?;
    stream
      .set_read_timeout(Some(self.timeout))
      .map_err(|e| e.to_string())?;
    stream
      .set_write_timeout(Some(self.timeout))
      .map_err(|e| e.to_string())?;

    let read_stream = stream
      .try_clone()
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

    let exists = line.starts_with("250") || line.starts_with("251");

    // 5. Quit
    self.write_line(&mut writer, b"QUIT")?;
    self.read_line(&mut reader, &mut line)?;

    Ok(exists)
  }

  /// AUTH PLAIN: sends base64(\0username\0password)
  fn auth_plain(
    &self,
    reader: &mut BufReader<TcpStream>,
    writer: &mut TcpStream,
    line: &mut String,
    auth: &SmtpAuth,
  ) -> Result<(), String> {
    // AUTH PLAIN credentials = base64(NUL + username + NUL + password)
    let mut credentials = Vec::new();
    credentials.push(0u8);
    credentials.extend_from_slice(auth.username.as_bytes());
    credentials.push(0u8);
    credentials.extend_from_slice(auth.password.as_bytes());

    let encoded = base64_encode(&credentials);
    let cmd = format!("AUTH PLAIN {}", encoded);
    self.write_line(writer, cmd.as_bytes())?;
    self.read_line(reader, line)?;
    if !line.starts_with("235") {
      return Err(format!("AUTH PLAIN failed: {}", line.trim()));
    }
    Ok(())
  }

  /// AUTH LOGIN: two-step base64 exchange
  fn auth_login(
    &self,
    reader: &mut BufReader<TcpStream>,
    writer: &mut TcpStream,
    line: &mut String,
    auth: &SmtpAuth,
  ) -> Result<(), String> {
    self.write_line(writer, b"AUTH LOGIN")?;
    self.read_line(reader, line)?;
    if !line.starts_with("334") {
      return Err(format!("AUTH LOGIN failed: {}", line.trim()));
    }

    // Send username (base64)
    let user_b64 = base64_encode(auth.username.as_bytes());
    self.write_line(writer, user_b64.as_bytes())?;
    self.read_line(reader, line)?;
    if !line.starts_with("334") {
      return Err(format!("AUTH LOGIN username rejected: {}", line.trim()));
    }

    // Send password (base64)
    let pass_b64 = base64_encode(auth.password.as_bytes());
    self.write_line(writer, pass_b64.as_bytes())?;
    self.read_line(reader, line)?;
    if !line.starts_with("235") {
      return Err(format!("AUTH LOGIN failed: {}", line.trim()));
    }
    Ok(())
  }

  /// Read multiline SMTP response (e.g., EHLO capabilities).
  /// Continues reading while response code is followed by '-'.
  /// Returns the list of capability lines.
  fn read_multiline(
    &self,
    reader: &mut BufReader<TcpStream>,
    line: &mut String,
  ) -> Result<Vec<String>, String> {
    let mut capabilities = Vec::new();
    loop {
      self.read_line(reader, line)?;
      let trimmed = line.trim().to_string();

      // Check if this is the last line (code followed by space, not hyphen)
      if trimmed.len() >= 4 {
        let separator = trimmed.as_bytes()[3];
        if separator == b'-' {
          // Continuation line: "250-CAPABILITY"
          capabilities.push(trimmed[4..].to_string());
        } else {
          // Final line: "250 CAPABILITY" or "250 OK"
          if trimmed.len() > 4 {
            capabilities.push(trimmed[4..].to_string());
          }
          if !trimmed.starts_with("250") {
            return Err(format!("EHLO failed: {}", trimmed));
          }
          break;
        }
      } else {
        return Err(format!("Invalid SMTP response: {}", trimmed));
      }
    }
    Ok(capabilities)
  }

  /// Build a MIME-compliant email message from EmailConfig.
  fn build_mime_message(config: &EmailConfig) -> String {
    let mut msg = String::new();

    // Generate a message ID
    let timestamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos();
    let msg_id = format!("<{}.{}@redblue.local>", timestamp, std::process::id());

    // RFC 2822 date
    let date = Self::rfc2822_date();

    // Required headers
    msg.push_str(&format!("From: {}\r\n", config.from));
    msg.push_str(&format!("To: {}\r\n", config.to.join(", ")));
    msg.push_str(&format!("Subject: {}\r\n", config.subject));
    msg.push_str(&format!("Date: {}\r\n", date));
    msg.push_str(&format!("Message-ID: {}\r\n", msg_id));
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str("X-Mailer: redblue\r\n");

    if let Some(reply_to) = &config.reply_to {
      msg.push_str(&format!("Reply-To: {}\r\n", reply_to));
    }

    // Custom headers
    for (key, value) in &config.headers {
      msg.push_str(&format!("{}: {}\r\n", key, value));
    }

    // Body - choose format based on what's provided
    match (&config.body_text, &config.body_html) {
      (Some(text), Some(html)) => {
        // Multipart/alternative
        let boundary = format!("----=_Part_{}", timestamp % 999_999_999);
        msg.push_str(&format!(
          "Content-Type: multipart/alternative; boundary=\"{}\"\r\n",
          boundary
        ));
        msg.push_str("\r\n");
        // Text part
        msg.push_str(&format!("--{}\r\n", boundary));
        msg.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
        msg.push_str("Content-Transfer-Encoding: 7bit\r\n");
        msg.push_str("\r\n");
        msg.push_str(&Self::dot_stuff(text));
        msg.push_str("\r\n");
        // HTML part
        msg.push_str(&format!("--{}\r\n", boundary));
        msg.push_str("Content-Type: text/html; charset=UTF-8\r\n");
        msg.push_str("Content-Transfer-Encoding: 7bit\r\n");
        msg.push_str("\r\n");
        msg.push_str(&Self::dot_stuff(html));
        msg.push_str("\r\n");
        // Closing boundary
        msg.push_str(&format!("--{}--\r\n", boundary));
      }
      (None, Some(html)) => {
        msg.push_str("Content-Type: text/html; charset=UTF-8\r\n");
        msg.push_str("Content-Transfer-Encoding: 7bit\r\n");
        msg.push_str("\r\n");
        msg.push_str(&Self::dot_stuff(html));
      }
      (Some(text), None) => {
        msg.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
        msg.push_str("Content-Transfer-Encoding: 7bit\r\n");
        msg.push_str("\r\n");
        msg.push_str(&Self::dot_stuff(text));
      }
      (None, None) => {
        msg.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
        msg.push_str("\r\n");
      }
    }

    msg
  }

  /// Dot-stuffing: lines starting with '.' must be escaped with an extra '.'
  /// (RFC 5321 Section 4.5.2)
  fn dot_stuff(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for line in text.split('\n') {
      let line = line.trim_end_matches('\r');
      if line.starts_with('.') {
        result.push('.');
      }
      result.push_str(line);
      result.push_str("\r\n");
    }
    result
  }

  /// Generate RFC 2822 formatted date string
  fn rfc2822_date() -> String {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs();

    // Calculate date components from unix timestamp
    let days = (now / 86400) as i64;
    let time_of_day = now % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Day of week: Jan 1 1970 was Thursday (4)
    let dow = ((days + 4) % 7) as usize;
    let dow_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    // Calculate year/month/day from days since epoch
    let (year, month, day) = Self::days_to_ymd(days);
    let month_names = [
      "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    format!(
      "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
      dow_names[dow],
      day,
      month_names[(month - 1) as usize],
      year,
      hours,
      minutes,
      seconds
    )
  }

  /// Convert days since epoch to (year, month, day)
  fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
  }

  fn read_line(&self, reader: &mut BufReader<TcpStream>, line: &mut String) -> Result<(), String> {
    line.clear();
    reader
      .read_line(line)
      .map_err(|e| format!("Failed to read from SMTP stream: {}", e))?;
    Ok(())
  }

  fn write_line(&self, stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    stream
      .write_all(data)
      .map_err(|e| format!("Failed to write to SMTP stream: {}", e))?;
    stream
      .write_all(b"\r\n")
      .map_err(|e| format!("Failed to write to SMTP stream: {}", e))?;
    Ok(())
  }
}
