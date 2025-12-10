/// Chrome DevTools Protocol Client
///
/// Communicates with Chrome/Chromium via DevTools Protocol
/// for headless screenshot capture

use std::net::TcpStream;
use std::io::{Read, Write, BufRead, BufReader};
use std::time::Duration;
use std::process::{Command, Child, Stdio};
use std::thread;
use std::sync::atomic::{AtomicU32, Ordering};

/// CDP client for browser communication
pub struct CdpClient {
    /// WebSocket connection to Chrome
    stream: Option<TcpStream>,
    /// Chrome process handle
    chrome_process: Option<Child>,
    /// Debug port
    port: u16,
    /// Message ID counter
    message_id: AtomicU32,
}

/// CDP message
#[derive(Debug)]
pub struct CdpMessage {
    pub id: u32,
    pub method: String,
    pub params: String,
}

/// CDP response
#[derive(Debug)]
pub struct CdpResponse {
    pub id: u32,
    pub result: Option<String>,
    pub error: Option<String>,
}

impl CdpClient {
    pub fn new(port: u16) -> Self {
        Self {
            stream: None,
            chrome_process: None,
            port,
            message_id: AtomicU32::new(1),
        }
    }

    /// Launch Chrome in headless mode
    pub fn launch_chrome(&mut self, chrome_path: Option<&str>) -> Result<(), String> {
        let chrome_binary = chrome_path
            .map(String::from)
            .or_else(|| self.find_chrome())
            .ok_or_else(|| "Chrome/Chromium not found".to_string())?;

        let args = vec![
            format!("--remote-debugging-port={}", self.port),
            "--headless".to_string(),
            "--disable-gpu".to_string(),
            "--no-sandbox".to_string(),
            "--disable-dev-shm-usage".to_string(),
            "--disable-background-networking".to_string(),
            "--disable-default-apps".to_string(),
            "--disable-extensions".to_string(),
            "--disable-sync".to_string(),
            "--disable-translate".to_string(),
            "--metrics-recording-only".to_string(),
            "--mute-audio".to_string(),
            "--no-first-run".to_string(),
            "--safebrowsing-disable-auto-update".to_string(),
            "--ignore-certificate-errors".to_string(),
            "--allow-running-insecure-content".to_string(),
        ];

        let process = Command::new(&chrome_binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to launch Chrome: {}", e))?;

        self.chrome_process = Some(process);

        // Wait for Chrome to start
        thread::sleep(Duration::from_secs(2));

        Ok(())
    }

    /// Find Chrome binary
    fn find_chrome(&self) -> Option<String> {
        let candidates = [
            // Linux
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/snap/bin/chromium",
            // macOS
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            // Windows (WSL)
            "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
            "/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe",
        ];

        for candidate in candidates {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate.to_string());
            }
        }

        // Try PATH
        if Command::new("which")
            .arg("google-chrome")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some("google-chrome".to_string());
        }

        if Command::new("which")
            .arg("chromium")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some("chromium".to_string());
        }

        None
    }

    /// Connect to Chrome DevTools
    pub fn connect(&mut self) -> Result<(), String> {
        // First, get WebSocket URL from HTTP endpoint
        let ws_url = self.get_websocket_url()?;

        // Parse WebSocket URL
        let (host, port, path) = self.parse_ws_url(&ws_url)?;

        // Connect via TCP
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("Invalid address: {}", e))?,
            Duration::from_secs(5),
        ).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        // Perform WebSocket handshake
        let mut stream = self.websocket_handshake(stream, &host, &path)?;

        self.stream = Some(stream);

        Ok(())
    }

    /// Get WebSocket URL from DevTools HTTP endpoint
    fn get_websocket_url(&self) -> Result<String, String> {
        let addr = format!("127.0.0.1:{}", self.port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("Invalid address: {}", e))?,
            Duration::from_secs(5),
        ).map_err(|e| format!("Failed to connect to DevTools: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let request = format!(
            "GET /json/version HTTP/1.1\r\n\
             Host: 127.0.0.1:{}\r\n\
             Connection: close\r\n\
             \r\n",
            self.port
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let response_str = String::from_utf8_lossy(&response);

        // Find webSocketDebuggerUrl in JSON
        if let Some(start) = response_str.find("\"webSocketDebuggerUrl\":") {
            let after = &response_str[start + 24..];
            if let Some(quote_start) = after.find('"') {
                let value_start = quote_start + 1;
                if let Some(quote_end) = after[value_start..].find('"') {
                    return Ok(after[value_start..value_start + quote_end].to_string());
                }
            }
        }

        Err("Failed to find WebSocket URL".to_string())
    }

    /// Parse WebSocket URL
    fn parse_ws_url(&self, url: &str) -> Result<(String, u16, String), String> {
        let url = url.trim_start_matches("ws://");
        let (host_port, path) = match url.find('/') {
            Some(pos) => (&url[..pos], &url[pos..]),
            None => (url, "/"),
        };

        let (host, port) = match host_port.find(':') {
            Some(pos) => (&host_port[..pos], host_port[pos + 1..].parse().unwrap_or(9222)),
            None => (host_port, 9222),
        };

        Ok((host.to_string(), port, path.to_string()))
    }

    /// Perform WebSocket handshake
    fn websocket_handshake(&self, mut stream: TcpStream, host: &str, path: &str) -> Result<TcpStream, String> {
        // Generate WebSocket key
        let key = self.generate_ws_key();

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            path, host, key
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        // Read response
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut response_line = String::new();
        reader.read_line(&mut response_line)
            .map_err(|e| format!("Failed to read handshake response: {}", e))?;

        if !response_line.contains("101") {
            return Err(format!("WebSocket handshake failed: {}", response_line));
        }

        // Read remaining headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok();
            if line.trim().is_empty() {
                break;
            }
        }

        Ok(stream)
    }

    /// Generate WebSocket key
    fn generate_ws_key(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Simple base64-like encoding for the key
        let bytes: [u8; 16] = [
            (nanos & 0xFF) as u8,
            ((nanos >> 8) & 0xFF) as u8,
            ((nanos >> 16) & 0xFF) as u8,
            ((nanos >> 24) & 0xFF) as u8,
            ((nanos >> 32) & 0xFF) as u8,
            ((nanos >> 40) & 0xFF) as u8,
            ((nanos >> 48) & 0xFF) as u8,
            ((nanos >> 56) & 0xFF) as u8,
            (nanos & 0xFF) as u8,
            ((nanos >> 8) & 0xFF) as u8,
            ((nanos >> 16) & 0xFF) as u8,
            ((nanos >> 24) & 0xFF) as u8,
            ((nanos >> 32) & 0xFF) as u8,
            ((nanos >> 40) & 0xFF) as u8,
            ((nanos >> 48) & 0xFF) as u8,
            ((nanos >> 56) & 0xFF) as u8,
        ];

        base64_encode(&bytes)
    }

    /// Send CDP command
    pub fn send(&mut self, method: &str, params: &str) -> Result<u32, String> {
        // Check connection first
        if self.stream.is_none() {
            return Err("Not connected".to_string());
        }

        let id = self.message_id.fetch_add(1, Ordering::SeqCst);

        let message = format!(
            r#"{{"id":{},"method":"{}","params":{}}}"#,
            id, method, params
        );

        // Create frame before borrowing stream mutably
        let frame = self.create_ws_frame(message.as_bytes());

        // Now borrow stream mutably
        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&frame)
            .map_err(|e| format!("Failed to send message: {}", e))?;

        Ok(id)
    }

    /// Receive CDP response
    pub fn receive(&mut self) -> Result<CdpResponse, String> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| "Not connected".to_string())?;

        // Read WebSocket frame
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)
            .map_err(|e| format!("Failed to read frame header: {}", e))?;

        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as u64;

        // Extended payload length
        if payload_len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).ok();
            payload_len = u16::from_be_bytes(ext) as u64;
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).ok();
            payload_len = u64::from_be_bytes(ext);
        }

        // Read mask if present
        let mask = if masked {
            let mut m = [0u8; 4];
            stream.read_exact(&mut m).ok();
            Some(m)
        } else {
            None
        };

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        stream.read_exact(&mut payload)
            .map_err(|e| format!("Failed to read payload: {}", e))?;

        // Unmask if needed
        if let Some(mask) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }

        let json = String::from_utf8_lossy(&payload).to_string();

        // Parse response
        self.parse_response(&json)
    }

    /// Create WebSocket frame
    fn create_ws_frame(&self, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();

        // FIN + Text opcode
        frame.push(0x81);

        // Payload length + mask bit
        let len = data.len();
        if len <= 125 {
            frame.push((len as u8) | 0x80);
        } else if len <= 65535 {
            frame.push(126 | 0x80);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127 | 0x80);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        // Masking key
        let mask = [0x12, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask);

        // Masked payload
        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        frame
    }

    /// Parse CDP response
    fn parse_response(&self, json: &str) -> Result<CdpResponse, String> {
        let mut response = CdpResponse {
            id: 0,
            result: None,
            error: None,
        };

        // Extract id
        if let Some(id_pos) = json.find("\"id\":") {
            let after = &json[id_pos + 5..];
            let num_end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
            response.id = after[..num_end].parse().unwrap_or(0);
        }

        // Check for error
        if json.contains("\"error\":") {
            if let Some(err_pos) = json.find("\"message\":") {
                let after = &json[err_pos + 11..];
                if let Some(end) = after.find('"') {
                    response.error = Some(after[..end].to_string());
                }
            }
        } else if json.contains("\"result\":") {
            // Extract result object
            if let Some(start) = json.find("\"result\":") {
                let after = &json[start + 9..];
                response.result = Some(after.to_string());
            }
        }

        Ok(response)
    }

    /// Navigate to URL
    pub fn navigate(&mut self, url: &str) -> Result<(), String> {
        let params = format!(r#"{{"url":"{}"}}"#, url);
        self.send("Page.navigate", &params)?;
        self.receive()?;

        // Wait for page load
        self.wait_for_load()?;

        Ok(())
    }

    /// Wait for page load
    fn wait_for_load(&mut self) -> Result<(), String> {
        // Enable Page domain
        self.send("Page.enable", "{}")?;
        self.receive()?;

        // Wait for loadEventFired
        let timeout = std::time::Instant::now();
        loop {
            if timeout.elapsed() > Duration::from_secs(30) {
                break;
            }

            if let Ok(response) = self.receive() {
                if let Some(result) = &response.result {
                    if result.contains("loadEventFired") {
                        break;
                    }
                }
            }

            thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }

    /// Take screenshot
    pub fn capture_screenshot(&mut self, full_page: bool, quality: u8) -> Result<Vec<u8>, String> {
        let params = if full_page {
            format!(r#"{{"format":"jpeg","quality":{},"captureBeyondViewport":true}}"#, quality)
        } else {
            format!(r#"{{"format":"jpeg","quality":{}}}"#, quality)
        };

        self.send("Page.captureScreenshot", &params)?;

        let response = self.receive()?;

        if let Some(error) = response.error {
            return Err(error);
        }

        // Extract base64 data from result
        if let Some(result) = response.result {
            if let Some(start) = result.find("\"data\":\"") {
                let after = &result[start + 8..];
                if let Some(end) = after.find('"') {
                    let base64_data = &after[..end];
                    return base64_decode(base64_data);
                }
            }
        }

        Err("Failed to extract screenshot data".to_string())
    }

    /// Get page title
    pub fn get_title(&mut self) -> Result<String, String> {
        let params = r#"{"expression":"document.title"}"#;
        self.send("Runtime.evaluate", params)?;

        let response = self.receive()?;

        if let Some(result) = response.result {
            if let Some(start) = result.find("\"value\":\"") {
                let after = &result[start + 9..];
                if let Some(end) = after.find('"') {
                    return Ok(after[..end].to_string());
                }
            }
        }

        Ok(String::new())
    }

    /// Set viewport size
    pub fn set_viewport(&mut self, width: u32, height: u32) -> Result<(), String> {
        let params = format!(
            r#"{{"width":{},"height":{},"deviceScaleFactor":1,"mobile":false}}"#,
            width, height
        );

        self.send("Emulation.setDeviceMetricsOverride", &params)?;
        self.receive()?;

        Ok(())
    }

    /// Set user agent
    pub fn set_user_agent(&mut self, user_agent: &str) -> Result<(), String> {
        let params = format!(r#"{{"userAgent":"{}"}}"#, user_agent);
        self.send("Emulation.setUserAgentOverride", &params)?;
        self.receive()?;

        Ok(())
    }

    /// Close browser
    pub fn close(&mut self) {
        // Try graceful shutdown
        if let Some(ref mut stream) = self.stream {
            let _ = self.send("Browser.close", "{}");
        }

        // Kill process if still running
        if let Some(ref mut process) = self.chrome_process {
            let _ = process.kill();
        }

        self.stream = None;
        self.chrome_process = None;
    }
}

impl Drop for CdpClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = data.get(i + 1).copied().unwrap_or(0);
        let b2 = data.get(i + 2).copied().unwrap_or(0);

        result.push(ALPHABET[(b0 >> 2) as usize] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4 | (b1 >> 4)) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0F) << 2 | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Base64 decode
fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let data = data.trim_end_matches('=');
    let mut result = Vec::new();

    let mut buffer = 0u32;
    let mut bits = 0;

    for c in data.chars() {
        let value = if c as usize >= 128 {
            return Err("Invalid base64 character".to_string());
        } else {
            DECODE[c as usize]
        };

        if value < 0 {
            continue; // Skip whitespace
        }

        buffer = (buffer << 6) | (value as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(result)
}
