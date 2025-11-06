/// Test TLS 1.3 connection to google.com
///
/// This example tests our pure Rust TLS 1.3 implementation
/// by connecting to Google and fetching the homepage.

use redblue::protocols::tls13::Tls13Client;
use std::io::{Read, Write};

fn main() -> Result<(), String> {
    println!("🔐 Testing TLS 1.3 connection to google.com...\n");

    // Connect to Google using TLS 1.3
    println!("⏳ Establishing TCP connection...");
    println!("🤝 Starting TLS 1.3 handshake...");

    let mut client = Tls13Client::new("google.com", 443)?;
    client.handshake()?;

    println!("✅ TLS 1.3 handshake completed!");

    // Show cipher suite
    if let Some(cipher) = client.cipher_suite() {
        println!("🔒 Negotiated cipher: {:?}", cipher);
    }
    println!();

    // Send HTTP GET request
    println!("📤 Sending HTTP GET request...");
    let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    client
        .write_all(request.as_bytes())
        .map_err(|e| format!("Failed to send request: {}", e))?;

    // Read response
    println!("📥 Reading response...\n");
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        match client.read(&mut buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                response.extend_from_slice(&buffer[..n]);

                // Break after reading response headers (for demo purposes)
                if response.len() > 1024 {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionAborted => break,
            Err(e) => return Err(format!("Read error: {}", e)),
        }
    }

    // Parse and display response
    let response_str = String::from_utf8_lossy(&response);
    let lines: Vec<&str> = response_str.lines().collect();

    println!("📄 HTTP Response:");
    println!("─────────────────────────────────────");

    // Show status line
    if let Some(status) = lines.first() {
        println!("Status: {}", status);
    }

    // Show headers
    println!("\n📋 Headers:");
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        println!("  {}", line);
    }

    // Show body preview
    println!("\n📝 Body preview:");
    let body_start = response_str.find("\r\n\r\n").unwrap_or(0) + 4;
    let body = &response_str[body_start..];
    let preview = if body.len() > 200 {
        format!("{}...", &body[..200])
    } else {
        body.to_string()
    };
    println!("{}", preview);

    println!("\n✅ TLS 1.3 test completed successfully!");
    println!("─────────────────────────────────────");
    println!("📊 Summary:");
    println!("  • Protocol: TLS 1.3");
    println!("  • Server: google.com:443");
    println!("  • Response size: {} bytes", response.len());

    if let Some(cipher) = client.cipher_suite() {
        println!("  • Cipher suite: {:?}", cipher);
    }

    Ok(())
}
