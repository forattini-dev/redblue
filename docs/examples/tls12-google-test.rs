/// Test TLS 1.2 connection to google.com
///
/// This example tests our pure Rust TLS 1.2 implementation
/// by connecting to Google and fetching the homepage.

use redblue::modules::network::tls::{TlsConfig, TlsStream, TlsVersion};
use std::io::{Read, Write};

fn main() -> Result<(), String> {
    println!("🔐 Testing TLS 1.2 connection to google.com...\n");

    // Connect to Google using TLS 1.2
    println!("⏳ Establishing TCP connection...");
    let config = TlsConfig::new()
        .with_version(TlsVersion::Tls12)
        .with_verify(false); // Skip cert verification for testing

    println!("🤝 Starting TLS 1.2 handshake...");
    let mut tls_stream = TlsStream::connect("google.com", 443, config)
        .map_err(|e| format!("TLS 1.2 connection failed: {}", e))?;

    println!("✅ TLS 1.2 handshake completed!\n");

    // Send HTTP GET request
    println!("📤 Sending HTTP GET request...");
    let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Failed to send request: {}", e))?;

    // Read response
    println!("📥 Reading response...\n");
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        match tls_stream.read(&mut buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("Read error: {}", e)),
        }

        // Break after reading response headers (for demo purposes)
        if response.len() > 1024 {
            break;
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

    println!("\n✅ TLS 1.2 test completed successfully!");
    println!("─────────────────────────────────────");
    println!("📊 Summary:");
    println!("  • Protocol: TLS 1.2");
    println!("  • Server: google.com:443");
    println!("  • Response size: {} bytes", response.len());
    println!("  • Cipher suite: ECDHE-RSA-AES128-GCM-SHA256 (likely)");

    Ok(())
}
