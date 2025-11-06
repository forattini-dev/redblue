/// Quick test for TLS 1.2 and 1.3 connections to google.com

extern crate redblue;

use std::io::{Read, Write};

fn main() {
    println!("========================================");
    println!("Testing TLS Implementations");
    println!("========================================\n");

    // Test TLS 1.3
    println!("🔐 Testing TLS 1.3 to google.com:443");
    println!("────────────────────────────────────────");
    match test_tls13() {
        Ok(_) => println!("✅ TLS 1.3 test PASSED!\n"),
        Err(e) => {
            println!("❌ TLS 1.3 test FAILED: {}\n", e);
            std::process::exit(1);
        }
    }

    // Test TLS 1.2
    println!("🔐 Testing TLS 1.2 to google.com:443");
    println!("────────────────────────────────────────");
    match test_tls12() {
        Ok(_) => println!("✅ TLS 1.2 test PASSED!\n"),
        Err(e) => {
            println!("❌ TLS 1.2 test FAILED: {}\n", e);
            std::process::exit(1);
        }
    }

    println!("========================================");
    println!("✅ ALL TESTS PASSED!");
    println!("========================================");
}

fn test_tls13() -> Result<(), String> {
    use redblue::protocols::tls13::Tls13Client;

    println!("⏳ Connecting...");
    let mut client = Tls13Client::new("google.com", 443)?.with_debug(true);

    println!("🤝 Performing handshake...");
    client.handshake()?;

    if let Some(cipher) = client.cipher_suite() {
        println!("🔒 Cipher: {:?}", cipher);
    }

    println!("📤 Sending HTTP GET...");
    let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    client
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    println!("📥 Reading response...");
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];

    match client.read(&mut buffer) {
        Ok(n) if n > 0 => {
            response.extend_from_slice(&buffer[..n]);
            let resp_str = String::from_utf8_lossy(&response);
            if resp_str.contains("HTTP/1.1") || resp_str.contains("HTTP/1.0") {
                println!("📄 Got HTTP response: {} bytes", n);
                Ok(())
            } else {
                Err("Invalid HTTP response".to_string())
            }
        }
        Ok(_) => Err("Empty response".to_string()),
        Err(e) => Err(format!("Read failed: {}", e)),
    }
}

fn test_tls12() -> Result<(), String> {
    use redblue::modules::network::tls::{TlsConfig, TlsStream, TlsVersion};

    println!("⏳ Connecting...");
    let config = TlsConfig::new()
        .with_version(TlsVersion::Tls12)
        .with_verify(false);

    let mut stream = TlsStream::connect("google.com", 443, config)?;

    println!("🔒 TLS 1.2 handshake complete");

    println!("📤 Sending HTTP GET...");
    let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    println!("📥 Reading response...");
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];

    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            response.extend_from_slice(&buffer[..n]);
            let resp_str = String::from_utf8_lossy(&response);
            if resp_str.contains("HTTP/1.1") || resp_str.contains("HTTP/1.0") {
                println!("📄 Got HTTP response: {} bytes", n);
                Ok(())
            } else {
                Err("Invalid HTTP response".to_string())
            }
        }
        Ok(_) => Err("Empty response".to_string()),
        Err(e) => Err(format!("Read failed: {}", e)),
    }
}
