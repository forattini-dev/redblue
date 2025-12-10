//! HTTP/2 Live Test Example
//!
//! Tests HTTP/2 implementation against real servers.

use redblue::protocols::http2::Http2Client;

fn main() {
    println!("=== HTTP/2 Live Test ===\n");

    // Test 1: Google.com
    println!("Test 1: Connecting to google.com:443...");
    test_http2("google.com", 443, "/");

    println!("\n{}\n", "=".repeat(60));

    // Test 2: Cloudflare
    println!("Test 2: Connecting to cloudflare.com:443...");
    test_http2("cloudflare.com", 443, "/");

    println!("\n{}\n", "=".repeat(60));

    // Test 3: GitHub
    println!("Test 3: Connecting to github.com:443...");
    test_http2("github.com", 443, "/");
}

fn test_http2(host: &str, port: u16, path: &str) {
    match Http2Client::connect(host, port) {
        Ok(mut client) => {
            println!("  ✅ Connected successfully");
            println!("  ✅ TLS handshake complete");
            println!("  ✅ ALPN negotiated: h2\n");

            println!("  Sending GET request for {}...", path);
            match client.get(path, host) {
                Ok(response) => {
                    println!("  ✅ Request successful!\n");
                    println!("  Status: {}", response.status);
                    println!("  Headers: {} received", response.headers.len());
                    println!("  Body size: {} bytes\n", response.body.len());

                    println!("  Sample headers:");
                    for header in response.headers.iter().take(5) {
                        println!("    {}: {}", header.name, header.value);
                    }

                    if !response.body.is_empty() && response.body.len() < 500 {
                        println!("\n  Body preview:");
                        if let Ok(body_str) = String::from_utf8(response.body.clone()) {
                            println!(
                                "    {}",
                                body_str.lines().take(10).collect::<Vec<_>>().join("\n    ")
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("  ❌ Request failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("  ❌ Connection failed: {}", e);
        }
    }
}
