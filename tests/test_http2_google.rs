// Simple HTTP/2 test against Google
// Run with: cargo test --test test_http2_google -- --nocapture

#[test]
#[ignore] // Run explicitly: cargo test test_http2_live -- --ignored --nocapture
fn test_http2_live() {
    println!("\n=== HTTP/2 Live Test: google.com ===\n");

    // Import types
    use redblue::protocols::http2::Http2Client;

    println!("1. Connecting to google.com:443...");
    let mut client = match Http2Client::connect("google.com", 443) {
        Ok(c) => {
            println!("   ✅ Connected successfully");
            println!("   ✅ TLS handshake complete");
            println!("   ✅ ALPN negotiated: h2\n");
            c
        }
        Err(e) => {
            println!("   ❌ Connection failed: {}", e);
            panic!("Connection failed");
        }
    };

    println!("2. Sending HTTP/2 GET request for /...");
    let response = match client.get("/", "google.com") {
        Ok(r) => {
            println!("   ✅ Request successful");
            r
        }
        Err(e) => {
            println!("   ❌ Request failed: {}", e);
            panic!("Request failed");
        }
    };

    println!("\n3. Response Details:");
    println!("   Status: {}", response.status);
    println!("   Headers: {} headers received", response.headers.len());
    println!("   Body size: {} bytes", response.body.len());

    // Show some headers
    println!("\n4. Sample Headers:");
    for header in response.headers.iter().take(5) {
        println!("   {}: {}", header.name, header.value);
    }

    // Verify response
    assert_eq!(response.status, 200, "Expected 200 OK");
    assert!(!response.body.is_empty(), "Body should not be empty");

    println!("\n✅ HTTP/2 Test PASSED!\n");
}
