/// Test TLS 1.3 client against local OpenSSL server
///
/// This connects to a local OpenSSL server (localhost:4433) to test our
/// TLS 1.3 implementation in a controlled environment.
///
/// Start the server first:
///   ./scripts/setup-tls13-server.sh
///
/// Then run this client:
///   cargo run --example tls13-localhost-test

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 TLS 1.3 Localhost Test");
    println!("========================\n");

    println!("📡 Connecting to localhost:4433...");

    // Import TLS 1.3 client
    use redblue::protocols::tls13::Tls13Client;

    println!("🤝 Starting TLS 1.3 handshake...");
    println!("   Server: localhost");
    println!("   Port: 4433");
    println!("   Cipher: TLS_AES_128_GCM_SHA256 (0x1301)\n");

    // Create TLS client - this establishes TCP connection
    let mut tls_client = Tls13Client::new("localhost", 4433)?;
    println!("✓ TCP connection established\n");

    // Perform TLS 1.3 handshake
    println!("🔑 Performing TLS 1.3 handshake...");
    match tls_client.handshake() {
        Ok(_) => {
            println!("✅ HANDSHAKE COMPLETED SUCCESSFULLY!");
            println!("\n🎉 TLS 1.3 connection established with localhost!\n");

            // Try to send HTTP GET request
            println!("📤 Sending HTTP GET request...");
            match tls_client.send_http_get("/") {
                Ok(response) => {
                    println!("✅ Response received:\n");
                    println!("{}", response);
                }
                Err(e) => {
                    println!("⚠️  Could not get HTTP response: {}", e);
                    println!("   (Handshake worked, but HTTP failed)");
                }
            }
        }
        Err(e) => {
            println!("❌ HANDSHAKE FAILED!");
            println!("   Error: {}\n", e);
            println!("🔍 This tells us WHERE the problem is:");
            println!("   - If error mentions 'Authentication tag': decryption problem");
            println!("   - If error mentions 'Unexpected message': protocol problem");
            println!("   - If error mentions 'Connection': network problem");
            println!("\n📊 Check the server output (Terminal 1) for detailed protocol messages.\n");
            return Err(e.into());
        }
    }

    Ok(())
}
