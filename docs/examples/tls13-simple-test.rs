/// Simple TLS 1.3 test to verify handshake flow
use redblue::protocols::tls13::Tls13Client;

fn main() {
    println!("Testing TLS 1.3 with cloudflare.com (often more permissive)...\n");

    let mut client = match Tls13Client::new("1.1.1.1", 443) {
        Ok(c) => {
            println!("✅ Connected to 1.1.1.1:443");
            c
        }
        Err(e) => {
            eprintln!("❌ Connection failed: {}", e);
            std::process::exit(1);
        }
    };

    match client.handshake() {
        Ok(_) => {
            println!("✅ TLS 1.3 handshake SUCCESS!\n");

            match client.send_http_get("/") {
                Ok(response) => {
                    println!("✅ HTTP GET successful");
                    if let Some(end) = response.find("\r\n") {
                        println!("Status: {}", &response[..end]);
                    }
                    println!("\n🎉 TLS 1.3 WORKS!");
                }
                Err(e) => {
                    eprintln!("HTTP failed: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Handshake failed: {}", e);
            std::process::exit(1);
        }
    }
}
