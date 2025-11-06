use redblue::modules::network::tls::{TlsConfig, TlsStream, TlsVersion};
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = "tls-v1-0.badssl.com";
    let port = 1010;

    let config = TlsConfig::new()
        .with_version(TlsVersion::Tls10)
        .with_verify(false)
        .with_debug(false);

    println!("Connecting to {}:{} using TLS 1.0 …", host, port);

    let mut stream = TlsStream::connect(host, port, config)
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    println!("Handshake completed. Sending HTTP request…");

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: redblue-probe\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    println!("Received response (truncated to 512 bytes):");
    let preview: String = response.chars().take(512).collect();
    println!("{}\n", preview);

    Ok(())
}
