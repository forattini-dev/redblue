//! TLS/SSL Support (from scratch)
//!
//! Implements TLS 1.2/1.3 handshake and encryption for secure communication.
//! This is a SIMPLIFIED implementation for netcat usage - NOT a full TLS library.
//!
//! Features:
//! - TLS 1.2 client handshake
//! - TLS 1.3 client handshake
//! - Basic cipher suite support
//! - Certificate verification (optional)
//! - Encrypted data transfer
//!
//! Replaces: ncat --ssl
//!
//! Module structure:
//! - `types`: Basic types, enums, and configuration
//! - `extensions`: TLS extension building functions
//! - `cipher`: Cipher suite utilities
//! - `helpers`: Crypto and utility helpers
//! - `stream`: TlsStream implementation

pub mod cipher;
pub mod extensions;
pub mod helpers;
pub mod stream;
pub mod types;

// Re-export commonly used types
pub use cipher::*;
pub use extensions::*;
pub use helpers::{
    bigint_to_32_bytes, build_digest_info_sha256, build_digest_info_sha384,
    build_tls13_certificate_verify_input, clamp_x25519_scalar, compute_p256_shared_secret,
    compute_record_mac, constant_time_eq, generate_p256_keypair, generate_random_32,
    generate_random_bytes, parse_ecdsa_signature, rand_byte, scalar_is_less_than_order,
    scalar_is_zero, tls12_handshake_hash, wrap_handshake, wrap_tls_record,
};
pub use stream::TlsStream;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_tls_config() {
        let config = TlsConfig::new()
            .with_version(TlsVersion::Tls13)
            .with_verify(true)
            .with_timeout(Duration::from_secs(5));

        assert_eq!(config.version, TlsVersion::Tls13);
        assert!(config.verify_cert);
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_wrap_tls_record() {
        let data = vec![1, 2, 3, 4];
        let record = wrap_tls_record(ContentType::Handshake, &data, (0x03, 0x01));

        assert_eq!(record[0], ContentType::Handshake as u8);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x01);
        assert_eq!(record[3], 0x00); // Length high byte
        assert_eq!(record[4], 0x04); // Length low byte
        assert_eq!(&record[5..], &data[..]);
    }

    #[test]
    fn test_wrap_handshake() {
        let data = vec![1, 2, 3];
        let handshake = wrap_handshake(HandshakeType::ClientHello, &data);

        assert_eq!(handshake[0], HandshakeType::ClientHello as u8);
        assert_eq!(handshake[1], 0x00); // Length byte 1
        assert_eq!(handshake[2], 0x00); // Length byte 2
        assert_eq!(handshake[3], 0x03); // Length byte 3
        assert_eq!(&handshake[4..], &data[..]);
    }

    #[test]
    fn test_cipher_suite_id() {
        assert_eq!(cipher_suite_id(CipherSuite::TlsRsaWithAes128CbcSha), 0x002F);
        assert_eq!(
            cipher_suite_id(CipherSuite::TlsEcdheRsaWithAes128GcmSha256),
            0xC02F
        );
    }

    #[test]
    fn test_build_sni_extension() {
        let ext = build_sni_extension("example.com");

        assert_eq!(ext[0], 0x00); // Extension type (SNI)
        assert_eq!(ext[1], 0x00);
        // Check that hostname is present
        assert!(ext
            .windows("example.com".len())
            .any(|w| w == b"example.com"));
    }

    #[test]
    fn test_signature_algorithms_extension_includes_rsa_sha256() {
        let ext = build_signature_algorithms_extension();

        // Expect signature_algorithms type (0x000d)
        assert_eq!(&ext[..2], &[0x00, 0x0d]);

        // Vector length
        let list_len = ((ext[4] as usize) << 8) | (ext[5] as usize);
        assert!(list_len >= 8);

        // Ensure rsa_pkcs1_sha256 (0x0401) is advertised
        let mut found = false;
        let mut offset = 6;
        while offset + 1 < ext.len() && offset < 6 + list_len {
            if ext[offset] == 0x04 && ext[offset + 1] == 0x01 {
                found = true;
                break;
            }
            offset += 2;
        }

        assert!(found, "rsa_pkcs1_sha256 missing from signature_algorithms");
    }

    #[test]
    fn test_tls12_sha1_mac_length() {
        let mac = compute_record_mac(
            MacAlgorithm::Sha1,
            &[0u8; 20],
            0,
            ContentType::ApplicationData,
            (0x03, 0x03),
            b"hello",
        );
        assert_eq!(mac.len(), 20);
    }

    #[test]
    #[ignore] // Run with: cargo test --release test_tls12_google_connection -- --ignored --nocapture
    fn test_tls12_google_connection() {
        use std::io::{Read, Write};

        println!("\n🔐 Testing TLS 1.2 connection to google.com...");

        // Connect and handshake
        println!("⏳ Establishing connection...");
        let config = TlsConfig::new()
            .with_version(TlsVersion::Tls12)
            .with_verify(false);

        let mut stream = TlsStream::connect("google.com", 443, config)
            .expect("Failed to establish TLS 1.2 connection");

        println!("✅ TLS 1.2 handshake complete!");

        // Send HTTP request
        println!("📤 Sending HTTP GET request...");
        let request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        println!("📥 Reading response...");
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                    if response.len() > 1024 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionAborted => break,
                Err(e) => panic!("Read failed: {}", e),
            }
        }

        // Verify response
        let response_str = String::from_utf8_lossy(&response);
        println!("📄 Response: {} bytes", response.len());

        assert!(
            response_str.contains("HTTP/1.1") || response_str.contains("HTTP/1.0"),
            "Invalid HTTP response"
        );

        println!("✅ TLS 1.2 test PASSED!");
    }
}
