// Integration test for HTTPS/TLS handshake
// Tests the complete RSA-based TLS 1.2 handshake

#[cfg(test)]
mod https_tests {

    use redblue::crypto::{BigInt, RsaPublicKey};
    use redblue::modules::network::tls::{TlsConfig, TlsStream, TlsVersion};
    use std::io::{Read, Write};
    use std::time::Duration;

    #[test]
    #[ignore] // Run with: cargo test --test https_handshake_test -- --ignored
    fn test_tls_handshake_google() {
        // TLS handshake + lightweight request to confirm TLS transport is usable
        let config = TlsConfig::new()
            .with_version(TlsVersion::Tls12)
            .with_verify(false)
            .with_timeout(Duration::from_secs(10));

        let mut stream = TlsStream::connect("google.com", 443, config)
            .expect("Failed to establish TLS 1.2 with google.com:443");

        let request = b"GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request)
            .expect("Failed to write HTTP request");

        let mut response = [0u8; 4096];
        let n = stream
            .read(&mut response)
            .expect("Failed to read TLS response");
        assert!(n > 0, "Received an empty response from TLS stream");

        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(
            response_str.starts_with("HTTP/1.") || response_str.contains("HTTP/1."),
            "Expected HTTP response, got: {}",
            response_str
        );

        println!("✓ TLS handshake + request on google.com succeeded");
    }

    #[test]
    fn test_rsa_encryption_basic() {
        // Use a small public key fixture and validate PKCS#1 v1.5 encryption output shape.
        let n = BigInt::from_bytes_be(&[0xFF; 128]); // 1024-bit modulus
        let e = BigInt::from_u64(65537);
        let key = RsaPublicKey::new(n, e);

        let plaintext = b"Hello RSA!";
        let encrypted = key
            .encrypt_pkcs1v15(plaintext)
            .expect("RSA encryption should succeed");

        assert_eq!(encrypted.len(), 128);
        assert_ne!(
            &encrypted,
            &vec![0u8; 128],
            "ciphertext should not be all zeros"
        );
    }

    #[test]
    fn test_bigint_operations() {
        let a = BigInt::from_u64(123);
        let b = BigInt::from_u64(456);

        let add = a.add(&b);
        let mul = a.mul(&b);
        let divmod = a.div_rem(&BigInt::from_u64(5));
        let modv = a.modulo(&BigInt::from_u64(1000));
        let mod_exp = a.mod_exp(&BigInt::from_u64(7), &BigInt::from_u64(1000));

        assert_eq!(add, BigInt::from_u64(579));
        assert_eq!(mul, BigInt::from_u64(56088));
        assert_eq!(divmod, (BigInt::from_u64(24), BigInt::from_u64(3)));
        assert_eq!(modv, BigInt::from_u64(123));
        assert_eq!(mod_exp, BigInt::from_u64(232));
    }
}
