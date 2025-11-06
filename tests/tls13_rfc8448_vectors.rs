/// RFC 8448 Test Vectors for TLS 1.3
///
/// This test uses the official IETF TLS 1.3 test vectors from RFC 8448 Section 3
/// to verify our implementation byte-by-byte against a known-good handshake.

#[cfg(test)]
mod rfc8448_tests {
    // Include our crypto implementations (adjust path as needed)
    // We'll test them directly using the internal modules
    use redblue::crypto::{
        hkdf, sha256::sha256, tls13_hash::Tls13HashAlgorithm, tls13_keyschedule::Tls13KeySchedule,
    };

    fn hex_decode(hex: &str) -> Vec<u8> {
        let hex = hex.replace(" ", "").replace("\n", "");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Test HKDF-Expand-Label against RFC 8448 values
    #[test]
    fn test_hkdf_expand_label_rfc8448() {
        // Load the crypto module
        use redblue::crypto::hkdf;

        // From RFC 8448, Section 3: "derive secret for handshake tls13 derived"

        // PRK (early secret)
        let prk_vec = hex_decode("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a");
        let mut prk = [0u8; 32];
        prk.copy_from_slice(&prk_vec);

        // Hash of empty message (SHA-256(""))
        let hash_vec = hex_decode("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_vec);

        // Expected expanded value
        let expected = hex_decode("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba");

        println!("Testing HKDF-Expand-Label RFC 8448:");
        println!("  PRK:      {:02x?}...", &prk[..8]);
        println!("  Hash:     {:02x?}...", &hash[..8]);
        println!("  Expected: {:02x?}...", &expected[..8]);

        // Call our derive_secret implementation (which uses HKDF-Expand-Label)
        let result = hkdf::derive_secret(&prk, b"derived", &hash);

        println!("  Got:      {:02x?}...", &result[..8]);

        if result[..] == expected[..] {
            println!("\n✅ HKDF-Expand-Label MATCHES RFC 8448!");
        } else {
            println!("\n❌ HKDF-Expand-Label MISMATCH!");
            println!("Expected: {:02x?}", expected);
            println!("Got:      {:02x?}", result);
            panic!("HKDF-Expand-Label does not match RFC 8448!");
        }

        assert_eq!(result[..], expected[..], "HKDF-Expand-Label mismatch!");
    }

    /// Test X25519 shared secret calculation
    #[test]
    fn test_x25519_shared_secret_rfc8448() {
        use redblue::crypto::x25519;

        // From RFC 8448, Section 3

        // Client private key
        let client_private_vec = hex_decode("49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05");
        let mut client_private = [0u8; 32];
        client_private.copy_from_slice(&client_private_vec);

        // Client public key (derived)
        let client_public = hex_decode("99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c");

        // Server private key
        let server_private_vec = hex_decode("b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e");
        let mut server_private = [0u8; 32];
        server_private.copy_from_slice(&server_private_vec);

        // Server public key (derived)
        let server_public_vec = hex_decode("c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f");
        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&server_public_vec);

        // Expected shared secret (IKM for handshake secret)
        let expected_shared_secret = hex_decode("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");

        println!("Testing X25519 RFC 8448:");
        println!("  Client private: {:02x?}...", &client_private[..8]);
        println!("  Server public:  {:02x?}...", &server_public[..8]);
        println!("  Expected:       {:02x?}...", &expected_shared_secret[..8]);

        // Call our X25519 implementation (client perspective)
        let shared = x25519::x25519(&client_private, &server_public);

        println!("  Got:            {:02x?}...", &shared[..8]);

        if shared[..] == expected_shared_secret[..] {
            println!("\n✅ X25519 shared secret MATCHES RFC 8448!");
        } else {
            println!("\n❌ X25519 shared secret MISMATCH!");
            println!("Expected: {:02x?}", expected_shared_secret);
            println!("Got:      {:02x?}", shared);
            panic!("X25519 shared secret does not match RFC 8448!");
        }

        assert_eq!(
            shared[..],
            expected_shared_secret[..],
            "X25519 shared secret mismatch!"
        );
    }

    /// Test handshake secret derivation
    #[test]
    fn test_handshake_secret_rfc8448() {
        // From RFC 8448, Section 3: "extract secret handshake"

        // Salt (from "tls13 derived")
        let salt = hex_decode("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba");

        // IKM (X25519 shared secret)
        let ikm = hex_decode("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");

        // Expected handshake secret
        let expected = hex_decode("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac");

        println!("RFC 8448 Handshake Secret:");
        println!("  Salt (derived): {:02x?}", &salt[..8]);
        println!("  IKM (X25519):   {:02x?}", &ikm[..8]);
        println!("  Expected:       {:02x?}", &expected[..8]);

        let result = hkdf::hkdf_extract(Some(&salt), &ikm);
        assert_eq!(result.to_vec(), expected, "Handshake secret mismatch!");

        println!("\n✅ RFC 8448 Handshake secret validated");
    }

    /// Test server handshake traffic secret
    #[test]
    fn test_server_handshake_traffic_secret_rfc8448() {
        // From RFC 8448, Section 3: "derive secret tls13 s hs traffic"

        // PRK (handshake secret)
        let prk = hex_decode("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac");

        // Hash (ClientHello + ServerHello)
        let hash = hex_decode("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");

        // Expected server handshake traffic secret
        let expected = hex_decode("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");

        println!("RFC 8448 Server Handshake Traffic Secret:");
        println!("  PRK:      {:02x?}", &prk[..8]);
        println!("  Hash:     {:02x?}", &hash[..8]);
        println!("  Expected: {:02x?}", &expected[..8]);

        let hash_alg = Tls13HashAlgorithm::Sha256;
        let result = hash_alg
            .derive_secret(&prk, b"s hs traffic", &hash)
            .expect("derive_secret failed");
        assert_eq!(
            result, expected,
            "Server handshake traffic secret mismatch!"
        );

        println!("\n✅ RFC 8448 Server handshake traffic secret validated");
    }

    /// Test client handshake traffic secret
    #[test]
    fn test_client_handshake_traffic_secret_rfc8448() {
        // From RFC 8448, Section 3: "derive secret tls13 c hs traffic"

        // PRK (handshake secret)
        let prk = hex_decode("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac");

        // Hash (ClientHello + ServerHello)
        let hash = hex_decode("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");

        // Expected client handshake traffic secret
        let expected = hex_decode("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");

        println!("RFC 8448 Client Handshake Traffic Secret:");
        println!("  PRK:      {:02x?}", &prk[..8]);
        println!("  Hash:     {:02x?}", &hash[..8]);
        println!("  Expected: {:02x?}", &expected[..8]);

        let hash_alg = Tls13HashAlgorithm::Sha256;
        let result = hash_alg
            .derive_secret(&prk, b"c hs traffic", &hash)
            .expect("derive_secret failed");
        assert_eq!(
            result, expected,
            "Client handshake traffic secret mismatch!"
        );

        println!("\n✅ RFC 8448 Client handshake traffic secret validated");
    }

    /// Test server handshake traffic keys
    #[test]
    fn test_server_handshake_keys_rfc8448() {
        // From RFC 8448, Section 3: "derive write traffic keys for handshake data"

        // PRK (server handshake traffic secret)
        let prk = hex_decode("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");

        // Expected key (16 bytes for AES-128-GCM)
        let expected_key = hex_decode("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc");

        // Expected IV (12 bytes)
        let expected_iv = hex_decode("5d 31 3e b2 67 12 76 ee 13 00 0b 30");

        println!("RFC 8448 Server Handshake Keys:");
        println!("  PRK: {:02x?}", &prk[..8]);
        println!("  Expected key: {:02x?}", &expected_key[..8]);
        println!("  Expected IV:  {:02x?}", &expected_iv);

        let schedule = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);
        let (key, iv) = schedule
            .derive_traffic_keys(&prk, 16, 12)
            .expect("derive_traffic_keys failed");
        assert_eq!(key, expected_key, "Server handshake key mismatch!");
        assert_eq!(iv, expected_iv, "Server handshake IV mismatch!");

        println!("\n✅ RFC 8448 Server handshake keys validated");
    }

    /// Test client handshake traffic keys
    #[test]
    fn test_client_handshake_keys_rfc8448() {
        // From RFC 8448, Section 3: "derive read traffic keys for handshake data"

        // PRK (client handshake traffic secret)
        let prk = hex_decode("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");

        // Expected key (16 bytes for AES-128-GCM)
        let expected_key = hex_decode("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01");

        // Expected IV (12 bytes)
        let expected_iv = hex_decode("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");

        println!("RFC 8448 Client Handshake Keys:");
        println!("  PRK: {:02x?}", &prk[..8]);
        println!("  Expected key: {:02x?}", &expected_key[..8]);
        println!("  Expected IV:  {:02x?}", &expected_iv);

        let schedule = Tls13KeySchedule::new(Tls13HashAlgorithm::Sha256);
        let (key, iv) = schedule
            .derive_traffic_keys(&prk, 16, 12)
            .expect("derive_traffic_keys failed");
        assert_eq!(key, expected_key, "Client handshake key mismatch!");
        assert_eq!(iv, expected_iv, "Client handshake IV mismatch!");

        println!("\n✅ RFC 8448 Client handshake keys validated");
    }

    /// Test transcript hash calculation
    #[test]
    fn test_transcript_hash_rfc8448() {
        // From RFC 8448, Section 3

        // ClientHello (196 bytes)
        let client_hello = hex_decode("01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01");

        // ServerHello (90 bytes)
        let server_hello = hex_decode("02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04");

        // Expected hash of ClientHello + ServerHello
        let expected_hash = hex_decode("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");

        println!("RFC 8448 Transcript Hash:");
        println!("  ClientHello len: {}", client_hello.len());
        println!("  ServerHello len: {}", server_hello.len());
        println!("  Total: {} bytes", client_hello.len() + server_hello.len());
        println!("  Expected hash: {:02x?}", &expected_hash[..8]);

        // Concatenate messages
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&client_hello);
        transcript.extend_from_slice(&server_hello);

        let hash = sha256(&transcript);
        assert_eq!(hash.to_vec(), expected_hash, "Transcript hash mismatch!");

        println!("\n✅ RFC 8448 Transcript structure validated");
    }

    /// Summary test showing the full key derivation chain
    #[test]
    fn test_full_key_derivation_chain() {
        println!("\n🔍 RFC 8448 TLS 1.3 Key Derivation Chain:");
        println!("\n1. Early Secret (from zeros):");
        println!("   33 ad 0a 1c 60 7e c0 3b ... (32 bytes)");

        println!("\n2. Derive 'tls13 derived' → Input to Handshake Extract:");
        println!("   6f 26 15 a1 08 c7 02 c5 ... (32 bytes)");

        println!("\n3. Handshake Secret (HKDF-Extract with X25519 shared secret):");
        println!("   Salt: 6f 26 15 a1 08 c7 02 c5 ...");
        println!("   IKM:  8b d4 05 4f b5 5b 9d 63 ... (X25519 output)");
        println!("   →     1d c8 26 e9 36 06 aa 6f ... (32 bytes)");

        println!("\n4. Server Handshake Traffic Secret:");
        println!("   PRK:  1d c8 26 e9 36 06 aa 6f ...");
        println!("   Hash: 86 0c 06 ed c0 78 58 ee ... (SHA256(CH||SH))");
        println!("   →     b6 7b 7d 69 0c c1 6c 4e ... (32 bytes)");

        println!("\n5. Server Handshake Traffic Keys:");
        println!("   Key: 3f ce 51 60 09 c2 17 27 ... (16 bytes)");
        println!("   IV:  5d 31 3e b2 67 12 76 ee ... (12 bytes)");

        println!("\n6. Client Handshake Traffic Secret:");
        println!("   PRK:  1d c8 26 e9 36 06 aa 6f ...");
        println!("   Hash: 86 0c 06 ed c0 78 58 ee ...");
        println!("   →     b3 ed db 12 6e 06 7f 35 ... (32 bytes)");

        println!("\n7. Client Handshake Traffic Keys:");
        println!("   Key: db fa a6 93 d1 76 2c 5b ... (16 bytes)");
        println!("   IV:  5b d3 c7 1b 83 6e 0b 76 ... (12 bytes)");

        println!("\n✅ All RFC 8448 test vectors loaded and ready for comparison!");
    }
}
