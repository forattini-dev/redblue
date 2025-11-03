// TLS 1.2 Protocol Implementation - RFC 5246
// Pure Rust implementation with ZERO external dependencies
//
// TLS Handshake Flow:
// 1. Client sends ClientHello
// 2. Server responds with ServerHello, Certificate, ServerHelloDone
// 3. Client sends ClientKeyExchange, ChangeCipherSpec, Finished
// 4. Server sends ChangeCipherSpec, Finished
// 5. Application data exchange
//
// This implementation focuses on the handshake to extract certificates
// (for the `rb web asset cert` command). Full encryption is TODO.

use super::x509::X509Certificate;
use std::io::{Read, Write};
use std::net::TcpStream;

/// TLS Protocol Version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

/// TLS Content Type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// TLS Handshake Type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

/// TLS Cipher Suites (subset - common ones)
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
}

/// TLS Client
pub struct TlsClient {
    stream: TcpStream,
    version: TlsVersion,
}

impl TlsClient {
    /// Connect to host and perform TLS handshake
    pub fn connect(host: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let mut client = TlsClient {
            stream,
            version: TlsVersion::Tls12,
        };

        // Perform handshake
        client.handshake(host)?;

        Ok(client)
    }

    /// Perform TLS handshake and return server certificates
    pub fn get_certificates(host: &str, port: u16) -> Result<Vec<X509Certificate>, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        // Send ClientHello
        let client_hello = build_client_hello(host, TlsVersion::Tls12)?;
        stream
            .write_all(&client_hello)
            .map_err(|e| format!("Failed to send ClientHello: {}", e))?;

        // Read server responses until we get Certificate message
        let mut certificates = Vec::new();
        let mut handshake_done = false;

        while !handshake_done {
            let record = read_tls_record(&mut stream)?;

            if record.content_type == ContentType::Handshake as u8 {
                let mut offset = 0;
                while offset < record.data.len() {
                    let handshake_type = record.data[offset];
                    offset += 1;

                    if offset + 3 > record.data.len() {
                        break;
                    }

                    let length = u32::from_be_bytes([
                        0,
                        record.data[offset],
                        record.data[offset + 1],
                        record.data[offset + 2],
                    ]) as usize;
                    offset += 3;

                    if offset + length > record.data.len() {
                        break;
                    }

                    let handshake_data = &record.data[offset..offset + length];

                    match handshake_type {
                        2 => {
                            // ServerHello
                        }
                        11 => {
                            // Certificate
                            if let Ok(certs) = parse_certificate_message(handshake_data) {
                                certificates = certs;
                            }
                        }
                        14 => {
                            // ServerHelloDone
                            handshake_done = true;
                            break;
                        }
                        _ => {}
                    }

                    offset += length;
                }
            } else if record.content_type == ContentType::Alert as u8 {
                // Alert received
                if record.data.len() >= 2 {
                    let level = record.data[0];
                    let description = record.data[1];
                    return Err(format!("TLS Alert: level={}, desc={}", level, description));
                }
            }
        }

        if certificates.is_empty() {
            return Err("No certificates received from server".to_string());
        }

        Ok(certificates)
    }

    fn handshake(&mut self, host: &str) -> Result<(), String> {
        // Send ClientHello
        let client_hello = build_client_hello(host, self.version)?;
        self.stream
            .write_all(&client_hello)
            .map_err(|e| format!("Failed to send ClientHello: {}", e))?;

        // Read ServerHello and other handshake messages
        // For now, we just read enough to establish connection
        let record = read_tls_record(&mut self.stream)?;
        if record.version < 0x0303 {
            return Err(format!(
                "Server negotiated unsupported TLS version 0x{:04x}",
                record.version
            ));
        }

        Ok(())
    }
}

/// TLS Record structure
struct TlsRecord {
    content_type: u8,
    version: u16,
    data: Vec<u8>,
}

/// Read a TLS record from stream
fn read_tls_record(stream: &mut TcpStream) -> Result<TlsRecord, String> {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|e| format!("Failed to read TLS record header: {}", e))?;

    let content_type = header[0];
    let version = u16::from_be_bytes([header[1], header[2]]);
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    if length > 16384 {
        // Max TLS record size
        return Err(format!("TLS record too large: {} bytes", length));
    }

    let mut data = vec![0u8; length];
    stream
        .read_exact(&mut data)
        .map_err(|e| format!("Failed to read TLS record data: {}", e))?;

    Ok(TlsRecord {
        content_type,
        version,
        data,
    })
}

/// Build ClientHello message
fn build_client_hello(host: &str, version: TlsVersion) -> Result<Vec<u8>, String> {
    let mut client_hello = Vec::new();

    // Handshake message: ClientHello
    let mut handshake_body = Vec::new();

    // Client Version (TLS 1.2 = 0x0303)
    handshake_body.push((version as u16 >> 8) as u8);
    handshake_body.push((version as u16 & 0xFF) as u8);

    // Random (32 bytes)
    let random = generate_random_bytes(32);
    handshake_body.extend_from_slice(&random);

    // Session ID (0 length)
    handshake_body.push(0);

    // Cipher Suites
    let cipher_suites = vec![
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as u16,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as u16,
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 as u16,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 as u16,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA as u16,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA as u16,
    ];

    // Cipher Suites Length
    let cipher_suites_len = (cipher_suites.len() * 2) as u16;
    handshake_body.push((cipher_suites_len >> 8) as u8);
    handshake_body.push((cipher_suites_len & 0xFF) as u8);

    // Cipher Suites
    for suite in cipher_suites {
        handshake_body.push((suite >> 8) as u8);
        handshake_body.push((suite & 0xFF) as u8);
    }

    // Compression Methods (1 byte length, 1 method = null)
    handshake_body.push(1);
    handshake_body.push(0); // null compression

    // Extensions
    let extensions = build_extensions(host)?;
    let extensions_len = extensions.len() as u16;
    handshake_body.push((extensions_len >> 8) as u8);
    handshake_body.push((extensions_len & 0xFF) as u8);
    handshake_body.extend_from_slice(&extensions);

    // Handshake header
    let mut handshake = Vec::new();
    handshake.push(HandshakeType::ClientHello as u8);

    // Handshake length (3 bytes)
    let handshake_len = handshake_body.len() as u32;
    handshake.push((handshake_len >> 16) as u8);
    handshake.push((handshake_len >> 8) as u8);
    handshake.push((handshake_len & 0xFF) as u8);

    handshake.extend_from_slice(&handshake_body);

    // TLS Record header
    client_hello.push(ContentType::Handshake as u8);
    client_hello.push((version as u16 >> 8) as u8);
    client_hello.push((version as u16 & 0xFF) as u8);

    // Record length
    let record_len = handshake.len() as u16;
    client_hello.push((record_len >> 8) as u8);
    client_hello.push((record_len & 0xFF) as u8);

    client_hello.extend_from_slice(&handshake);

    Ok(client_hello)
}

/// Build TLS extensions (Server Name Indication, etc.)
fn build_extensions(host: &str) -> Result<Vec<u8>, String> {
    let mut extensions = Vec::new();

    // Extension: Server Name Indication (SNI)
    // Extension type: 0x0000
    extensions.push(0x00);
    extensions.push(0x00);

    // Extension data
    let mut sni_data = Vec::new();

    // Server Name List Length
    let server_name_len = host.len() as u16;
    let list_len = server_name_len + 3; // type(1) + length(2) + name
    sni_data.push((list_len >> 8) as u8);
    sni_data.push((list_len & 0xFF) as u8);

    // Server Name Type (0 = host_name)
    sni_data.push(0);

    // Server Name Length
    sni_data.push((server_name_len >> 8) as u8);
    sni_data.push((server_name_len & 0xFF) as u8);

    // Server Name
    sni_data.extend_from_slice(host.as_bytes());

    // Extension length
    let ext_len = sni_data.len() as u16;
    extensions.push((ext_len >> 8) as u8);
    extensions.push((ext_len & 0xFF) as u8);

    extensions.extend_from_slice(&sni_data);

    // Extension: Supported Groups (elliptic curves)
    extensions.push(0x00);
    extensions.push(0x0a); // Extension type: supported_groups

    let groups = vec![
        0x001d, // x25519
        0x0017, // secp256r1
        0x0018, // secp384r1
    ];

    let groups_len = (groups.len() * 2) as u16;
    let ext_data_len = groups_len + 2;

    extensions.push((ext_data_len >> 8) as u8);
    extensions.push((ext_data_len & 0xFF) as u8);

    extensions.push((groups_len >> 8) as u8);
    extensions.push((groups_len & 0xFF) as u8);

    for group in groups {
        extensions.push((group >> 8) as u8);
        extensions.push((group & 0xFF) as u8);
    }

    // Extension: Signature Algorithms
    extensions.push(0x00);
    extensions.push(0x0d); // Extension type: signature_algorithms

    let sig_algs = vec![
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0603, // ecdsa_secp521r1_sha512
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0601, // rsa_pkcs1_sha512
    ];

    let sig_algs_len = (sig_algs.len() * 2) as u16;
    let sig_ext_len = sig_algs_len + 2;

    extensions.push((sig_ext_len >> 8) as u8);
    extensions.push((sig_ext_len & 0xFF) as u8);

    extensions.push((sig_algs_len >> 8) as u8);
    extensions.push((sig_algs_len & 0xFF) as u8);

    for alg in sig_algs {
        extensions.push((alg >> 8) as u8);
        extensions.push((alg & 0xFF) as u8);
    }

    Ok(extensions)
}

/// Parse Certificate handshake message
fn parse_certificate_message(data: &[u8]) -> Result<Vec<X509Certificate>, String> {
    if data.len() < 3 {
        return Err("Certificate message too short".to_string());
    }

    // Certificates length (3 bytes)
    let certs_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;

    if 3 + certs_len > data.len() {
        return Err("Invalid certificates length".to_string());
    }

    let mut offset = 3;
    let mut certificates = Vec::new();

    while offset < 3 + certs_len {
        if offset + 3 > data.len() {
            break;
        }

        // Certificate length (3 bytes)
        let cert_len =
            u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        if offset + cert_len > data.len() {
            break;
        }

        // Parse X.509 certificate
        let cert_data = &data[offset..offset + cert_len];
        if let Ok(cert) = X509Certificate::from_der(cert_data) {
            certificates.push(cert);
        }

        offset += cert_len;
    }

    Ok(certificates)
}

/// Generate random bytes (simple PRNG for TLS random field)
fn generate_random_bytes(len: usize) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut rng = SimpleRng::new(seed);
    (0..len).map(|_| rng.next_u8()).collect()
}

/// Simple PRNG (Linear Congruential Generator)
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        SimpleRng { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        // LCG parameters (from Numerical Recipes)
        self.state = self.state.wrapping_mul(1664525).wrapping_add(1013904223);
        (self.state >> 32) as u32
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u32() & 0xFF) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_construction() {
        let client_hello = build_client_hello("example.com", TlsVersion::Tls12).unwrap();

        // Should start with Handshake content type
        assert_eq!(client_hello[0], ContentType::Handshake as u8);

        // Version should be TLS 1.2
        assert_eq!(client_hello[1], 0x03);
        assert_eq!(client_hello[2], 0x03);

        // Should have reasonable length
        assert!(client_hello.len() > 100);
        assert!(client_hello.len() < 1000);
    }

    #[test]
    fn test_generate_random_bytes() {
        let random1 = generate_random_bytes(32);
        let random2 = generate_random_bytes(32);

        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);

        // Should be different (very high probability)
        assert_ne!(random1, random2);
    }

    #[test]
    fn test_simple_rng() {
        let mut rng = SimpleRng::new(12345);
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();

        assert_ne!(val1, val2);
    }
}
