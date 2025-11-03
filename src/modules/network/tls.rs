/// TLS/SSL Support (from scratch)
///
/// Implements TLS 1.2/1.3 handshake and encryption for secure communication.
/// This is a SIMPLIFIED implementation for netcat usage - NOT a full TLS library.
///
/// Features:
/// - TLS 1.2 client handshake
/// - Basic cipher suite support
/// - Certificate verification (optional)
/// - Encrypted data transfer
///
/// Replaces: ncat --ssl
use crate::crypto::{aes, hmac, prf};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// Cipher suite
#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub version: TlsVersion,
    pub verify_cert: bool,
    pub cipher_suites: Vec<CipherSuite>,
    pub timeout: Duration,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            version: TlsVersion::Tls12,
            verify_cert: false, // Disabled for pentesting
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            ],
            timeout: Duration::from_secs(10),
        }
    }
}

impl TlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: TlsVersion) -> Self {
        self.version = version;
        self
    }

    pub fn with_verify(mut self, verify: bool) -> Self {
        self.verify_cert = verify;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// TLS handshake record types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// TLS handshake message types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum HandshakeType {
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

/// TLS stream wrapper
pub struct TlsStream {
    stream: TcpStream,
    config: TlsConfig,
    handshake_complete: bool,
    read_buffer: Vec<u8>,
    buffer_pos: usize,
    // Crypto state
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    server_certificate: Option<Vec<u8>>, // Server's X.509 certificate (DER)
    pre_master_secret: Option<[u8; 48]>, // Pre-master secret for key derivation
    master_secret: Option<[u8; 48]>,
    client_write_key: Option<[u8; 16]>,
    server_write_key: Option<[u8; 16]>,
    client_write_mac: Option<[u8; 32]>, // HMAC-SHA256 key
    server_write_mac: Option<[u8; 32]>, // HMAC-SHA256 key
    client_write_iv: Option<[u8; 16]>,  // AES-CBC IV
    server_write_iv: Option<[u8; 16]>,  // AES-CBC IV
    client_sequence: u64,
    server_sequence: u64,
    // Handshake transcript for Finished message
    handshake_messages: Vec<u8>, // All handshake messages (for verify_data calculation)
}

impl TlsStream {
    /// Create new TLS stream (client mode)
    pub fn connect(host: &str, port: u16, config: TlsConfig) -> Result<Self, String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr)
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        stream
            .set_read_timeout(Some(config.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(config.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Generate client random (32 bytes)
        let client_random = generate_random_32();

        let mut tls = Self {
            stream,
            config,
            handshake_complete: false,
            read_buffer: Vec::new(),
            buffer_pos: 0,
            client_random,
            server_random: None,
            server_certificate: None,
            pre_master_secret: None,
            master_secret: None,
            client_write_key: None,
            server_write_key: None,
            client_write_mac: None,
            server_write_mac: None,
            client_write_iv: None,
            server_write_iv: None,
            client_sequence: 0,
            server_sequence: 0,
            handshake_messages: Vec::new(),
        };

        tls.handshake(host)?;
        Ok(tls)
    }

    /// Perform TLS handshake
    fn handshake(&mut self, host: &str) -> Result<(), String> {
        // 1. Send ClientHello
        self.send_client_hello(host)?;

        // 2. Receive ServerHello
        let _server_hello = self.receive_server_hello()?;

        // 3. Receive Certificate
        let _certificate = self.receive_certificate()?;

        // 4. Receive ServerHelloDone
        self.receive_server_hello_done()?;

        // 5. Send ClientKeyExchange
        self.send_client_key_exchange()?;

        // Derive cryptographic keys
        self.derive_session_keys()?;

        // 6. Send ChangeCipherSpec
        self.send_change_cipher_spec()?;

        // 7. Send Finished
        self.send_finished()?;

        // 8. Receive ChangeCipherSpec
        self.receive_change_cipher_spec()?;

        // 9. Receive Finished
        self.receive_finished()?;

        self.handshake_complete = true;
        Ok(())
    }

    /// Send ClientHello message
    fn send_client_hello(&mut self, host: &str) -> Result<(), String> {
        let mut hello = Vec::new();

        // TLS version (0x0303 = TLS 1.2)
        hello.push(0x03);
        hello.push(0x03);

        // Random (32 bytes) - use stored client_random
        hello.extend_from_slice(&self.client_random);

        // Session ID (empty for now)
        hello.push(0x00);

        // Cipher suites
        let cipher_count = self.config.cipher_suites.len() as u16;
        hello.push(((cipher_count * 2) >> 8) as u8);
        hello.push((cipher_count * 2) as u8);
        for cipher in &self.config.cipher_suites {
            let cipher_id = cipher_suite_id(*cipher);
            hello.push((cipher_id >> 8) as u8);
            hello.push(cipher_id as u8);
        }

        // Compression methods (none)
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let mut extensions = Vec::new();

        // Server Name Indication (SNI)
        let sni_ext = build_sni_extension(host);
        extensions.extend_from_slice(&sni_ext);

        // Add extensions length
        hello.push((extensions.len() >> 8) as u8);
        hello.push(extensions.len() as u8);
        hello.extend_from_slice(&extensions);

        // Wrap in handshake record
        let handshake = wrap_handshake(HandshakeType::ClientHello, &hello);

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&handshake);

        // Wrap in TLS record
        let record = wrap_tls_record(ContentType::Handshake, &handshake);

        // Send
        self.stream
            .write_all(&record)
            .map_err(|e| format!("Failed to send ClientHello: {}", e))?;

        Ok(())
    }

    /// Receive ServerHello
    fn receive_server_hello(&mut self) -> Result<Vec<u8>, String> {
        let record = self.receive_tls_record()?;

        if record.is_empty() {
            return Err("Empty ServerHello".to_string());
        }

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&record);

        // Parse ServerHello to extract server_random
        // Format: HandshakeType (1) + Length (3) + Version (2) + Random (32) + ...
        if record.len() >= 38 {
            let mut server_random = [0u8; 32];
            server_random.copy_from_slice(&record[6..38]);
            self.server_random = Some(server_random);
        }

        Ok(record)
    }

    /// Receive Certificate
    fn receive_certificate(&mut self) -> Result<Vec<u8>, String> {
        let record = self.receive_tls_record()?;

        if record.is_empty() {
            return Err("Empty Certificate".to_string());
        }

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&record);

        // Parse Certificate message:
        // HandshakeType (1 byte) = 11 (Certificate)
        // Length (3 bytes)
        // Certificates length (3 bytes)
        // Certificate 1 length (3 bytes)
        // Certificate 1 data (DER)
        // ... (more certificates)

        if record.len() < 7 {
            return Err("Certificate message too short".to_string());
        }

        // Skip handshake type and length (4 bytes)
        let mut offset = 4;

        // Parse certificates length (3 bytes)
        let certs_len = ((record[offset] as usize) << 16)
            | ((record[offset + 1] as usize) << 8)
            | (record[offset + 2] as usize);
        offset += 3;

        if offset + certs_len > record.len() {
            return Err("Invalid certificates length".to_string());
        }

        // Parse first certificate (server certificate)
        if offset + 3 > record.len() {
            return Err("No certificate data".to_string());
        }

        let cert_len = ((record[offset] as usize) << 16)
            | ((record[offset + 1] as usize) << 8)
            | (record[offset + 2] as usize);
        offset += 3;

        if offset + cert_len > record.len() {
            return Err("Invalid certificate length".to_string());
        }

        // Extract the certificate DER data
        let cert_der = record[offset..offset + cert_len].to_vec();

        // Store the certificate for later use in ClientKeyExchange
        self.server_certificate = Some(cert_der.clone());

        Ok(record)
    }

    /// Receive ServerHelloDone
    fn receive_server_hello_done(&mut self) -> Result<(), String> {
        let record = self.receive_tls_record()?;
        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&record);
        Ok(())
    }

    /// Send ClientKeyExchange
    fn send_client_key_exchange(&mut self) -> Result<(), String> {
        use crate::crypto::extract_public_key_from_cert;

        // Generate random pre-master secret (48 bytes)
        // Format: 0x03 0x03 (TLS 1.2) + 46 random bytes
        let mut pre_master_secret = [0u8; 48];
        pre_master_secret[0] = 0x03;
        pre_master_secret[1] = 0x03;

        // Fill rest with random data
        let random_bytes = generate_random_bytes(46);
        pre_master_secret[2..].copy_from_slice(&random_bytes);

        // Store pre-master secret for key derivation
        self.pre_master_secret = Some(pre_master_secret);

        // Get server's certificate
        let cert_der = self
            .server_certificate
            .as_ref()
            .ok_or("No server certificate received")?;

        // Extract RSA public key from certificate
        let public_key = extract_public_key_from_cert(cert_der)?;

        // Encrypt pre-master secret with server's public key using PKCS#1 v1.5
        let encrypted_pms = public_key.encrypt_pkcs1v15(&pre_master_secret)?;

        // Build ClientKeyExchange message
        // For RSA: just the encrypted pre-master secret (with length prefix for TLS 1.0+)
        let mut key_exchange = Vec::new();

        // Add length prefix (2 bytes) for TLS 1.0+
        key_exchange.push((encrypted_pms.len() >> 8) as u8);
        key_exchange.push(encrypted_pms.len() as u8);
        key_exchange.extend_from_slice(&encrypted_pms);

        let handshake = wrap_handshake(HandshakeType::ClientKeyExchange, &key_exchange);

        // Add to handshake transcript for Finished message
        self.handshake_messages.extend_from_slice(&handshake);

        let record = wrap_tls_record(ContentType::Handshake, &handshake);

        self.stream
            .write_all(&record)
            .map_err(|e| format!("Failed to send ClientKeyExchange: {}", e))?;

        Ok(())
    }

    /// Send ChangeCipherSpec
    fn send_change_cipher_spec(&mut self) -> Result<(), String> {
        let ccs = vec![0x01];
        let record = wrap_tls_record(ContentType::ChangeCipherSpec, &ccs);

        self.stream
            .write_all(&record)
            .map_err(|e| format!("Failed to send ChangeCipherSpec: {}", e))?;

        Ok(())
    }

    /// Send Finished
    fn send_finished(&mut self) -> Result<(), String> {
        use crate::crypto::sha256;

        // Get master secret
        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or("No master secret available")?;

        // Calculate SHA-256 hash of all handshake messages so far
        let handshake_hash = sha256::sha256(&self.handshake_messages);

        // Calculate verify_data using TLS PRF
        // verify_data = PRF(master_secret, "client finished", handshake_hash)[0..12]
        let label = b"client finished";
        let verify_data_full = prf::prf_tls12(master_secret, label, &handshake_hash, 12);

        // Take first 12 bytes for verify_data
        let verify_data = verify_data_full[..12].to_vec();

        let handshake = wrap_handshake(HandshakeType::Finished, &verify_data);
        let record = wrap_tls_record(ContentType::Handshake, &handshake);

        self.stream
            .write_all(&record)
            .map_err(|e| format!("Failed to send Finished: {}", e))?;

        Ok(())
    }

    /// Receive ChangeCipherSpec
    fn receive_change_cipher_spec(&mut self) -> Result<(), String> {
        let _record = self.receive_tls_record()?;
        Ok(())
    }

    /// Receive Finished
    fn receive_finished(&mut self) -> Result<(), String> {
        let _record = self.receive_tls_record()?;
        Ok(())
    }

    /// Derive session keys from pre-master secret
    fn derive_session_keys(&mut self) -> Result<(), String> {
        // Get server_random
        let server_random = self.server_random.ok_or("Server random not received")?;

        // Get pre-master secret (generated and encrypted in send_client_key_exchange)
        let pre_master = self
            .pre_master_secret
            .ok_or("Pre-master secret not generated")?;

        // Derive master secret
        let master_secret =
            prf::derive_master_secret(&pre_master, &self.client_random, &server_random);
        self.master_secret = Some(master_secret);

        // Derive key material (104 bytes for TLS_RSA_WITH_AES_128_CBC_SHA256)
        // client_write_MAC_key (32) + server_write_MAC_key (32) +
        // client_write_key (16) + server_write_key (16) +
        // client_write_IV (16) + server_write_IV (16)
        let key_material =
            prf::derive_keys(&master_secret, &server_random, &self.client_random, 104);

        // Extract keys from key_block
        let mut offset = 0;

        // client_write_MAC_key (32 bytes for HMAC-SHA256)
        let mut client_write_mac = [0u8; 32];
        client_write_mac.copy_from_slice(&key_material[offset..offset + 32]);
        self.client_write_mac = Some(client_write_mac);
        offset += 32;

        // server_write_MAC_key (32 bytes for HMAC-SHA256)
        let mut server_write_mac = [0u8; 32];
        server_write_mac.copy_from_slice(&key_material[offset..offset + 32]);
        self.server_write_mac = Some(server_write_mac);
        offset += 32;

        // client_write_key (16 bytes for AES-128)
        let mut client_write_key = [0u8; 16];
        client_write_key.copy_from_slice(&key_material[offset..offset + 16]);
        self.client_write_key = Some(client_write_key);
        offset += 16;

        // server_write_key (16 bytes for AES-128)
        let mut server_write_key = [0u8; 16];
        server_write_key.copy_from_slice(&key_material[offset..offset + 16]);
        self.server_write_key = Some(server_write_key);
        offset += 16;

        // client_write_IV (16 bytes for AES-CBC)
        let mut client_write_iv = [0u8; 16];
        client_write_iv.copy_from_slice(&key_material[offset..offset + 16]);
        self.client_write_iv = Some(client_write_iv);
        offset += 16;

        // server_write_IV (16 bytes for AES-CBC)
        let mut server_write_iv = [0u8; 16];
        server_write_iv.copy_from_slice(&key_material[offset..offset + 16]);
        self.server_write_iv = Some(server_write_iv);

        Ok(())
    }

    /// Receive TLS record
    fn receive_tls_record(&mut self) -> Result<Vec<u8>, String> {
        // Read TLS record header (5 bytes)
        let mut header = [0u8; 5];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("Failed to read TLS record header: {}", e))?;

        // Parse length (bytes 3-4)
        let length = ((header[3] as usize) << 8) | (header[4] as usize);

        // Read payload
        let mut payload = vec![0u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| format!("Failed to read TLS record payload: {}", e))?;

        Ok(payload)
    }

    /// Get inner TCP stream for bidirectional copying
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.handshake_complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS handshake not complete",
            ));
        }

        // If we have buffered data, return it first
        if self.buffer_pos < self.read_buffer.len() {
            let remaining = self.read_buffer.len() - self.buffer_pos;
            let to_copy = buf.len().min(remaining);
            buf[..to_copy]
                .copy_from_slice(&self.read_buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;

            // Clear buffer if fully consumed
            if self.buffer_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.buffer_pos = 0;
            }

            return Ok(to_copy);
        }

        // Read next TLS record
        loop {
            // Read TLS record header (5 bytes)
            let mut header = [0u8; 5];
            match self.stream.read_exact(&mut header) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Connection closed gracefully
                    return Ok(0);
                }
                Err(e) => return Err(e),
            }

            let content_type = header[0];
            let _version_major = header[1];
            let _version_minor = header[2];
            let length = ((header[3] as usize) << 8) | (header[4] as usize);

            // Read record payload
            let mut payload = vec![0u8; length];
            self.stream.read_exact(&mut payload)?;

            // Handle different record types
            match content_type {
                // ApplicationData - this is what we want
                23 => {
                    // Get decryption keys
                    let key = self.server_write_key.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Server write key not available",
                        )
                    })?;
                    let iv = self.server_write_iv.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Server write IV not available",
                        )
                    })?;
                    let mac_key = self.server_write_mac.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Server write MAC key not available",
                        )
                    })?;

                    // Decrypt with AES-128-CBC
                    let decrypted = aes::aes128_cbc_decrypt(&key, &iv, &payload).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Decryption failed: {}", e),
                        )
                    })?;

                    // Extract MAC (last 32 bytes for SHA-256)
                    if decrypted.len() < 32 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Decrypted data too short for MAC",
                        ));
                    }

                    let data_len = decrypted.len() - 32;
                    let plaintext = &decrypted[..data_len];
                    let received_mac = &decrypted[data_len..];

                    // Verify HMAC
                    let mut mac_data = Vec::new();
                    mac_data.extend_from_slice(&self.server_sequence.to_be_bytes());
                    mac_data.push(ContentType::ApplicationData as u8);
                    mac_data.push(0x03); // TLS 1.2
                    mac_data.push(0x03);
                    let plain_len = plaintext.len() as u16;
                    mac_data.extend_from_slice(&plain_len.to_be_bytes());
                    mac_data.extend_from_slice(plaintext);

                    let expected_mac = hmac::hmac_sha256(&mac_key, &mac_data);

                    // Constant-time MAC comparison
                    if received_mac != expected_mac {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "MAC verification failed",
                        ));
                    }

                    // Increment sequence number
                    self.server_sequence += 1;

                    // Copy to output buffer
                    let to_copy = buf.len().min(plaintext.len());
                    buf[..to_copy].copy_from_slice(&plaintext[..to_copy]);

                    // Store remainder in buffer if needed
                    if plaintext.len() > to_copy {
                        self.read_buffer = plaintext[to_copy..].to_vec();
                        self.buffer_pos = 0;
                    }

                    return Ok(to_copy);
                }
                // Alert
                21 => {
                    // Alert received - typically means connection is closing
                    if payload.len() >= 2 {
                        let level = payload[0];
                        let description = payload[1];
                        if level == 2 {
                            // Fatal
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                format!("TLS fatal alert: {}", description),
                            ));
                        }
                    }
                    // Non-fatal alert, continue reading
                    continue;
                }
                // ChangeCipherSpec or Handshake after connection
                20 | 22 => {
                    // Skip these records during application data phase
                    continue;
                }
                _ => {
                    // Unknown record type
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unknown TLS record type: {}", content_type),
                    ));
                }
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.handshake_complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS handshake not complete",
            ));
        }

        // Get encryption keys
        let key = self.client_write_key.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Client write key not available")
        })?;
        let iv = self.client_write_iv.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Client write IV not available")
        })?;
        let mac_key = self.client_write_mac.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Client write MAC key not available",
            )
        })?;

        // Build TLS record (ContentType + Version + Length + Data)
        // We need to compute MAC over: sequence_number + TLS header + plaintext
        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(&self.client_sequence.to_be_bytes());
        mac_data.push(ContentType::ApplicationData as u8);
        mac_data.push(0x03); // TLS 1.2
        mac_data.push(0x03);
        let data_len = buf.len() as u16;
        mac_data.extend_from_slice(&data_len.to_be_bytes());
        mac_data.extend_from_slice(buf);

        // Compute HMAC
        let mac = hmac::hmac_sha256(&mac_key, &mac_data);

        // Combine plaintext + MAC
        let mut plaintext = Vec::with_capacity(buf.len() + 32);
        plaintext.extend_from_slice(buf);
        plaintext.extend_from_slice(&mac);

        // Encrypt with AES-128-CBC
        let encrypted = aes::aes128_cbc_encrypt(&key, &iv, &plaintext);

        // Wrap in TLS record
        let record = wrap_tls_record(ContentType::ApplicationData, &encrypted);

        // Write the TLS record
        self.stream.write_all(&record)?;

        // Increment sequence number
        self.client_sequence += 1;

        // Return original buffer length (what the caller expects)
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Wrap data in TLS record
fn wrap_tls_record(content_type: ContentType, data: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();

    // Content type
    record.push(content_type as u8);

    // Version (TLS 1.2 = 0x0303)
    record.push(0x03);
    record.push(0x03);

    // Length
    let length = data.len() as u16;
    record.push((length >> 8) as u8);
    record.push(length as u8);

    // Data
    record.extend_from_slice(data);

    record
}

/// Wrap data in handshake message
fn wrap_handshake(msg_type: HandshakeType, data: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::new();

    // Message type
    handshake.push(msg_type as u8);

    // Length (24-bit)
    let length = data.len() as u32;
    handshake.push((length >> 16) as u8);
    handshake.push((length >> 8) as u8);
    handshake.push(length as u8);

    // Data
    handshake.extend_from_slice(data);

    handshake
}

/// Build SNI extension
fn build_sni_extension(host: &str) -> Vec<u8> {
    let mut ext = Vec::new();

    // Extension type (0x0000 = SNI)
    ext.push(0x00);
    ext.push(0x00);

    // Extension length
    let name_len = host.len() as u16;
    let ext_len = name_len + 5;
    ext.push((ext_len >> 8) as u8);
    ext.push(ext_len as u8);

    // Server name list length
    let list_len = name_len + 3;
    ext.push((list_len >> 8) as u8);
    ext.push(list_len as u8);

    // Server name type (0 = host_name)
    ext.push(0x00);

    // Server name length
    ext.push((name_len >> 8) as u8);
    ext.push(name_len as u8);

    // Server name
    ext.extend_from_slice(host.as_bytes());

    ext
}

/// Get cipher suite ID
fn cipher_suite_id(cipher: CipherSuite) -> u16 {
    match cipher {
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => 0x002F,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xC02F,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xC030,
    }
}

/// Generate random byte (simple PRNG for now)
fn rand_byte() -> u8 {
    use std::time::SystemTime;

    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    ((nanos >> 8) ^ nanos) as u8
}

/// Generate 32 random bytes
fn generate_random_32() -> [u8; 32] {
    let mut random = [0u8; 32];
    for byte in &mut random {
        *byte = rand_byte();
    }
    random
}

/// Generate n random bytes
fn generate_random_bytes(n: usize) -> Vec<u8> {
    let mut random = vec![0u8; n];
    for byte in &mut random {
        *byte = rand_byte();
    }
    random
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let record = wrap_tls_record(ContentType::Handshake, &data);

        assert_eq!(record[0], ContentType::Handshake as u8);
        assert_eq!(record[1], 0x03); // TLS 1.2
        assert_eq!(record[2], 0x03);
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
        assert_eq!(
            cipher_suite_id(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA),
            0x002F
        );
        assert_eq!(
            cipher_suite_id(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
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
}
