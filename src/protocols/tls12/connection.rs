use super::utils::{
  build_digest_info_sha1, build_digest_info_sha256, certificate_matches_host,
  chain_has_trusted_root, compute_ja3_from_client_hello, compute_ja3s_from_server_hello,
  der_to_pem, extract_public_key_from_cert, extract_tbs_and_signature,
  parse_server_hello_extensions, sha256_fingerprint_hex, verify_certificate_signature,
};
use super::*;

impl Tls12Client {
  /// Connect using a default 10 second timeout.
  pub fn connect(host: &str, port: u16) -> Result<Self, String> {
    Self::connect_with_timeout(host, port, Duration::from_secs(10))
  }

  /// Connect to the remote endpoint with a caller-provided timeout.
  pub fn connect_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<Self, String> {
    Self::connect_with_timeout_and_cipher_suites(host, port, timeout, SUPPORTED_CIPHER_SUITES)
  }

  pub fn connect_with_timeout_and_cipher_suites(
    host: &str,
    port: u16,
    timeout: Duration,
    cipher_suites: &[u16],
  ) -> Result<Self, String> {
    let timeout = if timeout.is_zero() {
      Duration::from_millis(1)
    } else {
      timeout
    };

    let mut addrs = (host, port)
      .to_socket_addrs()
      .map_err(|e| format!("Failed to resolve {}:{} - {}", host, port, e))?;

    let mut last_err = None;
    let stream = loop {
      match addrs.next() {
        Some(addr) => match TcpStream::connect_timeout(&addr, timeout) {
          Ok(stream) => break stream,
          Err(err) => last_err = Some(err),
        },
        None => {
          return Err(match last_err {
            Some(err) => format!("TCP connect failed: {}", err),
            None => "No addresses resolved for target".to_string(),
          })
        }
      }
    };

    stream
      .set_read_timeout(Some(timeout))
      .map_err(|e| format!("Failed to set read timeout: {}", e))?;
    stream
      .set_write_timeout(Some(timeout))
      .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    let rng =
      SecureRandom::new().map_err(|e| format!("Secure random initialization failed: {}", e))?;

    let mut client = Self {
      stream,
      server_name: host.to_string(),
      client_random: [0u8; 32],
      server_random: [0u8; 32],
      master_secret: None,
      handshake_messages: Vec::new(),
      ja3: None,
      ja3_raw: None,
      ja3s: None,
      ja3s_raw: None,
      client_write_key: None,
      server_write_key: None,
      client_write_iv: None,
      server_write_iv: None,
      client_write_mac: None,
      server_write_mac: None,
      client_seq: 0,
      server_seq: 0,
      selected_cipher_suite: None,
      rng,
      server_cert_chain: Vec::new(),
      peer_certificates: Vec::new(),
      server_public_key: None,
      ecdh_keypair: None,
      server_ecdh_public_key: None,
      offered_cipher_suites: cipher_suites.to_vec(),
    };

    client.generate_client_random()?;
    client.handshake()?;

    Ok(client)
  }

  fn handshake(&mut self) -> Result<(), String> {
    tls_debug!("[DEBUG] Starting TLS handshake");
    let client_hello = self.build_client_hello();
    if self.ja3.is_none() {
      if let Ok((raw, hash)) = compute_ja3_from_client_hello(&client_hello) {
        self.ja3_raw = Some(raw);
        self.ja3 = Some(hash);
      }
    }
    self.handshake_messages.extend_from_slice(&client_hello);
    self.send_record(TLS_CONTENT_TYPE_HANDSHAKE, &client_hello)?;
    tls_debug!("[DEBUG] Sent ClientHello");

    tls_debug!("[DEBUG] Waiting for ServerHello...");
    let server_hello = self.receive_handshake_message(TLS_HANDSHAKE_SERVER_HELLO)?;
    tls_debug!("[DEBUG] Received ServerHello");
    self.parse_server_hello(&server_hello)?;
    tls_debug!(
      "[DEBUG] Parsed ServerHello, cipher suite: 0x{:04X}",
      self.selected_cipher_suite.unwrap_or(0)
    );

    let certificate = self.receive_handshake_message(TLS_HANDSHAKE_CERTIFICATE)?;
    let cert_chain = self.parse_certificate_chain(&certificate)?;
    if cert_chain.is_empty() {
      return Err("Server did not present any certificates".to_string());
    }
    self.server_cert_chain = cert_chain.clone();
    self.peer_certificates = cert_chain
      .iter()
      .map(|der| {
        x509::X509Certificate::from_der(der)
          .map_err(|e| format!("Failed to parse certificate: {}", e))
      })
      .collect::<Result<Vec<_>, _>>()?;
    if let Some(leaf) = self.peer_certificates.first() {
      let (modulus, exponent) = leaf
        .subject_public_key_info
        .rsa_components()
        .map_err(|e| format!("Failed to parse server public key: {}", e))?;
      self.server_public_key = Some(RsaPublicKey::from_components(&modulus, &exponent));
    } else {
      return Err("Server certificate chain is empty".to_string());
    }
    self.verify_peer_certificate()?;

    // For ECDHE cipher suites, receive and parse ServerKeyExchange
    let cipher_suite = self.selected_cipher_suite.unwrap_or(0);
    if is_ecdhe_cipher(cipher_suite) {
      let server_key_exchange =
        self.receive_handshake_message(TLS_HANDSHAKE_SERVER_KEY_EXCHANGE)?;
      self.parse_server_key_exchange(&server_key_exchange)?;

      // Generate client ECDH keypair
      tls_debug!("[DEBUG] Generating client ECDH keypair...");
      self.ecdh_keypair = Some(
        EcdhKeyPair::generate().map_err(|e| format!("Failed to generate ECDH keypair: {}", e))?,
      );
      tls_debug!("[DEBUG] Generated ECDH keypair");
    } else {
      tls_debug!("[DEBUG] RSA cipher detected, skipping ServerKeyExchange");
    }

    tls_debug!("[DEBUG] Waiting for ServerHelloDone...");
    let _server_done = self.receive_handshake_message(TLS_HANDSHAKE_SERVER_HELLO_DONE)?;
    tls_debug!("[DEBUG] Received ServerHelloDone");

    // Generate premaster secret and build ClientKeyExchange
    tls_debug!("[DEBUG] Generating premaster secret...");
    let premaster_secret = if is_ecdhe_cipher(cipher_suite) {
      tls_debug!("[DEBUG] Computing ECDH shared secret...");
      // For ECDHE: compute shared secret from ECDH
      let server_public = self
        .server_ecdh_public_key
        .as_ref()
        .ok_or("Server ECDH public key not received")?;
      let keypair = self
        .ecdh_keypair
        .as_ref()
        .ok_or("ECDH keypair not generated")?;

      let shared_secret = keypair.compute_shared_secret(server_public);
      tls_debug!("[DEBUG] Computed shared secret (32 bytes)");
      shared_secret.to_vec()
    } else {
      tls_debug!("[DEBUG] Generating random premaster secret for RSA...");
      // For RSA: generate random 48-byte premaster secret
      self.generate_premaster_secret()?
    };

    tls_debug!("[DEBUG] Building ClientKeyExchange...");
    let client_key_exchange = if is_ecdhe_cipher(cipher_suite) {
      // For ECDHE: send our public key
      let public_key_bytes = self
        .ecdh_keypair
        .as_ref()
        .ok_or("ECDH keypair not generated")?
        .public_key_bytes();
      tls_debug!(
        "[DEBUG] Building ECDH ClientKeyExchange ({} bytes public key)",
        public_key_bytes.len()
      );
      self.build_client_key_exchange_ecdh(&public_key_bytes)
    } else {
      // For RSA: encrypt premaster secret
      tls_debug!("[DEBUG] Encrypting premaster secret with RSA...");
      let server_key = self
        .server_public_key
        .as_ref()
        .ok_or_else(|| "Server public key not available".to_string())?;
      let encrypted_pms = self.rsa_encrypt_premaster(server_key, &premaster_secret)?;
      tls_debug!(
        "[DEBUG] Building RSA ClientKeyExchange ({} bytes encrypted)",
        encrypted_pms.len()
      );
      self.build_client_key_exchange_rsa(&encrypted_pms)
    };
    self
      .handshake_messages
      .extend_from_slice(&client_key_exchange);
    tls_debug!("[DEBUG] Sending ClientKeyExchange...");
    self.send_record(TLS_CONTENT_TYPE_HANDSHAKE, &client_key_exchange)?;
    tls_debug!("[DEBUG] Sent ClientKeyExchange");

    tls_debug!("[DEBUG] Computing master secret...");
    self.compute_master_secret(&premaster_secret)?;
    tls_debug!("[DEBUG] Computed master secret");

    self.send_record(TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[0x01])?;

    let finished = self.build_finished(true)?;
    self.handshake_messages.extend_from_slice(&finished);
    self.send_encrypted_record(TLS_CONTENT_TYPE_HANDSHAKE, &finished)?;

    let (ccs_type, ccs_payload) = match self.receive_record() {
      Ok(record) => record,
      Err(RecordReadError::ConnectionClosed) => {
        return Err("Connection closed before ChangeCipherSpec".to_string())
      }
      Err(RecordReadError::Io(e)) => return Err(format!("Failed to read ChangeCipherSpec: {}", e)),
    };

    if ccs_type != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC || ccs_payload != [0x01] {
      return Err("Unexpected ChangeCipherSpec payload from server".to_string());
    }

    let server_finished = match self.receive_encrypted_record(TLS_CONTENT_TYPE_HANDSHAKE) {
      Ok(data) => data,
      Err(RecordReadError::ConnectionClosed) => {
        return Err("Connection closed before Finished message".to_string())
      }
      Err(RecordReadError::Io(e)) => return Err(format!("Failed to read Finished message: {}", e)),
    };

    self.verify_finished(false, &server_finished)?;
    self.handshake_messages.extend_from_slice(&server_finished);
    Ok(())
  }
}
