use super::utils::{
  build_digest_info_sha1, build_digest_info_sha256, certificate_matches_host,
  chain_has_trusted_root, compute_ja3_from_client_hello, compute_ja3s_from_server_hello,
  der_to_pem, extract_public_key_from_cert, extract_tbs_and_signature,
  parse_server_hello_extensions, sha256_fingerprint_hex, verify_certificate_signature,
};
use super::*;

impl Tls12Client {
  // Build supported_groups extension (RFC 8422 Section 5.1.1)
  // Advertises which elliptic curves we support
  fn build_supported_groups_extension() -> Vec<u8> {
    let mut ext = Vec::new();

    // Extension type: supported_groups (10)
    ext.extend_from_slice(&TLS_EXT_SUPPORTED_GROUPS.to_be_bytes());

    // Extension length (to be filled)
    let ext_len_pos = ext.len();
    ext.extend_from_slice(&[0, 0]);
    let ext_start = ext.len();

    // Supported Groups List Length (2 bytes for one curve)
    ext.extend_from_slice(&[0, 2]);

    // secp256r1 (P-256) = 23
    ext.extend_from_slice(&[0, 23]);

    // Fix extension length
    let ext_len = (ext.len() - ext_start) as u16;
    ext[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

    ext
  }

  // Build ec_point_formats extension (RFC 8422 Section 5.1.2)
  // Advertises which point formats we support
  fn build_ec_point_formats_extension() -> Vec<u8> {
    let mut ext = Vec::new();

    // Extension type: ec_point_formats (11)
    ext.extend_from_slice(&TLS_EXT_EC_POINT_FORMATS.to_be_bytes());

    // Extension length (to be filled)
    let ext_len_pos = ext.len();
    ext.extend_from_slice(&[0, 0]);
    let ext_start = ext.len();

    // EC Point Formats Length (1 format)
    ext.push(1);

    // uncompressed (0)
    ext.push(0);

    // Fix extension length
    let ext_len = (ext.len() - ext_start) as u16;
    ext[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

    ext
  }

  pub(super) fn build_client_hello(&self) -> Vec<u8> {
    let mut message = Vec::new();

    message.push(TLS_HANDSHAKE_CLIENT_HELLO);
    let length_pos = message.len();
    message.extend_from_slice(&[0, 0, 0]);

    message.push(TLS_VERSION_MAJOR);
    message.push(TLS_VERSION_MINOR);
    message.extend_from_slice(&self.client_random);

    // Session id
    message.push(0);

    // Cipher suites: advertise offered suites
    let cipher_suites = if self.offered_cipher_suites.is_empty() {
      SUPPORTED_CIPHER_SUITES
    } else {
      self.offered_cipher_suites.as_slice()
    };

    let cipher_count = cipher_suites.len() as u16;
    let cipher_bytes = cipher_count * 2;
    message.extend_from_slice(&cipher_bytes.to_be_bytes());
    for &cipher_suite in cipher_suites {
      message.extend_from_slice(&cipher_suite.to_be_bytes());
    }

    // Compression (null only)
    message.push(1);
    message.push(0);

    // Extensions
    let ext_len_pos = message.len();
    message.extend_from_slice(&[0, 0]);
    let ext_start = message.len();

    // SNI extension
    let server_name_bytes = self.server_name.as_bytes();
    let host_len = server_name_bytes.len() as u16;
    let server_name_list_len = host_len + 3;

    message.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
    message.extend_from_slice(&(server_name_list_len + 2).to_be_bytes());
    message.extend_from_slice(&server_name_list_len.to_be_bytes());
    message.push(0); // host_name
    message.extend_from_slice(&host_len.to_be_bytes());
    message.extend_from_slice(server_name_bytes);

    // Add ECDHE extensions for modern cipher suites
    message.extend_from_slice(&Self::build_supported_groups_extension());
    message.extend_from_slice(&Self::build_ec_point_formats_extension());

    let ext_len = (message.len() - ext_start) as u16;
    message[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_len.to_be_bytes());

    let msg_len = (message.len() - 4) as u32;
    message[length_pos..length_pos + 3].copy_from_slice(&msg_len.to_be_bytes()[1..]);

    message
  }

  pub(super) fn parse_server_hello(&mut self, data: &[u8]) -> Result<(), String> {
    if data.len() < 4 + 34 {
      return Err("ServerHello too short".to_string());
    }

    let mut offset = 4; // skip handshake header

    if data[offset] != TLS_VERSION_MAJOR || data[offset + 1] != TLS_VERSION_MINOR {
      return Err("Server negotiated unsupported TLS version".to_string());
    }
    offset += 2;

    self
      .server_random
      .copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    if offset >= data.len() {
      return Err("ServerHello missing session id length".to_string());
    }
    let session_id_len = data[offset] as usize;
    offset += 1;

    if offset + session_id_len > data.len() {
      return Err("ServerHello truncated while reading session id".to_string());
    }
    offset += session_id_len;

    if offset + 2 > data.len() {
      return Err("ServerHello missing cipher suite".to_string());
    }
    let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
    self.selected_cipher_suite = Some(cipher_suite);
    offset += 2;

    if offset >= data.len() {
      return Err("ServerHello missing compression method".to_string());
    }
    offset += 1; // compression

    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut ec_formats = Vec::new();

    if offset + 2 <= data.len() {
      let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
      offset += 2;
      if offset + ext_len > data.len() {
        return Err("ServerHello extensions truncated".to_string());
      }
      let ext_slice = &data[offset..offset + ext_len];
      let (ext_ids, group_ids, format_ids) = parse_server_hello_extensions(ext_slice);
      extensions = ext_ids;
      groups = group_ids;
      ec_formats = format_ids;
    }

    if self.ja3s.is_none() {
      let version_code = u16::from_be_bytes([TLS_VERSION_MAJOR, TLS_VERSION_MINOR]);
      let (raw, hash) = compute_ja3s_from_server_hello(
        version_code,
        cipher_suite,
        &extensions,
        &groups,
        &ec_formats,
      );
      self.ja3s_raw = Some(raw);
      self.ja3s = Some(hash);
    }

    Ok(())
  }

  pub(super) fn parse_certificate_chain(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if data.len() < 7 {
      return Err("Certificate message too short".to_string());
    }

    let mut offset = 4;
    if offset + 3 > data.len() {
      return Err("Certificate list length missing".to_string());
    }
    let cert_list_len = ((data[offset] as usize) << 16)
      | ((data[offset + 1] as usize) << 8)
      | (data[offset + 2] as usize);
    offset += 3;

    if data.len() < offset + cert_list_len {
      return Err("Certificate message truncated".to_string());
    }

    let list_end = offset + cert_list_len;
    let mut certificates = Vec::new();

    while offset < list_end {
      if offset + 3 > data.len() {
        return Err("Certificate entry truncated".to_string());
      }

      let cert_len = ((data[offset] as usize) << 16)
        | ((data[offset + 1] as usize) << 8)
        | (data[offset + 2] as usize);
      offset += 3;

      if offset + cert_len > data.len() {
        return Err("Certificate entry length exceeds message boundary".to_string());
      }

      certificates.push(data[offset..offset + cert_len].to_vec());
      offset += cert_len;
    }

    Ok(certificates)
  }

  /// Parse ServerKeyExchange message for ECDHE (RFC 8422 Section 5.4)
  pub(super) fn parse_server_key_exchange(&mut self, data: &[u8]) -> Result<(), String> {
    // ServerKeyExchange format for ECDHE:
    // - ECCurveType (1 byte): 3 = named_curve
    // - NamedCurve (2 bytes): 23 = secp256r1 (P-256)
    // - Public key length (1 byte)
    // - Public key (65 bytes for uncompressed P-256 point)
    // - Signature (RSA signature over params)

    if data.len() < 8 {
      return Err("ServerKeyExchange message too short".to_string());
    }

    let mut offset = 4; // Skip handshake header

    // Parse ECCurveType
    let curve_type = data[offset];
    offset += 1;
    if curve_type != 3 {
      return Err(format!(
        "Unsupported ECCurveType: {} (expected 3 for named_curve)",
        curve_type
      ));
    }

    // Parse NamedCurve
    let named_curve = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    if named_curve != 23 {
      return Err(format!(
        "Unsupported NamedCurve: {} (expected 23 for secp256r1/P-256)",
        named_curve
      ));
    }

    // Parse public key length
    if offset >= data.len() {
      return Err("ServerKeyExchange truncated at public key length".to_string());
    }
    let public_key_len = data[offset] as usize;
    offset += 1;

    if public_key_len != 65 {
      return Err(format!(
        "Unexpected ECDH public key length: {} (expected 65 for uncompressed P-256)",
        public_key_len
      ));
    }

    // Parse public key (uncompressed point: 0x04 || x || y)
    if offset + public_key_len > data.len() {
      return Err("ServerKeyExchange truncated at public key data".to_string());
    }

    let public_key_bytes = &data[offset..offset + public_key_len];
    let server_public_key = P256Point::from_uncompressed_bytes(public_key_bytes)
      .map_err(|e| format!("Failed to parse server ECDH public key: {}", e))?;

    offset += public_key_len;

    let params_end = offset;

    if offset + 2 > data.len() {
      return Err("ServerKeyExchange missing signature algorithms".to_string());
    }

    let hash_alg = data[offset];
    let sig_alg = data[offset + 1];
    offset += 2;

    if offset + 2 > data.len() {
      return Err("ServerKeyExchange truncated before signature length".to_string());
    }
    let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + sig_len > data.len() {
      return Err("ServerKeyExchange signature exceeds message boundary".to_string());
    }

    let signature = &data[offset..offset + sig_len];

    // Section 7.4.3 of RFC 5246: signed_params =
    // client_random || server_random || ServerECDHParams
    let mut signed_params = Vec::with_capacity(64 + (params_end - 4));
    signed_params.extend_from_slice(&self.client_random);
    signed_params.extend_from_slice(&self.server_random);
    signed_params.extend_from_slice(&data[4..params_end]);

    match sig_alg {
      1 => {
        // RSA signatures
        let server_key = self.server_public_key.as_ref().ok_or_else(|| {
          "Server RSA public key not available for signature verification".to_string()
        })?;

        let digest_info = match hash_alg {
          2 => {
            // SHA-1 (legacy but still required for interoperability)
            let hash = sha1(&signed_params);
            build_digest_info_sha1(&hash)
          }
          4 => {
            // SHA-256
            let hash = sha256(&signed_params);
            build_digest_info_sha256(&hash)
          }
          other => {
            return Err(format!(
              "Unsupported hash algorithm {} in ServerKeyExchange",
              other
            ))
          }
        };

        server_key
          .verify_pkcs1_v15(&digest_info, signature)
          .map_err(|e| format!("ServerKeyExchange signature verification failed: {}", e))?;
      }
      other => {
        return Err(format!(
          "Unsupported signature algorithm {} in ServerKeyExchange",
          other
        ));
      }
    }

    // Store server's ECDH public key for later use
    self.server_ecdh_public_key = Some(server_public_key);

    Ok(())
  }

  pub(super) fn rsa_encrypt_premaster(
    &self,
    public_key: &RsaPublicKey,
    premaster: &[u8],
  ) -> Result<Vec<u8>, String> {
    public_key
      .encrypt_pkcs1v15(premaster)
      .map_err(|e| format!("RSA encryption failed: {}", e))
  }

  pub(super) fn generate_client_random(&mut self) -> Result<(), String> {
    let timestamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_else(|_| Duration::from_secs(0))
      .as_secs() as u32;
    self.client_random[0..4].copy_from_slice(&timestamp.to_be_bytes());
    self
      .rng
      .fill_bytes(&mut self.client_random[4..])
      .map_err(|e| format!("RNG failure: {}", e))?;
    Ok(())
  }

  pub(super) fn generate_premaster_secret(&mut self) -> Result<Vec<u8>, String> {
    let mut secret = vec![TLS_VERSION_MAJOR, TLS_VERSION_MINOR];
    let mut remainder = vec![0u8; 46];
    self
      .rng
      .fill_bytes(&mut remainder)
      .map_err(|e| format!("RNG failure: {}", e))?;
    secret.extend_from_slice(&remainder);
    Ok(secret)
  }

  pub(super) fn compute_master_secret(&mut self, premaster_secret: &[u8]) -> Result<(), String> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(&self.client_random);
    seed.extend_from_slice(&self.server_random);

    let master_secret = tls12_prf(premaster_secret, b"master secret", &seed, 48);
    self.master_secret = Some(master_secret);
    self.derive_keys()
  }

  fn derive_keys(&mut self) -> Result<(), String> {
    let master_secret = self
      .master_secret
      .as_ref()
      .ok_or_else(|| "Master secret not derived".to_string())?;

    let cipher_suite = self
      .selected_cipher_suite
      .ok_or_else(|| "Cipher suite not set".to_string())?;

    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(&self.server_random);
    seed.extend_from_slice(&self.client_random);

    // GCM uses different key material: no MAC keys, but 4-byte fixed IVs
    // CBC uses 32-byte MAC keys and 16-byte IVs
    let key_block_len = if is_gcm_cipher(cipher_suite) {
      // GCM: 16-byte client key + 16-byte server key + 4-byte client IV + 4-byte server IV
      40
    } else {
      // CBC: 32-byte client MAC + 32-byte server MAC + 16-byte client key + 16-byte server key + 16-byte client IV + 16-byte server IV
      128
    };

    let key_block = tls12_prf(master_secret, b"key expansion", &seed, key_block_len);
    let mut offset = 0;

    if is_gcm_cipher(cipher_suite) {
      // GCM mode: no MAC keys
      self.client_write_mac = None;
      self.server_write_mac = None;

      // Client write key (16 bytes)
      let mut client_key = [0u8; 16];
      client_key.copy_from_slice(&key_block[offset..offset + 16]);
      self.client_write_key = Some(client_key);
      offset += 16;

      // Server write key (16 bytes)
      let mut server_key = [0u8; 16];
      server_key.copy_from_slice(&key_block[offset..offset + 16]);
      self.server_write_key = Some(server_key);
      offset += 16;

      // Client write IV (4 bytes fixed, will be extended to 12 bytes with explicit nonce)
      let mut client_iv = [0u8; 16];
      client_iv[..4].copy_from_slice(&key_block[offset..offset + 4]);
      self.client_write_iv = Some(client_iv);
      offset += 4;

      // Server write IV (4 bytes fixed)
      let mut server_iv = [0u8; 16];
      server_iv[..4].copy_from_slice(&key_block[offset..offset + 4]);
      self.server_write_iv = Some(server_iv);
    } else {
      // CBC mode: has MAC keys
      let mut client_mac = [0u8; 32];
      client_mac.copy_from_slice(&key_block[offset..offset + 32]);
      self.client_write_mac = Some(client_mac);
      offset += 32;

      let mut server_mac = [0u8; 32];
      server_mac.copy_from_slice(&key_block[offset..offset + 32]);
      self.server_write_mac = Some(server_mac);
      offset += 32;

      let mut client_key = [0u8; 16];
      client_key.copy_from_slice(&key_block[offset..offset + 16]);
      self.client_write_key = Some(client_key);
      offset += 16;

      let mut server_key = [0u8; 16];
      server_key.copy_from_slice(&key_block[offset..offset + 16]);
      self.server_write_key = Some(server_key);
      offset += 16;

      let mut client_iv = [0u8; 16];
      client_iv.copy_from_slice(&key_block[offset..offset + 16]);
      self.client_write_iv = Some(client_iv);
      offset += 16;

      let mut server_iv = [0u8; 16];
      server_iv.copy_from_slice(&key_block[offset..offset + 16]);
      self.server_write_iv = Some(server_iv);
    }

    Ok(())
  }

  /// Build ClientKeyExchange for RSA key exchange
  pub(super) fn build_client_key_exchange_rsa(&self, encrypted_pms: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);

    let length = (encrypted_pms.len() + 2) as u32;
    message.extend_from_slice(&length.to_be_bytes()[1..]);

    let pms_len = encrypted_pms.len() as u16;
    message.extend_from_slice(&pms_len.to_be_bytes());
    message.extend_from_slice(encrypted_pms);
    message
  }

  /// Build ClientKeyExchange for ECDHE key exchange (RFC 8422 Section 5.7)
  pub(super) fn build_client_key_exchange_ecdh(&self, public_key: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);

    // Message length: 1 byte (length prefix) + public key length
    let length = (1 + public_key.len()) as u32;
    message.extend_from_slice(&length.to_be_bytes()[1..]);

    // Public key with length prefix (1 byte)
    message.push(public_key.len() as u8);
    message.extend_from_slice(public_key);

    message
  }

  fn compute_finished_verify_data(&self, is_client: bool) -> Result<Vec<u8>, String> {
    let master_secret = self
      .master_secret
      .as_ref()
      .ok_or_else(|| "Master secret not derived".to_string())?;

    let label = if is_client {
      b"client finished"
    } else {
      b"server finished"
    };

    let handshake_hash = sha256(&self.handshake_messages);
    Ok(tls12_prf(master_secret, label, &handshake_hash, 12))
  }

  pub(super) fn build_finished(&self, is_client: bool) -> Result<Vec<u8>, String> {
    let verify_data = self.compute_finished_verify_data(is_client)?;
    let mut message = Vec::with_capacity(16);
    message.push(TLS_HANDSHAKE_FINISHED);
    message.extend_from_slice(&[0, 0, 12]);
    message.extend_from_slice(&verify_data);
    Ok(message)
  }

  pub(super) fn verify_finished(&self, is_client: bool, message: &[u8]) -> Result<(), String> {
    if message.len() != 16 || message[0] != TLS_HANDSHAKE_FINISHED {
      return Err("Malformed Finished message".to_string());
    }
    let expected = self.compute_finished_verify_data(is_client)?;
    let received = &message[4..16];
    if expected.as_slice() != received {
      return Err("TLS Finished verify_data mismatch".to_string());
    }
    Ok(())
  }
}
