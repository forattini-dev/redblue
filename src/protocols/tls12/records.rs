use super::*;

impl Tls12Client {
  pub(super) fn send_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), String> {
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(content_type);
    record.push(TLS_VERSION_MAJOR);
    record.push(TLS_VERSION_MINOR);
    let length = data.len() as u16;
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(data);

    self
      .stream
      .write_all(&record)
      .map_err(|e| format!("TLS write failed: {}", e))
  }

  pub(super) fn send_encrypted_record(
    &mut self,
    content_type: u8,
    data: &[u8],
  ) -> Result<(), String> {
    let key = self
      .client_write_key
      .ok_or_else(|| "Encryption key not available".to_string())?;
    let iv = self
      .client_write_iv
      .ok_or_else(|| "Encryption IV not available".to_string())?;

    let cipher_suite = self
      .selected_cipher_suite
      .ok_or_else(|| "No cipher suite selected".to_string())?;

    let ciphertext = if is_gcm_cipher(cipher_suite) {
      // GCM mode: AEAD encryption
      // Nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes = sequence number)
      let mut nonce = [0u8; 12];
      nonce[..4].copy_from_slice(&iv[..4]); // Fixed IV (4 bytes from key derivation)
      nonce[4..12].copy_from_slice(&self.client_seq.to_be_bytes()); // Explicit nonce (sequence number)

      // AAD = seq_num || record_type || version || length
      let mut aad = Vec::with_capacity(13);
      aad.extend_from_slice(&self.client_seq.to_be_bytes());
      aad.push(content_type);
      aad.push(TLS_VERSION_MAJOR);
      aad.push(TLS_VERSION_MINOR);
      aad.extend_from_slice(&(data.len() as u16).to_be_bytes());

      // GCM encrypt returns: explicit_nonce || ciphertext || tag
      // We need to prepend the explicit nonce to the output
      let encrypted = aes128_gcm_encrypt(&key, &nonce, data, &aad);
      let mut result = Vec::with_capacity(8 + encrypted.len());
      result.extend_from_slice(&self.client_seq.to_be_bytes()); // Explicit nonce
      result.extend_from_slice(&encrypted); // Ciphertext + tag
      result
    } else if is_cbc_cipher(cipher_suite) {
      // CBC mode: MAC-then-encrypt
      let mac_key = self
        .client_write_mac
        .ok_or_else(|| "MAC key not available".to_string())?;
      let mut mac_input = Vec::with_capacity(13 + data.len());
      mac_input.extend_from_slice(&self.client_seq.to_be_bytes());
      mac_input.push(content_type);
      mac_input.push(TLS_VERSION_MAJOR);
      mac_input.push(TLS_VERSION_MINOR);
      mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
      mac_input.extend_from_slice(data);
      let mac = hmac_sha256(&mac_key, &mac_input);
      let mut plaintext = Vec::with_capacity(data.len() + mac.len());
      plaintext.extend_from_slice(data);
      plaintext.extend_from_slice(&mac);
      aes128_cbc_encrypt(&key, &iv, &plaintext)
    } else {
      return Err(format!("Unsupported cipher suite: 0x{:04X}", cipher_suite));
    };

    self.client_seq = self.client_seq.wrapping_add(1);
    self.send_record(content_type, &ciphertext)
  }

  pub(super) fn receive_record(&mut self) -> Result<(u8, Vec<u8>), RecordReadError> {
    let mut header = [0u8; 5];
    if let Err(e) = self.stream.read_exact(&mut header) {
      if matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
      ) {
        return Err(RecordReadError::ConnectionClosed);
      }
      return Err(RecordReadError::Io(e));
    }

    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut data = vec![0u8; length];
    if let Err(e) = self.stream.read_exact(&mut data) {
      if matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
      ) {
        return Err(RecordReadError::ConnectionClosed);
      }
      return Err(RecordReadError::Io(e));
    }

    Ok((header[0], data))
  }

  pub(super) fn receive_handshake_message(&mut self, expected_type: u8) -> Result<Vec<u8>, String> {
    let (content_type, payload) = match self.receive_record() {
      Ok(record) => record,
      Err(RecordReadError::ConnectionClosed) => {
        return Err("Connection closed during handshake".to_string())
      }
      Err(RecordReadError::Io(e)) => return Err(format!("Handshake read failed: {}", e)),
    };

    if content_type == TLS_CONTENT_TYPE_ALERT {
      return Err("Received TLS alert from server".to_string());
    }

    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
      return Err(format!(
        "Unexpected TLS content type during handshake: {}",
        content_type
      ));
    }

    if payload.is_empty() || payload[0] != expected_type {
      return Err("Unexpected handshake message type".to_string());
    }

    self.handshake_messages.extend_from_slice(&payload);
    Ok(payload)
  }

  pub(super) fn receive_encrypted_record(
    &mut self,
    expected_content_type: u8,
  ) -> Result<Vec<u8>, RecordReadError> {
    let (content_type, ciphertext) = self.receive_record()?;

    if content_type != expected_content_type {
      return Err(RecordReadError::ConnectionClosed);
    }

    let key = self
      .server_write_key
      .ok_or_else(|| RecordReadError::ConnectionClosed)?;
    let iv = self
      .server_write_iv
      .ok_or_else(|| RecordReadError::ConnectionClosed)?;

    let cipher_suite = self
      .selected_cipher_suite
      .ok_or_else(|| RecordReadError::ConnectionClosed)?;

    let data = if is_gcm_cipher(cipher_suite) {
      // GCM mode: AEAD decryption
      // Ciphertext format: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)
      if ciphertext.len() < 24 {
        // 8 bytes nonce + 16 bytes tag minimum
        return Err(RecordReadError::Io(io::Error::new(
          io::ErrorKind::InvalidData,
          "GCM record too short",
        )));
      }

      // Extract explicit nonce from the beginning
      let explicit_nonce = &ciphertext[..8];
      let ciphertext_with_tag = &ciphertext[8..];

      // Construct full 12-byte nonce = fixed_iv (4 bytes) || explicit_nonce (8 bytes)
      let mut nonce = [0u8; 12];
      nonce[..4].copy_from_slice(&iv[..4]); // Fixed IV
      nonce[4..12].copy_from_slice(explicit_nonce); // Explicit nonce from record

      // AAD = seq_num || record_type || version || length
      let plaintext_len = ciphertext_with_tag.len().saturating_sub(16); // Subtract tag
      let mut aad = Vec::with_capacity(13);
      aad.extend_from_slice(&self.server_seq.to_be_bytes());
      aad.push(expected_content_type);
      aad.push(TLS_VERSION_MAJOR);
      aad.push(TLS_VERSION_MINOR);
      aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

      match aes128_gcm_decrypt(&key, &nonce, ciphertext_with_tag, &aad) {
        Ok(data) => data,
        Err(err) => {
          return Err(RecordReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            err,
          )))
        }
      }
    } else if is_cbc_cipher(cipher_suite) {
      // CBC mode: Decrypt then verify MAC
      let mac_key = self
        .server_write_mac
        .ok_or_else(|| RecordReadError::ConnectionClosed)?;
      let plaintext = match aes128_cbc_decrypt(&key, &iv, &ciphertext) {
        Ok(data) => data,
        Err(err) => {
          return Err(RecordReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            err,
          )))
        }
      };
      if plaintext.len() < 32 {
        return Err(RecordReadError::Io(io::Error::new(
          io::ErrorKind::InvalidData,
          "TLS record shorter than MAC",
        )));
      }
      let data_len = plaintext.len() - 32;
      let (data, received_mac) = plaintext.split_at(data_len);
      let mut mac_input = Vec::with_capacity(13 + data.len());
      mac_input.extend_from_slice(&self.server_seq.to_be_bytes());
      mac_input.push(expected_content_type);
      mac_input.push(TLS_VERSION_MAJOR);
      mac_input.push(TLS_VERSION_MINOR);
      mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
      mac_input.extend_from_slice(data);
      let expected_mac = hmac_sha256(&mac_key, &mac_input);
      if expected_mac.as_slice() != received_mac {
        return Err(RecordReadError::Io(io::Error::new(
          io::ErrorKind::InvalidData,
          "TLS record MAC verification failed",
        )));
      }
      data.to_vec()
    } else {
      return Err(RecordReadError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Unsupported cipher suite: 0x{:04X}", cipher_suite),
      )));
    };

    self.server_seq = self.server_seq.wrapping_add(1);
    Ok(data)
  }

  /// Send application data (e.g. HTTP request body) over the encrypted channel.
  pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), String> {
    if self.client_write_key.is_none() {
      return Err("TLS session not established".to_string());
    }
    self.send_encrypted_record(TLS_CONTENT_TYPE_APPLICATION_DATA, data)
  }

  /// Receive application data; returns `Ok(None)` when the peer closes the
  /// connection cleanly (EOF/timeout).
  pub fn receive_application_data(&mut self) -> Result<Option<Vec<u8>>, String> {
    match self.receive_encrypted_record(TLS_CONTENT_TYPE_APPLICATION_DATA) {
      Ok(data) => Ok(Some(data)),
      Err(RecordReadError::ConnectionClosed) => Ok(None),
      Err(RecordReadError::Io(e)) => Err(format!("Failed to read application data: {}", e)),
    }
  }
}
