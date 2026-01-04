//! TLS record layer encryption and decryption
//!
//! Handles encrypted record processing for:
//! - TLS 1.0/1.1 CBC mode with MAC-then-encrypt
//! - TLS 1.2 AES-GCM with explicit nonce
//! - TLS 1.3 AES-GCM with XOR nonce construction

use super::super::cipher::{
    cipher_suite_is_cbc, cipher_suite_is_gcm, cipher_suite_is_supported, cipher_suite_is_tls13,
    cipher_suite_mac_algorithm,
};
use super::super::helpers::{compute_record_mac, generate_random_bytes, wrap_tls_record};
use super::super::types::ContentType;

use crate::crypto::aes;
use crate::crypto::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::protocols::gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};

use super::TlsStream;

impl TlsStream {
    /// Send TLS record with optional encryption
    pub(super) fn send_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        encrypt: bool,
    ) -> Result<(), String> {
        use std::io::Write;

        let record = if encrypt {
            self.encrypt_record(content_type, payload)?
        } else {
            wrap_tls_record(content_type, payload, self.record_version())
        };

        self.stream
            .write_all(&record)
            .map_err(|e| format!("Failed to send record: {}", e))
    }

    /// Encrypt a TLS record
    ///
    /// Supports:
    /// - TLS 1.3 AEAD with inner content type
    /// - TLS 1.2 AES-GCM with explicit nonce
    /// - TLS 1.0/1.1/1.2 AES-CBC with MAC-then-encrypt
    pub(super) fn encrypt_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        if !cipher_suite_is_supported(cipher) {
            return Err(format!(
                "Cipher suite {:?} not supported for TLS write path",
                cipher
            ));
        }

        let record_version = self.record_version();

        if cipher_suite_is_tls13(cipher) {
            self.encrypt_tls13_record(content_type, payload, record_version)
        } else if cipher_suite_is_gcm(cipher) {
            self.encrypt_gcm_record(content_type, payload, record_version)
        } else if cipher_suite_is_cbc(cipher) {
            self.encrypt_cbc_record(content_type, payload, record_version)
        } else {
            Err(format!(
                "Cipher suite {:?} is not implemented for encryption",
                cipher
            ))
        }
    }

    /// Encrypt TLS 1.3 record with inner content type
    fn encrypt_tls13_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        record_version: (u8, u8),
    ) -> Result<Vec<u8>, String> {
        let cipher = self.negotiated_cipher_suite.unwrap();

        let key_bytes = self
            .client_write_key
            .as_ref()
            .ok_or("TLS 1.3 client write key not available")?;
        let iv = self
            .client_write_iv
            .as_ref()
            .ok_or("TLS 1.3 client write IV not available")?;

        if iv.len() != 12 {
            return Err("TLS 1.3 expected 12-byte IV for client records".to_string());
        }

        // XOR nonce with sequence number
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv);
        let seq_bytes = self.client_sequence.to_be_bytes();
        for (i, b) in seq_bytes.iter().enumerate() {
            nonce[12 - 8 + i] ^= b;
        }

        // Build inner plaintext with content type suffix
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type as u8);

        let ciphertext_len = inner.len() + 16;
        if ciphertext_len > u16::MAX as usize {
            return Err("TLS 1.3 record too large for AEAD length field".to_string());
        }

        // Build AAD (outer content type + version + length)
        let outer_type = ContentType::ApplicationData;
        let aad = vec![
            outer_type as u8,
            record_version.0,
            record_version.1,
            (ciphertext_len >> 8) as u8,
            (ciphertext_len & 0xff) as u8,
        ];

        let ciphertext = match key_bytes.len() {
            16 => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&key_bytes[..16]);
                aes128_gcm_encrypt(&key, &nonce, &inner, &aad)
            }
            32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes[..32]);
                aes256_gcm_encrypt(&key, &nonce, &aad, &inner)
            }
            other => {
                return Err(format!(
                    "Unsupported AES-GCM key size {} for cipher {:?}",
                    other, cipher
                ))
            }
        };

        // Build record
        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.push(outer_type as u8);
        record.push(record_version.0);
        record.push(record_version.1);
        record.push((ciphertext.len() >> 8) as u8);
        record.push((ciphertext.len() & 0xff) as u8);
        record.extend_from_slice(&ciphertext);

        self.client_sequence = self.client_sequence.wrapping_add(1);

        Ok(record)
    }

    /// Encrypt TLS 1.2 AES-GCM record with explicit nonce
    fn encrypt_gcm_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        record_version: (u8, u8),
    ) -> Result<Vec<u8>, String> {
        let cipher = self.negotiated_cipher_suite.unwrap();

        let key_bytes = self
            .client_write_key
            .as_ref()
            .ok_or("Client write key not available")?;
        let fixed_iv = self
            .client_write_iv
            .as_ref()
            .ok_or("Client write IV not available")?;

        if fixed_iv.len() != 4 {
            return Err("Invalid fixed IV length for GCM cipher".to_string());
        }

        // Build nonce: 4 bytes fixed IV + 8 bytes explicit (sequence)
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&fixed_iv[..4]);
        let explicit_nonce = self.client_sequence.to_be_bytes();
        nonce[4..].copy_from_slice(&explicit_nonce);

        let plaintext_len = payload.len();
        if plaintext_len > u16::MAX as usize {
            return Err("TLS record too large for AEAD length field".to_string());
        }

        // Build AAD: seq || type || version || plaintext_len
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.client_sequence.to_be_bytes());
        aad.push(content_type as u8);
        aad.push(record_version.0);
        aad.push(record_version.1);
        aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

        self.debug_log("gcm_client_nonce", &nonce);
        self.debug_log("gcm_client_aad", &aad);
        self.debug_log("gcm_client_plain", payload);

        let ciphertext = match key_bytes.len() {
            16 => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&key_bytes[..16]);
                aes128_gcm_encrypt(&key, &nonce, payload, &aad)
            }
            32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes[..32]);
                aes256_gcm_encrypt(&key, &nonce, &aad, payload)
            }
            other => {
                return Err(format!(
                    "Unsupported AES-GCM key size {} for cipher {:?}",
                    other, cipher
                ))
            }
        };

        // Fragment: explicit_nonce || ciphertext || tag
        let mut fragment = Vec::with_capacity(explicit_nonce.len() + ciphertext.len());
        fragment.extend_from_slice(&explicit_nonce);
        fragment.extend_from_slice(&ciphertext);

        let payload_len = fragment.len() as u16;
        let mut record = Vec::with_capacity(5 + fragment.len());
        record.push(content_type as u8);
        record.push(record_version.0);
        record.push(record_version.1);
        record.push((payload_len >> 8) as u8);
        record.push(payload_len as u8);
        record.extend_from_slice(&fragment);

        self.client_sequence = self.client_sequence.wrapping_add(1);

        Ok(record)
    }

    /// Encrypt TLS 1.0/1.1/1.2 AES-CBC record with MAC-then-encrypt
    fn encrypt_cbc_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
        record_version: (u8, u8),
    ) -> Result<Vec<u8>, String> {
        use super::super::types::TlsVersion;

        let cipher = self.negotiated_cipher_suite.unwrap();
        let mac_algo = cipher_suite_mac_algorithm(cipher)?;

        let mac_key = self
            .client_write_mac
            .as_ref()
            .ok_or("Client write MAC key not available")?;
        let enc_key = self
            .client_write_key
            .as_ref()
            .ok_or("Client write key not available")?;

        if enc_key.len() != 16 {
            return Err(format!(
                "Unsupported AES key size {} for cipher {:?}",
                enc_key.len(),
                cipher
            ));
        }

        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(enc_key);

        let explicit_iv_mode = matches!(self.config.version, TlsVersion::Tls11 | TlsVersion::Tls12);

        // Compute MAC over plaintext
        let mac = compute_record_mac(
            mac_algo,
            mac_key,
            self.client_sequence,
            content_type,
            record_version,
            payload,
        );

        // Build fragment: plaintext || MAC
        let mut fragment = Vec::with_capacity(payload.len() + mac.len());
        fragment.extend_from_slice(payload);
        fragment.extend_from_slice(&mac);

        let (ciphertext, explicit_iv) = if explicit_iv_mode {
            // TLS 1.1+: Generate random explicit IV
            let explicit_iv = generate_random_bytes(16);
            let mut iv_array = [0u8; 16];
            iv_array.copy_from_slice(&explicit_iv);
            let ciphertext = aes::aes128_cbc_encrypt(&key_array, &iv_array, &fragment);
            (ciphertext, Some(explicit_iv))
        } else {
            // TLS 1.0: Use IV from key material, update with last ciphertext block
            let iv_vec = self
                .client_write_iv
                .as_ref()
                .ok_or("Client write IV not available")?;
            if iv_vec.len() != 16 {
                return Err("Invalid client IV length for TLS 1.0 CBC".to_string());
            }
            let mut iv_array = [0u8; 16];
            iv_array.copy_from_slice(&iv_vec[..16]);
            let ciphertext = aes::aes128_cbc_encrypt(&key_array, &iv_array, &fragment);
            if ciphertext.len() < 16 {
                return Err("TLS 1.0 CBC ciphertext too short".to_string());
            }
            // Update IV to last ciphertext block (CBC chaining)
            let last_block = &ciphertext[ciphertext.len() - 16..];
            self.client_write_iv = Some(last_block.to_vec());
            (ciphertext, None)
        };

        let explicit_len = explicit_iv.as_ref().map_or(0, |v| v.len());
        let payload_len = explicit_len + ciphertext.len();

        let mut record = Vec::with_capacity(5 + payload_len);
        record.push(content_type as u8);
        record.push(record_version.0);
        record.push(record_version.1);
        record.push((payload_len >> 8) as u8);
        record.push(payload_len as u8);
        if let Some(explicit_iv) = explicit_iv {
            record.extend_from_slice(&explicit_iv);
        }
        record.extend_from_slice(&ciphertext);

        self.client_sequence = self.client_sequence.wrapping_add(1);

        Ok(record)
    }

    /// Decrypt a TLS record payload
    pub(super) fn decrypt_record_payload(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        if !cipher_suite_is_supported(cipher) {
            return Err(format!(
                "Cipher suite {:?} not supported for TLS read path",
                cipher
            ));
        }

        if cipher_suite_is_tls13(cipher) {
            self.decrypt_tls13_record(content_type, payload)
        } else if cipher_suite_is_gcm(cipher) {
            self.decrypt_gcm_record(content_type, payload)
        } else if cipher_suite_is_cbc(cipher) {
            self.decrypt_cbc_record(content_type, payload)
        } else {
            Err(format!(
                "Cipher suite {:?} is not implemented for decryption",
                cipher
            ))
        }
    }

    /// Decrypt TLS 1.3 record (inner content type + padding removal)
    pub(super) fn decrypt_tls13_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        if payload.len() < 16 {
            return Err("TLS 1.3 record too short".to_string());
        }

        let record_version = self.record_version();

        let key = self
            .server_write_key
            .as_ref()
            .ok_or("TLS 1.3 server write key not available")?;
        let iv = self
            .server_write_iv
            .as_ref()
            .ok_or("TLS 1.3 server write IV not available")?;

        if iv.len() != 12 {
            return Err("TLS 1.3 expected 12-byte IV".to_string());
        }

        // XOR nonce with sequence number
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv);
        let seq_bytes = self.server_sequence.to_be_bytes();
        for (i, b) in seq_bytes.iter().enumerate() {
            nonce[12 - 8 + i] ^= b;
        }

        let aad_len = payload.len();
        if aad_len > u16::MAX as usize {
            return Err("TLS 1.3 ciphertext length exceeds maximum record size".to_string());
        }

        let aad = vec![
            content_type as u8,
            record_version.0,
            record_version.1,
            (aad_len >> 8) as u8,
            (aad_len & 0xff) as u8,
        ];

        let mut output = match key.len() {
            16 => {
                let mut key_array = [0u8; 16];
                key_array.copy_from_slice(&key[..16]);
                aes128_gcm_decrypt(&key_array, &nonce, payload, &aad)?
            }
            32 => {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key[..32]);
                aes256_gcm_decrypt(&key_array, &nonce, &aad, payload)?
            }
            other => return Err(format!("TLS 1.3 unsupported GCM key length {}", other)),
        };

        self.server_sequence = self.server_sequence.wrapping_add(1);

        if output.is_empty() {
            return Err("TLS 1.3 plaintext empty".to_string());
        }

        // Extract inner content type (last byte)
        let inner_type = output
            .pop()
            .ok_or("TLS 1.3 plaintext missing content type".to_string())?;

        // Remove padding zeros if present
        if output.last() == Some(&0) && matches!(inner_type, 20 | 21 | 22 | 23) {
            while output.last() == Some(&0) {
                output.pop();
            }
        }

        // Dispatch based on inner content type
        match inner_type {
            21 => {
                // Alert
                if output.len() >= 2 {
                    Err(format!(
                        "Server sent TLS 1.3 alert: level={}, description={}",
                        output[0], output[1]
                    ))
                } else {
                    Err("Server sent TLS 1.3 alert".to_string())
                }
            }
            23 => Ok(output),     // Application data
            20 => Ok(Vec::new()), // ChangeCipherSpec (ignored in TLS 1.3)
            22 => Ok(output),     // Handshake
            other => Err(format!("Unexpected TLS 1.3 inner content type: {}", other)),
        }
    }

    /// Decrypt TLS 1.2 AES-GCM record
    fn decrypt_gcm_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cipher = self.negotiated_cipher_suite.unwrap();

        if payload.len() < 8 + 16 {
            return Err("TLS GCM record too short".to_string());
        }

        let fixed_iv = self
            .server_write_iv
            .as_ref()
            .ok_or("Server write IV not available")?;

        if fixed_iv.len() != 4 {
            return Err("Invalid fixed IV length for GCM cipher".to_string());
        }

        // Extract explicit nonce and build full nonce
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&fixed_iv[..4]);
        let explicit_nonce = &payload[..8];
        nonce[4..].copy_from_slice(explicit_nonce);

        let ciphertext = &payload[8..];
        let record_version = self.record_version();

        // Build AAD
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&self.server_sequence.to_be_bytes());
        aad.push(content_type as u8);
        aad.push(record_version.0);
        aad.push(record_version.1);

        if ciphertext.len() < 16 {
            return Err("TLS GCM record missing authentication tag".to_string());
        }
        let plaintext_len = ciphertext.len() - 16;
        if plaintext_len > u16::MAX as usize {
            return Err("TLS record too large for AEAD length field".to_string());
        }
        aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

        self.debug_log("gcm_server_nonce", &nonce);
        self.debug_log("gcm_server_aad", &aad);
        self.debug_log("gcm_server_cipher", ciphertext);

        let key_bytes = self
            .server_write_key
            .as_ref()
            .ok_or("Server write key not available")?;

        let plaintext = match key_bytes.len() {
            16 => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&key_bytes[..16]);
                aes128_gcm_decrypt(&key, &nonce, ciphertext, &aad)
                    .map_err(|e| format!("AES-128-GCM decrypt failed: {}", e))?
            }
            32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes[..32]);
                aes256_gcm_decrypt(&key, &nonce, &aad, ciphertext)
                    .map_err(|e| format!("AES-256-GCM decrypt failed: {}", e))?
            }
            other => {
                return Err(format!(
                    "Unsupported AES-GCM key size {} for cipher {:?}",
                    other, cipher
                ))
            }
        };

        self.server_sequence = self.server_sequence.wrapping_add(1);
        Ok(plaintext)
    }

    /// Decrypt TLS 1.0/1.1/1.2 AES-CBC record
    fn decrypt_cbc_record(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        use super::super::helpers::constant_time_eq;
        use super::super::types::TlsVersion;

        let cipher = self.negotiated_cipher_suite.unwrap();
        let mac_algo = cipher_suite_mac_algorithm(cipher)?;

        let mac_key = self
            .server_write_mac
            .as_ref()
            .ok_or("Server write MAC key not available")?;
        let enc_key = self
            .server_write_key
            .as_ref()
            .ok_or("Server write key not available")?;

        if enc_key.len() != 16 {
            return Err(format!(
                "Unsupported AES key size {} for cipher {:?}",
                enc_key.len(),
                cipher
            ));
        }

        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(enc_key);

        let explicit_iv_mode = matches!(self.config.version, TlsVersion::Tls11 | TlsVersion::Tls12);
        let record_version = self.record_version();

        let (ciphertext, iv_array_opt) = if explicit_iv_mode {
            if payload.len() < 16 {
                return Err("TLS record payload too short for explicit IV".to_string());
            }
            let explicit_iv = &payload[..16];
            let mut iv_array = [0u8; 16];
            iv_array.copy_from_slice(explicit_iv);
            (&payload[16..], Some(iv_array))
        } else {
            let iv_vec = self
                .server_write_iv
                .as_ref()
                .ok_or("Server write IV not available")?;
            if iv_vec.len() != 16 {
                return Err("Invalid server IV length for TLS 1.0 CBC".to_string());
            }
            let mut iv_array = [0u8; 16];
            iv_array.copy_from_slice(&iv_vec[..16]);
            (payload, Some(iv_array))
        };

        let iv_array = iv_array_opt.expect("IV should always be set");
        if ciphertext.is_empty() {
            return Err("TLS record missing ciphertext".to_string());
        }

        let plaintext = aes::aes128_cbc_decrypt(&key_array, &iv_array, ciphertext)?;
        let mac_len = mac_algo.mac_len();

        if plaintext.len() < mac_len {
            return Err("TLS plaintext shorter than MAC length".to_string());
        }

        let data_len = plaintext.len() - mac_len;
        let (data, received_mac) = plaintext.split_at(data_len);

        // Verify MAC
        let expected_mac = compute_record_mac(
            mac_algo,
            mac_key,
            self.server_sequence,
            content_type,
            record_version,
            data,
        );

        if !constant_time_eq(&expected_mac, received_mac) {
            return Err("TLS record MAC mismatch".to_string());
        }

        // Update IV for TLS 1.0 CBC chaining
        if !explicit_iv_mode {
            if ciphertext.len() < 16 {
                return Err("TLS 1.0 CBC ciphertext too short".to_string());
            }
            let last_block = &ciphertext[ciphertext.len() - 16..];
            self.server_write_iv = Some(last_block.to_vec());
        }

        self.server_sequence = self.server_sequence.wrapping_add(1);

        Ok(data.to_vec())
    }
}
