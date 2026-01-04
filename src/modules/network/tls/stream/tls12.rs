//! TLS 1.2 Handshake Implementation
//!
//! Handles the complete TLS 1.2 handshake flow:
//! - Certificate reception and parsing
//! - ServerKeyExchange (ECDHE) processing
//! - ClientKeyExchange (RSA/ECDHE)
//! - Key derivation
//! - Finished message exchange

use super::super::cipher::{
    cipher_suite_is_supported, cipher_suite_key_exchange, cipher_suite_key_sizes,
    cipher_suite_prf_algorithm,
};
use super::super::helpers::{
    compute_p256_shared_secret, constant_time_eq, generate_p256_keypair, generate_random_bytes,
    tls12_handshake_hash, wrap_handshake,
};
use super::super::types::{ContentType, EcdheParameters, HandshakeType, KeyExchange, TlsVersion};

use crate::crypto::md5;
use crate::crypto::prf;
use crate::crypto::rsa::extract_public_key_from_cert;
use crate::crypto::sha1;
use crate::crypto::x25519::{x25519, x25519_public_key};
use crate::protocols::p256::P256Point;
use crate::protocols::x509::X509Certificate;

use super::TlsStream;

impl TlsStream {
    /// Execute the full TLS 1.2 handshake sequence
    pub(super) fn handshake_tls12(&mut self, host: &str) -> Result<(), String> {
        self.send_client_hello(host)?;
        let _server_hello = self.receive_server_hello()?;
        let _certificate = self.receive_certificate()?;
        self.verify_peer_certificate()?;
        self.receive_server_key_exchange_and_done()?;
        self.send_client_key_exchange()?;
        self.derive_session_keys()?;
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.receive_change_cipher_spec()?;
        self.receive_finished()?;
        self.handshake_complete = true;
        Ok(())
    }

    /// Receive and parse server Certificate message
    pub(super) fn receive_certificate(&mut self) -> Result<Vec<u8>, String> {
        let (content_type, record) = self.receive_tls_record()?;

        if content_type != ContentType::Handshake {
            if content_type == ContentType::Alert && record.len() >= 2 {
                return Err(format!(
                    "Server sent alert during Certificate: level={}, description={}",
                    record[0], record[1]
                ));
            }
            return Err(format!("Expected Handshake record, got {:?}", content_type));
        }

        if record.is_empty() {
            return Err("Empty Certificate".to_string());
        }

        self.handshake_messages.extend_from_slice(&record);

        if record.len() < 7 {
            return Err("Certificate message too short".to_string());
        }

        let mut offset = 4;

        let certs_len = ((record[offset] as usize) << 16)
            | ((record[offset + 1] as usize) << 8)
            | (record[offset + 2] as usize);
        offset += 3;

        if offset + certs_len > record.len() {
            return Err("Invalid certificates length".to_string());
        }

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

        let cert_der = record[offset..offset + cert_len].to_vec();

        self.server_certificate = Some(cert_der.clone());
        if self.config.verify_cert {
            let parsed = X509Certificate::from_der(&cert_der)
                .map_err(|e| format!("Failed to parse server certificate: {}", e))?;
            self.server_x509 = Some(parsed);
        }

        Ok(record)
    }

    /// Receive optional ServerKeyExchange and mandatory ServerHelloDone
    pub(super) fn receive_server_key_exchange_and_done(&mut self) -> Result<(), String> {
        let (content_type, record) = self.receive_tls_record()?;
        if content_type != ContentType::Handshake {
            return Err("Expected Handshake record".to_string());
        }
        if record.is_empty() {
            return Err("Empty handshake record from server".to_string());
        }

        let message_type = record[0];
        if message_type == HandshakeType::ServerKeyExchange as u8 {
            self.handshake_messages.extend_from_slice(&record);
            self.parse_server_key_exchange(&record)?;

            let (ct, server_done) = self.receive_tls_record()?;
            if ct != ContentType::Handshake || server_done.is_empty() {
                return Err(format!(
                    "Expected ServerHelloDone after ServerKeyExchange, got {:?}",
                    ct
                ));
            }
            if server_done[0] != HandshakeType::ServerHelloDone as u8 {
                return Err(format!(
                    "Expected ServerHelloDone, got handshake type 0x{:02X}",
                    server_done[0]
                ));
            }
            self.handshake_messages.extend_from_slice(&server_done);
        } else if message_type == HandshakeType::ServerHelloDone as u8 {
            self.handshake_messages.extend_from_slice(&record);
        } else {
            return Err(format!(
                "Unexpected handshake message type 0x{:02X} from server",
                message_type
            ));
        }

        Ok(())
    }

    /// Parse ECDHE ServerKeyExchange and cache server public parameters
    fn parse_server_key_exchange(&mut self, record: &[u8]) -> Result<(), String> {
        if record.len() < 4 + 1 + 2 + 1 {
            return Err("ServerKeyExchange too short".to_string());
        }

        let mut offset = 4;

        let curve_type = record[offset];
        offset += 1;
        if curve_type != 3 {
            return Err(format!(
                "Unsupported curve type {} in ServerKeyExchange",
                curve_type
            ));
        }

        let named_curve = u16::from_be_bytes([record[offset], record[offset + 1]]);
        offset += 2;
        let public_len = record[offset] as usize;
        offset += 1;
        if offset + public_len > record.len() {
            return Err("Truncated ECDHE public key in ServerKeyExchange".to_string());
        }
        let public_bytes = &record[offset..offset + public_len];
        offset += public_len;

        let ecdhe_params = match named_curve {
            23 => {
                let server_point = P256Point::from_uncompressed_bytes(public_bytes)
                    .map_err(|e| format!("Failed to parse server ECDHE public key: {}", e))?;
                self.debug_log("server_ec_public", public_bytes);
                EcdheParameters::P256 {
                    server_public: server_point,
                }
            }
            0x001d => {
                if public_len != 32 {
                    return Err(format!(
                        "Invalid X25519 public key length {} in ServerKeyExchange",
                        public_len
                    ));
                }
                let mut server_public = [0u8; 32];
                server_public.copy_from_slice(public_bytes);
                self.debug_log("server_x25519_public", &server_public);
                EcdheParameters::X25519 { server_public }
            }
            other => {
                return Err(format!(
                    "Unsupported named curve 0x{:04X} in ServerKeyExchange",
                    other
                ))
            }
        };
        self.ecdhe_params = Some(ecdhe_params);

        if offset + 2 > record.len() {
            return Err("Missing signature algorithm in ServerKeyExchange".to_string());
        }
        offset += 2;

        if offset + 2 > record.len() {
            return Err("Missing signature length in ServerKeyExchange".to_string());
        }
        let sig_len = u16::from_be_bytes([record[offset], record[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_len > record.len() {
            return Err("Truncated signature in ServerKeyExchange".to_string());
        }

        Ok(())
    }

    /// Send ClientKeyExchange message
    pub(super) fn send_client_key_exchange(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        match cipher_suite_key_exchange(cipher) {
            KeyExchange::Rsa => self.send_client_key_exchange_rsa(),
            KeyExchange::Ecdhe => self.send_client_key_exchange_ecdhe(),
        }
    }

    fn send_client_key_exchange_rsa(&mut self) -> Result<(), String> {
        let mut pre_master_secret = [0u8; 48];
        let (major, minor) = self.config.version.to_bytes();
        pre_master_secret[0] = major;
        pre_master_secret[1] = minor;

        let random_bytes = generate_random_bytes(46);
        pre_master_secret[2..].copy_from_slice(&random_bytes);

        self.pre_master_secret = Some(pre_master_secret.to_vec());

        let cert_der = self
            .server_certificate
            .as_ref()
            .ok_or("No server certificate received")?;

        let public_key = extract_public_key_from_cert(cert_der)?;
        let encrypted_pms = public_key.encrypt_pkcs1v15(&pre_master_secret)?;

        let mut key_exchange = Vec::new();
        key_exchange.push((encrypted_pms.len() >> 8) as u8);
        key_exchange.push(encrypted_pms.len() as u8);
        key_exchange.extend_from_slice(&encrypted_pms);

        let handshake = wrap_handshake(HandshakeType::ClientKeyExchange, &key_exchange);

        self.handshake_messages.extend_from_slice(&handshake);

        self.send_record(ContentType::Handshake, &handshake, false)?;

        Ok(())
    }

    fn send_client_key_exchange_ecdhe(&mut self) -> Result<(), String> {
        let params = self
            .ecdhe_params
            .as_ref()
            .ok_or("Server ECDHE parameters not received")?;

        let (public_bytes, shared_secret) = match params {
            EcdheParameters::P256 { server_public } => {
                let (private_key, public_bytes) = generate_p256_keypair();
                let shared_secret = compute_p256_shared_secret(&private_key, server_public);
                self.debug_log("client_p256_private", &private_key);
                (public_bytes, shared_secret.to_vec())
            }
            EcdheParameters::X25519 { server_public } => {
                let mut private = [0u8; 32];
                let random = generate_random_bytes(32);
                private.copy_from_slice(&random[..32]);
                self.debug_log("client_x25519_private", &private);
                let public_key = x25519_public_key(&private);
                let shared = x25519(&private, server_public);
                (public_key.to_vec(), shared.to_vec())
            }
        };

        self.debug_log("client_ec_public", &public_bytes);
        self.debug_log("ecdhe_shared_secret", &shared_secret);

        self.pre_master_secret = Some(shared_secret);

        let handshake = wrap_handshake(HandshakeType::ClientKeyExchange, &{
            let mut body = Vec::with_capacity(1 + public_bytes.len());
            body.push(public_bytes.len() as u8);
            body.extend_from_slice(&public_bytes);
            body
        });

        self.handshake_messages.extend_from_slice(&handshake);
        self.send_record(ContentType::Handshake, &handshake, false)?;

        Ok(())
    }

    /// Send ChangeCipherSpec message
    pub(super) fn send_change_cipher_spec(&mut self) -> Result<(), String> {
        let ccs = vec![0x01];
        self.send_record(ContentType::ChangeCipherSpec, &ccs, false)?;
        self.client_encryption_active = true;
        self.client_sequence = 0;

        Ok(())
    }

    /// Send Finished message with verify_data
    pub(super) fn send_finished(&mut self) -> Result<(), String> {
        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or("No master secret available")?;

        let verify_data = match self.config.version {
            TlsVersion::Tls12 => {
                let cipher = self
                    .negotiated_cipher_suite
                    .ok_or("No cipher suite negotiated")?;
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                let handshake_hash = tls12_handshake_hash(&self.handshake_messages, prf_alg);
                let verify_data_full = prf::prf_tls12_with_hash(
                    master_secret,
                    b"client finished",
                    &handshake_hash,
                    12,
                    prf_alg,
                );
                verify_data_full[..12].to_vec()
            }
            TlsVersion::Tls11 | TlsVersion::Tls10 => {
                let md5_hash = md5(&self.handshake_messages);
                let sha1_hash = sha1::sha1(&self.handshake_messages);
                let mut seed = Vec::with_capacity(md5_hash.len() + sha1_hash.len());
                seed.extend_from_slice(&md5_hash);
                seed.extend_from_slice(&sha1_hash);
                let verify_data_full = prf::prf_tls10(master_secret, b"client finished", &seed, 12);
                verify_data_full[..12].to_vec()
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 uses dedicated Finished path"),
        };

        let handshake = wrap_handshake(HandshakeType::Finished, &verify_data);
        self.handshake_messages.extend_from_slice(&handshake);

        self.send_record(ContentType::Handshake, &handshake, true)?;
        Ok(())
    }

    /// Receive ChangeCipherSpec from server
    pub(super) fn receive_change_cipher_spec(&mut self) -> Result<(), String> {
        let (content_type, payload) = self.receive_tls_record()?;
        if content_type != ContentType::ChangeCipherSpec {
            if content_type == ContentType::Alert && payload.len() >= 2 {
                return Err(format!(
                    "Server sent alert instead of ChangeCipherSpec: level={}, description={}",
                    payload[0], payload[1]
                ));
            }
            return Err(format!(
                "Expected ChangeCipherSpec record, got {:?}",
                content_type
            ));
        }
        self.server_encryption_active = true;
        self.server_sequence = 0;
        Ok(())
    }

    /// Receive and verify server Finished message
    pub(super) fn receive_finished(&mut self) -> Result<(), String> {
        let (content_type, record) = self.receive_tls_record()?;
        if content_type != ContentType::Handshake {
            return Err("Expected encrypted Finished handshake".to_string());
        }

        if record.is_empty() || record[0] != HandshakeType::Finished as u8 {
            return Err("Server did not send Finished".to_string());
        }

        if record.len() < 4 {
            return Err("Finished handshake too short".to_string());
        }

        let verify_len =
            ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
        if record.len() < 4 + verify_len {
            return Err("Finished verify data truncated".to_string());
        }

        let verify_data = &record[4..4 + verify_len];

        let master_secret = self
            .master_secret
            .as_ref()
            .ok_or("No master secret available")?;

        let expected = match self.config.version {
            TlsVersion::Tls12 => {
                let cipher = self
                    .negotiated_cipher_suite
                    .ok_or("No cipher suite negotiated")?;
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                let handshake_hash = tls12_handshake_hash(&self.handshake_messages, prf_alg);
                prf::prf_tls12_with_hash(
                    master_secret,
                    b"server finished",
                    &handshake_hash,
                    verify_len,
                    prf_alg,
                )
            }
            TlsVersion::Tls11 | TlsVersion::Tls10 => {
                let md5_hash = md5(&self.handshake_messages);
                let sha1_hash = sha1::sha1(&self.handshake_messages);
                let mut seed = Vec::with_capacity(md5_hash.len() + sha1_hash.len());
                seed.extend_from_slice(&md5_hash);
                seed.extend_from_slice(&sha1_hash);
                prf::prf_tls10(master_secret, b"server finished", &seed, verify_len)
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 uses dedicated Finished handling"),
        };

        if !constant_time_eq(verify_data, &expected) {
            return Err("Server Finished verify_data mismatch".to_string());
        }

        self.handshake_messages.extend_from_slice(&record);
        Ok(())
    }

    /// Derive session keys from pre-master secret
    pub(super) fn derive_session_keys(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated")?;

        if !cipher_suite_is_supported(cipher) {
            return Err(format!(
                "Cipher suite {:?} not yet implemented for TLS 1.2 handshake",
                cipher
            ));
        }

        let server_random = self.server_random.ok_or("Server random not received")?;

        let pre_master = self
            .pre_master_secret
            .as_ref()
            .ok_or("Pre-master secret not generated")?;

        let master_secret = match self.config.version {
            TlsVersion::Tls10 | TlsVersion::Tls11 => {
                prf::derive_master_secret_tls10(pre_master, &self.client_random, &server_random)
            }
            TlsVersion::Tls12 => {
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                prf::derive_master_secret_tls12_with_hash(
                    pre_master,
                    &self.client_random,
                    &server_random,
                    prf_alg,
                )
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 should not use legacy key derivation"),
        };
        self.master_secret = Some(master_secret);
        self.debug_log("master_secret", &master_secret);

        let (mac_size, key_size, iv_size) = cipher_suite_key_sizes(cipher);

        let total_size = 2 * (mac_size + key_size + iv_size);

        let key_material = match self.config.version {
            TlsVersion::Tls10 | TlsVersion::Tls11 => prf::derive_keys_tls10(
                &master_secret,
                &server_random,
                &self.client_random,
                total_size,
            ),
            TlsVersion::Tls12 => {
                let prf_alg = cipher_suite_prf_algorithm(cipher);
                prf::derive_keys_tls12_with_hash(
                    &master_secret,
                    &server_random,
                    &self.client_random,
                    total_size,
                    prf_alg,
                )
            }
            TlsVersion::Tls13 => unreachable!("TLS 1.3 should not use legacy key derivation"),
        };
        self.debug_log("key_material", &key_material);

        let mut offset = 0;

        if mac_size > 0 {
            let client_write_mac = key_material[offset..offset + mac_size].to_vec();
            self.client_write_mac = Some(client_write_mac);
            offset += mac_size;
        } else {
            self.client_write_mac = Some(Vec::new());
        }

        if mac_size > 0 {
            let server_write_mac = key_material[offset..offset + mac_size].to_vec();
            self.server_write_mac = Some(server_write_mac);
            offset += mac_size;
        } else {
            self.server_write_mac = Some(Vec::new());
        }

        let client_write_key = key_material[offset..offset + key_size].to_vec();
        self.client_write_key = Some(client_write_key);
        offset += key_size;

        let server_write_key = key_material[offset..offset + key_size].to_vec();
        self.server_write_key = Some(server_write_key);
        offset += key_size;

        let client_write_iv = key_material[offset..offset + iv_size].to_vec();
        self.client_write_iv = Some(client_write_iv);
        offset += iv_size;

        let server_write_iv = key_material[offset..offset + iv_size].to_vec();
        self.server_write_iv = Some(server_write_iv);

        if let Some(ref key) = self.client_write_key {
            self.debug_log("client_write_key", key);
        }
        if let Some(ref key) = self.server_write_key {
            self.debug_log("server_write_key", key);
        }
        if let Some(ref iv) = self.client_write_iv {
            self.debug_log("client_write_iv", iv);
        }
        if let Some(ref iv) = self.server_write_iv {
            self.debug_log("server_write_iv", iv);
        }

        Ok(())
    }
}
