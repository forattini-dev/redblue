//! TLS 1.3 Handshake Implementation
//!
//! Handles the complete TLS 1.3 handshake flow:
//! - ServerHello parsing with extensions
//! - Encrypted handshake message processing
//! - Certificate chain handling
//! - CertificateVerify signature validation
//! - Key schedule and traffic key derivation

use std::cmp::Ordering;

use super::super::cipher::{cipher_suite_from_id, cipher_suite_is_tls13, cipher_suite_key_sizes};
use super::super::helpers::{
    bigint_to_32_bytes, build_digest_info_sha256, build_digest_info_sha384,
    build_tls13_certificate_verify_input, wrap_handshake,
};
use super::super::types::{
    ContentType, EcdheParameters, HandshakeType, Tls13NamedGroup, Tls13NewSessionTicket,
    TlsVersion, P256_ORDER_BYTES, TLS13_SERVER_CERT_VERIFY_CONTEXT,
};

use crate::crypto::rsa::extract_public_key_from_cert;
use crate::crypto::sha256;
use crate::crypto::sha384;
use crate::crypto::tls13_keyschedule::Tls13KeySchedule;
use crate::crypto::x25519::x25519;
use crate::crypto::{BigInt, Tls13HashAlgorithm};
use crate::protocols::p256::P256Point;
use crate::protocols::x509::X509Certificate;

use super::TlsStream;

impl TlsStream {
    /// Execute the full TLS 1.3 handshake sequence
    pub(super) fn handshake_tls13(&mut self, host: &str) -> Result<(), String> {
        self.send_client_hello(host)?;
        let server_hello = self.receive_tls13_server_hello()?;
        self.process_tls13_server_hello(&server_hello)?;

        self.receive_tls13_encrypted_handshake()?;
        self.send_tls13_client_auth_responses()?;
        self.send_tls13_finished()?;
        self.activate_tls13_application_keys()?;
        self.handshake_complete = true;

        Ok(())
    }

    /// Activate handshake traffic keys after ServerHello
    pub(super) fn activate_tls13_handshake_keys(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated for TLS 1.3 handshake")?;

        if !cipher_suite_is_tls13(cipher) {
            return Err(format!(
                "TLS 1.3 handshake negotiated non-TLS1.3 cipher {:?}",
                cipher
            ));
        }

        let schedule = self
            .tls13_key_schedule
            .as_ref()
            .ok_or("TLS 1.3 key schedule not initialized")?;

        let server_secret = schedule
            .server_handshake_traffic_secret
            .as_ref()
            .ok_or("Server handshake traffic secret missing")?;
        let client_secret = schedule
            .client_handshake_traffic_secret
            .as_ref()
            .ok_or("Client handshake traffic secret missing")?;

        let (_, key_len, iv_len) = cipher_suite_key_sizes(cipher);
        let (server_key, server_iv) = schedule
            .derive_traffic_keys(server_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive server traffic keys: {}", e))?;
        let (client_key, client_iv) = schedule
            .derive_traffic_keys(client_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive client traffic keys: {}", e))?;

        self.server_write_key = Some(server_key);
        self.server_write_iv = Some(server_iv);
        self.client_write_key = Some(client_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_mac = None;
        self.client_write_mac = None;

        self.server_encryption_active = true;
        self.client_encryption_active = true;
        self.server_sequence = 0;
        self.client_sequence = 0;

        Ok(())
    }

    /// Receive TLS 1.3 ServerHello
    pub(super) fn receive_tls13_server_hello(&mut self) -> Result<Vec<u8>, String> {
        let (content_type, record) = self.receive_tls_record()?;

        if content_type != ContentType::Handshake {
            if content_type == ContentType::Alert && record.len() >= 2 {
                return Err(format!(
                    "Server sent alert during TLS 1.3 ServerHello: level={}, description={}",
                    record[0], record[1]
                ));
            }
            return Err(format!(
                "Expected TLS 1.3 ServerHello handshake record, got {:?}",
                content_type
            ));
        }

        if record.is_empty() {
            return Err("Empty TLS 1.3 ServerHello".to_string());
        }

        self.handshake_messages.extend_from_slice(&record);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.add_to_transcript(&record);
        }

        Ok(record)
    }

    /// Process TLS 1.3 ServerHello and compute handshake keys
    pub(super) fn process_tls13_server_hello(&mut self, record: &[u8]) -> Result<(), String> {
        if record.len() < 4 {
            return Err("TLS 1.3 ServerHello too short".to_string());
        }

        if record[0] != HandshakeType::ServerHello as u8 {
            return Err(format!(
                "Unexpected handshake type in TLS 1.3 ServerHello: {}",
                record[0]
            ));
        }

        let body_len =
            ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
        if record.len() < 4 + body_len {
            return Err("TLS 1.3 ServerHello truncated".to_string());
        }

        let body = &record[4..4 + body_len];
        if body.len() < 38 {
            return Err("TLS 1.3 ServerHello body too short".to_string());
        }

        let mut offset = 0;

        let _legacy_version = u16::from_be_bytes([body[offset], body[offset + 1]]);
        offset += 2;

        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&body[offset..offset + 32]);
        offset += 32;
        self.server_random = Some(server_random);

        if offset >= body.len() {
            return Err("TLS 1.3 ServerHello missing session ID length".to_string());
        }
        let session_id_len = body[offset] as usize;
        offset += 1;

        if offset + session_id_len + 3 > body.len() {
            return Err("TLS 1.3 ServerHello truncated after session ID".to_string());
        }
        offset += session_id_len;

        let cipher_suite_id = u16::from_be_bytes([body[offset], body[offset + 1]]);
        offset += 2;
        let _legacy_compression_method = body[offset];
        offset += 1;

        if offset + 2 > body.len() {
            return Err("TLS 1.3 ServerHello missing extensions length".to_string());
        }
        let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        if offset + extensions_len > body.len() {
            return Err("TLS 1.3 ServerHello extensions truncated".to_string());
        }

        let extensions = &body[offset..offset + extensions_len];

        let negotiated = cipher_suite_from_id(cipher_suite_id)?;
        self.negotiated_cipher_suite = Some(negotiated);

        if self.config.version == TlsVersion::Tls13 {
            let hash_alg = match negotiated {
                super::super::types::CipherSuite::TlsAes256GcmSha384
                | super::super::types::CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                    Tls13HashAlgorithm::Sha384
                }
                _ => Tls13HashAlgorithm::Sha256,
            };

            let mut schedule = Tls13KeySchedule::new(hash_alg);
            schedule.set_transcript(&self.handshake_messages);
            self.tls13_key_schedule = Some(schedule);
        }

        let (supported_version, server_key_share_group, server_key_share_bytes) =
            self.parse_tls13_extensions(extensions)?;

        if supported_version != 0x0304 {
            return Err(format!(
                "Server selected unsupported TLS version: 0x{:04X}",
                supported_version
            ));
        }

        let server_key_bytes = server_key_share_bytes
            .ok_or_else(|| "TLS 1.3 ServerHello missing key_share extension".to_string())?;
        if server_key_bytes.len() != 32 {
            return Err(format!(
                "Unexpected TLS 1.3 server key share length: {}",
                server_key_bytes.len()
            ));
        }

        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&server_key_bytes);
        self.ecdhe_params = Some(EcdheParameters::X25519 { server_public });

        let client_share = self.tls13_client_key_share.as_ref().ok_or_else(|| {
            "TLS 1.3 client key share missing; ClientHello may not have been prepared correctly"
                .to_string()
        })?;

        if server_key_share_group != Some(Tls13NamedGroup::X25519.as_u16()) {
            return Err("Server selected unsupported key share group for TLS 1.3".to_string());
        }

        let shared_secret = x25519(&client_share.private_key, &server_public);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.derive_handshake_secret(&shared_secret);
            schedule.derive_handshake_traffic_secrets();
        }

        self.activate_tls13_handshake_keys()?;

        Ok(())
    }

    /// Parse TLS 1.3 extensions from ServerHello
    fn parse_tls13_extensions(
        &self,
        extensions: &[u8],
    ) -> Result<(u16, Option<u16>, Option<Vec<u8>>), String> {
        let mut supported_version = None;
        let mut server_key_share_group = None;
        let mut server_key_share_bytes: Option<Vec<u8>> = None;

        let mut ext_offset = 0;
        while ext_offset + 4 <= extensions.len() {
            let ext_type = u16::from_be_bytes([extensions[ext_offset], extensions[ext_offset + 1]]);
            let ext_len =
                u16::from_be_bytes([extensions[ext_offset + 2], extensions[ext_offset + 3]])
                    as usize;
            ext_offset += 4;

            if ext_offset + ext_len > extensions.len() {
                return Err("TLS 1.3 ServerHello extension truncated".to_string());
            }

            let ext_body = &extensions[ext_offset..ext_offset + ext_len];
            match ext_type {
                0x002b => {
                    if ext_body.len() != 2 {
                        return Err(
                            "Invalid supported_versions extension in TLS 1.3 ServerHello"
                                .to_string(),
                        );
                    }
                    supported_version = Some(u16::from_be_bytes([ext_body[0], ext_body[1]]));
                }
                0x0033 => {
                    if ext_body.len() < 4 {
                        return Err(
                            "Invalid key_share extension in TLS 1.3 ServerHello".to_string()
                        );
                    }

                    let mut body = ext_body;
                    if ext_body.len() >= 2
                        && (ext_body.len() - 2)
                            == u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize
                    {
                        body = &ext_body[2..];
                    }

                    if body.len() < 4 {
                        return Err(
                            "Invalid key_share extension body in TLS 1.3 ServerHello".to_string()
                        );
                    }
                    let group = u16::from_be_bytes([body[0], body[1]]);
                    let key_len = u16::from_be_bytes([body[2], body[3]]) as usize;
                    if body.len() < 4 + key_len {
                        return Err("Key share data truncated in TLS 1.3 ServerHello".to_string());
                    }
                    server_key_share_group = Some(group);
                    server_key_share_bytes = Some(body[4..4 + key_len].to_vec());
                }
                _ => {}
            }

            ext_offset += ext_len;
        }

        if ext_offset != extensions.len() {
            return Err("TLS 1.3 ServerHello extension parsing mismatch".to_string());
        }

        let version = supported_version.ok_or_else(|| {
            "TLS 1.3 ServerHello missing supported_versions extension".to_string()
        })?;

        Ok((version, server_key_share_group, server_key_share_bytes))
    }

    /// Receive encrypted handshake messages (EncryptedExtensions, Certificate, etc.)
    pub(super) fn receive_tls13_encrypted_handshake(&mut self) -> Result<(), String> {
        let mut server_finished = false;

        while !server_finished {
            let (content_type, payload) = self.receive_tls_record()?;

            match content_type {
                ContentType::ChangeCipherSpec => continue,
                ContentType::Alert => {
                    if payload.len() >= 2 {
                        return Err(format!(
                            "Server sent TLS 1.3 alert: level={}, description={}",
                            payload[0], payload[1]
                        ));
                    }
                    return Err("Server sent TLS 1.3 alert".to_string());
                }
                ContentType::Handshake | ContentType::ApplicationData => {
                    if payload.is_empty() {
                        continue;
                    }

                    server_finished = self.process_tls13_handshake_messages(&payload)?;
                }
            }
        }

        Ok(())
    }

    /// Process TLS 1.3 handshake messages from encrypted payload
    fn process_tls13_handshake_messages(&mut self, payload: &[u8]) -> Result<bool, String> {
        let mut server_finished = false;
        let mut offset = 0;

        while offset + 4 <= payload.len() {
            let msg_type = payload[offset];
            let msg_len = ((payload[offset + 1] as usize) << 16)
                | ((payload[offset + 2] as usize) << 8)
                | (payload[offset + 3] as usize);
            let total_len = 4 + msg_len;

            if offset + total_len > payload.len() {
                return Err("TLS 1.3 handshake message truncated in encrypted flight".to_string());
            }

            let message = &payload[offset..offset + total_len];
            let handshake_type = HandshakeType::from_u8(msg_type)
                .ok_or_else(|| format!("Unknown TLS 1.3 handshake message type {}", msg_type))?;

            match handshake_type {
                HandshakeType::EncryptedExtensions => {
                    self.handshake_messages.extend_from_slice(message);
                    if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                        schedule.add_to_transcript(message);
                    }
                }
                HandshakeType::Certificate => {
                    self.handshake_messages.extend_from_slice(message);
                    if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                        schedule.add_to_transcript(message);
                    }
                    self.parse_tls13_certificate(message)?;
                    self.verify_peer_certificate()?;
                }
                HandshakeType::CertificateVerify => {
                    self.verify_tls13_certificate_verify_message(message)?;
                    self.handshake_messages.extend_from_slice(message);
                    if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                        schedule.add_to_transcript(message);
                    }
                }
                HandshakeType::CertificateRequest => {
                    self.parse_tls13_certificate_request(message)?;
                }
                HandshakeType::NewSessionTicket => {
                    self.parse_tls13_new_session_ticket(message)?;
                }
                HandshakeType::Finished => {
                    let verify_data = &message[4..];
                    let expected = {
                        let schedule = self.tls13_key_schedule.as_ref().ok_or_else(|| {
                            "TLS 1.3 key schedule missing for server Finished".to_string()
                        })?;
                        schedule.server_finished_verify_data()?
                    };

                    if verify_data != expected {
                        return Err(
                            "Server Finished verify data mismatch in TLS 1.3 handshake".to_string()
                        );
                    }

                    self.handshake_messages.extend_from_slice(message);
                    if let Some(schedule) = self.tls13_key_schedule.as_mut() {
                        schedule.add_to_transcript(message);
                        schedule.derive_master_secret();
                        schedule.derive_application_traffic_secrets();
                    }

                    server_finished = true;
                }
                HandshakeType::KeyUpdate => {
                    return Err(
                        "Server sent TLS 1.3 KeyUpdate; key updates are not implemented yet"
                            .to_string(),
                    );
                }
                other => {
                    return Err(format!("Unsupported TLS 1.3 handshake message {:?}", other));
                }
            }

            offset += total_len;
            if server_finished {
                break;
            }
        }

        if offset != payload.len() && !server_finished {
            return Err("Extra bytes in TLS 1.3 handshake record".to_string());
        }

        Ok(server_finished)
    }

    /// Parse TLS 1.3 Certificate message
    fn parse_tls13_certificate(&mut self, message: &[u8]) -> Result<(), String> {
        if message.len() < 5 {
            return Err("TLS 1.3 Certificate message too short".to_string());
        }

        let mut offset = 4;
        if offset >= message.len() {
            return Err("TLS 1.3 Certificate missing request context length".to_string());
        }

        let context_len = message[offset] as usize;
        offset += 1;
        if offset + context_len > message.len() {
            return Err("TLS 1.3 Certificate request context truncated".to_string());
        }
        offset += context_len;

        if offset + 3 > message.len() {
            return Err("TLS 1.3 Certificate missing certificate list length".to_string());
        }

        let cert_list_len = ((message[offset] as usize) << 16)
            | ((message[offset + 1] as usize) << 8)
            | (message[offset + 2] as usize);
        offset += 3;

        if offset + cert_list_len > message.len() {
            return Err("TLS 1.3 Certificate list truncated".to_string());
        }

        if cert_list_len < 3 {
            return Err("TLS 1.3 Certificate list empty".to_string());
        }

        if offset + 3 > message.len() {
            return Err("TLS 1.3 Certificate missing certificate length".to_string());
        }
        let cert_len = ((message[offset] as usize) << 16)
            | ((message[offset + 1] as usize) << 8)
            | (message[offset + 2] as usize);
        offset += 3;

        if offset + cert_len > message.len() {
            return Err("TLS 1.3 certificate data truncated".to_string());
        }

        let cert_der = message[offset..offset + cert_len].to_vec();
        if self.config.verify_cert {
            let parsed = X509Certificate::from_der(&cert_der)
                .map_err(|e| format!("Failed to parse TLS 1.3 server certificate: {}", e))?;
            self.server_x509 = Some(parsed);
        }
        self.server_certificate = Some(cert_der);

        Ok(())
    }

    /// Parse TLS 1.3 CertificateRequest message
    fn parse_tls13_certificate_request(&mut self, message: &[u8]) -> Result<(), String> {
        if message.len() < 5 {
            return Err("TLS 1.3 CertificateRequest too short".to_string());
        }
        if message[0] != HandshakeType::CertificateRequest as u8 {
            return Err("Unexpected TLS 1.3 CertificateRequest handshake type".to_string());
        }

        let mut offset = 4;

        if offset >= message.len() {
            return Err("TLS 1.3 CertificateRequest missing context length".to_string());
        }
        let context_len = message[offset] as usize;
        offset += 1;
        if offset + context_len > message.len() {
            return Err("TLS 1.3 CertificateRequest context truncated".to_string());
        }
        let context = message[offset..offset + context_len].to_vec();
        offset += context_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 CertificateRequest missing signature schemes length".to_string());
        }
        let sig_algs_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + sig_algs_len > message.len() {
            return Err("TLS 1.3 CertificateRequest signature schemes truncated".to_string());
        }
        offset += sig_algs_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 CertificateRequest missing extensions length".to_string());
        }
        let extensions_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + extensions_len > message.len() {
            return Err("TLS 1.3 CertificateRequest extensions truncated".to_string());
        }
        offset += extensions_len;

        if offset != message.len() {
            return Err("TLS 1.3 CertificateRequest has extra bytes".to_string());
        }

        self.tls13_certificate_request_context = Some(context);
        Ok(())
    }

    /// Parse TLS 1.3 NewSessionTicket message
    fn parse_tls13_new_session_ticket(&mut self, message: &[u8]) -> Result<(), String> {
        if message.len() < 10 {
            return Err("TLS 1.3 NewSessionTicket too short".to_string());
        }
        if message[0] != HandshakeType::NewSessionTicket as u8 {
            return Err("Expected NewSessionTicket handshake type".to_string());
        }

        let mut offset = 4;

        if offset + 4 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing lifetime".to_string());
        }
        let lifetime = u32::from_be_bytes([
            message[offset],
            message[offset + 1],
            message[offset + 2],
            message[offset + 3],
        ]);
        offset += 4;

        if offset + 4 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing age_add".to_string());
        }
        let age_add = u32::from_be_bytes([
            message[offset],
            message[offset + 1],
            message[offset + 2],
            message[offset + 3],
        ]);
        offset += 4;

        if offset >= message.len() {
            return Err("TLS 1.3 NewSessionTicket missing nonce length".to_string());
        }
        let nonce_len = message[offset] as usize;
        offset += 1;
        if offset + nonce_len > message.len() {
            return Err("TLS 1.3 NewSessionTicket nonce truncated".to_string());
        }
        let nonce = message[offset..offset + nonce_len].to_vec();
        offset += nonce_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing ticket length".to_string());
        }
        let ticket_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + ticket_len > message.len() {
            return Err("TLS 1.3 NewSessionTicket ticket truncated".to_string());
        }
        let ticket = message[offset..offset + ticket_len].to_vec();
        offset += ticket_len;

        if offset + 2 > message.len() {
            return Err("TLS 1.3 NewSessionTicket missing extensions length".to_string());
        }
        let extensions_len = u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        offset += 2;
        if offset + extensions_len > message.len() {
            return Err("TLS 1.3 NewSessionTicket extensions truncated".to_string());
        }
        let extensions = message[offset..offset + extensions_len].to_vec();
        offset += extensions_len;

        if offset != message.len() {
            return Err("TLS 1.3 NewSessionTicket has extra bytes".to_string());
        }

        self.tls13_new_session_tickets.push(Tls13NewSessionTicket {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions,
        });

        Ok(())
    }

    /// Verify TLS 1.3 CertificateVerify message
    fn verify_tls13_certificate_verify_message(&mut self, message: &[u8]) -> Result<(), String> {
        let schedule = self
            .tls13_key_schedule
            .as_ref()
            .ok_or_else(|| "TLS 1.3 key schedule missing for CertificateVerify".to_string())?;
        let transcript_hash = schedule.get_handshake_hash_value();

        if message.len() < 8 {
            return Err("TLS 1.3 CertificateVerify message too short".to_string());
        }
        let signature_scheme = u16::from_be_bytes([message[4], message[5]]);
        let sig_len = u16::from_be_bytes([message[6], message[7]]) as usize;
        if message.len() < 8 + sig_len {
            return Err("TLS 1.3 CertificateVerify signature truncated".to_string());
        }
        let signature = &message[8..8 + sig_len];
        let signed_data = build_tls13_certificate_verify_input(
            TLS13_SERVER_CERT_VERIFY_CONTEXT,
            &transcript_hash,
        );

        self.verify_tls13_certificate_verify(signature_scheme, &signed_data, signature)
    }

    /// Verify certificate signature using the appropriate algorithm
    fn verify_tls13_certificate_verify(
        &mut self,
        signature_scheme: u16,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        if !self.config.verify_cert {
            return Ok(());
        }

        let cert_der = self
            .server_certificate
            .as_ref()
            .ok_or_else(|| "Server certificate not available for verification".to_string())?;

        let cert_x509 = self.server_x509.as_ref();

        match signature_scheme {
            0x0403 => {
                // ECDSA-P256-SHA256
                let cert = cert_x509.ok_or_else(|| {
                    "Parsed server certificate unavailable for ECDSA verification".to_string()
                })?;

                let alg_oid = cert.subject_public_key_info.algorithm.algorithm.as_str();
                if alg_oid != "1.2.840.10045.2.1" {
                    return Err(format!(
                        "Server certificate uses unsupported public key algorithm {}",
                        alg_oid
                    ));
                }

                let curve_oid = cert
                    .subject_public_key_info
                    .algorithm
                    .parameters_oid
                    .as_deref()
                    .unwrap_or_default();
                if curve_oid != "1.2.840.10045.3.1.7" {
                    return Err(format!(
                        "Server certificate ECDSA curve {} not supported (expect P-256)",
                        curve_oid
                    ));
                }

                let public_key_bytes = &cert.subject_public_key_info.public_key;
                let point = P256Point::from_uncompressed_bytes(public_key_bytes)
                    .map_err(|e| format!("Invalid P-256 public key: {}", e))?;

                verify_ecdsa_p256_signature(&point, signed_data, signature)
                    .map_err(|e| format!("ECDSA verification failed: {}", e))
            }
            0x0401 => {
                // RSA-PKCS1-SHA256
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha256::sha256(signed_data);
                let digest = build_digest_info_sha256(&hash);
                if digest.is_empty() {
                    return Err("Failed to build SHA-256 DigestInfo".to_string());
                }
                rsa.verify_pkcs1_v15(&digest, signature)
                    .map_err(|e| format!("RSA PKCS#1 verification failed: {}", e))
            }
            0x0501 => {
                // RSA-PKCS1-SHA384
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha384::sha384(signed_data);
                let digest = build_digest_info_sha384(&hash);
                if digest.is_empty() {
                    return Err("Failed to build SHA-384 DigestInfo".to_string());
                }
                rsa.verify_pkcs1_v15(&digest, signature)
                    .map_err(|e| format!("RSA PKCS#1 verification failed: {}", e))
            }
            0x0804 => {
                // RSA-PSS-SHA256
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha256::sha256(signed_data);
                rsa.verify_pss_sha256(&hash, signature)
                    .map_err(|e| format!("RSA-PSS verification failed: {}", e))
            }
            0x0805 => {
                // RSA-PSS-SHA384
                let rsa = extract_public_key_from_cert(cert_der)
                    .map_err(|e| format!("Failed to extract RSA public key: {}", e))?;
                let hash = sha384::sha384(signed_data);
                rsa.verify_pss_sha384(&hash, signature)
                    .map_err(|e| format!("RSA-PSS verification failed: {}", e))
            }
            _ => Err(format!(
                "Server used unsupported TLS 1.3 signature scheme 0x{:04X}",
                signature_scheme
            )),
        }
    }

    /// Send client auth responses (empty certificate if requested)
    pub(super) fn send_tls13_client_auth_responses(&mut self) -> Result<(), String> {
        if let Some(context) = self.tls13_certificate_request_context.take() {
            self.send_tls13_empty_certificate(&context)?;
        }
        Ok(())
    }

    /// Send empty certificate for client auth
    fn send_tls13_empty_certificate(&mut self, request_context: &[u8]) -> Result<(), String> {
        if request_context.len() > u8::MAX as usize {
            return Err("TLS 1.3 certificate_request_context too long".to_string());
        }

        let mut body = Vec::with_capacity(1 + request_context.len() + 3);
        body.push(request_context.len() as u8);
        body.extend_from_slice(request_context);
        body.extend_from_slice(&[0x00, 0x00, 0x00]);

        let handshake = wrap_handshake(HandshakeType::Certificate, &body);
        self.handshake_messages.extend_from_slice(&handshake);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.add_to_transcript(&handshake);
        }

        self.send_record(ContentType::Handshake, &handshake, true)
    }

    /// Send TLS 1.3 Finished message
    pub(super) fn send_tls13_finished(&mut self) -> Result<(), String> {
        let verify_data = {
            let schedule = self
                .tls13_key_schedule
                .as_ref()
                .ok_or_else(|| "TLS 1.3 key schedule not initialized".to_string())?;
            schedule.client_finished_verify_data()?
        };

        let handshake = wrap_handshake(HandshakeType::Finished, &verify_data);
        self.handshake_messages.extend_from_slice(&handshake);
        if let Some(schedule) = self.tls13_key_schedule.as_mut() {
            schedule.add_to_transcript(&handshake);
        }

        self.send_record(ContentType::Handshake, &handshake, true)?;

        Ok(())
    }

    /// Activate application traffic keys after handshake
    pub(super) fn activate_tls13_application_keys(&mut self) -> Result<(), String> {
        let cipher = self
            .negotiated_cipher_suite
            .ok_or("No cipher suite negotiated for TLS 1.3 application data")?;

        if !cipher_suite_is_tls13(cipher) {
            return Err(format!(
                "TLS 1.3 application data negotiated non-TLS1.3 cipher {:?}",
                cipher
            ));
        }

        let schedule = self
            .tls13_key_schedule
            .as_ref()
            .ok_or("TLS 1.3 key schedule not initialized for application data")?;

        let server_secret = schedule
            .server_application_traffic_secret
            .as_ref()
            .ok_or("Server application traffic secret missing")?;
        let client_secret = schedule
            .client_application_traffic_secret
            .as_ref()
            .ok_or("Client application traffic secret missing")?;

        let (_, key_len, iv_len) = cipher_suite_key_sizes(cipher);
        let (server_key, server_iv) = schedule
            .derive_traffic_keys(server_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive server application keys: {}", e))?;
        let (client_key, client_iv) = schedule
            .derive_traffic_keys(client_secret, key_len as u16, iv_len as u16)
            .map_err(|e| format!("Failed to derive client application keys: {}", e))?;

        self.server_write_key = Some(server_key);
        self.server_write_iv = Some(server_iv);
        self.client_write_key = Some(client_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_mac = None;
        self.client_write_mac = None;
        self.server_sequence = 0;
        self.client_sequence = 0;

        Ok(())
    }
}

// ============================================================================
// Helper: ECDSA P-256 Signature Verification
// ============================================================================

/// Verify ECDSA P-256 signature (used for TLS 1.3 CertificateVerify)
fn verify_ecdsa_p256_signature(
    point: &P256Point,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use super::super::helpers::parse_ecdsa_signature;

    let (r, s) = parse_ecdsa_signature(signature)?;
    let order = BigInt::from_bytes_be(&P256_ORDER_BYTES);

    if r.is_zero() || r.cmp(&order) != Ordering::Less {
        return Err("ECDSA signature 'r' out of range".to_string());
    }
    if s.is_zero() || s.cmp(&order) != Ordering::Less {
        return Err("ECDSA signature 's' out of range".to_string());
    }

    let hash_bytes = sha256::sha256(message);
    let hash = BigInt::from_bytes_be(&hash_bytes).mod_reduce(&order);
    let s_inv = s
        .mod_inv(&order)
        .ok_or_else(|| "ECDSA signature is not invertible".to_string())?;

    let u1 = hash.mod_mul(&s_inv, &order);
    let u2 = r.mod_mul(&s_inv, &order);

    let u1_bytes = bigint_to_32_bytes(&u1);
    let u2_bytes = bigint_to_32_bytes(&u2);

    let generator = P256Point::generator();
    let point1 = generator.scalar_mul(&u1_bytes);
    let point2 = point.scalar_mul(&u2_bytes);
    let sum = point1.add(&point2);

    if sum.is_infinity {
        return Err("ECDSA verification produced point at infinity".to_string());
    }

    let x_bytes = sum.x.to_bytes();
    let x = BigInt::from_bytes_be(&x_bytes).mod_reduce(&order);
    let r_mod = r.mod_reduce(&order);

    if x.cmp(&r_mod) == Ordering::Equal {
        Ok(())
    } else {
        Err("ECDSA signature verification failed".to_string())
    }
}
