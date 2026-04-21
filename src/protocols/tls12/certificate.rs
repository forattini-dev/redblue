use super::utils::{
  build_digest_info_sha1, build_digest_info_sha256, certificate_matches_host,
  chain_has_trusted_root, compute_ja3_from_client_hello, compute_ja3s_from_server_hello,
  der_to_pem, extract_public_key_from_cert, extract_tbs_and_signature,
  parse_server_hello_extensions, sha256_fingerprint_hex, verify_certificate_signature,
};
use super::*;

impl Tls12Client {
  fn verify_certificate_chain(&self) -> Result<(), String> {
    if self.peer_certificates.is_empty() {
      return Err("Server did not present a TLS certificate".to_string());
    }

    if self.peer_certificates.len() != self.server_cert_chain.len() {
      return Err(
        "Certificate chain parsed lengths do not match: chain metadata and DER payload mismatch"
          .to_string(),
      );
    }

    for (index, cert) in self.peer_certificates.iter().enumerate() {
      // Verify chain consistency (issuer/subject matching)
      if index + 1 < self.peer_certificates.len() {
        let issuer = &self.peer_certificates[index + 1];
        if cert.issuer != issuer.subject {
          return Err(format!(
            "Certificate issuer mismatch: expected '{}' but chain provides '{}'",
            cert.issuer, issuer.subject
          ));
        }

        let cert_der = &self.server_cert_chain[index];
        let (tbs, signature) = extract_tbs_and_signature(cert_der)?;
        let issuer_key = extract_public_key_from_cert(issuer)?;
        verify_certificate_signature(cert, &issuer_key, &tbs, &signature)?;
      }
    }

    if let Some(root) = self.peer_certificates.last() {
      let root_der = self
        .server_cert_chain
        .last()
        .ok_or_else(|| "Server did not provide root certificate bytes".to_string())?;
      let (tbs, signature) = extract_tbs_and_signature(root_der)?;
      let root_key = extract_public_key_from_cert(root)?;
      verify_certificate_signature(root, &root_key, &tbs, &signature)?;

      if !chain_has_trusted_root(root, root_der) {
        return Err("Root certificate is not trusted by available system trust stores".to_string());
      }
    }

    Ok(())
  }

  pub fn peer_certificates(&self) -> &[X509Certificate] {
    &self.peer_certificates
  }

  pub fn peer_certificate_chain(&self) -> &[Vec<u8>] {
    &self.server_cert_chain
  }

  pub fn verify_peer_certificate(&self) -> Result<(), String> {
    let leaf = self
      .peer_certificates
      .first()
      .ok_or_else(|| "Server did not present a TLS certificate".to_string())?;

    let now = SystemTime::now();
    let validity = &leaf.validity;

    let not_before = x509::parse_x509_time(&validity.not_before).ok_or_else(|| {
      format!(
        "Server certificate has unsupported notBefore timestamp '{}'",
        validity.not_before
      )
    })?;
    if now < not_before {
      return Err(format!(
        "Server certificate is not valid until {}",
        validity.not_before
      ));
    }

    let not_after = x509::parse_x509_time(&validity.not_after).ok_or_else(|| {
      format!(
        "Server certificate has unsupported notAfter timestamp '{}'",
        validity.not_after
      )
    })?;
    if now > not_after {
      return Err(format!(
        "Server certificate expired on {}",
        validity.not_after
      ));
    }

    if !certificate_matches_host(&self.server_name, leaf) {
      return Err(format!(
        "Server certificate does not match requested host '{}'",
        self.server_name
      ));
    }

    self.verify_certificate_chain()?;

    Ok(())
  }

  /// Expose the negotiated cipher suite for diagnostic callers (e.g. TLS auditor).
  pub fn selected_cipher_suite(&self) -> Option<u16> {
    self.selected_cipher_suite
  }

  pub fn ja3(&self) -> Option<&String> {
    self.ja3.as_ref()
  }

  pub fn ja3_raw(&self) -> Option<&String> {
    self.ja3_raw.as_ref()
  }

  pub fn ja3s(&self) -> Option<&String> {
    self.ja3s.as_ref()
  }

  pub fn ja3s_raw(&self) -> Option<&String> {
    self.ja3s_raw.as_ref()
  }

  pub fn peer_certificate_fingerprints(&self) -> Vec<String> {
    self
      .server_cert_chain
      .iter()
      .map(|der| sha256_fingerprint_hex(der))
      .collect()
  }

  pub fn certificate_chain_pem(&self) -> Vec<String> {
    self
      .server_cert_chain
      .iter()
      .map(|der| der_to_pem(der))
      .collect()
  }
}
