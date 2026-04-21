use super::*;

pub(crate) fn certificate_matches_host(host: &str, cert: &X509Certificate) -> bool {
  let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
  if normalized.is_empty() {
    return false;
  }

  let host_is_ip = IpAddr::from_str(&normalized).is_ok();

  let san_entries = cert.get_subject_alt_names();
  if san_entries
    .iter()
    .any(|entry| matches_pattern(entry, &normalized, host_is_ip))
  {
    return true;
  }

  let subject = cert.subject_string();
  for part in subject.split(',') {
    let part = part.trim();
    if let Some(value) = part.strip_prefix("CN=") {
      if matches_pattern(value.trim(), &normalized, host_is_ip) {
        return true;
      }
    }
  }

  false
}

pub(crate) fn compute_ja3_from_client_hello(
  client_hello: &[u8],
) -> Result<(String, String), String> {
  let mut record = Vec::with_capacity(client_hello.len() + 5);
  record.push(TLS_CONTENT_TYPE_HANDSHAKE);
  record.push(TLS_VERSION_MAJOR);
  record.push(TLS_VERSION_MINOR);
  record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
  record.extend_from_slice(client_hello);

  let fingerprint = JA3Fingerprint::from_client_hello(&record)?;
  let raw = fingerprint.to_string();
  let hash = md5_hex_lowercase(raw.as_bytes());
  Ok((raw, hash))
}

pub(crate) fn compute_ja3s_from_server_hello(
  version: u16,
  cipher_suite: u16,
  extensions: &[u16],
  groups: &[u16],
  ec_formats: &[u8],
) -> (String, String) {
  let raw = format!(
    "{},{},{},{},{}",
    version,
    cipher_suite,
    join_u16(extensions),
    join_u16(groups),
    join_u8(ec_formats)
  );
  let hash = md5_hex_lowercase(raw.as_bytes());
  (raw, hash)
}

pub(crate) fn parse_server_hello_extensions(data: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u8>) {
  let mut offset = 0usize;
  let mut extensions = Vec::new();
  let mut groups = Vec::new();
  let mut ec_formats = Vec::new();

  while offset + 4 <= data.len() {
    let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
    offset += 4;
    if offset + ext_len > data.len() {
      break;
    }
    let ext_data = &data[offset..offset + ext_len];
    offset += ext_len;

    if !is_grease_value(ext_type) {
      extensions.push(ext_type);
    }

    match ext_type {
      TLS_EXT_SUPPORTED_GROUPS => {
        if ext_data.len() >= 2 {
          let mut inner_offset = 2;
          while inner_offset + 1 < ext_data.len() {
            let group = u16::from_be_bytes([ext_data[inner_offset], ext_data[inner_offset + 1]]);
            if !is_grease_value(group) {
              groups.push(group);
            }
            inner_offset += 2;
          }
        }
      }
      TLS_EXT_EC_POINT_FORMATS => {
        if !ext_data.is_empty() {
          let len = ext_data[0] as usize;
          for i in 0..len {
            if 1 + i < ext_data.len() {
              ec_formats.push(ext_data[1 + i]);
            }
          }
        }
      }
      _ => {}
    }
  }

  (extensions, groups, ec_formats)
}

fn join_u16(values: &[u16]) -> String {
  if values.is_empty() {
    String::new()
  } else {
    values
      .iter()
      .map(|v| v.to_string())
      .collect::<Vec<_>>()
      .join("-")
  }
}

fn join_u8(values: &[u8]) -> String {
  if values.is_empty() {
    String::new()
  } else {
    values
      .iter()
      .map(|v| v.to_string())
      .collect::<Vec<_>>()
      .join("-")
  }
}

fn is_grease_value(value: u16) -> bool {
  let high = (value >> 8) & 0xFF;
  let low = value & 0xFF;
  high == low && (high & 0x0F) == 0x0A
}

fn md5_hex_lowercase(bytes: &[u8]) -> String {
  let digest = md5(bytes);
  let mut out = String::with_capacity(32);
  for byte in digest.iter() {
    let _ = write!(&mut out, "{:02x}", byte);
  }
  out
}

pub(crate) fn sha256_fingerprint_hex(der: &[u8]) -> String {
  let digest = sha256(der);
  digest
    .iter()
    .map(|b| format!("{:02X}", b))
    .collect::<Vec<_>>()
    .join(":")
}

pub(crate) fn der_to_pem(der: &[u8]) -> String {
  let b64 = encode_base64(der);
  let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
  let mut index = 0usize;
  while index < b64.len() {
    let end = (index + 64).min(b64.len());
    pem.push_str(&b64[index..end]);
    pem.push('\n');
    index = end;
  }
  pem.push_str("-----END CERTIFICATE-----");
  pem
}

fn matches_pattern(pattern: &str, host: &str, host_is_ip: bool) -> bool {
  let candidate = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
  if candidate.is_empty() {
    return false;
  }

  if host_is_ip {
    return candidate == host;
  }

  if candidate == host {
    return true;
  }

  if !candidate.starts_with("*.") {
    return false;
  }

  let suffix = &candidate[2..];
  if suffix.is_empty() || host_is_ip || !host.ends_with(suffix) {
    return false;
  }

  let host_labels = host.split('.').count();
  let suffix_labels = suffix.split('.').count();
  if host_labels != suffix_labels + 1 {
    return false;
  }

  let prefix_len = host.len().saturating_sub(suffix.len());
  if prefix_len == 0 {
    return false;
  }

  host
    .as_bytes()
    .get(prefix_len - 1)
    .map(|b| *b == b'.')
    .unwrap_or(false)
}

pub(crate) fn verify_certificate_signature(
  cert: &X509Certificate,
  issuer_key: &VerifierKey,
  tbs: &[u8],
  signature: &[u8],
) -> Result<(), String> {
  match cert.signature_algorithm.algorithm.as_str() {
    "1.2.840.113549.1.1.5" => match issuer_key {
      VerifierKey::Rsa(key) => {
        let hash = sha1(tbs);
        let digest_info = build_digest_info_sha1(&hash);
        key.verify_pkcs1_v15(&digest_info, signature)
      }
      _ => Err("Certificate uses RSA signature but issuer key is not RSA".to_string()),
    },
    "1.2.840.113549.1.1.11" => match issuer_key {
      VerifierKey::Rsa(key) => {
        let hash = sha256(tbs);
        let digest_info = build_digest_info_sha256(&hash);
        key.verify_pkcs1_v15(&digest_info, signature)
      }
      _ => Err("Certificate uses RSA signature but issuer key is not RSA".to_string()),
    },
    "1.2.840.10045.4.3.2" => match issuer_key {
      VerifierKey::EcP256(point) => verify_ecdsa_p256_sha256(point, tbs, signature),
      _ => Err("Certificate uses ECDSA signature but issuer key is not EC P-256".to_string()),
    },
    oid => Err(format!("Unsupported signature algorithm: {}", oid)),
  }
}

pub(crate) fn build_digest_info_sha256(hash: &[u8; 32]) -> Vec<u8> {
  const PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
  ];
  let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
  digest_info.extend_from_slice(&PREFIX);
  digest_info.extend_from_slice(hash);
  digest_info
}

pub(crate) fn build_digest_info_sha1(hash: &[u8; 20]) -> Vec<u8> {
  const PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
  ];
  let mut digest_info = Vec::with_capacity(PREFIX.len() + hash.len());
  digest_info.extend_from_slice(&PREFIX);
  digest_info.extend_from_slice(hash);
  digest_info
}

pub fn verify_ecdsa_p256_sha256(
  issuer_key: &P256Point,
  tbs: &[u8],
  signature: &[u8],
) -> Result<(), String> {
  let (r, s) = parse_ecdsa_signature(signature)?;
  let order = BigInt::from_bytes_be(&P256_ORDER_BYTES);

  if r.is_zero() || r.cmp(&order) != Ordering::Less {
    return Err("ECDSA signature 'r' out of range".to_string());
  }
  if s.is_zero() || s.cmp(&order) != Ordering::Less {
    return Err("ECDSA signature 's' out of range".to_string());
  }

  let hash = BigInt::from_bytes_be(&sha256(tbs)).mod_reduce(&order);
  let s_inv = s
    .mod_inv(&order)
    .ok_or_else(|| "ECDSA signature is not invertible".to_string())?;

  let u1 = hash.mod_mul(&s_inv, &order);
  let u2 = r.mod_mul(&s_inv, &order);

  let u1_bytes = bigint_to_32_bytes(&u1);
  let u2_bytes = bigint_to_32_bytes(&u2);

  let point = P256Point::generator()
    .scalar_mul(&u1_bytes)
    .add(&issuer_key.scalar_mul(&u2_bytes));

  if point.is_infinity {
    return Err("ECDSA verification produced point at infinity".to_string());
  }

  let x_bytes = point.x.to_bytes();
  let x_int = BigInt::from_bytes_be(&x_bytes).mod_reduce(&order);
  let r_mod = r.mod_reduce(&order);

  if x_int.cmp(&r_mod) == Ordering::Equal {
    Ok(())
  } else {
    Err("ECDSA signature verification failed".to_string())
  }
}

fn parse_ecdsa_signature(signature: &[u8]) -> Result<(BigInt, BigInt), String> {
  let (obj, consumed) = Asn1Object::from_der(signature)?;
  if consumed != signature.len() {
    return Err("Trailing data in ECDSA signature".to_string());
  }
  let seq = obj.as_sequence()?;
  if seq.len() != 2 {
    return Err("ECDSA signature must contain r and s".to_string());
  }
  let r_bytes = seq[0]
    .as_integer()
    .map_err(|e| format!("Invalid ECDSA 'r': {}", e))?
    .clone();
  let s_bytes = seq[1]
    .as_integer()
    .map_err(|e| format!("Invalid ECDSA 's': {}", e))?
    .clone();
  Ok((
    BigInt::from_bytes_be(&r_bytes),
    BigInt::from_bytes_be(&s_bytes),
  ))
}

fn bigint_to_32_bytes(value: &BigInt) -> [u8; 32] {
  let mut bytes = value.to_bytes_be();
  if bytes.len() > 32 {
    bytes = bytes[bytes.len() - 32..].to_vec();
  }
  let mut result = [0u8; 32];
  let offset = 32 - bytes.len();
  result[offset..].copy_from_slice(&bytes);
  result
}

pub(crate) fn extract_public_key_from_cert(cert: &X509Certificate) -> Result<VerifierKey, String> {
  let spki = &cert.subject_public_key_info;
  match spki.algorithm.algorithm.as_str() {
    "1.2.840.113549.1.1.1" => {
      let (modulus, exponent) = spki
        .rsa_components()
        .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;
      Ok(VerifierKey::Rsa(RsaPublicKey::from_components(
        &modulus, &exponent,
      )))
    }
    "1.2.840.10045.2.1" => {
      let curve_oid = spki
        .algorithm
        .parameters_oid
        .as_deref()
        .ok_or_else(|| "EC public key missing named curve".to_string())?;
      if curve_oid != "1.2.840.10045.3.1.7" {
        return Err(format!(
          "Unsupported EC named curve '{}' in certificate",
          curve_oid
        ));
      }
      let point = P256Point::from_uncompressed_bytes(&spki.public_key)
        .map_err(|e| format!("Failed to parse EC public key: {}", e))?;
      Ok(VerifierKey::EcP256(point))
    }
    oid => Err(format!(
      "Unsupported certificate public key algorithm: {}",
      oid
    )),
  }
}

// Note: convert_trust_key removed - TrustStore not yet implemented

fn parse_der_length(data: &[u8], offset: &mut usize) -> Result<usize, String> {
  if *offset >= data.len() {
    return Err("Unexpected end of data while parsing length".to_string());
  }

  let first = data[*offset];
  *offset += 1;

  if first & 0x80 == 0 {
    Ok(first as usize)
  } else {
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 4 {
      return Err("Invalid DER length".to_string());
    }
    if *offset + count > data.len() {
      return Err("Length exceeds available data".to_string());
    }
    let mut length = 0usize;
    for _ in 0..count {
      length = (length << 8) | (data[*offset] as usize);
      *offset += 1;
    }
    Ok(length)
  }
}

fn slice_der_element<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
  if *offset >= data.len() {
    return Err("Unexpected end of data while parsing element".to_string());
  }

  let start = *offset;
  *offset += 1; // tag
  let length = parse_der_length(data, offset)?;
  let end = offset
    .checked_add(length)
    .ok_or_else(|| "Length overflow".to_string())?;
  if end > data.len() {
    return Err("DER element extends beyond input".to_string());
  }
  *offset = end;
  Ok(&data[start..end])
}

pub(crate) fn extract_tbs_and_signature(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
  if cert_der.is_empty() || cert_der[0] != 0x30 {
    return Err("Certificate is not a SEQUENCE".to_string());
  }

  let mut offset = 1;
  let total_len = parse_der_length(cert_der, &mut offset)?;
  let seq_end = offset + total_len;
  if seq_end > cert_der.len() {
    return Err("Certificate length exceeds buffer".to_string());
  }

  let tbs = slice_der_element(cert_der, &mut offset)?.to_vec();

  // Skip signatureAlgorithm
  let _sig_alg = slice_der_element(cert_der, &mut offset)?;

  if offset >= seq_end {
    return Err("Certificate missing signature BIT STRING".to_string());
  }

  if cert_der[offset] != 0x03 {
    return Err("Expected BIT STRING for certificate signature".to_string());
  }
  offset += 1;
  let bit_len = parse_der_length(cert_der, &mut offset)?;
  if offset + bit_len > seq_end {
    return Err("Signature BIT STRING exceeds certificate".to_string());
  }
  if bit_len == 0 {
    return Err("Empty certificate signature".to_string());
  }
  let unused_bits = cert_der[offset];
  if unused_bits != 0 {
    return Err("Unsupported signature encoding with unused bits".to_string());
  }
  let signature = cert_der[offset + 1..offset + bit_len].to_vec();

  Ok((tbs, signature))
}

#[derive(Clone)]
struct TrustRoot {
  cert: X509Certificate,
  der: Vec<u8>,
}

pub(crate) fn chain_has_trusted_root(root: &X509Certificate, root_der: &[u8]) -> bool {
  if !root.is_self_signed() {
    return false;
  }

  let roots = load_system_trust_roots();
  if roots.is_empty() {
    return allow_untrusted_when_empty_system_store();
  }

  let root_fingerprint = sha256_fingerprint_hex(root_der);
  for anchor in roots {
    if anchor.cert.subject == root.subject && anchor.cert.issuer == root.issuer {
      return true;
    }

    if sha256_fingerprint_hex(&anchor.der) == root_fingerprint {
      return true;
    }
  }

  false
}

fn load_system_trust_roots() -> Vec<TrustRoot> {
  let mut roots = Vec::new();

  let mut candidate_paths = Vec::new();

  if let Some(cert_file) = env::var_os("SSL_CERT_FILE") {
    candidate_paths.push(PathBuf::from(cert_file));
  }
  if let Some(cert_dir) = env::var_os("SSL_CERT_DIR") {
    candidate_paths.push(PathBuf::from(cert_dir));
  }

  #[cfg(not(target_os = "windows"))]
  {
    candidate_paths.push(PathBuf::from("/etc/ssl/certs/ca-certificates.crt"));
    candidate_paths.push(PathBuf::from("/etc/ssl/cert.pem"));
    candidate_paths.push(PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"));
    candidate_paths.push(PathBuf::from("/usr/local/share/ca-certificates"));
    candidate_paths.push(PathBuf::from("/usr/share/ca-certificates"));
  }

  for path in candidate_paths {
    roots.extend(load_trust_roots_from_path(&path));
  }

  roots
}

fn load_trust_roots_from_path(path: &Path) -> Vec<TrustRoot> {
  if !path.exists() {
    return Vec::new();
  }

  if path.is_dir() {
    let mut roots = Vec::new();
    let mut dirs = vec![path.to_path_buf()];
    while let Some(current) = dirs.pop() {
      let entries = match fs::read_dir(&current) {
        Ok(entries) => entries,
        Err(_) => continue,
      };
      for entry in entries.flatten() {
        let file_type = match entry.file_type() {
          Ok(ft) => ft,
          Err(_) => continue,
        };

        let entry_path = entry.path();
        if file_type.is_dir() {
          dirs.push(entry_path);
          continue;
        }

        if file_type.is_file() {
          roots.extend(parse_trust_roots_from_file(&entry_path));
        }
      }
    }
    return roots;
  }

  parse_trust_roots_from_file(path)
}

fn parse_trust_roots_from_file(path: &Path) -> Vec<TrustRoot> {
  let data = match fs::read(path) {
    Ok(data) => data,
    Err(_) => return Vec::new(),
  };

  let mut roots = Vec::new();

  if let Ok(text) = std::str::from_utf8(&data) {
    roots.extend(parse_trust_roots_from_pem(text));
  }

  if !data.is_empty() && roots.is_empty() {
    if let Ok(cert) = X509Certificate::from_der(&data) {
      roots.push(TrustRoot { cert, der: data });
    }
  }

  roots
}

fn parse_trust_roots_from_pem(data: &str) -> Vec<TrustRoot> {
  const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
  const END: &str = "-----END CERTIFICATE-----";

  let mut roots = Vec::new();
  let mut active = false;
  let mut block = String::new();

  for line in data.lines() {
    if line.contains(BEGIN) {
      active = true;
      block.clear();
      continue;
    }

    if line.contains(END) {
      if active {
        if let Ok(der) = base64_decode(&block) {
          if let Ok(cert) = X509Certificate::from_der(&der) {
            roots.push(TrustRoot { cert, der });
          }
        }
      }
      active = false;
      block.clear();
      continue;
    }

    if active {
      block.push_str(line.trim());
    }
  }

  roots
}

fn allow_untrusted_when_empty_system_store() -> bool {
  env::var("RB_TLS_ALLOW_EMPTY_SYSTEM_ROOTS")
    .ok()
    .map(|value| {
      matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "on" | "yes"
      )
    })
    .unwrap_or(false)
}
