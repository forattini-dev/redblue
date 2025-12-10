use super::hmac::{hmac_sha256, hmac_sha384};
use super::sha256::sha256;
use super::sha384::sha384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls13HashAlgorithm {
    Sha256,
    Sha384,
}

impl Tls13HashAlgorithm {
    pub fn hash_len(&self) -> usize {
        match self {
            Tls13HashAlgorithm::Sha256 => 32,
            Tls13HashAlgorithm::Sha384 => 48,
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Tls13HashAlgorithm::Sha256 => sha256(data).to_vec(),
            Tls13HashAlgorithm::Sha384 => sha384(data).to_vec(),
        }
    }

    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Tls13HashAlgorithm::Sha256 => hmac_sha256(key, data).to_vec(),
            Tls13HashAlgorithm::Sha384 => hmac_sha384(key, data).to_vec(),
        }
    }

    pub fn hkdf_extract(&self, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let hash_len = self.hash_len();
        let zero_salt;
        let salt_bytes = match salt {
            Some(existing) => existing,
            None => {
                zero_salt = vec![0u8; hash_len];
                &zero_salt
            }
        };
        self.hmac(salt_bytes, ikm)
    }

    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let hash_len = self.hash_len();
        let iterations = if length == 0 {
            0
        } else {
            (length + hash_len - 1) / hash_len
        };

        let mut okm = Vec::with_capacity(iterations * hash_len);
        let mut previous = Vec::new();

        for counter in 1..=iterations {
            let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
            input.extend_from_slice(&previous);
            input.extend_from_slice(info);
            input.push(counter as u8);

            previous = self.hmac(prk, &input);
            okm.extend_from_slice(&previous);
        }

        okm.truncate(length);
        okm
    }

    pub fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, String> {
        if length > u16::MAX as usize {
            return Err("Requested HKDF length too large".to_string());
        }

        let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
        hkdf_label.push(((length >> 8) & 0xff) as u8);
        hkdf_label.push((length & 0xff) as u8);

        let mut full_label = Vec::with_capacity(6 + label.len());
        full_label.extend_from_slice(b"tls13 ");
        full_label.extend_from_slice(label);
        if full_label.len() > 255 {
            return Err("HKDF label too long".to_string());
        }
        if context.len() > 255 {
            return Err("HKDF context too long".to_string());
        }

        hkdf_label.push(full_label.len() as u8);
        hkdf_label.extend_from_slice(&full_label);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        eprintln!("TLS13 HKDF-Expand-Label: label={:?}, full_label={:?}, info_len={}",
            String::from_utf8_lossy(label), String::from_utf8_lossy(&full_label), hkdf_label.len());

        Ok(self.hkdf_expand(secret, &hkdf_label, length))
    }

    pub fn derive_secret(
        &self,
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, String> {
        if transcript_hash.len() != self.hash_len() {
            return Err("Transcript hash length mismatch".to_string());
        }
        self.hkdf_expand_label(secret, label, transcript_hash, self.hash_len())
    }
}
