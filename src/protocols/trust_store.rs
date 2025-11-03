use super::p256::P256Point;
use super::rsa::RsaPublicKey;
use super::x509;
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct TrustAnchor {
    pub subject: String,
    pub public_key: TrustPublicKey,
}

#[derive(Clone)]
pub enum TrustPublicKey {
    Rsa(RsaPublicKey),
    EcP256(P256Point),
}

#[derive(Clone)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    pub fn default() -> Self {
        let mut store = Self::new();
        let _ = store.add_pem(ISRG_ROOT_X1_BASE64);
        let _ = store.add_env_anchors();
        store
    }

    pub fn add_pem(&mut self, pem_body: &str) -> Result<(), String> {
        let anchor = load_anchor(pem_body)?;
        self.anchors.push(anchor);
        Ok(())
    }

    pub fn with_anchor(mut self, anchor: TrustAnchor) -> Self {
        self.anchors.push(anchor);
        self
    }

    pub fn add_pem_file(&mut self, path: &str) -> Result<(), String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read trust anchor '{}': {}", path, e))?;
        let mut loaded = false;
        for block in extract_pem_certificates(&content) {
            self.add_pem(&block)?;
            loaded = true;
        }
        if loaded {
            Ok(())
        } else {
            Err(format!(
                "No certificate blocks found in trust anchor file '{}'",
                path
            ))
        }
    }

    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    pub fn find_by_subject(&self, subject: &str) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|anchor| anchor.subject == subject)
    }

    fn add_env_anchors(&mut self) -> Result<(), String> {
        let paths = match std::env::var("RB_TRUST_ANCHORS") {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };

        let mut errors = Vec::new();
        for raw in paths.split(':') {
            let path = raw.trim();
            if path.is_empty() {
                continue;
            }
            if !Path::new(path).exists() {
                errors.push(format!("Trust anchor path '{}' does not exist", path));
                continue;
            }
            if let Err(err) = self.add_pem_file(path) {
                errors.push(err);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn load_anchor(pem_body: &str) -> Result<TrustAnchor, String> {
    let der = decode_base64(pem_body)?;
    let cert = x509::X509Certificate::from_der(&der)?;

    let subject = cert.subject_string();
    let spki = &cert.subject_public_key_info;
    let algorithm = spki.algorithm.algorithm.as_str();

    let public_key = match algorithm {
        "1.2.840.113549.1.1.1" => {
            let (modulus, exponent) = spki
                .rsa_components()
                .map_err(|e| format!("Failed to parse trust anchor RSA key: {}", e))?;
            TrustPublicKey::Rsa(RsaPublicKey::from_components(&modulus, &exponent))
        }
        "1.2.840.10045.2.1" => {
            let curve_oid = spki
                .algorithm
                .parameters_oid
                .as_deref()
                .ok_or_else(|| "EC public key missing named curve OID".to_string())?;
            if curve_oid != "1.2.840.10045.3.1.7" {
                return Err(format!(
                    "Unsupported EC named curve '{}' in trust anchor",
                    curve_oid
                ));
            }
            let point = P256Point::from_uncompressed_bytes(&spki.public_key)
                .map_err(|e| format!("Failed to parse EC trust anchor public key: {}", e))?;
            TrustPublicKey::EcP256(point)
        }
        oid => {
            return Err(format!(
                "Unsupported trust anchor public key algorithm: {}",
                oid
            ))
        }
    };

    Ok(TrustAnchor {
        subject,
        public_key,
    })
}

fn extract_pem_certificates(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut in_block = false;

    for line in content.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            in_block = true;
            current.clear();
        } else if line.starts_with("-----END CERTIFICATE") {
            if in_block {
                blocks.push(current.clone());
            }
            in_block = false;
        } else if in_block {
            current.push_str(line.trim());
        }
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pem_certificates() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----";
        let blocks = extract_pem_certificates(pem);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], "AAA");
        assert_eq!(blocks[1], "BBB");
    }
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let mut cleaned = Vec::with_capacity(input.len());
    for ch in input.chars() {
        if !ch.is_whitespace() {
            cleaned.push(ch);
        }
    }

    let mut output = Vec::with_capacity(cleaned.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits_collected = 0u8;

    for ch in cleaned {
        let value = match ch {
            'A'..='Z' => ch as u8 - b'A',
            'a'..='z' => ch as u8 - b'a' + 26,
            '0'..='9' => ch as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            '=' => {
                if bits_collected == 0 {
                    break;
                }
                while bits_collected >= 8 {
                    let byte = (buffer >> (bits_collected - 8)) as u8;
                    output.push(byte);
                    bits_collected -= 8;
                }
                return Ok(output);
            }
            _ => return Err(format!("Invalid base64 character '{}'", ch)),
        } as u32;

        buffer = (buffer << 6) | value;
        bits_collected += 6;
        if bits_collected >= 8 {
            let byte = (buffer >> (bits_collected - 8)) as u8;
            output.push(byte);
            bits_collected -= 8;
            buffer &= (1 << bits_collected) - 1;
        }
    }

    if bits_collected >= 8 {
        output.push((buffer >> (bits_collected - 8)) as u8);
    }

    Ok(output)
}

// ISRG Root X1 (Let's Encrypt)
const ISRG_ROOT_X1_BASE64: &str = "\
MIIFazCCA1OgAwIBAgIRAIIQz7DSQAUh2bFMvx6b1PEwDQYJKoZIhvcNAQELBQAw\
TzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkxldCdzIEVuY3J5cHQxIDAeBgNVBAMT\
F0xldCdzIEVuY3J5cHQgQXV0aG9yaXR5MB4XDTIwMTAyNzE4MjYwMFoXDTMwMTAy\
NTE4MjYwMFowTzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkxldCdzIEVuY3J5cHQx\
IDAeBgNVBAMTF0xldCdzIEVuY3J5cHQgQXV0aG9yaXR5MIICIjANBgkqhkiG9w0B\
AQEFAAOCAg8AMIICCgKCAgEA7ahP5sXzYmbYvSWuLU7tkFkBC5T9b0p70mqBW8Sb\
NkvA2gw2Zn2iXTW0/5Da1t5i+4wRKQ0ZTPbpQPYT8L7m7QOcG0b4obBOvdbZQ8d+\
Nf4wowKIi1K3ORAZbK6Uf0p2lo6fTqjrDodXwZ0A/VP11dYvF6fKob/oZfA8lHwu\
CkFxpRpoFrr63ub9ekxWWo/xpaCT7P0V9mX2wQub7aXMBmD0Z92w2E1E8J2+ffyJ\
82ccLeU8p11nJNdbidKfnUSXZweqqjZCChd4Eex3n0PsrhJXmSJPISfLduQT1+bd\
IO72ecxB2B7h4lX4KkdMst6D7FGTTsvh0kDkuAJ3GInV5N4bRUht3r7l0ocSVnLE\
F5t0vZ8BLEIoAA7HYd+91C8LbBY3M3x+o5oivo5eyouLva79Db5RCwWH24C2uD5W\
nQwZmb6sE15qgQ1m5AZdLr0A2D9m2ACyg9X1fd4wM8S70kQn1OZ3gC/GuAKQoYV0\
d3eyI2GTTFA8p90aG0Cami7DhxN57aBNTyetm6njhptP2srO0kipxcZVEXfBdW6U\
u0b4GHz2wEs7rm3D0v9Pi3Fica8FWHQrQQizxgxYkWwaRM42gnB0qxSYd4z7C0yD\
9W2F5M0cdCE1rNPqeCzgGuQn2bbKsR7wHXqZc48wGPRvAXJ/MtGO0wZJbm6l6F8H\
FadwCwECAwEAAaOCAXUwggFxMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTAD\
AQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSQr2MzH7l3eRZ2cITD\
w1BTsJEyGzAfBgNVHSMEGDAWgBSQr2MzH7l3eRZ2cITDw1BTsJEyGzBvBggrBgEF\
BQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmxldHNlbmNyeXB0Lm9y\
Zy8wLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmxldHNlbmNyeXB0Lm9yZy9yb290\
LmNydDAJBgNVHRMEAjAAMIIBBQYKKwYBBAHWeQIEAgSB9gSB8wDxAHYApLkJkLQY\
WQ4m7Q0u1Q7L5Q9KuZCbe6zk+QqrUugOAAABdiF6vV4AAAQDAEYwRAIgEUsVTNff\
kwh28ykVfoCENKz7dxyzKDn5XxhxL7sRKqMCIQCImQxGc1dQc5sKXc5teLoI0lp4\
sIwoMvVJE9idh+NangB1ALtTTME0fH5UNShUMpOWu1Zf4nHFD/1G2VNfz3gb2sAA\
AAF2IXq9sAAABAMARjBEAiBtyEiC5EvhczHxVn9Yx8RJWb1x1o1t4bm/FvGV8eK3\
4wIgBgE4nn3OJbGdv8ImZ/Sc7VcRbP5t6dv3Vv4Y20Q4R2s=";
