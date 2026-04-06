//! Hash Identification
//!
//! Identifies hash algorithms based on format, length, and patterns.

use std::collections::HashMap;

/// Information about a hash type
#[derive(Debug, Clone)]
pub struct HashType {
  /// Hash algorithm name
  pub name: &'static str,
  /// Hash length in bytes
  pub length: usize,
  /// Example hash pattern
  pub example: &'static str,
  /// Related hashcat mode
  pub hashcat_mode: Option<u32>,
  /// Related john format
  pub john_format: Option<&'static str>,
}

/// Hash identifier
pub struct HashIdentifier {
  patterns: HashMap<usize, Vec<HashType>>,
}

impl Default for HashIdentifier {
  fn default() -> Self {
    Self::new()
  }
}

impl HashIdentifier {
  /// Create new hash identifier with built-in patterns
  pub fn new() -> Self {
    let mut patterns: HashMap<usize, Vec<HashType>> = HashMap::new();

    // 32-char hashes (16 bytes)
    patterns.insert(
      32,
      vec![
        HashType {
          name: "MD5",
          length: 16,
          example: "d41d8cd98f00b204e9800998ecf8427e",
          hashcat_mode: Some(0),
          john_format: Some("raw-md5"),
        },
        HashType {
          name: "NTLM",
          length: 16,
          example: "31d6cfe0d16ae931b73c59d7e0c089c0",
          hashcat_mode: Some(1000),
          john_format: Some("nt"),
        },
        HashType {
          name: "MD4",
          length: 16,
          example: "31d6cfe0d16ae931b73c59d7e0c089c0",
          hashcat_mode: Some(900),
          john_format: Some("raw-md4"),
        },
      ],
    );

    // 40-char hashes (20 bytes)
    patterns.insert(
      40,
      vec![
        HashType {
          name: "SHA1",
          length: 20,
          example: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
          hashcat_mode: Some(100),
          john_format: Some("raw-sha1"),
        },
        HashType {
          name: "RIPEMD-160",
          length: 20,
          example: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
          hashcat_mode: Some(6000),
          john_format: None,
        },
      ],
    );

    // 64-char hashes (32 bytes)
    patterns.insert(
      64,
      vec![
        HashType {
          name: "SHA256",
          length: 32,
          example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          hashcat_mode: Some(1400),
          john_format: Some("raw-sha256"),
        },
        HashType {
          name: "SHA3-256",
          length: 32,
          example: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
          hashcat_mode: Some(17400),
          john_format: None,
        },
        HashType {
          name: "BLAKE2s",
          length: 32,
          example: "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
          hashcat_mode: None,
          john_format: None,
        },
      ],
    );

    // 96-char hashes (48 bytes)
    patterns.insert(
            96,
            vec![HashType {
                name: "SHA384",
                length: 48,
                example: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                hashcat_mode: Some(10800),
                john_format: Some("raw-sha384"),
            }],
        );

    // 128-char hashes (64 bytes)
    patterns.insert(
            128,
            vec![
                HashType {
                    name: "SHA512",
                    length: 64,
                    example: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                    hashcat_mode: Some(1700),
                    john_format: Some("raw-sha512"),
                },
                HashType {
                    name: "SHA3-512",
                    length: 64,
                    example: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                    hashcat_mode: Some(17600),
                    john_format: None,
                },
                HashType {
                    name: "BLAKE2b",
                    length: 64,
                    example: "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                    hashcat_mode: None,
                    john_format: None,
                },
                HashType {
                    name: "Whirlpool",
                    length: 64,
                    example: "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
                    hashcat_mode: Some(6100),
                    john_format: Some("whirlpool"),
                },
            ],
        );

    Self { patterns }
  }

  /// Identify possible hash types from a hash string
  pub fn identify(&self, hash: &str) -> Vec<HashType> {
    let hash = hash.trim();

    // Check for common prefixes/formats
    if let Some(result) = self.identify_prefixed(hash) {
      return vec![result];
    }

    // Check by length
    let len = hash.len();

    // Verify it's hex
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
      return vec![];
    }

    self.patterns.get(&len).cloned().unwrap_or_default()
  }

  /// Check for prefixed hash formats
  fn identify_prefixed(&self, hash: &str) -> Option<HashType> {
    // $1$ - MD5 crypt
    if hash.starts_with("$1$") {
      return Some(HashType {
        name: "MD5-Crypt",
        length: 22,
        example: "$1$salt$qJH7.N4xYta3aEG/dfqo/0",
        hashcat_mode: Some(500),
        john_format: Some("md5crypt"),
      });
    }

    // $2a$, $2b$, $2y$ - bcrypt
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
      return Some(HashType {
        name: "bcrypt",
        length: 60,
        example: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        hashcat_mode: Some(3200),
        john_format: Some("bcrypt"),
      });
    }

    // $5$ - SHA-256 crypt
    if hash.starts_with("$5$") {
      return Some(HashType {
        name: "SHA256-Crypt",
        length: 43,
        example: "$5$rounds=5000$salt$hash",
        hashcat_mode: Some(7400),
        john_format: Some("sha256crypt"),
      });
    }

    // $6$ - SHA-512 crypt
    if hash.starts_with("$6$") {
      return Some(HashType {
        name: "SHA512-Crypt",
        length: 86,
        example: "$6$rounds=5000$salt$hash",
        hashcat_mode: Some(1800),
        john_format: Some("sha512crypt"),
      });
    }

    // $argon2 - Argon2
    if hash.starts_with("$argon2") {
      return Some(HashType {
        name: "Argon2",
        length: 0,
        example: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash",
        hashcat_mode: None,
        john_format: Some("argon2"),
      });
    }

    None
  }

  /// Get all supported hash types
  pub fn list_all(&self) -> Vec<HashType> {
    let mut all: Vec<HashType> = self
      .patterns
      .values()
      .flat_map(|v| v.iter().cloned())
      .collect();

    // Add prefixed types
    all.push(HashType {
      name: "MD5-Crypt",
      length: 22,
      example: "$1$salt$hash",
      hashcat_mode: Some(500),
      john_format: Some("md5crypt"),
    });
    all.push(HashType {
      name: "bcrypt",
      length: 60,
      example: "$2a$10$hash",
      hashcat_mode: Some(3200),
      john_format: Some("bcrypt"),
    });
    all.push(HashType {
      name: "SHA256-Crypt",
      length: 43,
      example: "$5$salt$hash",
      hashcat_mode: Some(7400),
      john_format: Some("sha256crypt"),
    });
    all.push(HashType {
      name: "SHA512-Crypt",
      length: 86,
      example: "$6$salt$hash",
      hashcat_mode: Some(1800),
      john_format: Some("sha512crypt"),
    });
    all.push(HashType {
      name: "Argon2",
      length: 0,
      example: "$argon2id$v=19$...",
      hashcat_mode: None,
      john_format: Some("argon2"),
    });

    all
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_identify_md5() {
    let identifier = HashIdentifier::new();
    let results = identifier.identify("d41d8cd98f00b204e9800998ecf8427e");
    assert!(!results.is_empty());
    assert!(results.iter().any(|h| h.name == "MD5"));
  }

  #[test]
  fn test_identify_sha256() {
    let identifier = HashIdentifier::new();
    let results =
      identifier.identify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert!(!results.is_empty());
    assert!(results.iter().any(|h| h.name == "SHA256"));
  }

  #[test]
  fn test_identify_bcrypt() {
    let identifier = HashIdentifier::new();
    let results =
      identifier.identify("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "bcrypt");
  }

  #[test]
  fn test_identify_md5_crypt() {
    let identifier = HashIdentifier::new();
    let results = identifier.identify("$1$salt$qJH7.N4xYta3aEG/dfqo/0");
    assert!(!results.is_empty());
    assert_eq!(results[0].name, "MD5-Crypt");
  }
}
