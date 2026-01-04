//! Crypto MCP Tools
//!
//! Cipher encryption/decryption, codec encoding/decoding, and hash functions.

use crate::crypto::cipher::{BaconCipher, PlayfairCipher, VigenereCipher};
use crate::crypto::codec::{Codec, MorseCodec, TapCodec, UrlCodec};
use crate::crypto::{decode_base64, encode_base64, sha1, sha256};
use crate::mcp::types::{hex, ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register crypto tools with the server
pub fn register_crypto_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.crypto.cipher.list",
            description: "List available cipher algorithms (aes, chacha20, blowfish, bacon, playfair, vigenere, etc.).",
            fields: &[],
            handler: tool_crypto_cipher_list,
        },
        ToolDefinition {
            name: "rb.crypto.cipher.encrypt",
            description: "Encrypt data using a specified cipher algorithm.",
            fields: &[
                ToolField {
                    name: "cipher",
                    field_type: "string",
                    description: "Cipher name (aes-128-cbc, aes-256-gcm, chacha20, blowfish, bacon, playfair, vigenere, rot13, xor).",
                    required: true,
                },
                ToolField {
                    name: "plaintext",
                    field_type: "string",
                    description: "Text to encrypt (or hex-encoded binary with 'hex:' prefix).",
                    required: true,
                },
                ToolField {
                    name: "key",
                    field_type: "string",
                    description: "Encryption key (plain text or hex-encoded with 'hex:' prefix).",
                    required: true,
                },
                ToolField {
                    name: "iv",
                    field_type: "string",
                    description: "Initialization vector for block ciphers (hex-encoded).",
                    required: false,
                },
            ],
            handler: tool_crypto_cipher_encrypt,
        },
        ToolDefinition {
            name: "rb.crypto.cipher.decrypt",
            description: "Decrypt data using a specified cipher algorithm.",
            fields: &[
                ToolField {
                    name: "cipher",
                    field_type: "string",
                    description: "Cipher name (aes-128-cbc, aes-256-gcm, chacha20, blowfish, bacon, playfair, vigenere, rot13, xor).",
                    required: true,
                },
                ToolField {
                    name: "ciphertext",
                    field_type: "string",
                    description: "Encrypted data (hex-encoded or base64 with 'b64:' prefix).",
                    required: true,
                },
                ToolField {
                    name: "key",
                    field_type: "string",
                    description: "Decryption key (plain text or hex-encoded with 'hex:' prefix).",
                    required: true,
                },
                ToolField {
                    name: "iv",
                    field_type: "string",
                    description: "Initialization vector for block ciphers (hex-encoded).",
                    required: false,
                },
            ],
            handler: tool_crypto_cipher_decrypt,
        },
        ToolDefinition {
            name: "rb.crypto.codec.list",
            description: "List available codecs (base64, hex, url, morse, tap, binary).",
            fields: &[],
            handler: tool_crypto_codec_list,
        },
        ToolDefinition {
            name: "rb.crypto.codec.encode",
            description: "Encode data using a specified codec.",
            fields: &[
                ToolField {
                    name: "codec",
                    field_type: "string",
                    description: "Codec name (base64, hex, url, morse, tap, binary).",
                    required: true,
                },
                ToolField {
                    name: "data",
                    field_type: "string",
                    description: "Data to encode.",
                    required: true,
                },
            ],
            handler: tool_crypto_codec_encode,
        },
        ToolDefinition {
            name: "rb.crypto.codec.decode",
            description: "Decode data using a specified codec.",
            fields: &[
                ToolField {
                    name: "codec",
                    field_type: "string",
                    description: "Codec name (base64, hex, url, morse, tap, binary).",
                    required: true,
                },
                ToolField {
                    name: "data",
                    field_type: "string",
                    description: "Data to decode.",
                    required: true,
                },
            ],
            handler: tool_crypto_codec_decode,
        },
        ToolDefinition {
            name: "rb.crypto.hash",
            description: "Compute hash of data using various algorithms.",
            fields: &[
                ToolField {
                    name: "algorithm",
                    field_type: "string",
                    description: "Hash algorithm (md5, sha1, sha256, sha384, sha512).",
                    required: true,
                },
                ToolField {
                    name: "data",
                    field_type: "string",
                    description: "Data to hash.",
                    required: true,
                },
            ],
            handler: tool_crypto_hash,
        },
    ]
}

fn tool_crypto_cipher_list(
    _server: &mut McpServer,
    _args: &JsonValue,
) -> Result<ToolResult, String> {
    let ciphers = vec![
        ("aes-128-cbc", "AES-128 in CBC mode"),
        ("aes-256-cbc", "AES-256 in CBC mode"),
        ("aes-128-gcm", "AES-128 in GCM mode (authenticated)"),
        ("aes-256-gcm", "AES-256 in GCM mode (authenticated)"),
        ("chacha20", "ChaCha20 stream cipher"),
        ("blowfish", "Blowfish block cipher"),
        ("bacon", "Bacon cipher (steganographic)"),
        ("playfair", "Playfair cipher (digraph substitution)"),
        ("vigenere", "Vigenère polyalphabetic cipher"),
        ("rot13", "ROT13 Caesar cipher"),
        ("xor", "XOR cipher (key is repeated)"),
    ];

    let cipher_json: Vec<JsonValue> = ciphers
        .iter()
        .map(|(name, desc)| {
            JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(name.to_string())),
                (
                    "description".to_string(),
                    JsonValue::String(desc.to_string()),
                ),
            ])
        })
        .collect();

    Ok(ToolResult {
        text: format!("{} cipher algorithms available", ciphers.len()),
        data: JsonValue::object(vec![
            ("count".to_string(), JsonValue::Number(ciphers.len() as f64)),
            ("ciphers".to_string(), JsonValue::Array(cipher_json)),
        ]),
    })
}

fn tool_crypto_cipher_encrypt(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    use crate::crypto::cipher::{Cipher, CipherKey};

    let cipher_name = args
        .get("cipher")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: cipher")?;

    let plaintext = args
        .get("plaintext")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: plaintext")?;

    let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("");

    let ciphertext = match cipher_name.to_lowercase().as_str() {
        "bacon" => {
            let cipher = BaconCipher::new();
            let result = cipher
                .encrypt(plaintext.as_bytes(), &CipherKey::None)
                .map_err(|e| format!("Bacon cipher error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "playfair" => {
            let cipher = PlayfairCipher::new();
            let result = cipher
                .encrypt(plaintext.as_bytes(), &CipherKey::Text(key.to_string()))
                .map_err(|e| format!("Playfair cipher error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "vigenere" => {
            let cipher = VigenereCipher::new();
            let result = cipher
                .encrypt(plaintext.as_bytes(), &CipherKey::Text(key.to_string()))
                .map_err(|e| format!("Vigenere cipher error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "rot13" => plaintext
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                    let offset = (c as u8 - base + 13) % 26;
                    (base + offset) as char
                } else {
                    c
                }
            })
            .collect(),
        "xor" => {
            let key_bytes = key.as_bytes();
            if key_bytes.is_empty() {
                return Err("XOR cipher requires a key".to_string());
            }
            let encrypted: Vec<u8> = plaintext
                .as_bytes()
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
                .collect();
            hex::encode(&encrypted)
        }
        _ => return Err(format!("Unsupported cipher: {}", cipher_name)),
    };

    Ok(ToolResult {
        text: format!("Encrypted with {}", cipher_name),
        data: JsonValue::object(vec![
            (
                "cipher".to_string(),
                JsonValue::String(cipher_name.to_string()),
            ),
            ("ciphertext".to_string(), JsonValue::String(ciphertext)),
        ]),
    })
}

fn tool_crypto_cipher_decrypt(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    use crate::crypto::cipher::{Cipher, CipherKey};

    let cipher_name = args
        .get("cipher")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: cipher")?;

    let ciphertext = args
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: ciphertext")?;

    let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("");

    let plaintext = match cipher_name.to_lowercase().as_str() {
        "bacon" => {
            let cipher = BaconCipher::new();
            let result = cipher
                .decrypt(ciphertext.as_bytes(), &CipherKey::None)
                .map_err(|e| format!("Bacon cipher error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "playfair" => {
            let cipher = PlayfairCipher::new();
            let result = cipher
                .decrypt(ciphertext.as_bytes(), &CipherKey::Text(key.to_string()))
                .map_err(|e| format!("Playfair cipher error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "vigenere" => {
            let cipher = VigenereCipher::new();
            let result = cipher
                .decrypt(ciphertext.as_bytes(), &CipherKey::Text(key.to_string()))
                .map_err(|e| format!("Vigenere cipher error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "rot13" => {
            // ROT13 is symmetric
            ciphertext
                .chars()
                .map(|c| {
                    if c.is_ascii_alphabetic() {
                        let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                        let offset = (c as u8 - base + 13) % 26;
                        (base + offset) as char
                    } else {
                        c
                    }
                })
                .collect()
        }
        "xor" => {
            let encrypted = hex::decode(ciphertext).map_err(|_| "Invalid hex ciphertext")?;
            let key_bytes = key.as_bytes();
            if key_bytes.is_empty() {
                return Err("XOR cipher requires a key".to_string());
            }
            let decrypted: Vec<u8> = encrypted
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
                .collect();
            String::from_utf8_lossy(&decrypted).to_string()
        }
        _ => return Err(format!("Unsupported cipher: {}", cipher_name)),
    };

    Ok(ToolResult {
        text: format!("Decrypted with {}", cipher_name),
        data: JsonValue::object(vec![
            (
                "cipher".to_string(),
                JsonValue::String(cipher_name.to_string()),
            ),
            ("plaintext".to_string(), JsonValue::String(plaintext)),
        ]),
    })
}

fn tool_crypto_codec_list(
    _server: &mut McpServer,
    _args: &JsonValue,
) -> Result<ToolResult, String> {
    let codecs = vec![
        ("base64", "Base64 encoding (RFC 4648)"),
        ("hex", "Hexadecimal encoding"),
        ("url", "URL percent-encoding"),
        ("morse", "Morse code"),
        ("tap", "Tap code (prison code)"),
        ("binary", "Binary (8-bit representation)"),
    ];

    let codec_json: Vec<JsonValue> = codecs
        .iter()
        .map(|(name, desc)| {
            JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(name.to_string())),
                (
                    "description".to_string(),
                    JsonValue::String(desc.to_string()),
                ),
            ])
        })
        .collect();

    Ok(ToolResult {
        text: format!("{} codecs available", codecs.len()),
        data: JsonValue::object(vec![
            ("count".to_string(), JsonValue::Number(codecs.len() as f64)),
            ("codecs".to_string(), JsonValue::Array(codec_json)),
        ]),
    })
}

fn tool_crypto_codec_encode(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let codec_name = args
        .get("codec")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: codec")?;

    let data = args
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: data")?;

    let encoded = match codec_name.to_lowercase().as_str() {
        "base64" => encode_base64(data.as_bytes()),
        "hex" => hex::encode(data.as_bytes()),
        "url" => {
            let codec = UrlCodec::new();
            let result = codec
                .encode(data.as_bytes())
                .map_err(|e| format!("URL encode error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "morse" => {
            let codec = MorseCodec::new();
            let result = codec
                .encode(data.as_bytes())
                .map_err(|e| format!("Morse encode error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "tap" => {
            let codec = TapCodec::new();
            let result = codec
                .encode(data.as_bytes())
                .map_err(|e| format!("Tap encode error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "binary" => data
            .bytes()
            .map(|b| format!("{:08b}", b))
            .collect::<Vec<_>>()
            .join(" "),
        _ => return Err(format!("Unsupported codec: {}", codec_name)),
    };

    Ok(ToolResult {
        text: format!("Encoded with {}", codec_name),
        data: JsonValue::object(vec![
            (
                "codec".to_string(),
                JsonValue::String(codec_name.to_string()),
            ),
            ("encoded".to_string(), JsonValue::String(encoded)),
        ]),
    })
}

fn tool_crypto_codec_decode(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let codec_name = args
        .get("codec")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: codec")?;

    let data = args
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: data")?;

    let decoded = match codec_name.to_lowercase().as_str() {
        "base64" => {
            let bytes = decode_base64(data).ok_or("Invalid base64")?;
            String::from_utf8_lossy(&bytes).to_string()
        }
        "hex" => {
            let bytes = hex::decode(data).map_err(|_| "Invalid hex")?;
            String::from_utf8_lossy(&bytes).to_string()
        }
        "url" => {
            let codec = UrlCodec::new();
            let result = codec
                .decode(data.as_bytes())
                .map_err(|e| format!("URL decode error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "morse" => {
            let codec = MorseCodec::new();
            let result = codec
                .decode(data.as_bytes())
                .map_err(|e| format!("Morse decode error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "tap" => {
            let codec = TapCodec::new();
            let result = codec
                .decode(data.as_bytes())
                .map_err(|e| format!("Tap decode error: {}", e))?;
            String::from_utf8_lossy(&result).to_string()
        }
        "binary" => data
            .split_whitespace()
            .filter_map(|b| u8::from_str_radix(b, 2).ok())
            .map(|b| b as char)
            .collect(),
        _ => return Err(format!("Unsupported codec: {}", codec_name)),
    };

    Ok(ToolResult {
        text: format!("Decoded with {}", codec_name),
        data: JsonValue::object(vec![
            (
                "codec".to_string(),
                JsonValue::String(codec_name.to_string()),
            ),
            ("decoded".to_string(), JsonValue::String(decoded)),
        ]),
    })
}

fn tool_crypto_hash(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let algorithm = args
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: algorithm")?;

    let data = args
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: data")?;

    let hash = match algorithm.to_lowercase().as_str() {
        "sha256" => {
            let digest = sha256(data.as_bytes());
            hex::encode(&digest)
        }
        "sha1" => {
            let digest = sha1(data.as_bytes());
            hex::encode(&digest)
        }
        "md5" => {
            let digest = crate::crypto::md5(data.as_bytes());
            hex::encode(&digest)
        }
        _ => {
            return Err(format!(
                "Unsupported algorithm: {}. Supported: sha256, sha1, md5",
                algorithm
            ))
        }
    };

    let hash_len = hash.len() / 2; // Length in bytes (hex is 2 chars per byte)
    Ok(ToolResult {
        text: format!("{} hash computed", algorithm.to_uppercase()),
        data: JsonValue::object(vec![
            (
                "algorithm".to_string(),
                JsonValue::String(algorithm.to_string()),
            ),
            ("hash".to_string(), JsonValue::String(hash)),
            ("length".to_string(), JsonValue::Number(hash_len as f64)),
        ]),
    })
}
