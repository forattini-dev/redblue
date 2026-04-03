//! File MCP Tools
//!
//! File operations: compression, decompression, hash calculation/verification.

use crate::compression::{gzip_decompress, TarReader};
use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;
use std::fs;
use std::path::Path;

/// Register file tools with the server
pub fn register_file_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.file.unzip",
            description:
                "Decompress a file. Auto-detects format from magic bytes (gzip, tar, zip, tar.gz).",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Path to the compressed file.",
                    required: true,
                },
                ToolField {
                    name: "output",
                    field_type: "string",
                    description: "Output path (file for gzip, directory for archives).",
                    required: false,
                },
                ToolField {
                    name: "list_only",
                    field_type: "boolean",
                    description: "List archive contents without extracting.",
                    required: false,
                },
            ],
            handler: tool_file_unzip,
        },
        ToolDefinition {
            name: "rb.file.hash",
            description: "Calculate file hash using specified algorithm.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Path to the file.",
                    required: true,
                },
                ToolField {
                    name: "algorithm",
                    field_type: "string",
                    description: "Hash algorithm: md5, sha1, sha256, sha384, blake2b, crc32.",
                    required: true,
                },
            ],
            handler: tool_file_hash,
        },
        ToolDefinition {
            name: "rb.file.hash.verify",
            description: "Verify file hash against expected value.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Path to the file.",
                    required: true,
                },
                ToolField {
                    name: "algorithm",
                    field_type: "string",
                    description: "Hash algorithm: md5, sha1, sha256, sha384, blake2b, crc32.",
                    required: true,
                },
                ToolField {
                    name: "expected",
                    field_type: "string",
                    description: "Expected hash value (hex string).",
                    required: true,
                },
            ],
            handler: tool_file_hash_verify,
        },
        ToolDefinition {
            name: "rb.file.info",
            description: "Get file information: type, size, magic bytes, entropy.",
            fields: &[ToolField {
                name: "path",
                field_type: "string",
                description: "Path to the file.",
                required: true,
            }],
            handler: tool_file_info,
        },
    ]
}

/// Decompress a file
fn tool_file_unzip(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: path".to_string())?;

    let list_only = args
        .get("list_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let file_path = Path::new(path);
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }

    let data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let format = detect_format(&data, path);

    match format.as_str() {
        "gzip" | "gz" => {
            let decompressed =
                gzip_decompress(&data).map_err(|e| format!("Gzip decompression failed: {}", e))?;

            if list_only {
                let result = JsonValue::Object(vec![
                    ("format".to_string(), JsonValue::String("gzip".to_string())),
                    (
                        "original_size".to_string(),
                        JsonValue::Number(data.len() as f64),
                    ),
                    (
                        "decompressed_size".to_string(),
                        JsonValue::Number(decompressed.len() as f64),
                    ),
                ]);
                return Ok(ToolResult::with_data(
                    format!("Gzip file: {} -> {} bytes", data.len(), decompressed.len()),
                    result,
                ));
            }

            // Determine output path
            let output_path = args
                .get("output")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| strip_gz_extension(path));

            fs::write(&output_path, &decompressed)
                .map_err(|e| format!("Failed to write output: {}", e))?;

            let result = JsonValue::Object(vec![
                (
                    "status".to_string(),
                    JsonValue::String("success".to_string()),
                ),
                ("format".to_string(), JsonValue::String("gzip".to_string())),
                ("output".to_string(), JsonValue::String(output_path.clone())),
                (
                    "size".to_string(),
                    JsonValue::Number(decompressed.len() as f64),
                ),
            ]);
            Ok(ToolResult::with_data(
                format!(
                    "Decompressed to {} ({} bytes)",
                    output_path,
                    decompressed.len()
                ),
                result,
            ))
        }
        "tar" | "tar.gz" => {
            let tar_data = if format == "tar.gz" {
                gzip_decompress(&data).map_err(|e| format!("Gzip decompression failed: {}", e))?
            } else {
                data
            };

            let mut reader = TarReader::new(tar_data.as_slice());
            let mut entries = Vec::new();

            while let Some(entry) = reader
                .next_entry()
                .map_err(|e| format!("TAR read error: {}", e))?
            {
                entries.push(JsonValue::Object(vec![
                    ("name".to_string(), JsonValue::String(entry.name.clone())),
                    ("size".to_string(), JsonValue::Number(entry.size as f64)),
                    (
                        "type".to_string(),
                        JsonValue::String(
                            match entry.type_flag {
                                b'0' | 0 => "file",
                                b'5' => "directory",
                                b'1' => "link",
                                b'2' => "symlink",
                                _ => "unknown",
                            }
                            .to_string(),
                        ),
                    ),
                ]));

                // Skip data to advance to next entry
                reader
                    .skip_data(entry.size)
                    .map_err(|e| format!("Failed to skip entry: {}", e))?;
            }

            let entry_count = entries.len();
            let result = JsonValue::Object(vec![
                ("format".to_string(), JsonValue::String(format)),
                ("entries".to_string(), JsonValue::Array(entries)),
                (
                    "total_entries".to_string(),
                    JsonValue::Number(entry_count as f64),
                ),
            ]);
            Ok(ToolResult::with_data(
                format!("TAR archive with {} entries", entry_count),
                result,
            ))
        }
        _ => Err(format!(
            "Unsupported format '{}'. Supported: gzip, tar, zip, tar.gz",
            format
        )),
    }
}

/// Calculate file hash
fn tool_file_hash(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: path".to_string())?;

    let algorithm = args
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: algorithm".to_string())?;

    let file_path = Path::new(path);
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }

    let data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let hash_hex = calculate_hash(&data, algorithm)?;

    let result = JsonValue::Object(vec![
        ("path".to_string(), JsonValue::String(path.to_string())),
        (
            "algorithm".to_string(),
            JsonValue::String(algorithm.to_lowercase()),
        ),
        ("hash".to_string(), JsonValue::String(hash_hex.clone())),
        ("size".to_string(), JsonValue::Number(data.len() as f64)),
    ]);
    Ok(ToolResult::with_data(
        format!("{} ({})  {}", hash_hex, algorithm.to_uppercase(), path),
        result,
    ))
}

/// Verify file hash
fn tool_file_hash_verify(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: path".to_string())?;

    let algorithm = args
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: algorithm".to_string())?;

    let expected = args
        .get("expected")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: expected".to_string())?;

    let file_path = Path::new(path);
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }

    let data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;
    let actual_hash = calculate_hash(&data, algorithm)?;

    let matches = actual_hash.eq_ignore_ascii_case(expected);

    let result = JsonValue::Object(vec![
        ("path".to_string(), JsonValue::String(path.to_string())),
        (
            "algorithm".to_string(),
            JsonValue::String(algorithm.to_lowercase()),
        ),
        (
            "expected".to_string(),
            JsonValue::String(expected.to_string()),
        ),
        ("actual".to_string(), JsonValue::String(actual_hash)),
        ("verified".to_string(), JsonValue::Bool(matches)),
    ]);

    let msg = if matches {
        format!("✓ {} hash verified for {}", algorithm.to_uppercase(), path)
    } else {
        format!("✗ {} hash MISMATCH for {}", algorithm.to_uppercase(), path)
    };
    Ok(ToolResult::with_data(msg, result))
}

/// Get file information
fn tool_file_info(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: path".to_string())?;

    let file_path = Path::new(path);
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }

    let metadata =
        fs::metadata(file_path).map_err(|e| format!("Failed to read metadata: {}", e))?;
    let data = fs::read(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let file_type = detect_file_type(&data);
    let format = detect_format(&data, path);
    let entropy = calculate_entropy(&data);

    // Magic bytes (first 16)
    let magic_len = 16.min(data.len());
    let magic_hex: String = data[..magic_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");

    let result = JsonValue::Object(vec![
        ("path".to_string(), JsonValue::String(path.to_string())),
        ("size".to_string(), JsonValue::Number(metadata.len() as f64)),
        ("type".to_string(), JsonValue::String(file_type.to_string())),
        ("magic_bytes".to_string(), JsonValue::String(magic_hex)),
        (
            "compression_format".to_string(),
            if format != "unknown" {
                JsonValue::String(format)
            } else {
                JsonValue::Null
            },
        ),
        ("entropy".to_string(), JsonValue::Number(entropy)),
        (
            "entropy_analysis".to_string(),
            JsonValue::String(
                if entropy > 7.5 {
                    "likely compressed/encrypted"
                } else if entropy < 4.0 {
                    "likely text/structured data"
                } else {
                    "mixed content"
                }
                .to_string(),
            ),
        ),
    ]);

    Ok(ToolResult::with_data(
        format!(
            "{}: {} ({} bytes, entropy: {:.2})",
            path,
            file_type,
            metadata.len(),
            entropy
        ),
        result,
    ))
}

// Helper functions

fn detect_format(data: &[u8], file_path: &str) -> String {
    if data.len() >= 2 {
        if data[0] == 0x1f && data[1] == 0x8b {
            if file_path.ends_with(".tar.gz") || file_path.ends_with(".tgz") {
                return "tar.gz".to_string();
            }
            return "gzip".to_string();
        }
        if data[0] == 0x50 && data[1] == 0x4b {
            return "zip".to_string();
        }
    }

    if data.len() >= 263 && &data[257..262] == b"ustar" {
        return "tar".to_string();
    }

    let lower = file_path.to_lowercase();
    if lower.ends_with(".gz") || lower.ends_with(".gzip") {
        return "gzip".to_string();
    }
    if lower.ends_with(".tar") {
        return "tar".to_string();
    }
    if lower.ends_with(".zip") {
        return "zip".to_string();
    }

    "unknown".to_string()
}

fn detect_file_type(data: &[u8]) -> &'static str {
    if data.len() < 4 {
        return "unknown";
    }

    match &data[..4.min(data.len())] {
        [0x1f, 0x8b, ..] => "gzip compressed",
        [0x50, 0x4b, 0x03, 0x04] => "ZIP archive",
        [0x7f, 0x45, 0x4c, 0x46] => "ELF executable",
        [0x4d, 0x5a, ..] => "PE/DOS executable",
        [0x89, 0x50, 0x4e, 0x47] => "PNG image",
        [0xff, 0xd8, 0xff, ..] => "JPEG image",
        [0x25, 0x50, 0x44, 0x46] => "PDF document",
        _ => {
            if data.len() >= 263 && &data[257..262] == b"ustar" {
                return "TAR archive";
            }
            let printable = data
                .iter()
                .take(512)
                .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();
            if printable > data.len().min(512) * 9 / 10 {
                return "text/ASCII";
            }
            "binary data"
        }
    }
}

fn calculate_hash(data: &[u8], algorithm: &str) -> Result<String, String> {
    match algorithm.to_lowercase().as_str() {
        "md5" => {
            let hash = crate::crypto::md5::md5(data);
            Ok(hex_encode(&hash))
        }
        "sha1" => {
            let hash = crate::crypto::sha1::sha1(data);
            Ok(hex_encode(&hash))
        }
        "sha256" => {
            let hash = crate::crypto::sha256::sha256(data);
            Ok(hex_encode(&hash))
        }
        "sha384" => {
            let hash = crate::crypto::sha384::sha384(data);
            Ok(hex_encode(&hash))
        }
        "blake2b" => {
            use crate::storage::encryption::blake2b::Blake2b;
            let mut hasher = Blake2b::new(64);
            hasher.update(data);
            let hash = hasher.finalize();
            Ok(hex_encode(&hash))
        }
        "crc32" => {
            let crc = crate::compression::crc32(data);
            Ok(format!("{:08x}", crc))
        }
        _ => Err(format!(
            "Unknown algorithm '{}'. Supported: md5, sha1, sha256, sha384, blake2b, crc32",
            algorithm
        )),
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn strip_gz_extension(path: &str) -> String {
    if path.ends_with(".gz") {
        path[..path.len() - 3].to_string()
    } else if path.ends_with(".gzip") {
        path[..path.len() - 5].to_string()
    } else {
        format!("{}.out", path)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
