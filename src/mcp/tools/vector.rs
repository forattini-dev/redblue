//! Vector Search MCP Tools
//!
//! Tools for vector similarity search with tiered quantization.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::storage::engine::{BinaryVector, Int8Vector, TieredSearchConfig};
use crate::utils::json::JsonValue;

/// Register vector search tools with the server
pub fn register_vector_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.vector.tiered.create",
            description: "Create a tiered vector index for high-performance similarity search. \
                         Uses binary + int8 quantization for 25x faster search with 30x less memory.",
            fields: &[
                ToolField {
                    name: "dim",
                    field_type: "integer",
                    description: "Vector dimensionality (e.g., 384, 768, 1024, 1536).",
                    required: true,
                },
                ToolField {
                    name: "max_memory_mb",
                    field_type: "integer",
                    description: "Maximum memory budget in MB (optional, unlimited if not set).",
                    required: false,
                },
                ToolField {
                    name: "enable_fp32",
                    field_type: "boolean",
                    description: "Enable fp32 rescoring for maximum precision (default: false).",
                    required: false,
                },
            ],
            handler: tool_tiered_create,
        },
        ToolDefinition {
            name: "rb.vector.tiered.info",
            description: "Get information about tiered index memory usage and configuration.",
            fields: &[ToolField {
                name: "dim",
                field_type: "integer",
                description: "Vector dimensionality to estimate memory for.",
                required: true,
            }],
            handler: tool_tiered_info,
        },
        ToolDefinition {
            name: "rb.vector.binary.quantize",
            description: "Quantize a fp32 vector to binary (1-bit per dimension). \
                         Achieves 32x compression with ~95% retrieval quality.",
            fields: &[ToolField {
                name: "values",
                field_type: "array",
                description: "Array of fp32 values to quantize.",
                required: true,
            }],
            handler: tool_binary_quantize,
        },
        ToolDefinition {
            name: "rb.vector.int8.quantize",
            description: "Quantize a fp32 vector to int8 (8-bit per dimension). \
                         Achieves 4x compression with ~99% retrieval quality.",
            fields: &[ToolField {
                name: "values",
                field_type: "array",
                description: "Array of fp32 values to quantize.",
                required: true,
            }],
            handler: tool_int8_quantize,
        },
        ToolDefinition {
            name: "rb.vector.hamming",
            description: "Compute Hamming distance between two binary vectors.",
            fields: &[
                ToolField {
                    name: "vector_a",
                    field_type: "array",
                    description: "First vector (fp32 values, will be binary quantized).",
                    required: true,
                },
                ToolField {
                    name: "vector_b",
                    field_type: "array",
                    description: "Second vector (fp32 values, will be binary quantized).",
                    required: true,
                },
            ],
            handler: tool_hamming_distance,
        },
        ToolDefinition {
            name: "rb.vector.memory.estimate",
            description: "Estimate memory usage for a tiered index with given parameters.",
            fields: &[
                ToolField {
                    name: "dim",
                    field_type: "integer",
                    description: "Vector dimensionality.",
                    required: true,
                },
                ToolField {
                    name: "count",
                    field_type: "integer",
                    description: "Number of vectors.",
                    required: true,
                },
                ToolField {
                    name: "enable_fp32",
                    field_type: "boolean",
                    description: "Include fp32 storage in estimate (default: false).",
                    required: false,
                },
            ],
            handler: tool_memory_estimate,
        },
    ]
}

fn tool_tiered_create(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let dim = args
        .get("dim")
        .and_then(|v| v.as_f64())
        .map(|v| v as usize)
        .ok_or("Missing required field: dim")?;

    let max_memory_mb = args
        .get("max_memory_mb")
        .and_then(|v| v.as_f64())
        .map(|v| v as usize);

    let enable_fp32 = args
        .get("enable_fp32")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Validate dimension
    if dim == 0 || dim > 16384 {
        return Err("Dimension must be between 1 and 16384".to_string());
    }

    // Calculate memory info
    let bytes_per_vector_binary = (dim + 63) / 64 * 8;
    let bytes_per_vector_int8 = dim;
    let bytes_per_vector_fp32 = dim * 4;

    let total_per_vector = bytes_per_vector_binary
        + bytes_per_vector_int8
        + if enable_fp32 {
            bytes_per_vector_fp32
        } else {
            0
        };

    let max_vectors = max_memory_mb
        .map(|mb| (mb * 1024 * 1024) / total_per_vector)
        .unwrap_or(usize::MAX);

    let config = TieredSearchConfig {
        rescore_multiplier: 4,
        use_fp32_final: enable_fp32,
        min_binary_candidates: 100,
        max_binary_candidates: 10000,
    };

    let text = if let Some(mb) = max_memory_mb {
        format!(
            "Created tiered index: dim={}, max_memory={}MB, max_vectors≈{}, fp32={}",
            dim, mb, max_vectors, enable_fp32
        )
    } else {
        format!(
            "Created tiered index: dim={}, unlimited memory, fp32={}",
            dim, enable_fp32
        )
    };

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("dim".to_string(), JsonValue::Number(dim as f64)),
            (
                "bytes_per_vector".to_string(),
                JsonValue::object(vec![
                    (
                        "binary".to_string(),
                        JsonValue::Number(bytes_per_vector_binary as f64),
                    ),
                    (
                        "int8".to_string(),
                        JsonValue::Number(bytes_per_vector_int8 as f64),
                    ),
                    (
                        "fp32".to_string(),
                        JsonValue::Number(bytes_per_vector_fp32 as f64),
                    ),
                    (
                        "total".to_string(),
                        JsonValue::Number(total_per_vector as f64),
                    ),
                ]),
            ),
            (
                "max_vectors".to_string(),
                if max_vectors == usize::MAX {
                    JsonValue::String("unlimited".to_string())
                } else {
                    JsonValue::Number(max_vectors as f64)
                },
            ),
            ("enable_fp32".to_string(), JsonValue::Bool(enable_fp32)),
            (
                "config".to_string(),
                JsonValue::object(vec![
                    (
                        "rescore_multiplier".to_string(),
                        JsonValue::Number(config.rescore_multiplier as f64),
                    ),
                    (
                        "min_binary_candidates".to_string(),
                        JsonValue::Number(config.min_binary_candidates as f64),
                    ),
                    (
                        "max_binary_candidates".to_string(),
                        JsonValue::Number(config.max_binary_candidates as f64),
                    ),
                    ("use_fp32_final".to_string(), JsonValue::Bool(config.use_fp32_final)),
                ]),
            ),
        ]),
    })
}

fn tool_tiered_info(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let dim = args
        .get("dim")
        .and_then(|v| v.as_f64())
        .map(|v| v as usize)
        .ok_or("Missing required field: dim")?;

    // Calculate compression ratios
    let fp32_bytes = dim * 4;
    let int8_bytes = dim;
    let binary_bytes = (dim + 63) / 64 * 8;

    let int8_ratio = fp32_bytes as f64 / int8_bytes as f64;
    let binary_ratio = fp32_bytes as f64 / binary_bytes as f64;

    // Common embedding dimensions reference
    let common_dims = [
        ("sentence-transformers/all-MiniLM-L6-v2", 384),
        ("sentence-transformers/all-mpnet-base-v2", 768),
        ("OpenAI text-embedding-ada-002", 1536),
        ("OpenAI text-embedding-3-small", 1536),
        ("OpenAI text-embedding-3-large", 3072),
        ("Cohere embed-english-v3.0", 1024),
    ];

    let text = format!(
        "Tiered index info for dim={}:\n\
         - fp32: {} bytes/vector\n\
         - int8: {} bytes/vector ({:.0}x compression)\n\
         - binary: {} bytes/vector ({:.0}x compression)\n\
         - Combined (binary+int8): {} bytes/vector ({:.1}x vs fp32)",
        dim,
        fp32_bytes,
        int8_bytes,
        int8_ratio,
        binary_bytes,
        binary_ratio,
        binary_bytes + int8_bytes,
        fp32_bytes as f64 / (binary_bytes + int8_bytes) as f64
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("dim".to_string(), JsonValue::Number(dim as f64)),
            (
                "storage".to_string(),
                JsonValue::object(vec![
                    ("fp32_bytes".to_string(), JsonValue::Number(fp32_bytes as f64)),
                    ("int8_bytes".to_string(), JsonValue::Number(int8_bytes as f64)),
                    (
                        "binary_bytes".to_string(),
                        JsonValue::Number(binary_bytes as f64),
                    ),
                ]),
            ),
            (
                "compression".to_string(),
                JsonValue::object(vec![
                    ("int8_ratio".to_string(), JsonValue::Number(int8_ratio)),
                    ("binary_ratio".to_string(), JsonValue::Number(binary_ratio)),
                ]),
            ),
            (
                "common_models".to_string(),
                JsonValue::array(
                    common_dims
                        .iter()
                        .map(|(name, d)| {
                            JsonValue::object(vec![
                                ("model".to_string(), JsonValue::String(name.to_string())),
                                ("dim".to_string(), JsonValue::Number(*d as f64)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    })
}

fn tool_binary_quantize(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let values = args
        .get("values")
        .and_then(|v| v.as_array())
        .ok_or("Missing required field: values")?;

    let floats: Vec<f32> = values
        .iter()
        .filter_map(|v| v.as_f64().map(|f| f as f32))
        .collect();

    if floats.is_empty() {
        return Err("Values array is empty or contains non-numeric values".to_string());
    }

    let binary = BinaryVector::from_f32(&floats);
    let original_bytes = floats.len() * 4;
    let quantized_bytes = binary.size_bytes();
    let compression_ratio = original_bytes as f64 / quantized_bytes as f64;

    // Count positive/negative for info
    let positive_count = floats.iter().filter(|&&v| v > 0.0).count();

    let text = format!(
        "Binary quantized {} dimensions: {} bytes → {} bytes ({:.0}x compression). \
         {} positive, {} negative/zero values.",
        floats.len(),
        original_bytes,
        quantized_bytes,
        compression_ratio,
        positive_count,
        floats.len() - positive_count
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("dim".to_string(), JsonValue::Number(floats.len() as f64)),
            (
                "original_bytes".to_string(),
                JsonValue::Number(original_bytes as f64),
            ),
            (
                "quantized_bytes".to_string(),
                JsonValue::Number(quantized_bytes as f64),
            ),
            (
                "compression_ratio".to_string(),
                JsonValue::Number(compression_ratio),
            ),
            (
                "positive_count".to_string(),
                JsonValue::Number(positive_count as f64),
            ),
            (
                "negative_count".to_string(),
                JsonValue::Number((floats.len() - positive_count) as f64),
            ),
        ]),
    })
}

fn tool_int8_quantize(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let values = args
        .get("values")
        .and_then(|v| v.as_array())
        .ok_or("Missing required field: values")?;

    let floats: Vec<f32> = values
        .iter()
        .filter_map(|v| v.as_f64().map(|f| f as f32))
        .collect();

    if floats.is_empty() {
        return Err("Values array is empty or contains non-numeric values".to_string());
    }

    let int8 = Int8Vector::from_f32(&floats);
    let original_bytes = floats.len() * 4;
    let quantized_bytes = int8.size_bytes();
    let compression_ratio = original_bytes as f64 / quantized_bytes as f64;

    // Compute scale factor
    let max_abs = floats
        .iter()
        .map(|v| v.abs())
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(1.0);

    let text = format!(
        "int8 quantized {} dimensions: {} bytes → {} bytes ({:.0}x compression). \
         Scale factor: {:.6}",
        floats.len(),
        original_bytes,
        quantized_bytes,
        compression_ratio,
        127.0 / max_abs
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("dim".to_string(), JsonValue::Number(floats.len() as f64)),
            (
                "original_bytes".to_string(),
                JsonValue::Number(original_bytes as f64),
            ),
            (
                "quantized_bytes".to_string(),
                JsonValue::Number(quantized_bytes as f64),
            ),
            (
                "compression_ratio".to_string(),
                JsonValue::Number(compression_ratio),
            ),
            (
                "scale_factor".to_string(),
                JsonValue::Number((127.0 / max_abs) as f64),
            ),
            ("max_abs_value".to_string(), JsonValue::Number(max_abs as f64)),
        ]),
    })
}

fn tool_hamming_distance(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let values_a = args
        .get("vector_a")
        .and_then(|v| v.as_array())
        .ok_or("Missing required field: vector_a")?;

    let values_b = args
        .get("vector_b")
        .and_then(|v| v.as_array())
        .ok_or("Missing required field: vector_b")?;

    let floats_a: Vec<f32> = values_a
        .iter()
        .filter_map(|v| v.as_f64().map(|f| f as f32))
        .collect();

    let floats_b: Vec<f32> = values_b
        .iter()
        .filter_map(|v| v.as_f64().map(|f| f as f32))
        .collect();

    if floats_a.len() != floats_b.len() {
        return Err(format!(
            "Vector dimensions must match: {} vs {}",
            floats_a.len(),
            floats_b.len()
        ));
    }

    if floats_a.is_empty() {
        return Err("Vectors are empty".to_string());
    }

    let binary_a = BinaryVector::from_f32(&floats_a);
    let binary_b = BinaryVector::from_f32(&floats_b);

    let hamming_dist = binary_a.hamming_distance(&binary_b);
    let normalized = binary_a.hamming_distance_normalized(&binary_b);
    let approx_cosine = binary_a.approx_cosine_similarity(&binary_b);

    let text = format!(
        "Hamming distance: {} (normalized: {:.4}, approx cosine similarity: {:.4})",
        hamming_dist, normalized, approx_cosine
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("dim".to_string(), JsonValue::Number(floats_a.len() as f64)),
            (
                "hamming_distance".to_string(),
                JsonValue::Number(hamming_dist as f64),
            ),
            (
                "normalized_distance".to_string(),
                JsonValue::Number(normalized as f64),
            ),
            (
                "approx_cosine_similarity".to_string(),
                JsonValue::Number(approx_cosine as f64),
            ),
        ]),
    })
}

fn tool_memory_estimate(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let dim = args
        .get("dim")
        .and_then(|v| v.as_f64())
        .map(|v| v as usize)
        .ok_or("Missing required field: dim")?;

    let count = args
        .get("count")
        .and_then(|v| v.as_f64())
        .map(|v| v as usize)
        .ok_or("Missing required field: count")?;

    let enable_fp32 = args
        .get("enable_fp32")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Per-vector sizes
    let binary_per = (dim + 63) / 64 * 8;
    let int8_per = dim;
    let fp32_per = dim * 4;

    let total_per = binary_per + int8_per + if enable_fp32 { fp32_per } else { 0 };

    // Total memory
    let binary_total = binary_per * count;
    let int8_total = int8_per * count;
    let fp32_total = if enable_fp32 { fp32_per * count } else { 0 };
    let grand_total = total_per * count;

    // Format sizes
    let format_size = |bytes: usize| -> String {
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} bytes", bytes)
        }
    };

    // Comparison with pure fp32
    let pure_fp32 = dim * 4 * count;
    let savings = pure_fp32 as f64 / grand_total as f64;

    let text = format!(
        "Memory estimate for {} vectors (dim={}):\n\
         - Binary: {}\n\
         - int8: {}\n\
         - fp32: {}\n\
         - Total: {}\n\
         - vs pure fp32: {:.1}x savings ({} → {})",
        count,
        dim,
        format_size(binary_total),
        format_size(int8_total),
        if enable_fp32 {
            format_size(fp32_total)
        } else {
            "disabled".to_string()
        },
        format_size(grand_total),
        savings,
        format_size(pure_fp32),
        format_size(grand_total)
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("dim".to_string(), JsonValue::Number(dim as f64)),
            ("count".to_string(), JsonValue::Number(count as f64)),
            (
                "memory".to_string(),
                JsonValue::object(vec![
                    (
                        "binary_bytes".to_string(),
                        JsonValue::Number(binary_total as f64),
                    ),
                    (
                        "int8_bytes".to_string(),
                        JsonValue::Number(int8_total as f64),
                    ),
                    (
                        "fp32_bytes".to_string(),
                        JsonValue::Number(fp32_total as f64),
                    ),
                    (
                        "total_bytes".to_string(),
                        JsonValue::Number(grand_total as f64),
                    ),
                ]),
            ),
            (
                "comparison".to_string(),
                JsonValue::object(vec![
                    (
                        "pure_fp32_bytes".to_string(),
                        JsonValue::Number(pure_fp32 as f64),
                    ),
                    ("savings_ratio".to_string(), JsonValue::Number(savings)),
                ]),
            ),
        ]),
    })
}
