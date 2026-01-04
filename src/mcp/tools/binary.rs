//! Binary MCP Tools
//!
//! Binary analysis, exploitation helpers, and pwntools-style utilities.

use crate::mcp::types::{hex, ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::modules::binary::{
    p16, p32, p64, p8,
    shellcode::{Encoder, LinuxX64, LinuxX86},
    Binary, FmtStr, GadgetFinder, PatternGenerator,
};
use crate::utils::json::JsonValue;

/// Register binary tools with the server
pub fn register_binary_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.binary.parse",
            description: "Parse ELF or PE binary and return header information.",
            fields: &[ToolField {
                name: "path",
                field_type: "string",
                description: "Path to the binary file.",
                required: true,
            }],
            handler: tool_binary_parse,
        },
        ToolDefinition {
            name: "rb.binary.checksec",
            description: "Check security features of a binary (RELRO, Stack Canary, NX, PIE).",
            fields: &[ToolField {
                name: "path",
                field_type: "string",
                description: "Path to the binary file.",
                required: true,
            }],
            handler: tool_binary_checksec,
        },
        ToolDefinition {
            name: "rb.binary.symbols",
            description: "List symbols from a binary with optional filtering.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Path to the binary file.",
                    required: true,
                },
                ToolField {
                    name: "filter",
                    field_type: "string",
                    description: "Filter symbols by name pattern.",
                    required: false,
                },
            ],
            handler: tool_binary_symbols,
        },
        ToolDefinition {
            name: "rb.binary.rop.gadgets",
            description: "Find ROP gadgets in a binary's executable sections.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Path to the binary file.",
                    required: true,
                },
                ToolField {
                    name: "max_depth",
                    field_type: "number",
                    description: "Maximum gadget length in instructions (default: 5).",
                    required: false,
                },
            ],
            handler: tool_binary_rop_gadgets,
        },
        ToolDefinition {
            name: "rb.binary.fmtstr.payload",
            description: "Generate format string exploit payload for arbitrary write.",
            fields: &[
                ToolField {
                    name: "offset",
                    field_type: "number",
                    description: "Stack offset where format string input appears.",
                    required: true,
                },
                ToolField {
                    name: "address",
                    field_type: "string",
                    description: "Target address to write to (hex, e.g., '0x601040').",
                    required: true,
                },
                ToolField {
                    name: "value",
                    field_type: "string",
                    description: "Value to write (hex, e.g., '0x4011c0').",
                    required: true,
                },
                ToolField {
                    name: "arch",
                    field_type: "string",
                    description: "Architecture: 'x86' or 'x86_64' (default: x86_64).",
                    required: false,
                },
            ],
            handler: tool_binary_fmtstr_payload,
        },
        ToolDefinition {
            name: "rb.binary.shellcode.generate",
            description: "Generate shellcode for common payloads (execve, reverse_tcp, bind_tcp).",
            fields: &[
                ToolField {
                    name: "payload",
                    field_type: "string",
                    description: "Payload type: execve, reverse_tcp, bind_tcp, exit.",
                    required: true,
                },
                ToolField {
                    name: "arch",
                    field_type: "string",
                    description: "Architecture: 'x86' or 'x86_64' (default: x86_64).",
                    required: false,
                },
                ToolField {
                    name: "ip",
                    field_type: "string",
                    description: "IP address for reverse_tcp (e.g., '10.0.0.1').",
                    required: false,
                },
                ToolField {
                    name: "port",
                    field_type: "number",
                    description: "Port for reverse_tcp or bind_tcp.",
                    required: false,
                },
                ToolField {
                    name: "encode",
                    field_type: "boolean",
                    description: "XOR-encode shellcode to avoid null bytes.",
                    required: false,
                },
            ],
            handler: tool_binary_shellcode_generate,
        },
        ToolDefinition {
            name: "rb.binary.pattern.create",
            description: "Create a cyclic pattern for offset detection (De Bruijn sequence).",
            fields: &[ToolField {
                name: "length",
                field_type: "number",
                description: "Pattern length in bytes.",
                required: true,
            }],
            handler: tool_binary_pattern_create,
        },
        ToolDefinition {
            name: "rb.binary.pattern.offset",
            description: "Find offset of a value within a cyclic pattern.",
            fields: &[ToolField {
                name: "value",
                field_type: "string",
                description: "Value to search for (e.g., '0x41326241' or 'Ab1A').",
                required: true,
            }],
            handler: tool_binary_pattern_offset,
        },
        ToolDefinition {
            name: "rb.binary.pack",
            description: "Pack values into binary format (pwntools-style p32/p64).",
            fields: &[
                ToolField {
                    name: "value",
                    field_type: "string",
                    description: "Value to pack (hex or decimal, e.g., '0x401234' or '4198964').",
                    required: true,
                },
                ToolField {
                    name: "bits",
                    field_type: "number",
                    description: "Bit width: 8, 16, 32, or 64 (default: 64).",
                    required: false,
                },
                ToolField {
                    name: "endian",
                    field_type: "string",
                    description: "Endianness: 'little' or 'big' (default: little).",
                    required: false,
                },
            ],
            handler: tool_binary_pack,
        },
    ]
}

fn tool_binary_parse(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: path")?;

    let binary = Binary::from_file(path).map_err(|e| format!("Failed to parse binary: {}", e))?;

    Ok(ToolResult {
        text: format!("Parsed {} binary: {}", binary.format, path),
        data: JsonValue::object(vec![
            ("path".to_string(), JsonValue::String(path.to_string())),
            (
                "format".to_string(),
                JsonValue::String(binary.format.to_string()),
            ),
            (
                "arch".to_string(),
                JsonValue::String(binary.arch.to_string()),
            ),
            ("bits".to_string(), JsonValue::Number(binary.bits as f64)),
            (
                "endian".to_string(),
                JsonValue::String(binary.endian.to_string()),
            ),
            (
                "entry_point".to_string(),
                JsonValue::String(format!("0x{:x}", binary.entry_point)),
            ),
            (
                "sections".to_string(),
                JsonValue::Number(binary.sections.len() as f64),
            ),
            (
                "symbols".to_string(),
                JsonValue::Number(binary.symbols.len() as f64),
            ),
        ]),
    })
}

fn tool_binary_checksec(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: path")?;

    let binary = Binary::from_file(path).map_err(|e| format!("Failed to parse binary: {}", e))?;

    let sec = &binary.security;

    Ok(ToolResult {
        text: format!("Security features for {}", path),
        data: JsonValue::object(vec![
            ("path".to_string(), JsonValue::String(path.to_string())),
            (
                "relro".to_string(),
                JsonValue::String(sec.relro.to_string()),
            ),
            ("canary".to_string(), JsonValue::Bool(sec.canary)),
            ("nx".to_string(), JsonValue::Bool(sec.nx)),
            ("pie".to_string(), JsonValue::Bool(sec.pie)),
            ("rpath".to_string(), JsonValue::Bool(sec.rpath.is_some())),
            (
                "runpath".to_string(),
                JsonValue::Bool(sec.runpath.is_some()),
            ),
            ("fortify".to_string(), JsonValue::Bool(sec.fortify)),
        ]),
    })
}

fn tool_binary_symbols(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: path")?;

    let filter = args.get("filter").and_then(|v| v.as_str());

    let binary = Binary::from_file(path).map_err(|e| format!("Failed to parse binary: {}", e))?;

    let symbols: Vec<&crate::modules::binary::Symbol> = if let Some(pattern) = filter {
        binary.search_symbols(pattern)
    } else {
        binary.symbols.iter().collect()
    };

    let symbols_json: Vec<JsonValue> = symbols
        .iter()
        .take(100) // Limit output
        .map(|s| {
            JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(s.name.clone())),
                (
                    "address".to_string(),
                    JsonValue::String(format!("0x{:x}", s.value)),
                ),
                (
                    "type".to_string(),
                    JsonValue::String(s.sym_type.to_string()),
                ),
                (
                    "binding".to_string(),
                    JsonValue::String(s.binding.to_string()),
                ),
            ])
        })
        .collect();

    Ok(ToolResult {
        text: format!("Found {} symbols in {}", symbols.len(), path),
        data: JsonValue::object(vec![
            ("path".to_string(), JsonValue::String(path.to_string())),
            ("count".to_string(), JsonValue::Number(symbols.len() as f64)),
            ("symbols".to_string(), JsonValue::Array(symbols_json)),
        ]),
    })
}

fn tool_binary_rop_gadgets(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: path")?;

    let max_depth = args
        .get("max_depth")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .unwrap_or(5);

    let binary = Binary::from_file(path).map_err(|e| format!("Failed to parse binary: {}", e))?;

    let finder = GadgetFinder::new(binary.arch).with_depth(max_depth);
    let gadgets = finder.find_gadgets(&binary);

    let gadgets_json: Vec<JsonValue> = gadgets
        .iter()
        .take(100) // Limit output
        .map(|g| {
            JsonValue::object(vec![
                (
                    "address".to_string(),
                    JsonValue::String(format!("0x{:x}", g.address)),
                ),
                (
                    "instructions".to_string(),
                    JsonValue::String(g.instructions.clone()),
                ),
                (
                    "class".to_string(),
                    JsonValue::String(g.classification.to_string()),
                ),
            ])
        })
        .collect();

    Ok(ToolResult {
        text: format!("Found {} ROP gadgets in {}", gadgets.len(), path),
        data: JsonValue::object(vec![
            ("path".to_string(), JsonValue::String(path.to_string())),
            ("count".to_string(), JsonValue::Number(gadgets.len() as f64)),
            ("gadgets".to_string(), JsonValue::Array(gadgets_json)),
        ]),
    })
}

fn tool_binary_fmtstr_payload(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let offset = args
        .get("offset")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .ok_or("Missing required field: offset")?;

    let address_str = args
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: address")?;

    let value_str = args
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: value")?;

    let arch_str = args
        .get("arch")
        .and_then(|v| v.as_str())
        .unwrap_or("x86_64");

    // Parse hex addresses
    let address = u64::from_str_radix(address_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Invalid address format")?;
    let value = u64::from_str_radix(value_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Invalid value format")?;

    let fmtstr = if arch_str == "x86" {
        FmtStr::new_32(offset)
    } else {
        FmtStr::new_64(offset)
    };

    let payload = fmtstr.write64(address, value);

    Ok(ToolResult {
        text: format!(
            "Generated format string payload for {} -> {}",
            address_str, value_str
        ),
        data: JsonValue::object(vec![
            ("offset".to_string(), JsonValue::Number(offset as f64)),
            (
                "address".to_string(),
                JsonValue::String(address_str.to_string()),
            ),
            (
                "value".to_string(),
                JsonValue::String(value_str.to_string()),
            ),
            ("arch".to_string(), JsonValue::String(arch_str.to_string())),
            (
                "payload_hex".to_string(),
                JsonValue::String(hex::encode(&payload)),
            ),
            (
                "payload_len".to_string(),
                JsonValue::Number(payload.len() as f64),
            ),
        ]),
    })
}

fn tool_binary_shellcode_generate(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let payload_type = args
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: payload")?;

    let arch = args
        .get("arch")
        .and_then(|v| v.as_str())
        .unwrap_or("x86_64");

    let encode = args
        .get("encode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut shellcode = match (arch, payload_type) {
        ("x86_64", "execve") => LinuxX64::execve_sh(),
        ("x86_64", "exit") => LinuxX64::exit(0),
        ("x86_64", "reverse_tcp") => {
            let ip_str = args
                .get("ip")
                .and_then(|v| v.as_str())
                .ok_or("reverse_tcp requires 'ip' field")?;
            let port = args
                .get("port")
                .and_then(|v| v.as_f64())
                .map(|n| n as u16)
                .ok_or("reverse_tcp requires 'port' field")?;

            let ip_parts: Vec<u8> = ip_str.split('.').filter_map(|p| p.parse().ok()).collect();
            if ip_parts.len() != 4 {
                return Err("Invalid IP format".to_string());
            }
            LinuxX64::reverse_tcp([ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]], port)
        }
        ("x86_64", "bind_tcp") => {
            let port = args
                .get("port")
                .and_then(|v| v.as_f64())
                .map(|n| n as u16)
                .ok_or("bind_tcp requires 'port' field")?;
            LinuxX64::bind_tcp(port)
        }
        ("x86", "execve") => LinuxX86::execve_sh(),
        ("x86", "exit") => LinuxX86::exit(0),
        _ => {
            return Err(format!(
                "Unsupported payload: {} for {}",
                payload_type, arch
            ))
        }
    };

    if encode {
        if let Some((encoded, key)) = Encoder::eliminate_nulls(&shellcode) {
            let with_decoder = Encoder::xor_decoder_x64(&encoded, key);
            shellcode = with_decoder;
        }
    }

    Ok(ToolResult {
        text: format!("Generated {} shellcode for {}", payload_type, arch),
        data: JsonValue::object(vec![
            (
                "payload".to_string(),
                JsonValue::String(payload_type.to_string()),
            ),
            ("arch".to_string(), JsonValue::String(arch.to_string())),
            ("encoded".to_string(), JsonValue::Bool(encode)),
            (
                "length".to_string(),
                JsonValue::Number(shellcode.len() as f64),
            ),
            (
                "shellcode".to_string(),
                JsonValue::String(hex::encode(&shellcode)),
            ),
        ]),
    })
}

fn tool_binary_pattern_create(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let length = args
        .get("length")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .ok_or("Missing required field: length")?;

    if length > 20000 {
        return Err("Pattern length cannot exceed 20000".to_string());
    }

    let pattern = PatternGenerator::new(length).generate_string();

    Ok(ToolResult {
        text: format!("Created {} byte cyclic pattern", length),
        data: JsonValue::object(vec![
            ("length".to_string(), JsonValue::Number(length as f64)),
            ("pattern".to_string(), JsonValue::String(pattern)),
        ]),
    })
}

fn tool_binary_pattern_offset(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let value = args
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: value")?;

    // Parse as hex or string
    let search_bytes = if value.starts_with("0x") {
        let hex_val = u32::from_str_radix(value.trim_start_matches("0x"), 16)
            .map_err(|_| "Invalid hex value")?;
        hex_val.to_le_bytes().to_vec()
    } else {
        value.as_bytes().to_vec()
    };

    // Generate a large pattern and search
    let pattern = PatternGenerator::new(20000).generate_string();
    let search_str = String::from_utf8_lossy(&search_bytes);

    let offset = pattern.find(&*search_str);

    match offset {
        Some(off) => Ok(ToolResult {
            text: format!("Found pattern at offset {}", off),
            data: JsonValue::object(vec![
                ("value".to_string(), JsonValue::String(value.to_string())),
                ("offset".to_string(), JsonValue::Number(off as f64)),
            ]),
        }),
        None => Ok(ToolResult {
            text: "Pattern not found".to_string(),
            data: JsonValue::object(vec![
                ("value".to_string(), JsonValue::String(value.to_string())),
                ("offset".to_string(), JsonValue::Null),
            ]),
        }),
    }
}

fn tool_binary_pack(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let value_str = args
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: value")?;

    let bits = args
        .get("bits")
        .and_then(|v| v.as_f64())
        .map(|n| n as u8)
        .unwrap_or(64);

    let endian = args
        .get("endian")
        .and_then(|v| v.as_str())
        .unwrap_or("little");

    // Parse value as hex or decimal
    let value = if value_str.starts_with("0x") {
        u64::from_str_radix(value_str.trim_start_matches("0x"), 16)
            .map_err(|_| "Invalid hex value")?
    } else {
        value_str
            .parse::<u64>()
            .map_err(|_| "Invalid decimal value")?
    };

    let packed = match (bits, endian) {
        (8, _) => p8(value as u8),
        (16, "little") => p16(value as u16),
        (16, "big") => (value as u16).to_be_bytes().to_vec(),
        (32, "little") => p32(value as u32),
        (32, "big") => (value as u32).to_be_bytes().to_vec(),
        (64, "little") => p64(value),
        (64, "big") => value.to_be_bytes().to_vec(),
        _ => return Err(format!("Unsupported bit width: {}", bits)),
    };

    Ok(ToolResult {
        text: format!("Packed {} as {}-bit {} endian", value_str, bits, endian),
        data: JsonValue::object(vec![
            (
                "value".to_string(),
                JsonValue::String(value_str.to_string()),
            ),
            ("bits".to_string(), JsonValue::Number(bits as f64)),
            ("endian".to_string(), JsonValue::String(endian.to_string())),
            (
                "packed_hex".to_string(),
                JsonValue::String(hex::encode(&packed)),
            ),
            (
                "packed_bytes".to_string(),
                JsonValue::Array(
                    packed
                        .iter()
                        .map(|b| JsonValue::Number(*b as f64))
                        .collect(),
                ),
            ),
        ]),
    })
}
