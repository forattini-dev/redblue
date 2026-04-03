//! Memory Inspection MCP Tools
//!
//! Process memory scanning, region enumeration, reading, and pattern search.
//! These tools provide Cheat Engine-like functionality via MCP for process
//! memory analysis on Linux systems.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::utils::json::JsonValue;

/// Register memory inspection tools with the server
pub fn register_memory_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.memory.scan",
            description: "Scan process memory for a specific value. Attaches to the target process \
                         via ptrace and searches readable memory regions for the given value. \
                         Supports integer types (i8-i64, u8-u64) and floating point (f32, f64). \
                         Requires CAP_SYS_PTRACE or root. Linux only.",
            fields: &[
                ToolField {
                    name: "pid",
                    field_type: "number",
                    description: "Process ID to scan.",
                    required: true,
                },
                ToolField {
                    name: "value",
                    field_type: "string",
                    description: "Value to search for (e.g., '100', '3.14', '0xff').",
                    required: true,
                },
                ToolField {
                    name: "value_type",
                    field_type: "string",
                    description: "Type of value: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64 \
                                 (aliases: int, byte, short, long, float, double).",
                    required: true,
                },
                ToolField {
                    name: "max_results",
                    field_type: "number",
                    description: "Maximum number of results to return (default: 100).",
                    required: false,
                },
            ],
            handler: tool_memory_scan,
        },
        ToolDefinition {
            name: "rb.memory.regions",
            description: "List memory regions of a process by parsing /proc/<pid>/maps. \
                         Shows address ranges, permissions, and mapped files. \
                         Useful for understanding process memory layout before scanning. Linux only.",
            fields: &[
                ToolField {
                    name: "pid",
                    field_type: "number",
                    description: "Process ID to inspect.",
                    required: true,
                },
                ToolField {
                    name: "filter",
                    field_type: "string",
                    description: "Filter regions: 'all', 'readable', 'writable', 'executable', 'scannable' (default: 'all').",
                    required: false,
                },
            ],
            handler: tool_memory_regions,
        },
        ToolDefinition {
            name: "rb.memory.read",
            description: "Read bytes from a process at a specific memory address. \
                         Returns hex-encoded data and an ASCII representation. \
                         Requires CAP_SYS_PTRACE or root for non-owned processes. Linux only.",
            fields: &[
                ToolField {
                    name: "pid",
                    field_type: "number",
                    description: "Process ID to read from.",
                    required: true,
                },
                ToolField {
                    name: "address",
                    field_type: "string",
                    description: "Memory address to read from (hex, e.g., '0x7fff12340000' or '7fff12340000').",
                    required: true,
                },
                ToolField {
                    name: "size",
                    field_type: "number",
                    description: "Number of bytes to read (default: 256, max: 4096).",
                    required: false,
                },
            ],
            handler: tool_memory_read,
        },
        ToolDefinition {
            name: "rb.memory.pattern",
            description: "Search for a byte pattern (AOB/Array of Bytes) in process memory. \
                         Supports wildcards for unknown bytes. Useful for finding code signatures, \
                         function prologues, and data structures. Requires CAP_SYS_PTRACE or root. Linux only.",
            fields: &[
                ToolField {
                    name: "pid",
                    field_type: "number",
                    description: "Process ID to scan.",
                    required: true,
                },
                ToolField {
                    name: "pattern",
                    field_type: "string",
                    description: "Byte pattern with optional wildcards: '48 8B 05 ?? ?? ?? ??' or '488B05????????' \
                                 (use ?? or ** for wildcard bytes).",
                    required: true,
                },
                ToolField {
                    name: "max_results",
                    field_type: "number",
                    description: "Maximum number of matches to return (default: 50).",
                    required: false,
                },
            ],
            handler: tool_memory_pattern,
        },
    ]
}

#[cfg(target_os = "linux")]
fn tool_memory_scan(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::memory::{parse_maps, ProcessMemory, ScanType, Scanner, ValueType};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_f64())
        .map(|n| n as i32)
        .ok_or("Missing required field: pid")?;

    let value_str = args
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: value")?;

    let type_str = args
        .get("value_type")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: value_type")?;

    let max_results = args
        .get("max_results")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .unwrap_or(100);

    let value_type = ValueType::from_str(type_str)
        .ok_or_else(|| format!("Unknown value type '{}'. Valid: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64", type_str))?;

    // Build scan type from value string and type
    let scan_type = match value_type {
        ValueType::F32 | ValueType::F64 => {
            let val: f64 = value_str
                .parse()
                .map_err(|_| format!("Cannot parse '{}' as {}", value_str, type_str))?;
            let epsilon = if matches!(value_type, ValueType::F32) {
                1e-6
            } else {
                1e-12
            };
            ScanType::ExactFloat(val, epsilon)
        }
        _ => {
            // Parse integer value, supporting hex prefix
            let val: i64 = if value_str.starts_with("0x") || value_str.starts_with("0X") {
                let hex_str = value_str
                    .trim_start_matches("0x")
                    .trim_start_matches("0X");
                i64::from_str_radix(hex_str, 16)
                    .map_err(|_| format!("Cannot parse '{}' as hex integer", value_str))?
            } else {
                value_str
                    .parse()
                    .map_err(|_| format!("Cannot parse '{}' as {}", value_str, type_str))?
            };
            ScanType::Exact(val)
        }
    };

    // Attach to process
    let mut proc_mem = ProcessMemory::attach(pid)
        .map_err(|e| format!("Failed to attach to PID {}: {}. Ensure you have CAP_SYS_PTRACE or root.", pid, e))?;

    // Enumerate scannable memory regions
    let regions = parse_maps(pid)
        .map_err(|e| format!("Failed to read memory maps for PID {}: {}", pid, e))?;

    let scannable: Vec<_> = regions
        .iter()
        .filter(|r| r.perms.is_readable())
        .cloned()
        .collect();

    let num_regions = scannable.len();

    // Create scanner and perform first scan
    let mut scanner = Scanner::new(value_type);
    scanner
        .first_scan(&mut proc_mem, &scannable, scan_type)
        .map_err(|e| format!("Scan failed: {}", e))?;

    let total_found = scanner.count();
    let results = scanner.results();
    let capped_results: Vec<_> = results.iter().take(max_results).collect();

    let results_json: Vec<JsonValue> = capped_results
        .iter()
        .map(|r| {
            JsonValue::object(vec![
                (
                    "address".to_string(),
                    JsonValue::String(format!("0x{:x}", r.address)),
                ),
                (
                    "value".to_string(),
                    JsonValue::String(format!("{}", r.value)),
                ),
            ])
        })
        .collect();

    let text = format!(
        "Memory scan of PID {} for {} ({}): {} matches found{}",
        pid,
        value_str,
        type_str,
        total_found,
        if total_found > max_results {
            format!(" (showing first {})", max_results)
        } else {
            String::new()
        }
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("pid".to_string(), JsonValue::Number(pid as f64)),
            (
                "value".to_string(),
                JsonValue::String(value_str.to_string()),
            ),
            (
                "value_type".to_string(),
                JsonValue::String(type_str.to_string()),
            ),
            (
                "total_found".to_string(),
                JsonValue::Number(total_found as f64),
            ),
            (
                "regions_scanned".to_string(),
                JsonValue::Number(num_regions as f64),
            ),
            ("results".to_string(), JsonValue::array(results_json)),
        ]),
    })
}

#[cfg(not(target_os = "linux"))]
fn tool_memory_scan(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
    Ok(ToolResult::with_data(
        "Memory scanning is only supported on Linux (requires ptrace and /proc filesystem).",
        JsonValue::object(vec![(
            "error".to_string(),
            JsonValue::String("unsupported_platform".to_string()),
        )]),
    ))
}

#[cfg(target_os = "linux")]
fn tool_memory_regions(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::memory::parse_maps;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_f64())
        .map(|n| n as i32)
        .ok_or("Missing required field: pid")?;

    let filter = args
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    let regions = parse_maps(pid)
        .map_err(|e| format!("Failed to read /proc/{}/maps: {}", pid, e))?;

    let filtered: Vec<_> = regions
        .iter()
        .filter(|r| match filter {
            "readable" => r.perms.is_readable(),
            "writable" => r.perms.is_writable(),
            "executable" => r.perms.execute,
            "scannable" => r.region_type.is_scannable() && r.perms.is_readable(),
            _ => true, // "all"
        })
        .collect();

    let regions_json: Vec<JsonValue> = filtered
        .iter()
        .map(|r| {
            JsonValue::object(vec![
                (
                    "start".to_string(),
                    JsonValue::String(format!("0x{:x}", r.start)),
                ),
                (
                    "end".to_string(),
                    JsonValue::String(format!("0x{:x}", r.end)),
                ),
                (
                    "size".to_string(),
                    JsonValue::Number((r.end - r.start) as f64),
                ),
                (
                    "permissions".to_string(),
                    JsonValue::String(format!("{}", r.perms)),
                ),
                (
                    "type".to_string(),
                    JsonValue::String(format!("{:?}", r.region_type)),
                ),
                (
                    "path".to_string(),
                    match &r.region_type {
                        crate::modules::memory::maps::RegionType::File(p) => {
                            JsonValue::String(p.display().to_string())
                        }
                        _ => JsonValue::Null,
                    },
                ),
            ])
        })
        .collect();

    let total_size: usize = filtered.iter().map(|r| r.end - r.start).sum();

    let text = format!(
        "Memory regions for PID {} (filter: {}): {} regions, {} total bytes",
        pid,
        filter,
        filtered.len(),
        format_bytes(total_size),
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("pid".to_string(), JsonValue::Number(pid as f64)),
            (
                "filter".to_string(),
                JsonValue::String(filter.to_string()),
            ),
            (
                "region_count".to_string(),
                JsonValue::Number(filtered.len() as f64),
            ),
            (
                "total_size".to_string(),
                JsonValue::Number(total_size as f64),
            ),
            ("regions".to_string(), JsonValue::array(regions_json)),
        ]),
    })
}

#[cfg(not(target_os = "linux"))]
fn tool_memory_regions(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
    Ok(ToolResult::with_data(
        "Memory region listing is only supported on Linux (requires /proc filesystem).",
        JsonValue::object(vec![(
            "error".to_string(),
            JsonValue::String("unsupported_platform".to_string()),
        )]),
    ))
}

#[cfg(target_os = "linux")]
fn tool_memory_read(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::memory::ProcessMemory;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_f64())
        .map(|n| n as i32)
        .ok_or("Missing required field: pid")?;

    let addr_str = args
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: address")?;

    let size = args
        .get("size")
        .and_then(|v| v.as_f64())
        .map(|n| (n as usize).min(4096))
        .unwrap_or(256);

    // Parse hex address
    let addr_clean = addr_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| addr_str.trim().strip_prefix("0X"))
        .unwrap_or(addr_str.trim());

    let address = usize::from_str_radix(addr_clean, 16)
        .map_err(|_| format!("Invalid hex address: '{}'", addr_str))?;

    // Attach and read
    let mut proc_mem = ProcessMemory::attach(pid)
        .map_err(|e| format!("Failed to attach to PID {}: {}", pid, e))?;

    let bytes = proc_mem
        .read_bytes(address, size)
        .map_err(|e| format!("Failed to read {} bytes at 0x{:x}: {}", size, address, e))?;

    // Format as hex dump
    let hex_str = crate::mcp::types::hex::encode(&bytes);

    // Build ASCII representation (printable chars only)
    let ascii: String = bytes
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect();

    // Build hex dump lines (16 bytes per line)
    let mut hex_lines = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = address + i * 16;
        let hex_part: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii_part: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        hex_lines.push(format!(
            "0x{:012x}  {:48}  |{}|",
            offset,
            hex_part.join(" "),
            ascii_part
        ));
    }

    let text = format!(
        "Read {} bytes from PID {} at 0x{:x}:\n{}",
        bytes.len(),
        pid,
        address,
        hex_lines.join("\n")
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("pid".to_string(), JsonValue::Number(pid as f64)),
            (
                "address".to_string(),
                JsonValue::String(format!("0x{:x}", address)),
            ),
            ("size".to_string(), JsonValue::Number(bytes.len() as f64)),
            ("hex".to_string(), JsonValue::String(hex_str)),
            ("ascii".to_string(), JsonValue::String(ascii)),
        ]),
    })
}

#[cfg(not(target_os = "linux"))]
fn tool_memory_read(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
    Ok(ToolResult::with_data(
        "Memory reading is only supported on Linux (requires ptrace and /proc filesystem).",
        JsonValue::object(vec![(
            "error".to_string(),
            JsonValue::String("unsupported_platform".to_string()),
        )]),
    ))
}

#[cfg(target_os = "linux")]
fn tool_memory_pattern(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    use crate::modules::memory::{parse_maps, Pattern, PatternScanner, ProcessMemory};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_f64())
        .map(|n| n as i32)
        .ok_or("Missing required field: pid")?;

    let pattern_str = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: pattern")?;

    let max_results = args
        .get("max_results")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize)
        .unwrap_or(50);

    // Parse the pattern
    let pattern = Pattern::parse(pattern_str)
        .map_err(|e| format!("Invalid pattern '{}': {}", pattern_str, e))?;

    // Attach to process
    let mut proc_mem = ProcessMemory::attach(pid)
        .map_err(|e| format!("Failed to attach to PID {}: {}", pid, e))?;

    // Get readable memory regions
    let regions = parse_maps(pid)
        .map_err(|e| format!("Failed to read memory maps for PID {}: {}", pid, e))?;

    let scannable: Vec<_> = regions
        .iter()
        .filter(|r| r.perms.is_readable())
        .cloned()
        .collect();

    let num_regions = scannable.len();

    // Scan for pattern using PatternScanner static method
    let matches = PatternScanner::scan(&mut proc_mem, &scannable, &pattern, Some(max_results))
        .map_err(|e| format!("Pattern scan failed: {}", e))?;

    let results_json: Vec<JsonValue> = matches
        .iter()
        .map(|m| {
            JsonValue::object(vec![
                (
                    "address".to_string(),
                    JsonValue::String(format!("0x{:x}", m.address)),
                ),
                (
                    "bytes".to_string(),
                    JsonValue::String(m.bytes_hex()),
                ),
                (
                    "region".to_string(),
                    JsonValue::String(m.region_name.clone()),
                ),
            ])
        })
        .collect();

    let text = format!(
        "Pattern scan of PID {} for '{}': {} matches found{}",
        pid,
        pattern_str,
        matches.len(),
        if matches.len() >= max_results {
            " (limit reached)"
        } else {
            ""
        }
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("pid".to_string(), JsonValue::Number(pid as f64)),
            (
                "pattern".to_string(),
                JsonValue::String(pattern_str.to_string()),
            ),
            (
                "match_count".to_string(),
                JsonValue::Number(matches.len() as f64),
            ),
            (
                "regions_scanned".to_string(),
                JsonValue::Number(num_regions as f64),
            ),
            ("matches".to_string(), JsonValue::array(results_json)),
        ]),
    })
}

#[cfg(not(target_os = "linux"))]
fn tool_memory_pattern(_server: &mut McpServer, _args: &JsonValue) -> Result<ToolResult, String> {
    Ok(ToolResult::with_data(
        "Pattern scanning is only supported on Linux (requires ptrace and /proc filesystem).",
        JsonValue::object(vec![(
            "error".to_string(),
            JsonValue::String("unsupported_platform".to_string()),
        )]),
    ))
}

/// Format byte count in human-readable form
fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
