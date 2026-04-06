//! Hex editor command - File-based hex viewing and editing
//!
//! Provides functionality for:
//! - Viewing files in hex format with configurable display
//! - Editing bytes at specific offsets
//! - Searching for patterns (hex or text)
//! - Find and replace operations
//! - Data interpretation at cursor position

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::json;
use crate::modules::hex::OffsetFormat;
use crate::modules::hex::{
    parse_hex, replace, replace_all, search_text, to_hex, BoyerMooreSearcher, DataInterpreter,
    Endian, FileSource, HexView, PagedBuffer, UndoStack, ViewSettings,
};
use std::path::Path;

pub struct HexCommand;

impl Command for HexCommand {
    fn domain(&self) -> &str {
        "hex"
    }

    fn resource(&self) -> &str {
        "file"
    }

    fn description(&self) -> &str {
        "Hex editor for viewing and editing binary files"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "view",
                summary: "View file contents in hex format",
                usage: "rb hex file view <file> [--offset 0] [--lines 32] [--width 16]",
            },
            Route {
                verb: "read",
                summary: "Read bytes at specific offset",
                usage: "rb hex file read <file> <offset> [--size 64]",
            },
            Route {
                verb: "write",
                summary: "Write bytes at specific offset",
                usage: "rb hex file write <file> <offset> <hex-bytes>",
            },
            Route {
                verb: "search",
                summary: "Search for hex or text pattern",
                usage: "rb hex file search <file> <pattern> [--text] [--all]",
            },
            Route {
                verb: "replace",
                summary: "Find and replace pattern",
                usage: "rb hex file replace <file> <find> <replace> [--all]",
            },
            Route {
                verb: "inspect",
                summary: "Inspect data types at offset",
                usage: "rb hex file inspect <file> <offset> [--endian little]",
            },
            Route {
                verb: "info",
                summary: "Show file information and statistics",
                usage: "rb hex file info <file>",
            },
            Route {
                verb: "compare",
                summary: "Compare two files byte-by-byte",
                usage: "rb hex file compare <file1> <file2> [--max 100]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("offset", "Starting offset (hex or decimal)")
                .with_short('o')
                .with_default("0"),
            Flag::new("size", "Number of bytes to read")
                .with_short('s')
                .with_default("64"),
            Flag::new("lines", "Number of lines to display")
                .with_short('l')
                .with_default("32"),
            Flag::new("width", "Bytes per line (8, 16, 32)")
                .with_short('w')
                .with_default("16"),
            Flag::new("text", "Search as text instead of hex"),
            Flag::new("case-insensitive", "Case-insensitive text search").with_short('i'),
            Flag::new("all", "Find/replace all occurrences"),
            Flag::new("endian", "Byte order (little, big)")
                .with_short('e')
                .with_default("little"),
            Flag::new("max", "Maximum results to show")
                .with_short('m')
                .with_default("100"),
            Flag::new("no-ascii", "Hide ASCII panel"),
            Flag::new("decimal", "Show offsets in decimal"),
            Flag::new("format", "Output format (text, json)")
                .with_short('f')
                .with_default("text"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("View file in hex", "rb hex file view binary.bin"),
            (
                "View with offset",
                "rb hex file view binary.bin --offset 0x100 --lines 16",
            ),
            (
                "Read bytes at offset",
                "rb hex file read binary.bin 0x400 --size 32",
            ),
            (
                "Write bytes",
                "rb hex file write binary.bin 0x100 \"90 90 90 90\"",
            ),
            (
                "Search hex pattern",
                "rb hex file search binary.bin \"4D 5A 90 00\"",
            ),
            (
                "Search text",
                "rb hex file search binary.bin \"password\" --text",
            ),
            (
                "Replace pattern",
                "rb hex file replace binary.bin \"41 42\" \"58 59\" --all",
            ),
            (
                "Inspect data types",
                "rb hex file inspect binary.bin 0x100 --endian little",
            ),
            ("File info", "rb hex file info binary.bin"),
            (
                "Compare files",
                "rb hex file compare original.bin modified.bin",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "view" => self.cmd_view(ctx),
            "read" => self.cmd_read(ctx),
            "write" => self.cmd_write(ctx),
            "search" => self.cmd_search(ctx),
            "replace" => self.cmd_replace(ctx),
            "inspect" => self.cmd_inspect(ctx),
            "info" => self.cmd_info(ctx),
            "compare" => self.cmd_compare(ctx),
            _ => {
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}

impl HexCommand {
    fn parse_offset(s: &str) -> Result<u64, String> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid hex offset: {}", s))
        } else {
            s.parse::<u64>()
                .map_err(|_| format!("Invalid offset: {}", s))
        }
    }

    fn get_file_path(ctx: &CliContext) -> Result<&str, String> {
        ctx.target
            .as_deref()
            .ok_or_else(|| "Missing file path".to_string())
    }

    fn cmd_view(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;
        let offset = Self::parse_offset(ctx.get_flag("offset").as_deref().unwrap_or("0"))?;
        let lines: usize = ctx
            .get_flag("lines")
            .and_then(|s| s.parse().ok())
            .unwrap_or(32);
        let width: usize = ctx
            .get_flag("width")
            .and_then(|s| s.parse().ok())
            .unwrap_or(16);

        let source = Box::new(
            FileSource::open(Path::new(file_path))
                .map_err(|e| format!("Failed to open file: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);

        let mut settings = ViewSettings::default();
        settings.bytes_per_line = width;
        settings.show_ascii = !ctx.flags.contains_key("no-ascii");
        if ctx.flags.contains_key("decimal") {
            settings.offset_format = OffsetFormat::Decimal;
        }

        let view = HexView::with_settings(settings);

        if is_json {
            let bytes_per_line = view.settings().bytes_per_line;
            let total_bytes = lines * bytes_per_line;
            let data = buffer
                .read(offset, total_bytes)
                .map_err(|e| format!("Read error: {}", e))?;
            let lines_json: Vec<_> = data
                .chunks(bytes_per_line)
                .enumerate()
                .map(|(i, chunk)| hex_line_to_json(offset + (i * bytes_per_line) as u64, chunk))
                .collect();

            Output::json_value(&json!({
                "file": file_path.to_string(),
                "offset": format!("0x{:x}", offset),
                "size": buffer.size(),
                "bytes_read": data.len(),
                "lines": lines_json
            }));
            return Ok(());
        }

        Output::header(&format!("Hex View: {}", file_path));
        Output::info(&format!(
            "Size: {} bytes ({:.2} KB)",
            buffer.size(),
            buffer.size() as f64 / 1024.0
        ));
        println!();

        let output = view.render(&mut buffer, offset, lines);
        print!("{}", output);

        Ok(())
    }

    fn cmd_read(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;
        let offset_str = ctx.args.get(0).ok_or("Missing offset argument")?;
        let offset = Self::parse_offset(offset_str)?;
        let size: usize = ctx
            .get_flag("size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);

        let source = Box::new(
            FileSource::open(Path::new(file_path))
                .map_err(|e| format!("Failed to open file: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);

        let data = buffer
            .read(offset, size)
            .map_err(|e| format!("Read error: {}", e))?;

        if is_json {
            let hex_str: String = data.iter().map(|b| format!("{:02X}", b)).collect();
            Output::json_value(&json!({
                "file": file_path.to_string(),
                "offset": format!("0x{:x}", offset),
                "size": data.len(),
                "hex": hex_str,
                "ascii": ascii_preview(&data)
            }));
            return Ok(());
        }

        Output::header(&format!("Reading {} bytes at offset 0x{:x}", size, offset));
        println!();
        println!("Hex:   {}", to_hex(&data, true));
        println!();

        let view = HexView::new();
        let output = view.render_bytes(&data, offset);
        print!("{}", output);

        Ok(())
    }

    fn cmd_write(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;
        let offset_str = ctx.args.get(0).ok_or("Missing offset argument")?;
        let offset = Self::parse_offset(offset_str)?;
        let hex_bytes = ctx.args.get(1).ok_or("Missing hex bytes argument")?;

        let bytes = parse_hex(hex_bytes)?;

        // Open file for read-write
        let source = Box::new(
            FileSource::open_rw(Path::new(file_path))
                .map_err(|e| format!("Failed to open file for writing: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);
        let mut undo = UndoStack::new();

        // Read old bytes
        let old_bytes = buffer
            .read(offset, bytes.len())
            .map_err(|e| format!("Read error: {}", e))?;

        // Write new bytes
        buffer
            .write(offset, &bytes)
            .map_err(|e| format!("Write error: {}", e))?;

        undo.record_deltas(&mut buffer, "hex write");

        // Flush to disk
        buffer.flush().map_err(|e| format!("Flush error: {}", e))?;

        if is_json {
            Output::json_value(&json!({
                "file": file_path.to_string(),
                "offset": format!("0x{:x}", offset),
                "size": bytes.len(),
                "before": to_hex(&old_bytes, true).replace(' ', ""),
                "after": to_hex(&bytes, true).replace(' ', ""),
                "success": true
            }));
            return Ok(());
        }

        Output::header(&format!(
            "Writing {} bytes at offset 0x{:x}",
            bytes.len(),
            offset
        ));
        Output::info(&format!("Before: {}", to_hex(&old_bytes, true)));
        Output::success(&format!("After:  {}", to_hex(&bytes, true)));

        Ok(())
    }

    fn cmd_search(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;
        let pattern_str = ctx.args.get(0).ok_or("Missing pattern argument")?;
        let is_text = ctx.flags.contains_key("text");
        let case_insensitive = ctx.flags.contains_key("case-insensitive");
        let find_all = ctx.flags.contains_key("all");
        let max_results: usize = ctx
            .get_flag("max")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let source = Box::new(
            FileSource::open(Path::new(file_path))
                .map_err(|e| format!("Failed to open file: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);

        let pattern = if is_text {
            pattern_str.as_bytes().to_vec()
        } else {
            parse_hex(pattern_str)?
        };

        if !is_json {
            if is_text {
                Output::header(&format!("Searching for text: \"{}\"", pattern_str));
            } else {
                Output::header(&format!("Searching for hex: {}", to_hex(&pattern, true)));
            }
        }

        let mut results = Vec::new();

        if is_text && case_insensitive {
            let mut offset = 0u64;
            while results.len() < max_results {
                match search_text(&mut buffer, pattern_str, true, offset) {
                    Ok(Some(found)) => {
                        results.push(found);
                        if !find_all {
                            break;
                        }
                        offset = found + 1;
                    }
                    Ok(None) => break,
                    Err(e) => return Err(format!("Search error: {}", e)),
                }
            }
        } else {
            let searcher = BoyerMooreSearcher::new(&pattern);
            if find_all {
                let all_results = searcher
                    .search_all(&mut buffer)
                    .map_err(|e| format!("Search error: {}", e))?;
                results = all_results.into_iter().take(max_results).collect();
            } else if let Some(found) = searcher
                .search(&mut buffer, 0)
                .map_err(|e| format!("Search error: {}", e))?
            {
                results.push(found);
            }
        }

        if is_json {
            let matches_json: Vec<_> = results
                .iter()
                .map(|offset| json!({ "offset": format!("0x{:x}", offset) }))
                .collect();
            Output::json_value(&json!({
                "file": file_path.to_string(),
                "pattern": pattern_str.clone(),
                "is_text": is_text,
                "case_insensitive": case_insensitive,
                "total_matches": results.len(),
                "matches": matches_json
            }));
            return Ok(());
        }

        if results.is_empty() {
            Output::warning("No matches found");
        } else {
            Output::success(&format!("Found {} match(es)", results.len()));
            println!();

            let view = HexView::new();
            for (i, &offset) in results.iter().enumerate() {
                if i >= 10 && !find_all {
                    println!("... and {} more matches", results.len() - 10);
                    break;
                }

                // Show context around match
                let context_start = offset.saturating_sub(16);
                let context = buffer
                    .read(context_start, pattern.len() + 32)
                    .unwrap_or_default();

                println!("Match {} at offset 0x{:x}:", i + 1, offset);
                println!("{}", view.render_bytes(&context, context_start));
            }
        }

        Ok(())
    }

    fn cmd_replace(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;
        let find_hex = ctx.args.get(0).ok_or("Missing find pattern")?;
        let replace_hex = ctx.args.get(1).ok_or("Missing replace pattern")?;
        let replace_all_flag = ctx.flags.contains_key("all");

        let find_bytes = parse_hex(find_hex)?;
        let replace_bytes = parse_hex(replace_hex)?;

        if find_bytes.len() != replace_bytes.len() {
            return Err("Find and replace patterns must be the same length".to_string());
        }

        let source = Box::new(
            FileSource::open_rw(Path::new(file_path))
                .map_err(|e| format!("Failed to open file: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);

        if !is_json {
            Output::header(&format!(
                "Replacing {} with {}",
                to_hex(&find_bytes, true),
                to_hex(&replace_bytes, true)
            ));
        }

        let count = if replace_all_flag {
            replace_all(&mut buffer, &find_bytes, &replace_bytes)
                .map_err(|e| format!("Replace error: {}", e))?
        } else {
            match replace(&mut buffer, &find_bytes, &replace_bytes, 0)
                .map_err(|e| format!("Replace error: {}", e))?
            {
                Some(_) => 1,
                None => 0,
            }
        };

        buffer.flush().map_err(|e| format!("Flush error: {}", e))?;

        if is_json {
            Output::json_value(&json!({
                "file": file_path.to_string(),
                "find": to_hex(&find_bytes, true).replace(' ', ""),
                "replace": to_hex(&replace_bytes, true).replace(' ', ""),
                "replace_all": replace_all_flag,
                "replacements": count,
                "success": true
            }));
            return Ok(());
        }

        if count == 0 {
            Output::warning("No matches found to replace");
        } else {
            Output::success(&format!("Replaced {} occurrence(s)", count));
        }

        Ok(())
    }

    fn cmd_inspect(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;
        let offset_str = ctx.args.get(0).ok_or("Missing offset argument")?;
        let offset = Self::parse_offset(offset_str)?;

        let endian = match ctx.get_flag("endian").as_deref() {
            Some("big") => Endian::Big,
            _ => Endian::Little,
        };

        let source = Box::new(
            FileSource::open(Path::new(file_path))
                .map_err(|e| format!("Failed to open file: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);

        // Read enough bytes for all interpretations
        let data = buffer
            .read(offset, 64)
            .map_err(|e| format!("Read error: {}", e))?;

        let interp = DataInterpreter::with_endian(endian);
        let values = interp.interpret_all(&data);

        if is_json {
            let interpretations = values
                .iter()
                .map(|(name, value)| (name.to_string(), json!(format!("{}", value))))
                .collect::<crate::serde_json::Map<_, _>>();
            Output::json_value(&json!({
                "file": file_path.to_string(),
                "offset": format!("0x{:x}", offset),
                "endian": if endian == Endian::Little { "little" } else { "big" },
                "raw_bytes": to_hex(&data[..8.min(data.len())], true).replace(' ', ""),
                "interpretations": crate::serde_json::Value::Object(interpretations)
            }));
            return Ok(());
        }

        Output::header(&format!("Data Inspection at offset 0x{:x}", offset));
        Output::info(&format!(
            "Endian: {}",
            if endian == Endian::Little {
                "Little"
            } else {
                "Big"
            }
        ));
        println!();

        // Show raw bytes
        println!("Raw bytes: {}", to_hex(&data[..8.min(data.len())], true));
        println!();

        // Show interpretations
        println!("{:<12} VALUE", "TYPE");
        println!("{}", "-".repeat(60));

        for (name, value) in values {
            println!("{:<12} {}", name, value);
        }

        Ok(())
    }

    fn cmd_info(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file_path = Self::get_file_path(ctx)?;

        let source = Box::new(
            FileSource::open(Path::new(file_path))
                .map_err(|e| format!("Failed to open file: {}", e))?,
        );
        let mut buffer = PagedBuffer::new(source);

        let size = buffer.size();
        let first_bytes = buffer.read(0, 16).unwrap_or_default();

        // Try to detect file type from magic bytes
        let file_type = Self::detect_file_type(&first_bytes);

        // Calculate simple entropy estimate
        let sample = buffer.read(0, 1024.min(size as usize)).unwrap_or_default();
        let entropy = Self::calculate_entropy(&sample);

        if is_json {
            Output::json_value(&json!({
                "file": file_path.to_string(),
                "size_bytes": size,
                "size_kb": size as f64 / 1024.0,
                "size_mb": size as f64 / 1024.0 / 1024.0,
                "magic_bytes": to_hex(&first_bytes[..4.min(first_bytes.len())], true).replace(' ', ""),
                "detected_type": file_type,
                "entropy": entropy
            }));
            return Ok(());
        }

        Output::header(&format!("File Information: {}", file_path));
        println!();
        println!(
            "Size:         {} bytes ({:.2} KB, {:.2} MB)",
            size,
            size as f64 / 1024.0,
            size as f64 / 1024.0 / 1024.0
        );
        println!(
            "Magic bytes:  {}",
            to_hex(&first_bytes[..4.min(first_bytes.len())], true)
        );
        println!("Detected:     {}", file_type);
        println!("Entropy:      {:.4} (0=uniform, 8=random)", entropy);

        if entropy > 7.5 {
            Output::info("High entropy suggests encrypted or compressed data");
        }

        Ok(())
    }

    fn cmd_compare(&self, ctx: &CliContext) -> Result<(), String> {
        let is_json = ctx.get_output_format() == crate::cli::format::OutputFormat::Json;

        let file1_path = Self::get_file_path(ctx)?;
        let file2_path = ctx.args.get(0).ok_or("Missing second file path")?;
        let max_diffs: usize = ctx
            .get_flag("max")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let source1 = Box::new(
            FileSource::open(Path::new(file1_path))
                .map_err(|e| format!("Failed to open file1: {}", e))?,
        );
        let source2 = Box::new(
            FileSource::open(Path::new(file2_path))
                .map_err(|e| format!("Failed to open file2: {}", e))?,
        );

        let mut buffer1 = PagedBuffer::new(source1);
        let mut buffer2 = PagedBuffer::new(source2);

        let size1 = buffer1.size();
        let size2 = buffer2.size();
        let compare_size = size1.min(size2);

        if !is_json {
            Output::header("File Comparison");
            Output::info(&format!("File 1: {} ({} bytes)", file1_path, size1));
            Output::info(&format!("File 2: {} ({} bytes)", file2_path, size2));
        }

        // Compare in chunks
        let chunk_size = 4096;
        let mut differences = Vec::new();
        let mut offset = 0u64;

        while offset < compare_size && differences.len() < max_diffs {
            let len = (chunk_size as u64).min(compare_size - offset) as usize;

            let data1 = buffer1.read(offset, len).unwrap_or_default();
            let data2 = buffer2.read(offset, len).unwrap_or_default();

            for i in 0..data1.len().min(data2.len()) {
                if data1[i] != data2[i] {
                    differences.push((offset + i as u64, data1[i], data2[i]));
                    if differences.len() >= max_diffs {
                        break;
                    }
                }
            }

            offset += len as u64;
        }

        if is_json {
            let differences_json: Vec<_> = differences
                .iter()
                .map(|(off, b1, b2)| {
                    json!({
                        "offset": format!("0x{:x}", off),
                        "file1": format!("0x{:02X}", b1),
                        "file2": format!("0x{:02X}", b2)
                    })
                })
                .collect();
            Output::json_value(&json!({
                "file1": file1_path.to_string(),
                "file1_size": size1,
                "file2": file2_path.clone(),
                "file2_size": size2,
                "size_difference": (size1 as i64 - size2 as i64).abs(),
                "bytes_compared": compare_size,
                "differences_found": differences.len(),
                "max_shown": max_diffs,
                "differences": differences_json,
                "identical": differences.is_empty() && size1 == size2
            }));
            return Ok(());
        }

        if size1 != size2 {
            Output::warning(&format!(
                "Size difference: {} bytes",
                (size1 as i64 - size2 as i64).abs()
            ));
        }

        if differences.is_empty() {
            if size1 == size2 {
                Output::success("Files are identical");
            } else {
                Output::warning("No byte differences in overlapping region");
            }
        } else {
            Output::warning(&format!("Found {} byte difference(s)", differences.len()));
            println!();
            println!("{:<12} {:>8} {:>8}", "OFFSET", "FILE1", "FILE2");
            println!("{}", "-".repeat(30));

            for (off, b1, b2) in &differences {
                println!(
                    "{:<12} {:>8} {:>8}",
                    format!("0x{:x}", off),
                    format!("0x{:02X}", b1),
                    format!("0x{:02X}", b2)
                );
            }

            if differences.len() >= max_diffs {
                println!("... (showing first {} differences)", max_diffs);
            }
        }

        Ok(())
    }

    fn detect_file_type(bytes: &[u8]) -> &'static str {
        if bytes.len() < 4 {
            return "Unknown";
        }

        // ELF
        if bytes.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
            return "ELF executable";
        }

        // PE (MZ header)
        if bytes.starts_with(&[0x4D, 0x5A]) {
            return "PE/DOS executable";
        }

        // PDF
        if bytes.starts_with(b"%PDF") {
            return "PDF document";
        }

        // PNG
        if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            return "PNG image";
        }

        // JPEG
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return "JPEG image";
        }

        // GIF
        if bytes.starts_with(b"GIF8") {
            return "GIF image";
        }

        // ZIP/JAR/DOCX/etc
        if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            return "ZIP archive";
        }

        // GZIP
        if bytes.starts_with(&[0x1F, 0x8B]) {
            return "GZIP compressed";
        }

        // Mach-O (64-bit)
        if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
            return "Mach-O 64-bit";
        }

        // Mach-O (32-bit)
        if bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
            return "Mach-O 32-bit";
        }

        // SQLite
        if bytes.len() >= 16 && bytes.starts_with(b"SQLite format 3") {
            return "SQLite database";
        }

        "Unknown/Data"
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

fn ascii_preview(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn hex_line_to_json(offset: u64, data: &[u8]) -> crate::serde_json::Value {
    let hex = data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    json!({
        "offset": format!("0x{:08x}", offset),
        "hex": hex,
        "ascii": ascii_preview(data)
    })
}
