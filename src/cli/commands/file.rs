//! File operations command - compression, decompression, and hash verification
//!
//! Commands:
//! - rb file zip <format> <file> - Compress file
//! - rb file unzip <file> - Decompress file (auto-detect format)
//! - rb file hash <algo> <file> - Calculate/verify file hash

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use std::fs;
use std::path::Path;

/// File operations command
pub struct FileCommand;

impl Command for FileCommand {
    fn domain(&self) -> &str {
        "file"
    }

    fn resource(&self) -> &str {
        "ops"
    }

    fn description(&self) -> &str {
        "File operations - compression, decompression, and hash verification"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "zip",
                summary: "Compress a file",
                usage: "rb file ops zip <format> <file> [-o OUTPUT]",
            },
            Route {
                verb: "unzip",
                summary: "Decompress a file (auto-detect format)",
                usage: "rb file ops unzip <file> [-o OUTPUT] [--list]",
            },
            Route {
                verb: "hash",
                summary: "Calculate or verify file hash",
                usage: "rb file ops hash <algo> <file> [--verify HASH]",
            },
            Route {
                verb: "info",
                summary: "Show file information (magic bytes, type)",
                usage: "rb file ops info <file>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output file path")
                .with_short('o')
                .with_arg("FILE"),
            Flag::new("verify", "Hash to verify against")
                .with_short('v')
                .with_arg("HASH"),
            Flag::new("list", "List archive contents without extracting").with_short('l'),
            Flag::new("format", "Force specific format (gzip, tar, zip)")
                .with_short('f')
                .with_arg("FORMAT"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            // Compression (future)
            ("Compress with gzip", "rb file ops zip gzip data.txt"),
            (
                "Compress with output path",
                "rb file ops zip gzip data.txt -o data.txt.gz",
            ),
            // Decompression
            (
                "Decompress gzip (auto-detect)",
                "rb file ops unzip data.txt.gz",
            ),
            ("List tar contents", "rb file ops unzip archive.tar --list"),
            (
                "Extract tar to directory",
                "rb file ops unzip archive.tar -o ./output",
            ),
            ("Extract zip archive", "rb file ops unzip archive.zip"),
            // Hash
            ("Calculate SHA256", "rb file ops hash sha256 file.bin"),
            ("Calculate MD5", "rb file ops hash md5 file.bin"),
            (
                "Verify SHA256",
                "rb file ops hash sha256 file.bin --verify abc123...",
            ),
            (
                "Verify from file",
                "rb file ops hash sha256 file.bin --verify checksums.txt",
            ),
            // Info
            ("Show file info", "rb file ops info mystery.bin"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "zip" => self.compress(ctx),
            "unzip" => self.decompress(ctx),
            "hash" => self.hash(ctx),
            "info" => self.info(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use 'rb file ops help' for available commands.",
                verb
            )),
        }
    }
}

impl FileCommand {
    /// Compress a file
    fn compress(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx
            .target
            .as_ref()
            .ok_or("Missing format. Usage: rb file ops zip <format> <file>")?;

        let file_path = ctx
            .args
            .first()
            .ok_or("Missing file path. Usage: rb file ops zip <format> <file>")?;

        match format.as_str() {
            "gzip" | "gz" => Err(format!(
                "Gzip compression not yet implemented. Only decompression is available.\n\
                     Use 'rb file ops unzip' to decompress gzip files."
            )),
            "tar" => {
                Err("TAR creation not yet implemented. Only reading is available.".to_string())
            }
            "zip" => {
                Err("ZIP creation not yet implemented. Only reading is available.".to_string())
            }
            _ => Err(format!(
                "Unknown format '{}'. Supported: gzip, tar, zip",
                format
            )),
        }
    }

    /// Decompress a file
    fn decompress(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx
            .target
            .as_ref()
            .ok_or("Missing file path. Usage: rb file ops unzip <file>")?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", file_path));
        }

        let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

        let list_only = ctx.has_flag("list") || ctx.has_flag("l");
        let output_path = ctx.get_flag("output").or_else(|| ctx.get_flag("o"));
        let forced_format = ctx.get_flag("format").or_else(|| ctx.get_flag("f"));

        // Detect format from magic bytes or extension
        let format = forced_format
            .as_deref()
            .map(String::from)
            .unwrap_or_else(|| self.detect_format(&data, file_path));

        match format.as_str() {
            "gzip" | "gz" => self.decompress_gzip(&data, output_path.as_deref(), file_path),
            "tar" => self.decompress_tar(&data, output_path.as_deref(), list_only),
            "zip" => self.decompress_zip(&data, output_path.as_deref(), list_only),
            "tar.gz" | "tgz" => self.decompress_tar_gz(&data, output_path.as_deref(), list_only),
            _ => Err(format!(
                "Unknown or unsupported format '{}'. Supported: gzip, tar, zip, tar.gz",
                format
            )),
        }
    }

    /// Detect compression format from magic bytes and extension
    fn detect_format(&self, data: &[u8], file_path: &str) -> String {
        // Check magic bytes first
        if data.len() >= 2 {
            // Gzip: 1f 8b
            if data[0] == 0x1f && data[1] == 0x8b {
                // Could be .tar.gz
                if file_path.ends_with(".tar.gz") || file_path.ends_with(".tgz") {
                    return "tar.gz".to_string();
                }
                return "gzip".to_string();
            }
            // ZIP: 50 4b (PK)
            if data[0] == 0x50 && data[1] == 0x4b {
                return "zip".to_string();
            }
        }

        // Check for TAR (magic at offset 257)
        if data.len() >= 263 {
            let magic = &data[257..262];
            if magic == b"ustar" {
                return "tar".to_string();
            }
        }

        // Fall back to extension
        let lower = file_path.to_lowercase();
        if lower.ends_with(".gz") || lower.ends_with(".gzip") {
            if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
                return "tar.gz".to_string();
            }
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

    /// Decompress gzip file
    fn decompress_gzip(
        &self,
        data: &[u8],
        output_path: Option<&str>,
        original_path: &str,
    ) -> Result<(), String> {
        use crate::compression::gzip_decompress;

        Output::info(&format!("Decompressing gzip: {}", original_path));

        let decompressed =
            gzip_decompress(data).map_err(|e| format!("Gzip decompression failed: {}", e))?;

        let out_path = output_path
            .map(String::from)
            .unwrap_or_else(|| self.strip_gz_extension(original_path));

        fs::write(&out_path, &decompressed)
            .map_err(|e| format!("Failed to write output: {}", e))?;

        Output::success(&format!(
            "Decompressed {} → {} ({} bytes)",
            original_path,
            out_path,
            decompressed.len()
        ));

        Ok(())
    }

    /// Decompress tar archive
    fn decompress_tar(
        &self,
        data: &[u8],
        output_path: Option<&str>,
        list_only: bool,
    ) -> Result<(), String> {
        use crate::compression::TarReader;

        let mut reader = TarReader::new(data);
        let mut entries = Vec::new();

        while let Some(entry) = reader
            .next_entry()
            .map_err(|e| format!("TAR read error: {}", e))?
        {
            let entry_size = entry.size;
            let entry_name = entry.name.clone();
            let entry_type = entry.type_flag;

            entries.push((entry_name.clone(), entry_size, entry_type));

            if !list_only && entry_type != b'5' && !entry_name.ends_with('/') {
                // Read entry data using read_data
                let mut entry_data = vec![0u8; entry_size as usize];
                reader
                    .read_data(entry_size, &mut entry_data)
                    .map_err(|e| format!("Failed to read entry data: {}", e))?;

                // Determine output directory
                let base_dir = output_path.unwrap_or(".");
                let full_path = format!("{}/{}", base_dir, entry_name);

                // Create parent directories
                if let Some(parent) = Path::new(&full_path).parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create directory: {}", e))?;
                }

                // Write file
                fs::write(&full_path, &entry_data)
                    .map_err(|e| format!("Failed to write {}: {}", full_path, e))?;
            }

            // Skip remaining data + padding to advance to next entry
            reader
                .skip_data(entry_size)
                .map_err(|e| format!("Failed to skip entry: {}", e))?;
        }

        if list_only {
            Output::header("TAR Archive Contents");
            println!("{:<12} {:<8} {}", "SIZE", "TYPE", "NAME");
            println!("{}", "-".repeat(60));
            for (name, size, type_flag) in &entries {
                let type_str = match type_flag {
                    b'0' | 0 => "file",
                    b'5' => "dir",
                    b'1' => "link",
                    b'2' => "sym",
                    _ => "?",
                };
                println!("{:<12} {:<8} {}", size, type_str, name);
            }
            println!("\nTotal: {} entries", entries.len());
        } else {
            Output::success(&format!("Extracted {} entries", entries.len()));
        }

        Ok(())
    }

    /// Decompress zip archive
    fn decompress_zip(
        &self,
        data: &[u8],
        output_path: Option<&str>,
        list_only: bool,
    ) -> Result<(), String> {
        use crate::compression::zip::ZipReader;

        let mut reader = ZipReader::new(data).map_err(|e| format!("ZIP open error: {}", e))?;
        let mut entries = Vec::new();

        while let Some(entry) = reader
            .next_entry()
            .map_err(|e| format!("ZIP read error: {}", e))?
        {
            entries.push((
                entry.name.clone(),
                entry.uncompressed_size,
                entry.compression_method,
            ));

            if !list_only {
                // Read entry data
                let entry_data = reader
                    .read_entry_data(&entry)
                    .map_err(|e| format!("Failed to read entry: {}", e))?;

                // Determine output directory
                let base_dir = output_path.unwrap_or(".");
                let full_path = format!("{}/{}", base_dir, entry.name);

                // Create parent directories
                if let Some(parent) = Path::new(&full_path).parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create directory: {}", e))?;
                }

                // Write file (skip directories)
                if !entry.name.ends_with('/') {
                    fs::write(&full_path, &entry_data)
                        .map_err(|e| format!("Failed to write {}: {}", full_path, e))?;
                }
            }
        }

        if list_only {
            Output::header("ZIP Archive Contents");
            println!("{:<12} {:<12} {}", "SIZE", "METHOD", "NAME");
            println!("{}", "-".repeat(60));
            for (name, size, method) in &entries {
                let method_str = match method {
                    0 => "stored",
                    8 => "deflate",
                    _ => "unknown",
                };
                println!("{:<12} {:<12} {}", size, method_str, name);
            }
            println!("\nTotal: {} entries", entries.len());
        } else {
            Output::success(&format!("Extracted {} entries", entries.len()));
        }

        Ok(())
    }

    /// Decompress tar.gz (gzip + tar)
    fn decompress_tar_gz(
        &self,
        data: &[u8],
        output_path: Option<&str>,
        list_only: bool,
    ) -> Result<(), String> {
        use crate::compression::gzip_decompress;

        Output::info("Decompressing gzip layer...");
        let tar_data =
            gzip_decompress(data).map_err(|e| format!("Gzip decompression failed: {}", e))?;

        self.decompress_tar(&tar_data, output_path, list_only)
    }

    /// Calculate or verify file hash
    fn hash(&self, ctx: &CliContext) -> Result<(), String> {
        let algo = ctx
            .target
            .as_ref()
            .ok_or("Missing algorithm. Usage: rb file ops hash <algo> <file>")?;

        let file_path = ctx
            .args
            .first()
            .ok_or("Missing file path. Usage: rb file ops hash <algo> <file>")?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", file_path));
        }

        let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
        let verify_hash = ctx.get_flag("verify").or_else(|| ctx.get_flag("v"));

        let hash_hex = match algo.to_lowercase().as_str() {
            "md5" => {
                let hash = crate::crypto::md5::md5(&data);
                hex_encode(&hash)
            }
            "sha1" => {
                let hash = crate::crypto::sha1::sha1(&data);
                hex_encode(&hash)
            }
            "sha256" => {
                let hash = crate::crypto::sha256::sha256(&data);
                hex_encode(&hash)
            }
            "sha384" => {
                let hash = crate::crypto::sha384::sha384(&data);
                hex_encode(&hash)
            }
            "blake2b" => {
                use crate::storage::encryption::blake2b::Blake2b;
                let mut hasher = Blake2b::new(64); // 64 bytes = 512 bits
                hasher.update(&data);
                let hash = hasher.finalize();
                hex_encode(&hash)
            }
            "crc32" => {
                let crc = crate::compression::crc32(&data);
                format!("{:08x}", crc)
            }
            _ => {
                return Err(format!(
                    "Unknown algorithm '{}'. Supported: md5, sha1, sha256, sha384, blake2b, crc32",
                    algo
                ))
            }
        };

        // Verify mode
        if let Some(expected) = verify_hash {
            let expected_clean = self.extract_hash(&expected, file_path)?;
            let matches = hash_hex.eq_ignore_ascii_case(&expected_clean);

            if matches {
                Output::success(&format!(
                    "✓ {} hash verified: {}",
                    algo.to_uppercase(),
                    &hash_hex[..16.min(hash_hex.len())]
                ));
                Ok(())
            } else {
                Output::error(&format!(
                    "✗ {} hash mismatch!\n  Expected: {}\n  Got:      {}",
                    algo.to_uppercase(),
                    expected_clean,
                    hash_hex
                ));
                Err("Hash verification failed".to_string())
            }
        } else {
            // Calculate mode
            let json_output = ctx.get_flag("output").map(|f| f == "json").unwrap_or(false)
                || ctx.get_flag("o").map(|f| f == "json").unwrap_or(false);

            if json_output {
                println!(
                    "{{\"file\":\"{}\",\"algorithm\":\"{}\",\"hash\":\"{}\"}}",
                    file_path,
                    algo.to_lowercase(),
                    hash_hex
                );
            } else {
                println!("{}  {}", hash_hex, file_path);
            }
            Ok(())
        }
    }

    /// Extract hash from string or file
    fn extract_hash(&self, input: &str, target_file: &str) -> Result<String, String> {
        // Check if input is a file path
        let path = Path::new(input);
        if path.exists() && path.is_file() {
            // Read hash file and find matching entry
            let content =
                fs::read_to_string(path).map_err(|e| format!("Failed to read hash file: {}", e))?;

            let target_name = Path::new(target_file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(target_file);

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Format: "hash  filename" or "hash *filename" (BSD style)
                let parts: Vec<&str> = line.splitn(2, |c| c == ' ' || c == '\t').collect();
                if parts.len() >= 2 {
                    let hash = parts[0].trim();
                    let filename = parts[1].trim().trim_start_matches('*');

                    if filename == target_name || filename == target_file {
                        return Ok(hash.to_string());
                    }
                } else if parts.len() == 1 {
                    // Just a hash on its own line
                    return Ok(parts[0].to_string());
                }
            }

            Err(format!("No hash found for '{}' in {}", target_name, input))
        } else {
            // Input is the hash itself
            Ok(input.to_string())
        }
    }

    /// Show file information
    fn info(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx
            .target
            .as_ref()
            .ok_or("Missing file path. Usage: rb file ops info <file>")?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", file_path));
        }

        let metadata = fs::metadata(path).map_err(|e| format!("Failed to read metadata: {}", e))?;
        let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

        Output::header(&format!("File: {}", file_path));

        // Basic info
        println!("Size:        {} bytes", metadata.len());

        // Detect type from magic bytes
        let file_type = self.detect_file_type(&data);
        println!("Type:        {}", file_type);

        // Show magic bytes
        let magic_len = 16.min(data.len());
        let magic_hex: String = data[..magic_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!("Magic:       {}", magic_hex);

        // Show printable ASCII
        let magic_ascii: String = data[..magic_len]
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();
        println!("ASCII:       {}", magic_ascii);

        // Compression format if applicable
        let format = self.detect_format(&data, file_path);
        if format != "unknown" {
            println!("Compression: {}", format);
        }

        // Quick entropy estimate
        let entropy = self.calculate_entropy(&data);
        println!("Entropy:     {:.2} bits/byte", entropy);
        if entropy > 7.5 {
            println!("             (likely compressed/encrypted)");
        } else if entropy < 4.0 {
            println!("             (likely text/structured data)");
        }

        Ok(())
    }

    /// Detect file type from magic bytes
    fn detect_file_type(&self, data: &[u8]) -> &'static str {
        if data.len() < 4 {
            return "unknown (too small)";
        }

        // Common magic bytes
        match &data[..4.min(data.len())] {
            // Compression
            [0x1f, 0x8b, ..] => "gzip compressed",
            [0x50, 0x4b, 0x03, 0x04] => "ZIP archive",
            [0x50, 0x4b, 0x05, 0x06] => "ZIP archive (empty)",
            [0xfd, 0x37, 0x7a, 0x58] => "XZ compressed",
            [0x42, 0x5a, 0x68, ..] => "bzip2 compressed",
            [0x28, 0xb5, 0x2f, 0xfd] => "Zstandard compressed",

            // Executables
            [0x7f, 0x45, 0x4c, 0x46] => "ELF executable",
            [0x4d, 0x5a, ..] => "PE/DOS executable",
            [0xca, 0xfe, 0xba, 0xbe] => "Mach-O (universal)",
            [0xcf, 0xfa, 0xed, 0xfe] => "Mach-O (64-bit)",
            [0xce, 0xfa, 0xed, 0xfe] => "Mach-O (32-bit)",

            // Images
            [0x89, 0x50, 0x4e, 0x47] => "PNG image",
            [0xff, 0xd8, 0xff, ..] => "JPEG image",
            [0x47, 0x49, 0x46, 0x38] => "GIF image",
            [0x42, 0x4d, ..] => "BMP image",

            // Documents
            [0x25, 0x50, 0x44, 0x46] => "PDF document",

            // Audio/Video
            [0x49, 0x44, 0x33, ..] => "MP3 audio (ID3)",
            [0xff, 0xfb, ..] | [0xff, 0xfa, ..] => "MP3 audio",
            [0x4f, 0x67, 0x67, 0x53] => "OGG container",

            // Data formats
            [0x7b, ..] => "JSON (probable)",
            [0x3c, 0x3f, 0x78, 0x6d] => "XML document",
            [0x3c, 0x21, 0x44, 0x4f] => "HTML document",

            _ => {
                // Check for TAR at offset 257
                if data.len() >= 263 && &data[257..262] == b"ustar" {
                    return "TAR archive";
                }
                // Check if mostly printable ASCII
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

    /// Calculate Shannon entropy
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
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

    /// Strip .gz extension
    fn strip_gz_extension(&self, path: &str) -> String {
        if path.ends_with(".gz") {
            path[..path.len() - 3].to_string()
        } else if path.ends_with(".gzip") {
            path[..path.len() - 5].to_string()
        } else {
            format!("{}.out", path)
        }
    }
}

/// Hex encode bytes
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
