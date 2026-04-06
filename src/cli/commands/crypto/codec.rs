//! Codec command - Encoding/decoding operations

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::crypto::codec::CodecRegistry;
use crate::json;
use std::fs;
use std::io::Write;

use super::helpers::hex_encode;

/// Encoding/decoding command
pub struct CryptoCodecCommand;

impl Command for CryptoCodecCommand {
    fn domain(&self) -> &str {
        "crypto"
    }

    fn resource(&self) -> &str {
        "codec"
    }

    fn description(&self) -> &str {
        "Encoding and decoding operations (Base64, Hex, URL, HTML, Unicode)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "encode",
                summary: "Encode data using a codec",
                usage: "rb crypto codec encode <codec> <input> [--file INPUT]",
            },
            Route {
                verb: "decode",
                summary: "Decode data using a codec",
                usage: "rb crypto codec decode <codec> <input> [--file INPUT]",
            },
            Route {
                verb: "list",
                summary: "List available codecs",
                usage: "rb crypto codec list",
            },
            Route {
                verb: "detect",
                summary: "Auto-detect encoding of input",
                usage: "rb crypto codec detect <input>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("file", "Read input from file")
                .with_short('f')
                .with_arg("FILE"),
            Flag::new("format", "Output format (text, hex, json)").with_default("text"),
            Flag::new("raw", "Output raw bytes (no formatting)").with_short('r'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Encode to base64",
                "rb crypto codec encode base64 'Hello World'",
            ),
            (
                "Decode base64",
                "rb crypto codec decode base64 'SGVsbG8gV29ybGQ='",
            ),
            (
                "Encode file to hex",
                "rb crypto codec encode hex --file data.bin",
            ),
            (
                "Decode URL encoding",
                "rb crypto codec decode url 'hello%20world'",
            ),
            ("List all codecs", "rb crypto codec list"),
            ("Auto-detect encoding", "rb crypto codec detect 'SGVsbG8='"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "encode" => self.encode(ctx),
            "decode" => self.decode(ctx),
            "list" => self.list_codecs(ctx),
            "detect" => self.detect_encoding(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: rb crypto codec help",
                verb
            )),
        }
    }
}

impl CryptoCodecCommand {
    fn get_input(&self, ctx: &CliContext) -> Result<Vec<u8>, String> {
        if let Some(file) = ctx.get_flag("file") {
            fs::read(&file).map_err(|e| format!("Failed to read file '{}': {}", file, e))
        } else if let Some(target) = ctx.target.as_ref() {
            Ok(target.as_bytes().to_vec())
        } else if let Some(arg) = ctx.args.first() {
            Ok(arg.as_bytes().to_vec())
        } else {
            Err("No input provided. Use --file or provide input as argument.".to_string())
        }
    }

    fn encode(&self, ctx: &CliContext) -> Result<(), String> {
        let codec_name = ctx
            .target
            .as_ref()
            .ok_or("Missing codec name. Usage: rb crypto codec encode <codec> <input>")?;

        let input = if let Some(file) = ctx.get_flag("file") {
            fs::read(&file).map_err(|e| format!("Failed to read file '{}': {}", file, e))?
        } else if let Some(arg) = ctx.args.first() {
            arg.as_bytes().to_vec()
        } else {
            return Err(
                "No input provided. Usage: rb crypto codec encode <codec> <input>".to_string(),
            );
        };

        let registry = CodecRegistry::new();
        let codec = registry.get(codec_name).ok_or_else(|| {
            format!(
                "Unknown codec '{}'. Use 'rb crypto codec list' to see available codecs.",
                codec_name
            )
        })?;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

        let encoded = codec.encode(&input).map_err(|e| e.to_string())?;

        if ctx.has_flag("raw") {
            std::io::stdout()
                .write_all(&encoded)
                .map_err(|e| e.to_string())?;
        } else if format == "json" {
            let value = if let Ok(s) = String::from_utf8(encoded.clone()) {
                json!({
                    "codec": codec_name,
                    "operation": "encode",
                    "input_size": input.len(),
                    "output_size": encoded.len(),
                    "output": s,
                })
            } else {
                json!({
                    "codec": codec_name,
                    "operation": "encode",
                    "input_size": input.len(),
                    "output_size": encoded.len(),
                    "output_hex": hex_encode(&encoded),
                })
            };
            Output::json_value(&value);
        } else if let Ok(s) = String::from_utf8(encoded.clone()) {
            println!("{}", s);
        } else {
            println!("{}", hex_encode(&encoded));
        }

        Ok(())
    }

    fn decode(&self, ctx: &CliContext) -> Result<(), String> {
        let codec_name = ctx
            .target
            .as_ref()
            .ok_or("Missing codec name. Usage: rb crypto codec decode <codec> <input>")?;

        let input = if let Some(file) = ctx.get_flag("file") {
            fs::read(&file).map_err(|e| format!("Failed to read file '{}': {}", file, e))?
        } else if let Some(arg) = ctx.args.first() {
            arg.as_bytes().to_vec()
        } else {
            return Err(
                "No input provided. Usage: rb crypto codec decode <codec> <input>".to_string(),
            );
        };

        let registry = CodecRegistry::new();
        let codec = registry.get(codec_name).ok_or_else(|| {
            format!(
                "Unknown codec '{}'. Use 'rb crypto codec list' to see available codecs.",
                codec_name
            )
        })?;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

        let decoded = codec.decode(&input).map_err(|e| e.to_string())?;

        if ctx.has_flag("raw") {
            std::io::stdout()
                .write_all(&decoded)
                .map_err(|e| e.to_string())?;
        } else if format == "json" {
            let value = if let Ok(s) = String::from_utf8(decoded.clone()) {
                json!({
                    "codec": codec_name,
                    "operation": "decode",
                    "input_size": input.len(),
                    "output_size": decoded.len(),
                    "output": s,
                })
            } else {
                json!({
                    "codec": codec_name,
                    "operation": "decode",
                    "input_size": input.len(),
                    "output_size": decoded.len(),
                    "output_hex": hex_encode(&decoded),
                })
            };
            Output::json_value(&value);
        } else if let Ok(s) = String::from_utf8(decoded.clone()) {
            println!("{}", s);
        } else {
            // Print as hex if not valid UTF-8
            println!("{}", hex_encode(&decoded));
        }

        Ok(())
    }

    fn list_codecs(&self, ctx: &CliContext) -> Result<(), String> {
        let registry = CodecRegistry::new();
        let codecs = registry.list();
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

        if format == "json" {
            let codecs_json: Vec<_> = codecs
                .iter()
                .filter_map(|name| {
                    registry.get(name).map(|codec| {
                        json!({
                            "name": name,
                            "description": codec.description(),
                        })
                    })
                })
                .collect();
            Output::json_value(&json!(codecs_json));
        } else {
            Output::header("Available Codecs");
            println!();
            for name in codecs {
                if let Some(codec) = registry.get(name) {
                    println!("  {:16} {}", name, codec.description());
                }
            }
        }

        Ok(())
    }

    fn detect_encoding(&self, ctx: &CliContext) -> Result<(), String> {
        let input = self.get_input(ctx)?;
        let registry = CodecRegistry::new();
        let detections = registry.detect_all(&input);
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

        if format == "json" {
            let detections_json: Vec<_> = detections
                .iter()
                .map(|det| {
                    json!({
                        "codec": det.codec_name,
                        "confidence": det.confidence,
                    })
                })
                .collect();
            Output::json_value(&json!(detections_json));
        } else {
            Output::header("Encoding Detection");
            println!();
            if detections.is_empty() {
                Output::info("No encodings detected with confidence.");
            } else {
                for det in detections.iter().take(5) {
                    let bar_len = (det.confidence * 20.0) as usize;
                    let bar = "█".repeat(bar_len) + &"░".repeat(20 - bar_len);
                    println!(
                        "  {:16} {:5.1}% {}",
                        det.codec_name,
                        det.confidence * 100.0,
                        bar
                    );
                }
            }
        }

        Ok(())
    }
}
