//! Codec command - Encoding/decoding operations

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::crypto::codec::CodecRegistry;
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
            println!("{{");
            println!("  \"codec\": \"{}\",", codec_name);
            println!("  \"operation\": \"encode\",");
            println!("  \"input_size\": {},", input.len());
            println!("  \"output_size\": {},", encoded.len());
            if let Ok(s) = String::from_utf8(encoded.clone()) {
                println!(
                    "  \"output\": \"{}\"",
                    s.replace('"', "\\\"").replace('\n', "\\n")
                );
            } else {
                println!("  \"output_hex\": \"{}\"", hex_encode(&encoded));
            }
            println!("}}");
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
            println!("{{");
            println!("  \"codec\": \"{}\",", codec_name);
            println!("  \"operation\": \"decode\",");
            println!("  \"input_size\": {},", input.len());
            println!("  \"output_size\": {},", decoded.len());
            if let Ok(s) = String::from_utf8(decoded.clone()) {
                println!(
                    "  \"output\": \"{}\"",
                    s.replace('"', "\\\"").replace('\n', "\\n")
                );
            } else {
                println!("  \"output_hex\": \"{}\"", hex_encode(&decoded));
            }
            println!("}}");
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
            println!("[");
            for (i, name) in codecs.iter().enumerate() {
                if let Some(codec) = registry.get(name) {
                    print!(
                        "  {{\"name\": \"{}\", \"description\": \"{}\"}}",
                        name,
                        codec.description()
                    );
                    if i < codecs.len() - 1 {
                        println!(",");
                    } else {
                        println!();
                    }
                }
            }
            println!("]");
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
            println!("[");
            for (i, det) in detections.iter().enumerate() {
                print!(
                    "  {{\"codec\": \"{}\", \"confidence\": {:.2}}}",
                    det.codec_name, det.confidence
                );
                if i < detections.len() - 1 {
                    println!(",");
                } else {
                    println!();
                }
            }
            println!("]");
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
