//! Analyze command - Hash identification, frequency analysis, entropy, auto-detect

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::crypto::analysis::{AutoDetector, EntropyAnalyzer, FrequencyAnalyzer, HashIdentifier};
use crate::json;
use std::fs;

/// Analysis command (hash ID, frequency, auto-detect)
pub struct CryptoAnalyzeCommand;

impl Command for CryptoAnalyzeCommand {
  fn domain(&self) -> &str {
    "crypto"
  }

  fn resource(&self) -> &str {
    "analyze"
  }

  fn description(&self) -> &str {
    "Cryptographic analysis (hash identification, frequency analysis, auto-detect)"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "hash",
        summary: "Identify hash type from string",
        usage: "rb crypto analyze hash <hash_string>",
      },
      Route {
        verb: "frequency",
        summary: "Frequency analysis of text",
        usage: "rb crypto analyze frequency <text>",
      },
      Route {
        verb: "entropy",
        summary: "Calculate Shannon entropy of data",
        usage: "rb crypto analyze entropy <input> [--file FILE]",
      },
      Route {
        verb: "auto",
        summary: "Auto-detect and decode (Ciphey-style magic)",
        usage: "rb crypto analyze auto <input>",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("format", "Output format (text, json)").with_default("text"),
      Flag::new("file", "Read input from file")
        .with_short('f')
        .with_arg("FILE"),
      Flag::new("depth", "Maximum recursion depth for auto-detect")
        .with_short('d')
        .with_arg("N")
        .with_default("5"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Identify hash type",
        "rb crypto analyze hash '5d41402abc4b2a76b9719d911017c592'",
      ),
      (
        "Frequency analysis",
        "rb crypto analyze frequency 'KHOOR ZRUOG'",
      ),
      (
        "Calculate entropy",
        "rb crypto analyze entropy --file suspicious.bin",
      ),
      (
        "Auto-decode (magic)",
        "rb crypto analyze auto 'U0dWc2JHOGdWMjl5YkdRPQ=='",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "hash" => self.identify_hash(ctx),
      "frequency" => self.frequency_analysis(ctx),
      "entropy" => self.entropy_analysis(ctx),
      "auto" => self.auto_detect(ctx),
      "help" => {
        print_help(self);
        Ok(())
      }
      _ => Err(format!(
        "Unknown verb '{}'. Use: rb crypto analyze help",
        verb
      )),
    }
  }
}

impl CryptoAnalyzeCommand {
  fn get_input(&self, ctx: &CliContext) -> Result<String, String> {
    if let Some(file) = ctx.get_flag("file") {
      fs::read_to_string(&file).map_err(|e| format!("Failed to read file '{}': {}", file, e))
    } else if let Some(target) = ctx.target.as_ref() {
      Ok(target.clone())
    } else if let Some(arg) = ctx.args.first() {
      Ok(arg.clone())
    } else {
      Err("No input provided.".to_string())
    }
  }

  fn identify_hash(&self, ctx: &CliContext) -> Result<(), String> {
    let input = self.get_input(ctx)?;
    let identifier = HashIdentifier::new();
    let results = identifier.identify(&input);
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    // Calculate confidence based on match quality
    let confidence_base = if results.len() == 1 {
      0.95
    } else {
      0.7 / results.len() as f64
    };

    if format == "json" {
      let results_json: Vec<_> = results
        .iter()
        .enumerate()
        .map(|(i, result)| {
          let confidence = confidence_base + (results.len() - i) as f64 * 0.05;
          json!({
              "name": result.name,
              "hashcat_mode": result.hashcat_mode.map(|m| m.to_string()),
              "john_format": result.john_format.clone(),
              "confidence": confidence.min(1.0),
          })
        })
        .collect();
      Output::json_value(&json!(results_json));
    } else {
      Output::header("Hash Identification");
      Output::item("Input", &input);
      Output::item("Length", &input.len().to_string());
      println!();

      if results.is_empty() {
        Output::info("No hash types identified.");
      } else {
        for (i, result) in results.iter().take(5).enumerate() {
          let confidence = confidence_base + (results.len() - i) as f64 * 0.05;
          let bar_len = (confidence.min(1.0) * 20.0) as usize;
          let bar = "█".repeat(bar_len) + &"░".repeat(20 - bar_len);
          println!(
            "  {:20} {:5.1}% {}",
            result.name,
            confidence.min(1.0) * 100.0,
            bar
          );
          if let Some(mode) = result.hashcat_mode {
            println!("    └─ hashcat: -m {}", mode);
          }
          if let Some(fmt) = &result.john_format {
            println!("    └─ john: --format={}", fmt);
          }
        }
      }
    }

    Ok(())
  }

  fn frequency_analysis(&self, ctx: &CliContext) -> Result<(), String> {
    let input = self.get_input(ctx)?;
    let analyzer = FrequencyAnalyzer::new();
    let result = analyzer.analyze(&input);
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let cipher_type = analyzer.detect_cipher_type(&input);

    if format == "json" {
      let top_chars: Vec<_> = result
        .top_chars
        .iter()
        .take(10)
        .map(|(c, freq)| {
          json!({
              "char": c.to_string(),
              "frequency": freq,
          })
        })
        .collect();
      Output::json_value(&json!({
          "ioc": result.ioc,
          "likely_language": result.likely_language.clone(),
          "cipher_type": cipher_type,
          "top_chars": top_chars,
      }));
    } else {
      Output::header("Frequency Analysis");
      Output::item("Index of Coincidence", &format!("{:.4}", result.ioc));
      Output::item("Likely language", &result.likely_language);
      Output::item("Probable cipher type", &cipher_type);
      println!();

      Output::subheader("Top Characters");
      for (c, freq) in result.top_chars.iter().take(10) {
        let bar_len = (freq * 100.0) as usize;
        let bar = "█".repeat(bar_len.min(30));
        println!("  '{}' {:6.2}% {}", c, freq * 100.0, bar);
      }

      if !result.bigrams.is_empty() {
        println!();
        Output::subheader("Top Bigrams");
        for (bigram, freq) in result.bigrams.iter().take(5) {
          println!("  \"{}\" {:6.2}%", bigram, freq * 100.0);
        }
      }
    }

    Ok(())
  }

  fn entropy_analysis(&self, ctx: &CliContext) -> Result<(), String> {
    // Get input as bytes (can be binary data)
    let input_bytes = if let Some(file_path) = ctx.get_flag("file") {
      std::fs::read(&file_path).map_err(|e| format!("Failed to read file: {}", e))?
    } else if let Some(target) = ctx.target.as_ref() {
      target.as_bytes().to_vec()
    } else if let Some(arg) = ctx.args.first() {
      arg.as_bytes().to_vec()
    } else {
      return Err("No input provided. Use: rb crypto analyze entropy <data> [--file FILE]".into());
    };

    let analyzer = EntropyAnalyzer::new();
    let result = analyzer.analyze(&input_bytes);
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    if format == "json" {
      Output::json_value(&json!({
          "entropy": result.entropy,
          "entropy_percent": result.entropy_percent,
          "classification": format!("{}", result.classification),
          "unique_bytes": result.unique_bytes,
          "total_bytes": result.total_bytes,
          "is_likely_compressed": result.is_likely_compressed,
          "is_likely_encrypted": result.is_likely_encrypted,
          "is_likely_text": result.is_likely_text,
      }));
    } else {
      Output::header("Entropy Analysis");
      Output::item("Total bytes", &format!("{}", result.total_bytes));
      Output::item(
        "Unique byte values",
        &format!("{}/256", result.unique_bytes),
      );
      println!();

      Output::subheader("Shannon Entropy");
      let entropy_bar_len = (result.entropy / 8.0 * 40.0) as usize;
      let entropy_bar = "█".repeat(entropy_bar_len);
      let empty_bar = "░".repeat(40 - entropy_bar_len);
      println!(
        "  {:.4} bits/byte ({:.1}%)",
        result.entropy, result.entropy_percent
      );
      println!("  [{}{}] 0-8 bits", entropy_bar, empty_bar);
      println!();

      Output::item("Classification", &format!("{}", result.classification));
      println!();

      Output::subheader("Data Type Indicators");
      let indicator = |b: bool| if b { "Yes" } else { "No" };
      println!("  Likely text:       {}", indicator(result.is_likely_text));
      println!(
        "  Likely compressed: {}",
        indicator(result.is_likely_compressed)
      );
      println!(
        "  Likely encrypted:  {}",
        indicator(result.is_likely_encrypted)
      );

      // Chi-squared test
      let chi_sq = analyzer.chi_squared(&input_bytes);
      println!();
      Output::item(
        "Chi-squared",
        &format!("{:.2} (vs uniform distribution)", chi_sq),
      );

      // Guidance based on classification
      println!();
      Output::subheader("Analysis");
      match result.classification {
        crate::crypto::analysis::EntropyClassification::VeryLow => {
          println!("  Data is highly uniform/repetitive. Likely sparse or constant data.");
        }
        crate::crypto::analysis::EntropyClassification::Low => {
          println!("  Low entropy suggests repetitive patterns. May be simple encoding.");
        }
        crate::crypto::analysis::EntropyClassification::Medium => {
          println!("  Medium entropy typical of natural language text or source code.");
        }
        crate::crypto::analysis::EntropyClassification::High => {
          println!("  High entropy suggests binary/compiled data or mixed content.");
        }
        crate::crypto::analysis::EntropyClassification::VeryHigh => {
          println!("  Very high entropy suggests compressed data (gzip, zlib, etc).");
        }
        crate::crypto::analysis::EntropyClassification::Maximum => {
          println!("  Near-maximum entropy indicates encrypted or cryptographically random data.");
        }
      }
    }

    Ok(())
  }

  fn auto_detect(&self, ctx: &CliContext) -> Result<(), String> {
    let input = self.get_input(ctx)?;
    let depth = ctx
      .get_flag("depth")
      .map(|s| s.parse::<usize>())
      .transpose()
      .map_err(|_| "Invalid depth value")?
      .unwrap_or(5);

    let detector = AutoDetector::new();
    let paths = detector.magic(input.as_bytes(), depth);
    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());

    // Extract best path (already sorted by confidence)
    let (chain, plaintext, confidence) = if let Some(best_path) = paths.first() {
      let chain: Vec<String> = best_path.iter().map(|d| d.name.clone()).collect();
      let plaintext = best_path
        .last()
        .and_then(|d| d.decoded.clone())
        .unwrap_or_else(|| input.clone());
      let confidence: f64 = best_path.iter().map(|d| d.confidence).product();
      (chain, plaintext, confidence)
    } else {
      // No decoding paths found - input is likely plaintext
      (Vec::new(), input.clone(), 1.0)
    };

    if format == "json" {
      Output::json_value(&json!({
          "input": input,
          "output": plaintext,
          "confidence": confidence,
          "chain": chain,
      }));
    } else {
      Output::header("Auto-Detect (Magic Mode)");
      Output::item("Input", &input);
      println!();

      if chain.is_empty() {
        Output::info("Input appears to already be plaintext.");
        println!("  {}", plaintext);
      } else {
        Output::subheader("Decoding Chain");
        for (i, step) in chain.iter().enumerate() {
          println!("  {}. {}", i + 1, step);
        }
        println!();
        Output::subheader("Result");
        println!("  {}", plaintext);
        println!();
        Output::item("Confidence", &format!("{:.0}%", confidence * 100.0));
      }
    }

    Ok(())
  }
}
