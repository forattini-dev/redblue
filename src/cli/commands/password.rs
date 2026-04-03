//! Password Cracking Commands
//!
//! Hash cracking with dictionary, mask, and hybrid attacks.
//! Inspired by hashcat and John the Ripper.

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::modules::password::{
    detect_format, format_hash, parse_hash, verify_hash, AttackMode, Cracker, HashFormat,
    MaskGenerator, RuleEngine,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

pub struct PasswordCommand;

impl Command for PasswordCommand {
    fn domain(&self) -> &str {
        "password"
    }

    fn resource(&self) -> &str {
        "hash"
    }

    fn description(&self) -> &str {
        "Password hash cracking - dictionary, mask, and hybrid attacks"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "identify",
                summary: "Identify hash type from hash string",
                usage: "rb password hash identify <hash>",
            },
            Route {
                verb: "crack",
                summary: "Crack password hash(es) with wordlist or mask",
                usage: "rb password hash crack <hash_or_file> -w wordlist.txt",
            },
            Route {
                verb: "verify",
                summary: "Verify a password against a hash",
                usage: "rb password hash verify <hash> <password>",
            },
            Route {
                verb: "generate",
                summary: "Generate hash from password",
                usage: "rb password hash generate <password> --type md5",
            },
            Route {
                verb: "benchmark",
                summary: "Benchmark hash cracking speed",
                usage: "rb password hash benchmark [--type md5]",
            },
            Route {
                verb: "mask",
                summary: "Show mask pattern keyspace",
                usage: "rb password hash mask '?l?l?l?d?d'",
            },
            Route {
                verb: "rules",
                summary: "Show available mutation rules",
                usage: "rb password hash rules [--preset best64]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("wordlist", "Wordlist file for dictionary attack")
                .with_short('w')
                .with_arg("FILE"),
            Flag::new("wordlist2", "Second wordlist file for combinator attack")
                .with_short('W')
                .with_arg("FILE"),
            Flag::new("mask", "Mask pattern for brute-force (e.g., ?l?l?l?d?d)")
                .with_short('m')
                .with_arg("PATTERN"),
            Flag::new("rules", "Rule mutations (comma-separated or preset name)")
                .with_short('r')
                .with_arg("RULES"),
            Flag::new("type", "Hash type (md5, sha1, sha256, ntlm, etc)")
                .with_short('t')
                .with_arg("TYPE"),
            Flag::new("format", "Output format (text, json)").with_default("text"),
            Flag::new("limit", "Maximum candidates to try")
                .with_short('n')
                .with_arg("NUM"),
            Flag::new("potfile", "Potfile to store/load cracked hashes")
                .with_short('p')
                .with_arg("FILE"),
            Flag::new("show", "Show cracked hashes from potfile"),
            Flag::new("left", "Show uncracked hashes"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Identify hash type",
                "rb password hash identify 5d41402abc4b2a76b9719d911017c592",
            ),
            (
                "Crack with wordlist",
                "rb password hash crack hashes.txt -w rockyou.txt",
            ),
            (
                "Combinator attack with two wordlists",
                "rb password hash crack hash.txt -w words.txt -W words2.txt",
            ),
            (
                "Crack with rules",
                "rb password hash crack hash.txt -w words.txt -r best64",
            ),
            (
                "Mask attack (3 lowercase + 2 digits)",
                "rb password hash crack <hash> -m '?l?l?l?d?d'",
            ),
            (
                "Hybrid attack",
                "rb password hash crack <hash> -w words.txt -m '?d?d?d?d'",
            ),
            (
                "Verify password",
                "rb password hash verify 5d41402abc4b2a76b9719d911017c592 hello",
            ),
            (
                "Generate MD5 hash",
                "rb password hash generate password --type md5",
            ),
            (
                "Show mask keyspace",
                "rb password hash mask '?u?l?l?l?l?d?d?d'",
            ),
            (
                "Benchmark speed",
                "rb password hash benchmark --type sha256",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "identify" => self.identify_hash(ctx),
            "crack" => self.crack_hashes(ctx),
            "verify" => self.verify_password(ctx),
            "generate" => self.generate_hash(ctx),
            "benchmark" => self.benchmark(ctx),
            "mask" => self.show_mask_keyspace(ctx),
            "rules" => self.show_rules(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: rb password hash help",
                verb
            )),
        }
    }
}

impl PasswordCommand {
    fn identify_hash(&self, ctx: &CliContext) -> Result<(), String> {
        let hash = ctx
            .target
            .as_ref()
            .ok_or("Missing hash. Usage: rb password hash identify <hash>")?;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let detected = detect_format(hash);
        let parsed = parse_hash(hash);

        if is_json {
            println!("{{");
            println!("  \"hash\": \"{}\",", hash.replace('"', "\\\""));
            if let Some(fmt) = &detected {
                println!("  \"format\": \"{}\",", fmt.name());
                println!("  \"hashcat_mode\": {},", fmt.hashcat_mode());
                println!("  \"salted\": {},", fmt.is_salted());
                println!("  \"slow\": {},", fmt.is_slow());
                if let Some(len) = fmt.hash_length() {
                    println!("  \"expected_length\": {},", len);
                }
            } else {
                println!("  \"format\": null,");
            }
            if let Some(info) = &parsed {
                if let Some(salt) = &info.salt {
                    println!("  \"salt\": \"{}\",", salt.replace('"', "\\\""));
                }
                if let Some(rounds) = info.rounds {
                    println!("  \"rounds\": {},", rounds);
                }
            }
            println!("}}");
            return Ok(());
        }

        Output::header("Hash Identification");
        Output::item("Input", hash);
        println!();

        if let Some(fmt) = detected {
            Output::success(&format!("Detected: {}", fmt.name()));
            println!();
            Output::subheader("Details");
            Output::item("Format", fmt.name());
            Output::item("Hashcat mode", &fmt.hashcat_mode().to_string());
            Output::item("Salted", if fmt.is_salted() { "Yes" } else { "No" });
            Output::item("Slow hash", if fmt.is_slow() { "Yes" } else { "No" });

            if let Some(len) = fmt.hash_length() {
                Output::item("Expected length", &format!("{} chars", len));
            }

            if let Some(info) = parsed {
                if let Some(salt) = &info.salt {
                    Output::item("Salt", salt);
                }
                if let Some(rounds) = info.rounds {
                    Output::item("Rounds", &rounds.to_string());
                }
            }

            println!();
            Output::subheader("Crack Command");
            println!("  rb password hash crack {} -w wordlist.txt", hash);
        } else {
            Output::warning("Could not identify hash format");
        }

        Ok(())
    }

    fn crack_hashes(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx
            .target
            .as_ref()
            .ok_or("Missing hash or hash file. Usage: rb password hash crack <target>")?;

        // Check if target is a file or a hash
        let hashes: Vec<String> = if Path::new(target).exists() {
            // Load from file
            let file =
                File::open(target).map_err(|e| format!("Failed to open '{}': {}", target, e))?;
            let reader = BufReader::new(file);
            reader
                .lines()
                .filter_map(|l| l.ok())
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        } else {
            // Single hash
            vec![target.to_string()]
        };

        if hashes.is_empty() {
            return Err("No hashes to crack".to_string());
        }

        // Determine attack mode
        let wordlist = ctx.get_flag("wordlist");
        let mask = ctx.get_flag("mask");
        let second_wordlist = ctx.get_flag("wordlist2");

        let mode = match (&wordlist, &mask, &second_wordlist) {
            (Some(_), Some(_), None) => AttackMode::HybridDictMask,
            (Some(_), None, Some(_)) => AttackMode::Combinator,
            (Some(_), None, None) => AttackMode::Dictionary,
            (None, Some(_), None) => AttackMode::Mask,
            (None, None, Some(_)) => {
                return Err("Invalid arguments: --wordlist2 requires --wordlist".to_string());
            }
            (Some(_), Some(_), Some(_)) => {
                return Err(
                    "Invalid arguments: choose either --wordlist + --mask (hybrid) or --wordlist + --wordlist2 (combinator)"
                        .to_string(),
                );
            }
            (None, None, None) => {
                // Try quick crack with common passwords
                return self.quick_crack(&hashes, ctx);
            }
            _ => {
                return Err("Invalid combination of arguments".to_string());
            }
        };

        Output::header("Password Hash Cracker");
        Output::item("Target", target);
        Output::item("Hashes", &hashes.len().to_string());
        Output::item("Mode", mode.name());

        if let Some(wl) = &wordlist {
            Output::item("Wordlist", wl);
        }
        if let Some(m) = &mask {
            Output::item("Mask", m);
            let gen = MaskGenerator::from_pattern(m);
            Output::item("Keyspace", &format!("{}", gen.keyspace()));
        }
        if let Some(wl2) = &second_wordlist {
            Output::item("Second wordlist", wl2);
        }
        println!();

        // Build cracker
        let mut cracker = Cracker::new().mode(mode);

        if let Some(wl) = wordlist {
            cracker = cracker.wordlist(&wl);
        }
        if let Some(wl2) = second_wordlist {
            cracker = cracker.second_wordlist(&wl2);
        }
        if let Some(m) = mask {
            cracker = cracker.mask(&m);
        }

        // Parse hash type if specified
        if let Some(hash_type) = ctx.get_flag("type") {
            if let Some(fmt) = parse_hash_type(&hash_type) {
                cracker = cracker.format(fmt);
            }
        }

        // Add rules if specified
        if let Some(rules_str) = ctx.get_flag("rules") {
            let rules: Vec<&str> =
                if rules_str == "best64" || rules_str == "toggles" || rules_str == "append_numbers"
                {
                    // Preset
                    cracker = cracker.add_preset(&rules_str);
                    vec![]
                } else {
                    rules_str.split(',').collect()
                };
            if !rules.is_empty() {
                cracker = cracker.add_rules(&rules);
            }
        }

        // Set limit if specified
        if let Some(limit_str) = ctx.get_flag("limit") {
            if let Ok(limit) = limit_str.parse::<u64>() {
                cracker = cracker.limit(limit);
            }
        }

        // Set potfile if specified
        if let Some(potfile) = ctx.get_flag("potfile") {
            cracker = cracker.potfile(&potfile);
        }

        // Add hashes
        for hash in &hashes {
            cracker.add_hash(hash);
        }

        Output::spinner_start("Cracking hashes");
        let start = Instant::now();

        // Run attack
        let (results, stats) = cracker.run();

        Output::spinner_done();
        let elapsed = start.elapsed();

        println!();
        Output::subheader("Results");

        if results.is_empty() {
            Output::warning("No passwords cracked");
        } else {
            for result in &results {
                Output::success(&format!("{} : {}", result.hash, result.password));
            }
        }

        println!();
        Output::subheader("Statistics");
        Output::item("Total hashes", &stats.total_hashes.to_string());
        Output::item("Cracked", &stats.cracked.to_string());
        Output::item("Crack rate", &format!("{:.1}%", stats.crack_rate()));
        Output::item("Candidates tested", &stats.candidates_tested.to_string());
        Output::item("Duration", &format!("{:.2}s", elapsed.as_secs_f64()));
        Output::item("Speed", &format!("{:.0} H/s", stats.speed()));

        Ok(())
    }

    fn quick_crack(&self, hashes: &[String], ctx: &CliContext) -> Result<(), String> {
        Output::header("Quick Crack (Common Passwords)");
        Output::item("Hashes", &hashes.len().to_string());
        println!();

        let start = Instant::now();
        let mut cracked = 0;

        for hash in hashes {
            if let Some(password) = Cracker::quick_crack(hash) {
                Output::success(&format!("{} : {}", hash, password));
                cracked += 1;
            }
        }

        let elapsed = start.elapsed();
        println!();

        if cracked == 0 {
            Output::warning("No passwords found with common passwords");
            Output::info("Try: rb password hash crack <hash> -w wordlist.txt");
        } else {
            Output::item("Cracked", &format!("{}/{}", cracked, hashes.len()));
        }

        Output::item("Duration", &format!("{:.2}s", elapsed.as_secs_f64()));

        Ok(())
    }

    fn verify_password(&self, ctx: &CliContext) -> Result<(), String> {
        let hash = ctx
            .target
            .as_ref()
            .ok_or("Missing hash. Usage: rb password hash verify <hash> <password>")?;

        let password = ctx
            .args
            .get(0)
            .ok_or("Missing password. Usage: rb password hash verify <hash> <password>")?;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let info = parse_hash(hash).ok_or("Could not parse hash")?;
        let matches = verify_hash(password, &info);

        if is_json {
            println!("{{");
            println!("  \"hash\": \"{}\",", hash.replace('"', "\\\""));
            println!("  \"password\": \"{}\",", password.replace('"', "\\\""));
            println!("  \"format\": \"{}\",", info.format.name());
            println!("  \"matches\": {}", matches);
            println!("}}");
            return Ok(());
        }

        Output::header("Password Verification");
        Output::item("Hash", hash);
        Output::item("Password", password);
        Output::item("Format", info.format.name());
        println!();

        if matches {
            Output::success("✓ Password MATCHES hash");
        } else {
            Output::error("✗ Password does NOT match hash");
        }

        Ok(())
    }

    fn generate_hash(&self, ctx: &CliContext) -> Result<(), String> {
        let password = ctx
            .target
            .as_ref()
            .ok_or("Missing password. Usage: rb password hash generate <password>")?;

        let hash_type = ctx.get_flag("type").unwrap_or_else(|| "md5".to_string());

        let format = parse_hash_type(&hash_type)
            .ok_or_else(|| format!("Unknown hash type: {}", hash_type))?;

        let output_format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = output_format == "json";

        let hash = format_hash(password, format, None);

        if is_json {
            println!("{{");
            println!("  \"password\": \"{}\",", password.replace('"', "\\\""));
            println!("  \"format\": \"{}\",", format.name());
            println!("  \"hash\": \"{}\"", hash);
            println!("}}");
            return Ok(());
        }

        Output::header("Hash Generation");
        Output::item("Password", password);
        Output::item("Format", format.name());
        println!();
        Output::success(&format!("Hash: {}", hash));

        Ok(())
    }

    fn benchmark(&self, ctx: &CliContext) -> Result<(), String> {
        let hash_type = ctx.get_flag("type").unwrap_or_else(|| "md5".to_string());

        let format = parse_hash_type(&hash_type)
            .ok_or_else(|| format!("Unknown hash type: {}", hash_type))?;

        Output::header("Hash Benchmark");
        Output::item("Format", format.name());
        println!();

        // Generate test hash
        let test_password = "benchmark_test_password";
        let test_hash = format_hash(test_password, format, None);
        let info = parse_hash(&test_hash).ok_or("Failed to create test hash")?;

        // Benchmark
        let iterations = 100_000u64;
        Output::spinner_start(&format!("Testing {} iterations", iterations));

        let start = Instant::now();
        for i in 0..iterations {
            let candidate = format!("wrong_password_{}", i);
            let _ = verify_hash(&candidate, &info);
        }
        let elapsed = start.elapsed();

        Output::spinner_done();

        let speed = iterations as f64 / elapsed.as_secs_f64();

        println!();
        Output::subheader("Results");
        Output::item("Iterations", &iterations.to_string());
        Output::item("Duration", &format!("{:.2}s", elapsed.as_secs_f64()));
        Output::item("Speed", &format!("{:.0} H/s", speed));
        Output::item(
            "Time per hash",
            &format!("{:.3}μs", elapsed.as_micros() as f64 / iterations as f64),
        );

        // Estimate crack times
        println!();
        Output::subheader("Estimated Crack Times");

        let keyspaces = [
            ("4 digits (0000-9999)", 10_000u64),
            ("6 lowercase (aaaaaa-zzzzzz)", 26u64.pow(6)),
            ("8 lowercase", 26u64.pow(8)),
            ("8 mixed case", 52u64.pow(8)),
            ("8 alphanumeric", 62u64.pow(8)),
            ("10 all chars", 95u64.pow(10)),
        ];

        for (name, keyspace) in keyspaces {
            let seconds = keyspace as f64 / speed;
            let time_str = format_duration(seconds);
            Output::item(name, &format!("{} ({} combinations)", time_str, keyspace));
        }

        Ok(())
    }

    fn show_mask_keyspace(&self, ctx: &CliContext) -> Result<(), String> {
        let pattern = ctx
            .target
            .as_ref()
            .ok_or("Missing mask pattern. Usage: rb password hash mask '?l?l?l?d?d'")?;

        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let generator = MaskGenerator::from_pattern(pattern);
        let keyspace = generator.keyspace();

        if is_json {
            println!("{{");
            println!("  \"pattern\": \"{}\",", pattern.replace('"', "\\\""));
            println!("  \"keyspace\": {},", keyspace);
            println!("  \"length\": {}", pattern.matches('?').count());
            println!("}}");
            return Ok(());
        }

        Output::header("Mask Pattern Analysis");
        Output::item("Pattern", pattern);
        println!();

        Output::subheader("Character Sets");
        Output::item("?l", "lowercase (a-z) - 26 chars");
        Output::item("?u", "uppercase (A-Z) - 26 chars");
        Output::item("?d", "digits (0-9) - 10 chars");
        Output::item("?s", "special chars - 33 chars");
        Output::item("?a", "all printable - 95 chars");

        println!();
        Output::subheader("Keyspace");
        Output::item("Total combinations", &format!("{}", keyspace));
        Output::item("Pattern length", &pattern.matches('?').count().to_string());

        // Show first few examples
        println!();
        Output::subheader("Sample Candidates");
        let mut gen = MaskGenerator::from_pattern(pattern);
        for candidate in gen.by_ref().take(5) {
            println!("  {}", candidate);
        }
        println!("  ...");

        Ok(())
    }

    fn show_rules(&self, ctx: &CliContext) -> Result<(), String> {
        let preset = ctx.get_flag("preset");

        Output::header("Password Mutation Rules");

        if let Some(preset_name) = preset {
            Output::subheader(&format!("Preset: {}", preset_name));
            let mut engine = RuleEngine::new();
            engine.add_preset(&preset_name);

            Output::item("Rules count", &engine.len().to_string());

            // Show sample mutations
            println!();
            Output::subheader("Sample Mutations (word: 'password')");
            for mutation in engine.generate("password").iter().take(10) {
                println!("  {}", mutation);
            }

            return Ok(());
        }

        // Show all available rules
        Output::subheader("Case Operations");
        println!("  l    - lowercase all");
        println!("  u    - uppercase all");
        println!("  c    - capitalize first letter");
        println!("  C    - lowercase first, uppercase rest");
        println!("  t    - toggle case of all");
        println!("  TN   - toggle case at position N");

        println!();
        Output::subheader("Append/Prepend");
        println!("  $X   - append character X");
        println!("  ^X   - prepend character X");

        println!();
        Output::subheader("Delete");
        println!("  [    - delete first character");
        println!("  ]    - delete last character");
        println!("  DN   - delete character at position N");

        println!();
        Output::subheader("Duplicate");
        println!("  d    - duplicate word");
        println!("  pN   - duplicate word N times");
        println!("  zN   - duplicate first char N times");
        println!("  ZN   - duplicate last char N times");
        println!("  q    - duplicate every character");
        println!("  f    - reflect (append reversed)");

        println!();
        Output::subheader("Transform");
        println!("  r    - reverse");
        println!("  {{    - rotate left");
        println!("  }}    - rotate right");
        println!("  sXY  - replace X with Y");
        println!("  @X   - purge all X");

        println!();
        Output::subheader("Insert/Swap");
        println!("  iNX  - insert X at position N");
        println!("  oNX  - overwrite position N with X");
        println!("  k    - swap first two chars");
        println!("  K    - swap last two chars");
        println!("  *NM  - swap positions N and M");

        println!();
        Output::subheader("Extract/Truncate");
        println!("  xNM  - extract M chars from position N");
        println!("  ONM  - omit M chars from position N");
        println!("  'N   - truncate at position N");

        println!();
        Output::subheader("Rejection Filters");
        println!("  <N   - reject if length < N");
        println!("  >N   - reject if length > N");
        println!("  !X   - reject if contains X");
        println!("  /X   - reject if doesn't contain X");

        println!();
        Output::subheader("Presets");
        println!("  best64         - Common password mutations");
        println!("  toggles        - Toggle case at each position");
        println!("  append_numbers - Append digits and years");
        println!("  append_symbols - Append special characters");

        Ok(())
    }
}

/// Parse hash type string to HashFormat
fn parse_hash_type(s: &str) -> Option<HashFormat> {
    match s.to_lowercase().as_str() {
        "md5" | "0" => Some(HashFormat::MD5),
        "sha1" | "100" => Some(HashFormat::SHA1),
        "sha256" | "1400" => Some(HashFormat::SHA256),
        "sha384" | "10800" => Some(HashFormat::SHA384),
        "sha512" | "1700" => Some(HashFormat::SHA512),
        "ntlm" | "1000" => Some(HashFormat::NTLM),
        "lm" | "3000" => Some(HashFormat::LM),
        "md5crypt" | "500" => Some(HashFormat::MD5Crypt),
        "sha512crypt" | "1800" => Some(HashFormat::SHA512Crypt),
        "bcrypt" | "3200" => Some(HashFormat::BCrypt),
        "mysql" | "mysql41" | "300" => Some(HashFormat::MySQL41),
        "postgres" | "postgresql" => Some(HashFormat::PostgresMD5),
        "phpass" | "wordpress" | "400" => Some(HashFormat::PHPass),
        _ => None,
    }
}

/// Format duration in human readable format
fn format_duration(seconds: f64) -> String {
    if seconds < 0.001 {
        "instant".to_string()
    } else if seconds < 1.0 {
        format!("{:.0}ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.1}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1}m", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1}h", seconds / 3600.0)
    } else if seconds < 86400.0 * 365.0 {
        format!("{:.1}d", seconds / 86400.0)
    } else if seconds < 86400.0 * 365.0 * 100.0 {
        format!("{:.1}y", seconds / (86400.0 * 365.0))
    } else {
        "centuries".to_string()
    }
}
