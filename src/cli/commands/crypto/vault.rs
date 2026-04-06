//! Vault command - Secure file encryption with AES-256-GCM

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::crypto::sha256::Sha256;
use crate::crypto::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::json;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use super::helpers::{generate_random_bytes, hex_encode, pbkdf2_sha256, read_password};
use super::{
    KEY_SIZE, NONCE_SIZE, PBKDF2_ITERATIONS, SALT_SIZE, TAG_SIZE, VAULT_MAGIC, VAULT_VERSION,
};

pub struct CryptoCommand;

impl Command for CryptoCommand {
    fn domain(&self) -> &str {
        "crypto"
    }

    fn resource(&self) -> &str {
        "vault"
    }

    fn description(&self) -> &str {
        "Secure file encryption vault - AES-256-GCM with password"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "hash",
                summary: "Hash utilities (verify checksums)",
                usage: "rb crypto hash verify <file> <expected_hash>",
            },
            Route {
                verb: "encrypt",
                summary: "Encrypt a file with password",
                usage: "rb crypto vault encrypt <file> [-o output] [--password PASS]",
            },
            Route {
                verb: "decrypt",
                summary: "Decrypt a vault file with password",
                usage: "rb crypto vault decrypt <file.vault> [-o output] [--password PASS]",
            },
            Route {
                verb: "info",
                summary: "Show info about an encrypted vault file",
                usage: "rb crypto vault info <file.vault>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("output", "Output file path")
                .with_short('o')
                .with_arg("FILE"),
            Flag::new("format", "Output format (text, json)").with_default("text"),
            Flag::new("password", "Password (omit for secure prompt)")
                .with_short('p')
                .with_arg("PASS"),
            Flag::new("force", "Overwrite existing output file").with_short('f'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Verify file checksum",
                "rb crypto hash verify ./bin/rb <sha256_hash>",
            ),
            (
                "Encrypt a file (password prompt)",
                "rb crypto vault encrypt secrets.txt",
            ),
            (
                "Encrypt with output path",
                "rb crypto vault encrypt config.json -o config.vault",
            ),
            (
                "Decrypt a vault file",
                "rb crypto vault decrypt secrets.vault",
            ),
            (
                "Decrypt to specific file",
                "rb crypto vault decrypt data.vault -o data.json",
            ),
            ("Show vault info", "rb crypto vault info secrets.vault"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "hash" => self.hash_ops(ctx),
            "encrypt" => self.encrypt_file(ctx),
            "decrypt" => self.decrypt_file(ctx),
            "info" => self.show_info(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => Err(format!(
                "Unknown verb '{}'. Use: rb crypto vault help",
                verb
            )),
        }
    }
}

impl CryptoCommand {
    fn encrypt_file(&self, ctx: &CliContext) -> Result<(), String> {
        let input_path = ctx
            .target
            .as_ref()
            .ok_or("Missing input file. Usage: rb crypto vault encrypt <file>")?;

        // Read input file
        let plaintext =
            fs::read(input_path).map_err(|e| format!("Failed to read '{}': {}", input_path, e))?;

        // Determine output path
        let output_path = ctx
            .get_flag("output")
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}.vault", input_path));

        // Check if output exists
        if fs::metadata(&output_path).is_ok() && !ctx.has_flag("force") {
            return Err(format!(
                "Output file '{}' already exists. Use --force to overwrite.",
                output_path
            ));
        }

        // Get password
        let password = self.get_password(ctx, true)?;

        Output::header("Encrypting File");
        Output::item("Input", input_path);
        Output::item("Output", &output_path);
        Output::item("Size", &format!("{} bytes", plaintext.len()));
        println!();

        Output::spinner_start("Deriving key from password");

        // Generate random salt and nonce
        let salt = generate_random_bytes(SALT_SIZE);
        let nonce = generate_random_bytes(NONCE_SIZE);

        // Derive key using PBKDF2
        let key = pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS, KEY_SIZE);
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| "Key derivation failed".to_string())?;
        let nonce_array: [u8; 12] = nonce
            .clone()
            .try_into()
            .map_err(|_| "Nonce generation failed".to_string())?;

        Output::spinner_done();
        Output::spinner_start("Encrypting with AES-256-GCM");

        // Encrypt using AES-256-GCM (returns ciphertext + tag)
        let ciphertext_with_tag = aes256_gcm_encrypt(&key_array, &nonce_array, &[], &plaintext);

        Output::spinner_done();

        // Build vault file: MAGIC + VERSION + SALT + NONCE + CIPHERTEXT_WITH_TAG
        let mut vault_data = Vec::with_capacity(
            VAULT_MAGIC.len() + 1 + SALT_SIZE + NONCE_SIZE + ciphertext_with_tag.len(),
        );
        vault_data.extend_from_slice(VAULT_MAGIC);
        vault_data.push(VAULT_VERSION);
        vault_data.extend_from_slice(&salt);
        vault_data.extend_from_slice(&nonce);
        vault_data.extend_from_slice(&ciphertext_with_tag);

        // Write vault file
        fs::write(&output_path, &vault_data)
            .map_err(|e| format!("Failed to write '{}': {}", output_path, e))?;

        println!();
        Output::success(&format!(
            "Encrypted {} bytes -> {}",
            plaintext.len(),
            output_path
        ));
        Output::info(&format!(
            "Vault size: {} bytes (overhead: {} bytes)",
            vault_data.len(),
            vault_data.len() - plaintext.len()
        ));

        Ok(())
    }

    fn decrypt_file(&self, ctx: &CliContext) -> Result<(), String> {
        let input_path = ctx
            .target
            .as_ref()
            .ok_or("Missing vault file. Usage: rb crypto vault decrypt <file.vault>")?;

        // Read vault file
        let vault_data =
            fs::read(input_path).map_err(|e| format!("Failed to read '{}': {}", input_path, e))?;

        // Validate minimum size (magic + version + salt + nonce + tag)
        let min_size = VAULT_MAGIC.len() + 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE;
        if vault_data.len() < min_size {
            return Err("Invalid vault file: too small".to_string());
        }

        // Validate magic
        if &vault_data[0..4] != VAULT_MAGIC {
            return Err("Invalid vault file: bad magic bytes (not a redblue vault)".to_string());
        }

        // Check version
        let version = vault_data[4];
        if version != VAULT_VERSION {
            return Err(format!(
                "Unsupported vault version {} (this version supports {})",
                version, VAULT_VERSION
            ));
        }

        // Extract components
        let salt = &vault_data[5..5 + SALT_SIZE];
        let nonce = &vault_data[5 + SALT_SIZE..5 + SALT_SIZE + NONCE_SIZE];
        let ciphertext_with_tag = &vault_data[5 + SALT_SIZE + NONCE_SIZE..];

        if ciphertext_with_tag.len() < TAG_SIZE {
            return Err("Invalid vault file: missing authentication tag".to_string());
        }

        // Determine output path
        let output_path = ctx
            .get_flag("output")
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Remove .vault extension if present
                if input_path.ends_with(".vault") {
                    input_path[..input_path.len() - 6].to_string()
                } else {
                    format!("{}.decrypted", input_path)
                }
            });

        // Check if output exists
        if fs::metadata(&output_path).is_ok() && !ctx.has_flag("force") {
            return Err(format!(
                "Output file '{}' already exists. Use --force to overwrite.",
                output_path
            ));
        }

        // Get password
        let password = self.get_password(ctx, false)?;

        Output::header("Decrypting Vault");
        Output::item("Input", input_path);
        Output::item("Output", &output_path);
        Output::item(
            "Encrypted size",
            &format!("{} bytes", ciphertext_with_tag.len() - TAG_SIZE),
        );
        println!();

        Output::spinner_start("Deriving key from password");

        // Derive key using PBKDF2
        let key = pbkdf2_sha256(password.as_bytes(), salt, PBKDF2_ITERATIONS, KEY_SIZE);
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| "Key derivation failed".to_string())?;
        let nonce_array: [u8; 12] = nonce
            .try_into()
            .map_err(|_| "Invalid nonce in vault".to_string())?;

        Output::spinner_done();
        Output::spinner_start("Decrypting and verifying");

        // Decrypt using AES-256-GCM
        let plaintext = aes256_gcm_decrypt(&key_array, &nonce_array, &[], ciphertext_with_tag)
            .map_err(|_| "Authentication failed: wrong password or corrupted data".to_string())?;

        Output::spinner_done();

        // Write decrypted file
        fs::write(&output_path, &plaintext)
            .map_err(|e| format!("Failed to write '{}': {}", output_path, e))?;

        println!();
        Output::success(&format!(
            "Decrypted {} bytes -> {}",
            plaintext.len(),
            output_path
        ));

        Ok(())
    }

    fn show_info(&self, ctx: &CliContext) -> Result<(), String> {
        let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
        let is_json = format == "json";

        let input_path = ctx
            .target
            .as_ref()
            .ok_or("Missing vault file. Usage: rb crypto vault info <file.vault>")?;

        // Read vault file
        let vault_data =
            fs::read(input_path).map_err(|e| format!("Failed to read '{}': {}", input_path, e))?;

        // Validate minimum size
        let min_size = VAULT_MAGIC.len() + 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE;
        let is_valid = vault_data.len() >= min_size && &vault_data[0..4] == VAULT_MAGIC;

        if is_json {
            let mut payload = json!({
                "file": input_path,
                "total_size": vault_data.len(),
                "valid": is_valid
            });
            if is_valid {
                let version = vault_data[4];
                let ciphertext_size = vault_data.len() - min_size;
                if let Some(map) = payload.as_object().cloned() {
                    let mut map = map;
                    map.insert("version".to_string(), json!(version));
                    map.insert("salt_size".to_string(), json!(SALT_SIZE));
                    map.insert("nonce_size".to_string(), json!(NONCE_SIZE));
                    map.insert("ciphertext_size".to_string(), json!(ciphertext_size));
                    map.insert("tag_size".to_string(), json!(TAG_SIZE));
                    map.insert("encryption".to_string(), json!("AES-256-GCM"));
                    map.insert("key_derivation".to_string(), json!("PBKDF2-HMAC-SHA256"));
                    map.insert("iterations".to_string(), json!(PBKDF2_ITERATIONS));
                    payload = crate::serde_json::Value::Object(map);
                }
            }
            Output::json_value(&payload);
            return Ok(());
        }

        Output::header("Vault File Info");
        Output::item("File", input_path);
        Output::item("Total size", &format!("{} bytes", vault_data.len()));

        if vault_data.len() < min_size {
            Output::error("Invalid vault file: too small");
            return Ok(());
        }

        // Check magic
        if &vault_data[0..4] != VAULT_MAGIC {
            Output::error("Invalid vault file: not a redblue vault");
            return Ok(());
        }

        let version = vault_data[4];
        let ciphertext_size = vault_data.len() - min_size;

        println!();
        Output::subheader("Vault Details");
        Output::item("Magic", "RBVT (valid)");
        Output::item("Version", &format!("{}", version));
        Output::item("Salt size", &format!("{} bytes", SALT_SIZE));
        Output::item("Nonce size", &format!("{} bytes", NONCE_SIZE));
        Output::item("Ciphertext size", &format!("{} bytes", ciphertext_size));
        Output::item("Auth tag size", &format!("{} bytes", TAG_SIZE));

        println!();
        Output::subheader("Security");
        Output::item("Encryption", "AES-256-GCM");
        Output::item(
            "Key derivation",
            &format!("PBKDF2-HMAC-SHA256 ({} iterations)", PBKDF2_ITERATIONS),
        );
        Output::item("Authentication", "GCM (AEAD)");

        Ok(())
    }

    fn hash_ops(&self, ctx: &CliContext) -> Result<(), String> {
        let resource = ctx.resource.as_deref().unwrap_or("");

        match resource {
            "verify" => self.verify_checksum(ctx),
            _ => Err(format!(
                "Unknown hash operation '{}'. Try: rb crypto hash verify <file> <hash>",
                resource
            )),
        }
    }

    fn verify_checksum(&self, ctx: &CliContext) -> Result<(), String> {
        let file_path = ctx
            .target
            .as_ref()
            .ok_or("Missing file path. Usage: rb crypto hash verify <file> <hash>")?;

        // The hash should be the first argument
        let expected_hash = ctx
            .args
            .get(0)
            .ok_or("Missing expected hash. Usage: rb crypto hash verify <file> <hash>")?;

        let path = Path::new(file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", file_path));
        }

        Output::header("Checksum Verification");
        Output::item("File", file_path);
        Output::item("Expected", expected_hash);
        println!();

        Output::spinner_start("Calculating SHA-256");

        let mut file = fs::File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let n = file
                .read(&mut buffer)
                .map_err(|e| format!("Read failed: {}", e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let digest = hasher.finalize();
        let actual_hash = hex_encode(&digest);

        Output::spinner_done();

        println!();
        if actual_hash.eq_ignore_ascii_case(expected_hash) {
            Output::success("Checksum MATCHED");
            Output::item("Actual", &actual_hash);
        } else {
            Output::error("Checksum MISMATCH");
            Output::item("Actual", &actual_hash);
            Output::item("Expect", expected_hash);
            return Err("Checksum verification failed".to_string());
        }

        Ok(())
    }

    fn get_password(&self, ctx: &CliContext, confirm: bool) -> Result<String, String> {
        // Check if password provided via flag
        if let Some(pass) = ctx.get_flag("password") {
            return Ok(pass.to_string());
        }

        // Prompt for password
        eprint!("Password: ");
        io::stderr().flush().ok();

        let password = read_password()?;

        if password.is_empty() {
            return Err("Password cannot be empty".to_string());
        }

        if confirm {
            eprint!("Confirm password: ");
            io::stderr().flush().ok();
            let confirm_pass = read_password()?;

            if password != confirm_pass {
                return Err("Passwords do not match".to_string());
            }
        }

        Ok(password)
    }
}
