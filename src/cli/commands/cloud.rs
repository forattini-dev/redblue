use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::cloud::s3_scanner::S3Scanner;

pub struct CloudCommand;

impl Command for CloudCommand {
    fn domain(&self) -> &str {
        "cloud"
    }

    fn resource(&self) -> &str {
        "storage"
    }

    fn description(&self) -> &str {
        "Cloud storage security testing (S3, Azure Blob, GCS)"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "scan",
                summary: "Scan S3 bucket for existence and permissions",
                usage: "rb cloud storage scan <bucket-name>",
            },
            Route {
                verb: "enumerate",
                summary: "Enumerate buckets with common name patterns",
                usage: "rb cloud storage enumerate <base-name>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("generate", "Generate bucket name variations from base name").with_short('g'),
            Flag::new("wordlist", "Use custom wordlist file for bucket names")
                .with_short('w')
                .with_arg("FILE"),
            Flag::new("check-path-style", "Also check path-style URLs").with_short('p'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("Check single bucket", "rb cloud storage scan my-bucket"),
            (
                "Enumerate with variations",
                "rb cloud storage enumerate company --generate",
            ),
            (
                "Use custom wordlist",
                "rb cloud storage scan company --wordlist buckets.txt",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "scan" => self.scan(ctx),
            "enumerate" => self.enumerate(ctx),
            _ => {
                print_help(self);
                Err(format!("Invalid verb: {}", verb))
            }
        }
    }
}

impl CloudCommand {
    /// Scan a single bucket or list of buckets
    fn scan(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or(
            "Missing bucket name.\nUsage: rb cloud storage scan <bucket-name> [--generate]",
        )?;

        Output::header("S3 Bucket Scanner");
        Output::item("Target", target);

        let scanner = S3Scanner::new();

        // Check if we should generate variations
        if ctx.has_flag("generate") {
            Output::info(&format!(
                "Generating bucket name variations for: {}",
                target
            ));
            let bucket_names = scanner.generate_bucket_names(target);

            Output::item("Total variations", &bucket_names.len().to_string());
            println!();

            Output::spinner_start(&format!("Scanning {} buckets", bucket_names.len()));
            let result = scanner.scan_buckets(&bucket_names);
            Output::spinner_done();

            self.display_scan_results(&result);
        } else if let Some(wordlist_path) = ctx.get_flag("wordlist") {
            // Read wordlist from file
            use std::fs;
            let wordlist_content = fs::read_to_string(&wordlist_path)
                .map_err(|e| format!("Failed to read wordlist: {}", e))?;

            let bucket_names: Vec<String> = wordlist_content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
                .collect();

            Output::item("Wordlist", &wordlist_path);
            Output::item("Total buckets", &bucket_names.len().to_string());
            println!();

            Output::spinner_start(&format!("Scanning {} buckets", bucket_names.len()));
            let result = scanner.scan_buckets(&bucket_names);
            Output::spinner_done();

            self.display_scan_results(&result);
        } else {
            // Single bucket check
            Output::spinner_start(&format!("Checking bucket: {}", target));
            let bucket = scanner.check_bucket(target)?;
            Output::spinner_done();

            self.display_single_bucket(&bucket);

            // Also check path-style if requested
            if ctx.has_flag("check-path-style") {
                println!();
                Output::info("Checking path-style URL...");
                let path_style_bucket = scanner.check_bucket_path_style(target)?;
                self.display_single_bucket(&path_style_bucket);
            }
        }

        Ok(())
    }

    /// Enumerate buckets with generated variations
    fn enumerate(&self, ctx: &CliContext) -> Result<(), String> {
        let base_name = ctx
            .target
            .as_ref()
            .ok_or("Missing base name.\nUsage: rb cloud storage enumerate <base-name>")?;

        Output::header("S3 Bucket Enumeration");
        Output::item("Base name", base_name);

        let scanner = S3Scanner::new();
        let bucket_names = scanner.generate_bucket_names(base_name);

        Output::item("Generated variations", &bucket_names.len().to_string());
        println!();

        // Show first 10 variations as preview
        Output::subheader("Sample variations:");
        for (i, name) in bucket_names.iter().take(10).enumerate() {
            println!("  {}. {}", i + 1, name);
        }
        if bucket_names.len() > 10 {
            println!("  ... and {} more", bucket_names.len() - 10);
        }
        println!();

        Output::spinner_start(&format!("Scanning {} buckets", bucket_names.len()));
        let result = scanner.scan_buckets(&bucket_names);
        Output::spinner_done();

        self.display_scan_results(&result);

        Ok(())
    }

    /// Display results for a single bucket
    fn display_single_bucket(&self, bucket: &crate::modules::cloud::s3_scanner::S3Bucket) {
        println!();
        Output::item("Bucket", &bucket.name);

        if bucket.exists {
            Output::success("Status: EXISTS");

            if let Some(region) = &bucket.region {
                Output::item("Region", region);
            }

            if bucket.accessible {
                Output::warning("⚠️  PUBLICLY ACCESSIBLE!");
                Output::warning(&format!("   {}", bucket.message));

                if bucket.public_list {
                    Output::warning("   - Can list objects (ListBucket)");
                }
                if bucket.public_read {
                    Output::warning("   - Can read objects (GetObject)");
                }
            } else {
                Output::info(&format!("Access: {}", bucket.message));
            }
        } else {
            Output::dim(&format!("Status: {}", bucket.message));
        }
    }

    /// Display scan results for multiple buckets
    fn display_scan_results(&self, result: &crate::modules::cloud::s3_scanner::S3ScanResult) {
        println!();
        Output::subheader("Scan Summary");
        Output::item("Total scanned", &result.total_scanned.to_string());
        Output::item("Buckets exist", &result.total_exists.to_string());

        if result.total_public > 0 {
            Output::warning(&format!("⚠️  Public buckets: {}", result.total_public));
        } else {
            Output::item("Public buckets", "0");
        }

        // Show existing buckets
        if result.total_exists > 0 {
            println!();
            Output::subheader("Existing Buckets:");

            for bucket in &result.buckets {
                if bucket.exists {
                    let status = if bucket.accessible {
                        "🔓 PUBLIC"
                    } else {
                        "🔒 Private"
                    };

                    let region_str = bucket.region.as_deref().unwrap_or("unknown");

                    println!(
                        "  {} | {} | {} | {}",
                        Output::colorize(&bucket.name, "blue"),
                        status,
                        region_str,
                        bucket.message
                    );
                }
            }
        }

        // Show public buckets with details
        if result.total_public > 0 {
            println!();
            Output::warning("⚠️  PUBLIC BUCKETS FOUND:");

            for bucket in &result.buckets {
                if bucket.public_list || bucket.public_read {
                    Output::warning(&format!("  • {}", bucket.name));
                    Output::warning(&format!(
                        "    Region: {}",
                        bucket.region.as_deref().unwrap_or("unknown")
                    ));
                    Output::warning(&format!("    Access: {}", bucket.message));

                    if bucket.public_list {
                        Output::warning("    - Can LIST objects");
                    }
                    if bucket.public_read {
                        Output::warning("    - Can READ objects");
                    }
                }
            }

            println!();
            Output::warning("⚠️  SECURITY RISK: These buckets are publicly accessible!");
            Output::warning("   Recommended action: Review bucket policies and ACLs");
        }

        println!();
        Output::success("Scan complete!");
    }
}
