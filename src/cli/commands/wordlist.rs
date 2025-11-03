/// Wordlist management command
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::wordlists::{Downloader, WordlistManager};

pub struct WordlistCommand;

impl Command for WordlistCommand {
    fn domain(&self) -> &str {
        "wordlist"
    }

    fn resource(&self) -> &str {
        "collection"
    }

    fn description(&self) -> &str {
        "Manage wordlist collections for fuzzing and enumeration"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "list",
                summary: "List available wordlists (embedded + cached)",
                usage: "rb wordlist collection list [--embedded] [--cached]",
            },
            Route {
                verb: "info",
                summary: "Show wordlist details",
                usage: "rb wordlist collection info <name>",
            },
            Route {
                verb: "status",
                summary: "Show cache status and directory info",
                usage: "rb wordlist collection status",
            },
            Route {
                verb: "init",
                summary: "Initialize .redblue wordlist directory",
                usage: "rb wordlist collection init",
            },
            Route {
                verb: "install",
                summary: "Install wordlist collection",
                usage: "rb wordlist collection install <source>",
            },
            Route {
                verb: "update",
                summary: "Update installed wordlist collection",
                usage: "rb wordlist collection update <source>",
            },
            Route {
                verb: "remove",
                summary: "Remove cached wordlist collection",
                usage: "rb wordlist collection remove <source>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("embedded", "Show only embedded wordlists"),
            Flag::new("cached", "Show only cached wordlists"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("List all wordlists", "rb wordlist collection list"),
            (
                "List embedded only",
                "rb wordlist collection list --embedded",
            ),
            (
                "Show wordlist info",
                "rb wordlist collection info subdomains-top100",
            ),
            ("Check cache status", "rb wordlist collection status"),
            ("Initialize cache", "rb wordlist collection init"),
            (
                "Install SecLists",
                "rb wordlist collection install seclists",
            ),
            (
                "Install Assetnote DNS",
                "rb wordlist collection install assetnote-dns",
            ),
            ("Update SecLists", "rb wordlist collection update seclists"),
            (
                "Remove collection",
                "rb wordlist collection remove seclists",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "list" => self.list(ctx),
            "info" => self.info(ctx),
            "status" => self.status(ctx),
            "init" => self.init(ctx),
            "install" => self.install(ctx),
            "update" => self.update(ctx),
            "remove" => self.remove(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl WordlistCommand {
    fn list(&self, ctx: &CliContext) -> Result<(), String> {
        let manager = WordlistManager::new()?;
        let wordlists = manager.list();

        let show_embedded = ctx.has_flag("embedded");
        let show_cached = ctx.has_flag("cached");

        Output::header("Available Wordlists");

        if wordlists.is_empty() {
            Output::warning("No wordlists found");
            println!("\nRun `rb wordlist collection init` to initialize cache directory");
            return Ok(());
        }

        // Filter by flags
        let filtered: Vec<_> = wordlists
            .iter()
            .filter(|w| {
                if show_embedded && show_cached {
                    true
                } else if show_embedded {
                    w.source == "embedded"
                } else if show_cached {
                    w.source == "cached"
                } else {
                    true
                }
            })
            .collect();

        if filtered.is_empty() {
            Output::warning("No wordlists match the filter");
            return Ok(());
        }

        // Group by source
        let mut embedded_lists = Vec::new();
        let mut project_lists = Vec::new();
        let mut cached_lists = Vec::new();

        for wordlist in &filtered {
            match wordlist.source.as_str() {
                "embedded" => embedded_lists.push(wordlist),
                "project" => project_lists.push(wordlist),
                "cached" => cached_lists.push(wordlist),
                _ => {}
            }
        }

        // Display embedded wordlists
        if !embedded_lists.is_empty() && (!show_cached || show_embedded) {
            Output::section("Embedded Wordlists (Built-in)");
            println!("{:<30} {:>10}", "NAME", "LINES");
            println!("{}", "━".repeat(45));

            for wordlist in embedded_lists {
                println!("{:<30} {:>10}", wordlist.name, wordlist.line_count);
            }
            println!();
        }

        // Display project wordlists
        if !project_lists.is_empty() {
            Output::section("Project Wordlists (Shipped with redblue)");
            println!("{:<40} {:>10} {:>10}", "NAME", "LINES", "SIZE");
            println!("{}", "━".repeat(65));

            for wordlist in project_lists {
                let size_str = if wordlist.size_kb < 1024 {
                    format!("{}KB", wordlist.size_kb)
                } else {
                    format!("{:.1}MB", wordlist.size_kb as f64 / 1024.0)
                };
                println!(
                    "{:<40} {:>10} {:>10}",
                    wordlist.name, wordlist.line_count, size_str
                );
            }
            println!();
        }

        // Display cached wordlists
        if !cached_lists.is_empty() && (!show_embedded || show_cached) {
            Output::section("Cached Wordlists (.redblue/wordlists/)");
            println!("{:<30} {:>10} {:>10}", "NAME", "LINES", "SIZE");
            println!("{}", "━".repeat(55));

            for wordlist in cached_lists {
                let size_str = if wordlist.size_kb < 1024 {
                    format!("{}KB", wordlist.size_kb)
                } else {
                    format!("{:.1}MB", wordlist.size_kb as f64 / 1024.0)
                };
                println!(
                    "{:<30} {:>10} {:>10}",
                    wordlist.name, wordlist.line_count, size_str
                );
            }
            println!();
        }

        println!("  Total: {} wordlist(s)", filtered.len());

        Ok(())
    }

    fn info(&self, ctx: &CliContext) -> Result<(), String> {
        let name = ctx.target.as_ref().ok_or(
            "Missing wordlist name.\nUsage: rb wordlist collection info <name>\nExample: rb wordlist collection info subdomains-top100",
        )?;

        let manager = WordlistManager::new()?;

        // Try to get the wordlist
        match manager.get(name) {
            Ok(wordlist) => {
                Output::header(&format!("Wordlist: {}", name));

                Output::item("Name", name);
                Output::item("Lines", &wordlist.len().to_string());

                let size_bytes = wordlist.iter().map(|s| s.len()).sum::<usize>();
                let size_kb = size_bytes / 1024;
                Output::item("Size", &format!("~{}KB", size_kb));

                // Determine source
                let source = if crate::wordlists::is_embedded(name) {
                    "Embedded (built-in)"
                } else {
                    "Cached or external file"
                };
                Output::item("Source", source);

                // Show first 10 entries as preview
                Output::section("Preview (first 10 entries)");
                for (i, entry) in wordlist.iter().take(10).enumerate() {
                    println!("  {}. {}", i + 1, entry);
                }

                if wordlist.len() > 10 {
                    Output::dim(&format!("  ... and {} more", wordlist.len() - 10));
                }

                Ok(())
            }
            Err(e) => {
                Output::error(&format!("Failed to load wordlist: {}", e));
                Err(e)
            }
        }
    }

    fn status(&self, ctx: &CliContext) -> Result<(), String> {
        let manager = WordlistManager::new()?;

        Output::header("Wordlist Cache Status");

        let cache_dir = manager.cache_dir();
        Output::item("Cache Directory", &cache_dir.display().to_string());

        if cache_dir.exists() {
            Output::success("  ✓ Directory exists");

            // Calculate cache size
            let cache_size = self.calculate_dir_size(cache_dir)?;
            let size_mb = cache_size / 1024 / 1024;
            Output::item("Cache Size", &format!("{}MB", size_mb));

            // Count wordlists
            let wordlists = manager.list();
            let embedded_count = wordlists.iter().filter(|w| w.source == "embedded").count();
            let cached_count = wordlists.iter().filter(|w| w.source == "cached").count();

            Output::section("Wordlist Count");
            println!("  Embedded: {}", embedded_count);
            println!("  Cached:   {}", cached_count);
            println!("  Total:    {}", embedded_count + cached_count);
        } else {
            Output::warning("  ✗ Directory does not exist");
            println!("\nRun `rb wordlist collection init` to initialize");
        }

        Ok(())
    }

    fn init(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::header("Initializing Wordlist Cache");

        let manager = WordlistManager::new()?;
        manager.init()?;

        Output::success("✓ Cache directory initialized");
        Output::dim(&format!("  Location: {}", manager.cache_dir().display()));

        Output::section("Directory Structure");
        println!("  .redblue/");
        println!("  └── wordlists/");
        println!("      ├── seclists/     (for SecLists collection)");
        println!("      ├── assetnote/    (for Assetnote wordlists)");
        println!("      └── custom/       (for custom wordlists)");

        Ok(())
    }

    fn calculate_dir_size(&self, path: &std::path::Path) -> Result<u64, String> {
        use std::fs;

        let mut total_size = 0u64;

        if path.is_dir() {
            for entry in
                fs::read_dir(path).map_err(|e| format!("Failed to read directory: {}", e))?
            {
                let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
                let metadata = entry
                    .metadata()
                    .map_err(|e| format!("Failed to read metadata: {}", e))?;

                if metadata.is_file() {
                    total_size += metadata.len();
                } else if metadata.is_dir() {
                    total_size += self.calculate_dir_size(&entry.path())?;
                }
            }
        }

        Ok(total_size)
    }

    fn install(&self, ctx: &CliContext) -> Result<(), String> {
        let source = ctx.target.as_ref().ok_or(
            "Missing source.\nUsage: rb wordlist collection install <source>\nAvailable: seclists, assetnote-dns",
        )?;

        let manager = WordlistManager::new()?;
        manager.init()?; // Ensure cache directory exists

        let downloader = Downloader::new(manager.cache_dir().to_path_buf());

        match source.as_str() {
            "seclists" => downloader.download_seclists(),
            "assetnote-dns" | "assetnote" => downloader.download_assetnote_dns(),
            _ => {
                Output::error(&format!("Unknown source: {}", source));
                println!("\nAvailable sources:");
                println!("  • seclists      - SecLists collection (~1.2GB)");
                println!("  • assetnote-dns - Assetnote DNS wordlist (~15MB)");
                Err(format!("Unknown source: {}", source))
            }
        }
    }

    fn update(&self, ctx: &CliContext) -> Result<(), String> {
        let source = ctx.target.as_ref().ok_or(
            "Missing source.\nUsage: rb wordlist collection update <source>\nExample: rb wordlist collection update seclists",
        )?;

        let manager = WordlistManager::new()?;
        let downloader = Downloader::new(manager.cache_dir().to_path_buf());

        match source.as_str() {
            "seclists" => downloader.update_seclists(),
            _ => {
                Output::error(&format!(
                    "Cannot update '{}' - only git-based collections support updates",
                    source
                ));
                println!("\nUpdatable sources:");
                println!("  • seclists - SecLists collection (git)");
                Err(format!("Source '{}' does not support updates", source))
            }
        }
    }

    fn remove(&self, ctx: &CliContext) -> Result<(), String> {
        let source = ctx.target.as_ref().ok_or(
            "Missing source.\nUsage: rb wordlist collection remove <source>\nExample: rb wordlist collection remove seclists",
        )?;

        let manager = WordlistManager::new()?;
        let downloader = Downloader::new(manager.cache_dir().to_path_buf());

        downloader.remove(source)
    }
}
