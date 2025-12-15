/// Wordlist management command
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::wordlists::{get_wordlist_sources, Downloader, WordlistCategory, WordlistManager};

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
                verb: "sources",
                summary: "List downloadable wordlist sources",
                usage: "rb wordlist collection sources [--category passwords|subdomains|dirs|usernames]",
            },
            Route {
                verb: "search",
                summary: "Search downloadable wordlists",
                usage: "rb wordlist collection search <query>",
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
                verb: "get",
                summary: "Download a wordlist (alias: install)",
                usage: "rb wordlist collection get <name>",
            },
            Route {
                verb: "install",
                summary: "Install wordlist collection or single wordlist",
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
            Flag::new(
                "category",
                "Filter by category (passwords, subdomains, dirs, usernames)",
            )
            .with_short('c'),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("List installed wordlists", "rb wordlist collection list"),
            (
                "List downloadable sources",
                "rb wordlist collection sources",
            ),
            (
                "List password wordlists",
                "rb wordlist collection sources --category passwords",
            ),
            ("Search for wordlists", "rb wordlist collection search rock"),
            ("Download rockyou.txt", "rb wordlist collection get rockyou"),
            (
                "Download common passwords",
                "rb wordlist collection get common-passwords",
            ),
            ("Check cache status", "rb wordlist collection status"),
            ("Initialize cache", "rb wordlist collection init"),
            (
                "Install SecLists (full)",
                "rb wordlist collection install seclists",
            ),
            ("Update SecLists", "rb wordlist collection update seclists"),
            ("Remove wordlist", "rb wordlist collection remove rockyou"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "list" => self.list(ctx),
            "sources" => self.sources(ctx),
            "search" => self.search(ctx),
            "info" => self.info(ctx),
            "status" => self.status(ctx),
            "init" => self.init(ctx),
            "get" => self.get(ctx),
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

    fn sources(&self, ctx: &CliContext) -> Result<(), String> {
        let sources = get_wordlist_sources();

        // Check for category filter
        let category_filter = ctx.get_flag("category");

        Output::header("Downloadable Wordlist Sources");

        let filtered: Vec<_> = if let Some(cat) = category_filter {
            let cat_enum = match cat.to_lowercase().as_str() {
                "passwords" | "password" | "pass" => Some(WordlistCategory::Passwords),
                "subdomains" | "subdomain" | "dns" => Some(WordlistCategory::Subdomains),
                "dirs" | "directories" | "dir" | "web" => Some(WordlistCategory::Directories),
                "usernames" | "username" | "users" | "user" => Some(WordlistCategory::Usernames),
                _ => None,
            };

            if let Some(c) = cat_enum {
                sources.into_iter().filter(|s| s.category == c).collect()
            } else {
                Output::warning(&format!("Unknown category: {}", cat));
                println!("Available: passwords, subdomains, dirs, usernames");
                return Ok(());
            }
        } else {
            sources
        };

        if filtered.is_empty() {
            Output::warning("No wordlists found for this category");
            return Ok(());
        }

        // Group by category
        let passwords: Vec<_> = filtered
            .iter()
            .filter(|s| s.category == WordlistCategory::Passwords)
            .collect();
        let subdomains: Vec<_> = filtered
            .iter()
            .filter(|s| s.category == WordlistCategory::Subdomains)
            .collect();
        let dirs: Vec<_> = filtered
            .iter()
            .filter(|s| s.category == WordlistCategory::Directories)
            .collect();
        let usernames: Vec<_> = filtered
            .iter()
            .filter(|s| s.category == WordlistCategory::Usernames)
            .collect();

        let print_section = |title: &str, items: &[&crate::wordlists::WordlistSource]| {
            if !items.is_empty() {
                Output::section(title);
                println!("  {:<20} {:<10} {}", "NAME", "SIZE", "DESCRIPTION");
                println!("  {}", "─".repeat(70));
                for s in items {
                    println!("  {:<20} {:<10} {}", s.name, s.size_hint, s.description);
                }
                println!();
            }
        };

        print_section("🔑 Passwords", &passwords);
        print_section("🌐 Subdomains", &subdomains);
        print_section("📁 Directories", &dirs);
        print_section("👤 Usernames", &usernames);

        println!("To download: rb wordlist collection get <name>");
        println!("Example:     rb wordlist collection get rockyou");

        Ok(())
    }

    fn search(&self, ctx: &CliContext) -> Result<(), String> {
        let query = ctx.target.as_ref().ok_or(
            "Missing search query.\nUsage: rb wordlist collection search <query>\nExample: rb wordlist collection search rock",
        )?;

        let manager = WordlistManager::new()?;
        let downloader = Downloader::new(manager.cache_dir().to_path_buf());
        let results = downloader.search_sources(query);

        Output::header(&format!("Search Results for '{}'", query));

        if results.is_empty() {
            Output::warning("No wordlists found matching your query");
            println!("\nTry: rb wordlist collection sources");
            return Ok(());
        }

        println!(
            "  {:<20} {:<12} {:<10} {}",
            "NAME", "CATEGORY", "SIZE", "DESCRIPTION"
        );
        println!("  {}", "─".repeat(75));

        for s in &results {
            let cat = match s.category {
                WordlistCategory::Passwords => "passwords",
                WordlistCategory::Subdomains => "subdomains",
                WordlistCategory::Directories => "dirs",
                WordlistCategory::Usernames => "usernames",
                WordlistCategory::Mixed => "mixed",
            };
            println!(
                "  {:<20} {:<12} {:<10} {}",
                s.name, cat, s.size_hint, s.description
            );
        }

        println!("\nFound {} result(s)", results.len());
        println!("To download: rb wordlist collection get <name>");

        Ok(())
    }

    fn get(&self, ctx: &CliContext) -> Result<(), String> {
        let name = ctx.target.as_ref().ok_or(
            "Missing wordlist name.\nUsage: rb wordlist collection get <name>\nExample: rb wordlist collection get rockyou",
        )?;

        let manager = WordlistManager::new()?;
        manager.init()?; // Ensure cache directory exists

        let downloader = Downloader::new(manager.cache_dir().to_path_buf());
        downloader.download_wordlist(name)
    }

    fn install(&self, ctx: &CliContext) -> Result<(), String> {
        let source = ctx.target.as_ref().ok_or(
            "Missing source.\nUsage: rb wordlist collection install <source>\nRun `rb wordlist collection sources` to see available wordlists",
        )?;

        let manager = WordlistManager::new()?;
        manager.init()?; // Ensure cache directory exists

        let downloader = Downloader::new(manager.cache_dir().to_path_buf());

        // First check for known collections
        match source.as_str() {
            "seclists" => return downloader.download_seclists(),
            "assetnote-dns" | "assetnote" => return downloader.download_assetnote_dns(),
            _ => {}
        }

        // Try to download from wordlist registry
        let sources = get_wordlist_sources();
        if sources.iter().any(|s| s.name == source.as_str()) {
            return downloader.download_wordlist(source);
        }

        // Not found
        Output::error(&format!("Unknown source: {}", source));
        println!("\nCollections:");
        println!("  • seclists      - Full SecLists collection (~1.2GB)");
        println!("  • assetnote-dns - Assetnote DNS wordlist (~15MB)");
        println!("\nIndividual wordlists:");
        println!("  Run `rb wordlist collection sources` to see available");
        Err(format!("Unknown source: {}", source))
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

pub struct WordlistFileCommand;

impl Command for WordlistFileCommand {
    fn domain(&self) -> &str {
        "wordlist"
    }

    fn resource(&self) -> &str {
        "file"
    }

    fn description(&self) -> &str {
        "Operations on local wordlist files"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "info",
                summary: "Show wordlist file statistics and preview",
                usage: "rb wordlist file info <path>",
            },
            Route {
                verb: "filter",
                summary: "Filter wordlist by pattern or length",
                usage: "rb wordlist file filter <path> --pattern <str> --min <n> --max <n>",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("pattern", "Filter by pattern (substring)").with_arg("str"),
            Flag::new("min", "Minimum length").with_arg("n"),
            Flag::new("max", "Maximum length").with_arg("n"),
            Flag::new("inverse", "Invert pattern match (grep -v)"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Show stats for a wordlist",
                "rb wordlist file info rockyou.txt",
            ),
            (
                "Filter words containing 'admin'",
                "rb wordlist file filter rockyou.txt --pattern admin",
            ),
            (
                "Filter passwords > 8 chars",
                "rb wordlist file filter rockyou.txt --min 8",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "info" => self.info(ctx),
            "filter" => self.filter(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Err("Invalid verb".to_string())
            }
        }
    }
}

impl WordlistFileCommand {
    fn info(&self, ctx: &CliContext) -> Result<(), String> {
        let path_str = ctx
            .target
            .as_ref()
            .ok_or("Missing wordlist path.\nUsage: rb wordlist file info <path>")?;
        let path = std::path::Path::new(path_str);

        if !path.exists() {
            return Err(format!("File not found: {}", path_str));
        }

        use crate::modules::wordlist::analysis::Analyzer;
        use crate::modules::wordlist::loader::Loader;
        use std::io::{BufRead, BufReader};

        Output::header(&format!("Wordlist Analysis: {}", path_str));

        let reader = Loader::open(path).map_err(|e| e.to_string())?;
        let buf_reader = BufReader::new(reader);

        // Load into memory for analysis?
        // Analyzer::analyze takes &[String].
        // For huge files this is bad.
        // But our Analyzer implementation handles &[String].
        // Ideally we should stream.
        // For now, let's load line by line and accumulate stats manually or collect if small enough?
        // Let's implement a streaming analysis in WordlistFileCommand for now,
        // or update Analyzer to accept iterator.

        // Simpler: Read lines and analyze.
        let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
        let lines = lines.map_err(|e| e.to_string())?;

        let stats = Analyzer::analyze(&lines);

        Output::item("Lines", &stats.line_count.to_string());
        Output::item("Unique", &stats.unique_count.to_string());
        Output::item("Avg Length", &format!("{:.1}", stats.avg_length));
        Output::item("Min Length", &stats.min_length.to_string());
        Output::item("Max Length", &stats.max_length.to_string());
        Output::item("Charset", &stats.charset);

        // Preview
        Output::section("Preview (first 10)");
        for line in lines.iter().take(10) {
            println!("  {}", line);
        }

        Ok(())
    }

    fn filter(&self, ctx: &CliContext) -> Result<(), String> {
        let path_str = ctx
            .target
            .as_ref()
            .ok_or("Missing wordlist path.\nUsage: rb wordlist file filter <path>")?;
        let path = std::path::Path::new(path_str);

        use crate::modules::wordlist::filter::Filter;
        use crate::modules::wordlist::loader::Loader;
        use std::io::{BufRead, BufReader};

        let reader = Loader::open(path).map_err(|e| e.to_string())?;
        let buf_reader = BufReader::new(reader);
        let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
        let mut words = lines.map_err(|e| e.to_string())?;

        // Apply length filter
        let min = ctx.get_flag("min").and_then(|s| s.parse().ok());
        let max = ctx.get_flag("max").and_then(|s| s.parse().ok());

        if min.is_some() || max.is_some() {
            words = Filter::by_length(words, min, max);
        }

        // Apply pattern filter
        if let Some(pattern) = ctx.get_flag("pattern") {
            let inverse = ctx.has_flag("inverse");
            words = Filter::by_pattern(words, &pattern, inverse);
        }

        for w in words {
            println!("{}", w);
        }

        Ok(())
    }
}
