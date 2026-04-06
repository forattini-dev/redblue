/// Wordlist management command
use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::json;
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
        usage:
          "rb wordlist collection sources [--category passwords|subdomains|dirs|usernames|vhosts]",
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
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
      Flag::new("embedded", "Show only embedded wordlists"),
      Flag::new("cached", "Show only cached wordlists"),
      Flag::new(
        "category",
        "Filter by category (passwords, subdomains, dirs, usernames, vhosts)",
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
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let manager = WordlistManager::new()?;
    let wordlists = manager.list();

    let show_embedded = ctx.has_flag("embedded");
    let show_cached = ctx.has_flag("cached");

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

    if is_json {
      let wordlists_json: Vec<crate::serde_json::Value> =
        filtered.iter().map(|w| wordlist_info_to_json(w)).collect();
      Output::json_value(&json!({
          "total": filtered.len(),
          "wordlists": wordlists_json
      }));
      return Ok(());
    }

    Output::header("Available Wordlists");

    if wordlists.is_empty() {
      Output::warning("No wordlists found");
      println!("\nRun `rb wordlist collection init` to initialize cache directory");
      return Ok(());
    }

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
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let name = ctx.target.as_ref().ok_or(
            "Missing wordlist name.\nUsage: rb wordlist collection info <name>\nExample: rb wordlist collection info subdomains-top100",
        )?;

    let manager = WordlistManager::new()?;

    // Try to get the wordlist
    match manager.get(name) {
      Ok(wordlist) => {
        let size_bytes: usize = wordlist.iter().map(|s| s.len()).sum();
        let size_kb = size_bytes / 1024;
        let source = if crate::wordlists::is_embedded(name) {
          "embedded"
        } else {
          "cached"
        };

        if is_json {
          let preview: Vec<String> = wordlist.iter().take(10).cloned().collect();
          Output::json_value(&json!({
              "name": name.clone(),
              "lines": wordlist.len(),
              "size_bytes": size_bytes,
              "size_kb": size_kb,
              "source": source,
              "preview": preview
          }));
          return Ok(());
        }

        Output::header(&format!("Wordlist: {}", name));

        Output::item("Name", name);
        Output::item("Lines", &wordlist.len().to_string());
        Output::item("Size", &format!("~{}KB", size_kb));

        let source_display = if source == "embedded" {
          "Embedded (built-in)"
        } else {
          "Cached or external file"
        };
        Output::item("Source", source_display);

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
        if is_json {
          Output::json_value(&json!({
              "success": false,
              "error": e.clone(),
              "name": name.clone()
          }));
        } else {
          Output::error(&format!("Failed to load wordlist: {}", e));
        }
        Err(e)
      }
    }
  }

  fn status(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let manager = WordlistManager::new()?;
    let cache_dir = manager.cache_dir();
    let dir_exists = cache_dir.exists();

    let cache_size = if dir_exists {
      self.calculate_dir_size(cache_dir).unwrap_or(0)
    } else {
      0
    };
    let size_mb = cache_size / 1024 / 1024;

    let wordlists = manager.list();
    let embedded_count = wordlists.iter().filter(|w| w.source == "embedded").count();
    let cached_count = wordlists.iter().filter(|w| w.source == "cached").count();

    if is_json {
      let counts_json = json!({
          "embedded": embedded_count,
          "cached": cached_count,
          "total": embedded_count + cached_count
      });
      Output::json_value(&json!({
          "cache_directory": cache_dir.display().to_string(),
          "directory_exists": dir_exists,
          "cache_size_bytes": cache_size,
          "cache_size_mb": size_mb,
          "counts": counts_json
      }));
      return Ok(());
    }

    Output::header("Wordlist Cache Status");

    Output::item("Cache Directory", &cache_dir.display().to_string());

    if dir_exists {
      Output::success("  ✓ Directory exists");
      Output::item("Cache Size", &format!("{}MB", size_mb));

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
      for entry in fs::read_dir(path).map_err(|e| format!("Failed to read directory: {}", e))? {
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
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let sources = get_wordlist_sources();

    // Check for category filter
    let category_filter = ctx.get_flag("category");

    let filtered: Vec<_> = if let Some(cat) = category_filter {
      let cat_enum = match cat.to_lowercase().as_str() {
        "passwords" | "password" | "pass" => Some(WordlistCategory::Passwords),
        "subdomains" | "subdomain" | "dns" => Some(WordlistCategory::Subdomains),
        "dirs" | "directories" | "dir" | "web" => Some(WordlistCategory::Directories),
        "usernames" | "username" | "users" | "user" => Some(WordlistCategory::Usernames),
        "vhosts" | "vhost" | "virtualhosts" => Some(WordlistCategory::Vhosts),
        _ => None,
      };

      if let Some(c) = cat_enum {
        sources.into_iter().filter(|s| s.category == c).collect()
      } else {
        if is_json {
          Output::json_value(&json!({
              "success": false,
              "error": "unknown_category",
              "category": cat.clone()
          }));
        } else {
          Output::warning(&format!("Unknown category: {}", cat));
          println!("Available: passwords, subdomains, dirs, usernames, vhosts");
        }
        return Ok(());
      }
    } else {
      sources
    };

    if is_json {
      let sources_json: Vec<crate::serde_json::Value> = filtered
        .iter()
        .map(|s| wordlist_source_to_json(s))
        .collect();
      Output::json_value(&json!({
          "total": filtered.len(),
          "sources": sources_json
      }));
      return Ok(());
    }

    Output::header("Downloadable Wordlist Sources");

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
    let vhosts: Vec<_> = filtered
      .iter()
      .filter(|s| s.category == WordlistCategory::Vhosts)
      .collect();

    let print_section = |title: &str, items: &[&crate::wordlists::WordlistSource]| {
      if !items.is_empty() {
        Output::section(title);
        println!("  {:<20} {:<10} DESCRIPTION", "NAME", "SIZE");
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
    print_section("🖥️ Virtual Hosts", &vhosts);

    println!("To download: rb wordlist collection get <name>");
    println!("Example:     rb wordlist collection get rockyou");

    Ok(())
  }

  fn search(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let query = ctx.target.as_ref().ok_or(
            "Missing search query.\nUsage: rb wordlist collection search <query>\nExample: rb wordlist collection search rock",
        )?;

    let manager = WordlistManager::new()?;
    let downloader = Downloader::new(manager.cache_dir().to_path_buf());
    let results = downloader.search_sources(query);

    if is_json {
      let results_json: Vec<crate::serde_json::Value> =
        results.iter().map(|s| wordlist_source_to_json(s)).collect();
      Output::json_value(&json!({
          "query": query.clone(),
          "total": results.len(),
          "results": results_json
      }));
      return Ok(());
    }

    Output::header(&format!("Search Results for '{}'", query));

    if results.is_empty() {
      Output::warning("No wordlists found matching your query");
      println!("\nTry: rb wordlist collection sources");
      return Ok(());
    }

    println!(
      "  {:<20} {:<12} {:<10} DESCRIPTION",
      "NAME", "CATEGORY", "SIZE"
    );
    println!("  {}", "─".repeat(75));

    for s in &results {
      let cat = match s.category {
        WordlistCategory::Passwords => "passwords",
        WordlistCategory::Subdomains => "subdomains",
        WordlistCategory::Directories => "dirs",
        WordlistCategory::Usernames => "usernames",
        WordlistCategory::Vhosts => "vhosts",
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
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
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
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let path_str = ctx
      .target
      .as_ref()
      .ok_or("Missing wordlist path.\nUsage: rb wordlist file info <path>")?;
    let path = std::path::Path::new(path_str);

    if !path.exists() {
      if is_json {
        Output::json_value(&json!({
            "success": false,
            "error": "File not found",
            "path": path_str.clone()
        }));
      }
      return Err(format!("File not found: {}", path_str));
    }

    use crate::modules::wordlist::analysis::Analyzer;
    use crate::modules::wordlist::loader::Loader;
    use std::io::{BufRead, BufReader};

    let reader = Loader::open(path).map_err(|e| e.to_string())?;
    let buf_reader = BufReader::new(reader);

    let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
    let lines = lines.map_err(|e| e.to_string())?;

    let stats = Analyzer::analyze(&lines);

    if is_json {
      let preview: Vec<String> = lines.iter().take(10).cloned().collect();
      Output::json_value(&json!({
          "path": path_str.clone(),
          "line_count": stats.line_count,
          "unique_count": stats.unique_count,
          "avg_length": stats.avg_length,
          "min_length": stats.min_length,
          "max_length": stats.max_length,
          "charset": stats.charset.clone(),
          "preview": preview
      }));
      return Ok(());
    }

    Output::header(&format!("Wordlist Analysis: {}", path_str));

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

/// Intelligent wordlist operations (context resolution, mutation, learning)
pub struct WordlistIntelCommand;

impl Command for WordlistIntelCommand {
  fn domain(&self) -> &str {
    "wordlist"
  }

  fn resource(&self) -> &str {
    "intel"
  }

  fn description(&self) -> &str {
    "Intelligent wordlist operations: context-aware resolution, mutation, and TF-IDF learning"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "resolve",
        summary: "Resolve context-aware wordlist for a scanning context",
        usage: "rb wordlist intel resolve <context> [--size small|medium|large]",
      },
      Route {
        verb: "mutate",
        summary: "Apply mutation rules to wordlist",
        usage: "rb wordlist intel mutate <file> --rules <rule1,rule2>",
      },
      Route {
        verb: "learn",
        summary: "Show learned words from previous scans",
        usage: "rb wordlist intel learn --from-scan <scan_id>",
      },
      Route {
        verb: "extract",
        summary: "Extract words from HTML/JS content using TF-IDF",
        usage: "rb wordlist intel extract <file_or_url>",
      },
      Route {
        verb: "checkpoints",
        summary: "List available scan checkpoints for resume",
        usage: "rb wordlist intel checkpoints",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json)")
        .with_short('o')
        .with_default("text"),
      Flag::new("size", "Wordlist size: small, medium, large, or auto")
        .with_short('s')
        .with_default("auto"),
      Flag::new(
        "rules",
        "Mutation rules: leet, case, suffix, prefix, append-numbers",
      )
      .with_short('r'),
      Flag::new("from-scan", "Learn from scan ID"),
      Flag::new("domain", "Filter learned words by domain"),
      Flag::new("top", "Show top N words")
        .with_short('n')
        .with_default("100"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "Resolve directory wordlist",
        "rb wordlist intel resolve directories --size medium",
      ),
      (
        "Resolve subdomain wordlist",
        "rb wordlist intel resolve subdomains --size large",
      ),
      (
        "Apply leet mutations",
        "rb wordlist intel mutate passwords.txt --rules leet,case",
      ),
      (
        "Extract words from HTML",
        "rb wordlist intel extract response.html --top 50",
      ),
      ("List scan checkpoints", "rb wordlist intel checkpoints"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "resolve" => self.resolve(ctx),
      "mutate" => self.mutate(ctx),
      "learn" => self.learn(ctx),
      "extract" => self.extract(ctx),
      "checkpoints" => self.checkpoints(ctx),
      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        Err("Invalid verb".to_string())
      }
    }
  }
}

impl WordlistIntelCommand {
  fn resolve(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let context_str = ctx.target.as_ref().ok_or(
            "Missing context.\nUsage: rb wordlist intel resolve <context>\n\nContexts: directories, files, subdomains, parameters, passwords, usernames",
        )?;

    use crate::modules::wordlist::{ContextResolver, WordlistContext, WordlistSize};

    let context = match context_str.to_lowercase().as_str() {
      "directories" | "dirs" | "dir" => WordlistContext::Directories,
      "files" | "file" => WordlistContext::Files,
      "subdomains" | "subdomain" | "sub" => WordlistContext::Subdomains,
      "parameters" | "params" | "param" => WordlistContext::Parameters,
      "passwords" | "password" | "pass" => WordlistContext::Passwords,
      "usernames" | "username" | "user" => WordlistContext::Usernames,
      other => WordlistContext::Custom(other.to_string()),
    };

    let size_str = ctx.get_flag("size").unwrap_or_else(|| "auto".to_string());
    let size = match size_str.to_lowercase().as_str() {
      "small" | "s" => WordlistSize::Small,
      "medium" | "m" => WordlistSize::Medium,
      "large" | "l" => WordlistSize::Large,
      _ => {
        // Auto-detect based on context (use default target for size suggestion)
        ContextResolver::suggest_size("", None)
      }
    };

    let recommendations = ContextResolver::recommended_wordlists(&context);

    if is_json {
      let wordlists: Vec<String> = recommendations
        .iter()
        .map(|name| (*name).to_string())
        .collect();
      Output::json_value(&json!({
          "context": format!("{:?}", context),
          "size": format!("{:?}", size),
          "wordlists": wordlists
      }));
      return Ok(());
    }

    Output::header(&format!("Wordlist Resolution: {:?}", context));
    Output::item("Context", &format!("{:?}", context));
    Output::item("Size", &format!("{:?}", size));

    Output::section("Recommended Wordlists");
    for name in &recommendations {
      println!("  • {}", name);
    }

    // Show extensions for this context
    let extensions = ContextResolver::context_extensions(&context);
    if !extensions.is_empty() {
      Output::section("Common Extensions");
      println!("  {}", extensions.join(", "));
    }

    Ok(())
  }

  fn mutate(&self, ctx: &CliContext) -> Result<(), String> {
    let path_str = ctx
      .target
      .as_ref()
      .ok_or("Missing wordlist path.\nUsage: rb wordlist intel mutate <file> --rules <rules>")?;

    let rules_str = ctx.get_flag("rules").ok_or(
            "Missing rules.\nUsage: rb wordlist intel mutate <file> --rules leet,case\n\nRules: leet, case, suffix, prefix, append-numbers",
        )?;

    use crate::modules::wordlist::loader::Loader;
    use crate::modules::wordlist::mutations::Mutator;
    use std::io::{BufRead, BufReader};

    let path = std::path::Path::new(path_str);
    let reader = Loader::open(path).map_err(|e| e.to_string())?;
    let buf_reader = BufReader::new(reader);
    let lines: Result<Vec<String>, _> = buf_reader.lines().collect();
    let words = lines.map_err(|e| e.to_string())?;

    // Parse rules
    let rules: Vec<&str> = rules_str.split(',').map(|s| s.trim()).collect();

    let mut mutated: std::collections::HashSet<String> = std::collections::HashSet::new();

    for word in &words {
      // Always include original
      mutated.insert(word.clone());

      for rule in &rules {
        let mutations: Vec<String> = match *rule {
          "leet" | "l33t" => vec![Mutator::l33t(word)],
          "case" => Mutator::common_mutations(word),
          "suffix" => {
            let suffixes = ["123", "1", "!", "@", "2024", "2025"];
            suffixes.iter().map(|s| format!("{}{}", word, s)).collect()
          }
          "prefix" => {
            let prefixes = ["the", "my", "admin", "root", "test"];
            prefixes.iter().map(|p| format!("{}{}", p, word)).collect()
          }
          "append-numbers" | "numbers" => Mutator::append_numbers(word, 99),
          _ => vec![],
        };
        mutated.extend(mutations);
      }
    }

    for word in mutated {
      println!("{}", word);
    }

    Ok(())
  }

  fn learn(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let top_n: usize = ctx
      .get_flag("top")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    // Note: This is a placeholder - actual learned words would come from storage
    Output::warning("TF-IDF learning integration requires active scan data");
    Output::info("Learned words are captured during scans with --learn-words flag");

    if is_json {
      Output::json_value(&json!({
          "learned_words": [],
          "total": 0,
          "note": "No learned words available. Run a scan with --learn-words to collect vocabulary."
      }));
    } else {
      Output::header("Learned Words");
      println!("\n  No learned words found in storage.");
      println!("\n  To learn words during a scan:");
      println!("    rb web fuzz http://target/FUZZ --learn-words");
      println!("\n  To view learned words after a scan:");
      println!(
        "    rb wordlist intel learn --from-scan <scan_id> --top {}",
        top_n
      );
    }

    Ok(())
  }

  fn extract(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    let path_str = ctx.target.as_ref().ok_or(
            "Missing file path.\nUsage: rb wordlist intel extract <file>\nExample: rb wordlist intel extract response.html",
        )?;

    let top_n: usize = ctx
      .get_flag("top")
      .and_then(|s| s.parse().ok())
      .unwrap_or(100);

    // Read file
    let content =
      std::fs::read_to_string(path_str).map_err(|e| format!("Failed to read file: {}", e))?;

    use crate::modules::wordlist::{Document, TfIdfEngine, WordExtractor};

    // Extract words
    let extractor = WordExtractor::with_defaults();
    let result = extractor.extract(&content);

    if result.is_empty() {
      if is_json {
        Output::json_value(&json!({
            "words": [],
            "total": 0
        }));
      } else {
        Output::warning("No words extracted from content");
      }
      return Ok(());
    }

    // Calculate TF-IDF scores
    let mut engine = TfIdfEngine::with_defaults();
    engine.add_document(Document::new(path_str, result.all_words.clone()));
    let scores = engine.top_words(top_n);

    if is_json {
      let words_json: Vec<crate::serde_json::Value> = scores
        .iter()
        .map(|word| {
          json!({
              "word": word.word.clone(),
              "score": word.tfidf
          })
        })
        .collect();
      Output::json_value(&json!({
          "source": path_str.clone(),
          "total_extracted": result.all_words.len(),
          "words": words_json
      }));
      return Ok(());
    }

    Output::header(&format!("Word Extraction: {}", path_str));
    Output::item("Total Extracted", &result.all_words.len().to_string());
    Output::item("Text Words", &result.text_words.len().to_string());
    Output::item("Path Words", &result.path_words.len().to_string());
    Output::item("Form Fields", &result.form_fields.len().to_string());
    Output::item("JS Identifiers", &result.js_identifiers.len().to_string());

    Output::section(&format!(
      "Top {} Words (TF-IDF Scored)",
      top_n.min(scores.len())
    ));
    println!("{:<30} {:>10}", "WORD", "SCORE");
    println!("{}", "━".repeat(45));

    for word in scores.iter().take(top_n) {
      println!("{:<30} {:>10.4}", word.word, word.tfidf);
    }

    Ok(())
  }

  fn checkpoints(&self, ctx: &CliContext) -> Result<(), String> {
    let format = ctx.get_output_format();
    let is_json = format == crate::cli::format::OutputFormat::Json;

    use crate::modules::web::fuzzer::ResumeManager;

    let manager = ResumeManager::with_defaults();
    let checkpoints = manager.list_checkpoints();

    if is_json {
      let checkpoints_json: Vec<crate::serde_json::Value> = checkpoints
        .iter()
        .map(|cp| checkpoint_info_to_json(cp))
        .collect();
      Output::json_value(&json!({
          "checkpoints": checkpoints_json
      }));
      return Ok(());
    }

    Output::header("Scan Checkpoints");

    if checkpoints.is_empty() {
      Output::info("No checkpoints found");
      println!("\n  Checkpoints are created during scans with --checkpoint flag:");
      println!("    rb web fuzz http://target/FUZZ --checkpoint");
      println!("\n  To resume a scan:");
      println!("    rb web fuzz --resume <scan_id>");
      return Ok(());
    }

    println!(
      "{:<20} {:<40} {:>8} {:>10}",
      "SCAN ID", "TARGET", "PROGRESS", "ELAPSED"
    );
    println!("{}", "━".repeat(85));

    for cp in &checkpoints {
      let target_display = if cp.target_url.len() > 38 {
        format!("{}...", &cp.target_url[..35])
      } else {
        cp.target_url.clone()
      };

      println!(
        "{:<20} {:<40} {:>7.1}% {:>10}",
        &cp.scan_id.as_str()[..16.min(cp.scan_id.as_str().len())],
        target_display,
        cp.progress_percent,
        cp.elapsed_string()
      );
    }

    println!("\n  Total: {} checkpoint(s)", checkpoints.len());
    println!("\n  To resume a scan: rb web fuzz --resume <scan_id>");

    Ok(())
  }
}

fn wordlist_category_name(category: WordlistCategory) -> &'static str {
  match category {
    WordlistCategory::Passwords => "passwords",
    WordlistCategory::Subdomains => "subdomains",
    WordlistCategory::Directories => "directories",
    WordlistCategory::Usernames => "usernames",
    WordlistCategory::Vhosts => "vhosts",
    WordlistCategory::Mixed => "mixed",
  }
}

fn wordlist_info_to_json(
  info: &crate::wordlists::manager::WordlistInfo,
) -> crate::serde_json::Value {
  json!({
      "name": info.name.clone(),
      "source": info.source.clone(),
      "line_count": info.line_count,
      "size_kb": info.size_kb
  })
}

fn wordlist_source_to_json(
  source: &crate::wordlists::downloader::WordlistSource,
) -> crate::serde_json::Value {
  json!({
      "name": source.name,
      "category": wordlist_category_name(source.category),
      "size_hint": source.size_hint,
      "description": source.description
  })
}

fn checkpoint_info_to_json(
  checkpoint: &crate::modules::web::fuzzer::resume::CheckpointInfo,
) -> crate::serde_json::Value {
  json!({
      "scan_id": checkpoint.scan_id.to_string(),
      "target": checkpoint.target_url.clone(),
      "progress": checkpoint.progress_percent,
      "requests": checkpoint.requests_made,
      "elapsed": checkpoint.elapsed_string()
  })
}
