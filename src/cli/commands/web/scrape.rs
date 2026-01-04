//! Web scraping and DOM extraction operations

use crate::cli::output::Output;
use crate::cli::validator::Validator;
use crate::cli::CliContext;
use crate::modules::web::crawler::WebCrawler;
use crate::modules::web::dom::Document;
use crate::modules::web::extractors;
use crate::modules::web::linkfinder::{EndpointType, LinkFinder};
use crate::protocols::http::HttpClient;

use super::types::{escape_json, extract_host};

/// Crawl website discovering pages, links, forms, assets
pub fn crawl(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset crawl <URL> [--depth N] [--max-pages N] Example: rb web asset crawl http://example.com",
    )?;

    Validator::validate_url(url)?;

    Output::header("Web Crawler - Site Mapping");
    Output::item("Target", url);

    // Parse options
    let max_depth = ctx
        .get_flag("depth")
        .or_else(|| ctx.get_flag("d"))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3);

    let max_pages = ctx
        .get_flag("max-pages")
        .or_else(|| ctx.get_flag("m"))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);

    let same_origin = !ctx.has_flag("external");

    Output::item("Max Depth", &max_depth.to_string());
    Output::item("Max Pages", &max_pages.to_string());
    Output::item("Same Origin", if same_origin { "Yes" } else { "No" });
    println!();

    Output::spinner_start("Crawling website");

    // Create crawler
    let mut crawler = WebCrawler::new()
        .with_max_depth(max_depth)
        .with_max_pages(max_pages)
        .with_same_origin(same_origin);

    // Crawl
    let result = crawler.crawl(url)?;

    Output::spinner_done();

    // Display results
    Output::success(&format!(
        "Crawled {} pages (depth: {})",
        result.total_urls, result.max_depth_reached
    ));
    println!();

    // Group pages by depth
    let mut by_depth: std::collections::HashMap<usize, Vec<&str>> =
        std::collections::HashMap::new();

    for page in &result.pages {
        by_depth
            .entry(page.depth)
            .or_insert_with(Vec::new)
            .push(&page.url);
    }

    // Display pages by depth
    for depth in 0..=result.max_depth_reached {
        if let Some(urls) = by_depth.get(&depth) {
            println!(
                "\x1b[1m\x1b[36m● Depth {}\x1b[0m ({} pages)",
                depth,
                urls.len()
            );

            // Show first 5 URLs per depth
            for (i, url) in urls.iter().take(5).enumerate() {
                println!("  {}. {}", i + 1, url);
            }

            if urls.len() > 5 {
                println!("  \x1b[90m... and {} more\x1b[0m", urls.len() - 5);
            }

            println!();
        }
    }

    // Display forms found
    let total_forms: usize = result.pages.iter().map(|p| p.forms.len()).sum();
    if total_forms > 0 {
        println!(
            "\x1b[1m\x1b[33m● Forms Found\x1b[0m ({} total)",
            total_forms
        );

        let mut form_count = 0;
        for page in &result.pages {
            for form in &page.forms {
                if form_count >= 5 {
                    break;
                }
                println!(
                    "  {} {} (inputs: {:?})",
                    form.method, form.action, form.inputs
                );
                form_count += 1;
            }
            if form_count >= 5 {
                break;
            }
        }

        if total_forms > 5 {
            println!("  \x1b[90m... and {} more\x1b[0m", total_forms - 5);
        }

        println!();
    }

    // Display assets summary
    let total_js: usize = result
        .pages
        .iter()
        .map(|p| {
            p.assets
                .iter()
                .filter(|a| a.asset_type == crate::modules::web::crawler::AssetType::JavaScript)
                .count()
        })
        .sum();

    let total_css: usize = result
        .pages
        .iter()
        .map(|p| {
            p.assets
                .iter()
                .filter(|a| a.asset_type == crate::modules::web::crawler::AssetType::CSS)
                .count()
        })
        .sum();

    let total_images: usize = result
        .pages
        .iter()
        .map(|p| {
            p.assets
                .iter()
                .filter(|a| a.asset_type == crate::modules::web::crawler::AssetType::Image)
                .count()
        })
        .sum();

    if total_js + total_css + total_images > 0 {
        println!("\x1b[1m\x1b[35m● Assets Discovered\x1b[0m");
        println!("  JavaScript: {}", total_js);
        println!("  CSS: {}", total_css);
        println!("  Images: {}", total_images);
        println!();
    }

    // Statistics
    println!("\x1b[1mStatistics:\x1b[0m");
    println!("  Pages crawled: {}", result.total_urls);
    println!("  Total links found: {}", result.total_links);
    println!("  Max depth reached: {}", result.max_depth_reached);
    println!("  Forms discovered: {}", total_forms);
    println!("  Assets found: {}", total_js + total_css + total_images);

    Ok(())
}

/// Extract endpoints from JavaScript files
pub fn linkfinder(ctx: &CliContext) -> Result<(), String> {
    let js_url = ctx.target.as_ref().ok_or(
        "Missing JavaScript URL. Usage: rb web asset linkfinder <js-url> [--type api|s3|websocket|graphql|all] Example: rb web asset linkfinder https://example.com/app.js",
    )?;

    Validator::validate_url(js_url)?;

    Output::header("LinkFinder - JS Endpoint Extractor");
    Output::item("Target", js_url);

    let filter_type = ctx.get_flag("type").or_else(|| ctx.get_flag("t"));
    if let Some(ref t) = filter_type {
        Output::item("Filter Type", t);
    }
    println!();

    Output::spinner_start("Extracting endpoints from JavaScript");

    let finder = LinkFinder::new();
    let endpoints = finder.extract_from_url(js_url)?;

    Output::spinner_done();

    if endpoints.is_empty() {
        Output::warning("No endpoints found in JavaScript file");
        return Ok(());
    }

    // Apply type filter if specified
    let filtered_endpoints = if let Some(ref type_filter) = filter_type {
        match type_filter.to_lowercase().as_str() {
            "api" => LinkFinder::filter_by_type(endpoints, EndpointType::ApiEndpoint),
            "s3" => LinkFinder::filter_by_type(endpoints, EndpointType::S3Bucket),
            "websocket" | "ws" => LinkFinder::filter_by_type(endpoints, EndpointType::WebSocket),
            "graphql" | "gql" => LinkFinder::filter_by_type(endpoints, EndpointType::GraphQL),
            "cloud" => LinkFinder::filter_by_type(endpoints, EndpointType::CloudStorage),
            "relative" => LinkFinder::filter_by_type(endpoints, EndpointType::RelativePath),
            "absolute" | "url" => LinkFinder::filter_by_type(endpoints, EndpointType::AbsoluteUrl),
            "all" => endpoints,
            _ => {
                return Err(format!(
                    "Invalid type '{}'. Valid types: api, s3, websocket, graphql, cloud, relative, absolute, all",
                    type_filter
                ));
            }
        }
    } else {
        endpoints
    };

    if filtered_endpoints.is_empty() {
        let filter_str = filter_type.as_deref().unwrap_or("all");
        Output::warning(&format!(
            "No endpoints found matching filter '{}'",
            filter_str
        ));
        return Ok(());
    }

    // Group by endpoint type
    let mut by_type: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for endpoint in &filtered_endpoints {
        let type_name = match endpoint.endpoint_type {
            EndpointType::RelativePath => "Relative Paths",
            EndpointType::AbsoluteUrl => "Absolute URLs",
            EndpointType::ApiEndpoint => "API Endpoints",
            EndpointType::S3Bucket => "S3 Buckets",
            EndpointType::CloudStorage => "Cloud Storage",
            EndpointType::WebSocket => "WebSockets",
            EndpointType::GraphQL => "GraphQL",
        };
        by_type
            .entry(type_name.to_string())
            .or_insert_with(Vec::new)
            .push(endpoint.url.clone());
    }

    // Display results grouped by type
    Output::success(&format!("Found {} endpoints", filtered_endpoints.len()));
    println!();

    for (type_name, urls) in by_type.iter() {
        // Color based on type
        let color = match type_name.as_str() {
            "API Endpoints" => "\x1b[36m",  // Cyan
            "S3 Buckets" => "\x1b[33m",     // Yellow
            "Cloud Storage" => "\x1b[33m",  // Yellow
            "WebSockets" => "\x1b[35m",     // Magenta
            "GraphQL" => "\x1b[36m",        // Cyan
            "Relative Paths" => "\x1b[32m", // Green
            "Absolute URLs" => "\x1b[34m",  // Blue
            _ => "\x1b[0m",                 // Default
        };

        println!("{}● {}\x1b[0m ({} found)", color, type_name, urls.len());

        // Show first 10 URLs per type
        for (i, url) in urls.iter().take(10).enumerate() {
            println!("  {}. {}", i + 1, url);
        }

        if urls.len() > 10 {
            println!("  \x1b[90m... and {} more\x1b[0m", urls.len() - 10);
        }
        println!();
    }

    // Show statistics
    println!("\x1b[1mStatistics:\x1b[0m");
    println!("  Total endpoints: {}", filtered_endpoints.len());
    println!("  Unique types: {}", by_type.len());

    Ok(())
}

/// Extract data using CSS selectors
pub fn scrape(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset scrape <URL> --select SELECTOR [--attr NAME]\nExample: rb web asset scrape http://example.com --select \"div.content p\"",
    )?;

    let selector = ctx.get_flag("select").or_else(|| ctx.get_flag("S")).ok_or(
        "Missing selector. Use --select or -S to specify a CSS selector\nExample: rb web asset scrape http://example.com --select \"div.content p\"",
    )?;

    Validator::validate_url(url)?;

    Output::header("Web Scraper - CSS Selector Extraction");
    Output::item("URL", url);
    Output::item("Selector", &selector);

    let attr = ctx.get_flag("attr").or_else(|| ctx.get_flag("a"));
    if let Some(ref a) = attr {
        Output::item("Attribute", a);
    }

    let format_str = ctx.get_flag("format");
    let format = format_str.as_deref().unwrap_or("text");
    println!();

    Output::spinner_start("Fetching page and extracting data");

    // Fetch HTML
    let client = HttpClient::new();
    let response = client.get(url)?;
    let html = String::from_utf8_lossy(&response.body);

    // Parse DOM
    let doc = Document::parse(&html);

    // Select elements
    let elements = doc.select(&selector);

    Output::spinner_done();

    if elements.is_empty() {
        Output::warning(&format!("No elements match selector: {}", selector));
        return Ok(());
    }

    Output::success(&format!("Found {} matching elements", elements.len()));
    println!();

    if format == "json" {
        // JSON output
        println!("[");
        for (i, elem) in elements.iter().enumerate() {
            let value = if let Some(ref attr_name) = attr {
                elem.attr(attr_name).cloned().unwrap_or_default()
            } else {
                elem.text()
            };
            let escaped = escape_json(&value);
            if i < elements.len() - 1 {
                println!("  \"{}\",", escaped);
            } else {
                println!("  \"{}\"", escaped);
            }
        }
        println!("]");
    } else {
        // Text output
        for (i, elem) in elements.iter().enumerate() {
            let value = if let Some(ref attr_name) = attr {
                elem.attr(attr_name).cloned().unwrap_or_default()
            } else {
                elem.text()
            };
            println!("{:3}. {}", i + 1, value);
        }
    }

    Ok(())
}

/// Extract all links from a page
pub fn links(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset links <URL> [--link-type internal|external|all]\nExample: rb web asset links http://example.com",
    )?;

    Validator::validate_url(url)?;

    Output::header("Link Extractor");
    Output::item("URL", url);

    let link_type_str = ctx.get_flag("link-type").or_else(|| ctx.get_flag("type"));
    let link_type = link_type_str.as_deref().unwrap_or("all");

    Output::item("Filter", link_type);
    println!();

    Output::spinner_start("Extracting links from page");

    // Fetch HTML
    let client = HttpClient::new();
    let response = client.get(url)?;
    let html = String::from_utf8_lossy(&response.body);

    // Parse and extract links
    let doc = Document::parse(&html);
    let extracted_links = extractors::links(&doc);

    Output::spinner_done();

    // Get base domain for filtering
    let base_domain = extract_host(url);

    let mut internal_links: Vec<&str> = Vec::new();
    let mut external_links: Vec<&str> = Vec::new();

    for link in &extracted_links {
        if link.url.contains(&base_domain)
            || link.href.starts_with('/')
            || link.href.starts_with('#')
        {
            internal_links.push(&link.url);
        } else if link.href.starts_with("http") {
            external_links.push(&link.url);
        } else {
            internal_links.push(&link.url); // Relative links are internal
        }
    }

    let show_internal = link_type == "all" || link_type == "internal";
    let show_external = link_type == "all" || link_type == "external";

    if show_internal && !internal_links.is_empty() {
        println!(
            "\x1b[1m\x1b[32m● Internal Links\x1b[0m ({} found)",
            internal_links.len()
        );
        for (i, link) in internal_links.iter().take(20).enumerate() {
            println!("  {:3}. {}", i + 1, link);
        }
        if internal_links.len() > 20 {
            println!(
                "  \x1b[90m... and {} more\x1b[0m",
                internal_links.len() - 20
            );
        }
        println!();
    }

    if show_external && !external_links.is_empty() {
        println!(
            "\x1b[1m\x1b[33m● External Links\x1b[0m ({} found)",
            external_links.len()
        );
        for (i, link) in external_links.iter().take(20).enumerate() {
            println!("  {:3}. {}", i + 1, link);
        }
        if external_links.len() > 20 {
            println!(
                "  \x1b[90m... and {} more\x1b[0m",
                external_links.len() - 20
            );
        }
        println!();
    }

    // Statistics
    println!("\x1b[1mStatistics:\x1b[0m");
    println!("  Internal: {}", internal_links.len());
    println!("  External: {}", external_links.len());
    println!("  Total: {}", extracted_links.len());

    Ok(())
}

/// Extract all images from a page
pub fn images(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset images <URL>\nExample: rb web asset images http://example.com",
    )?;

    Validator::validate_url(url)?;

    Output::header("Image Extractor");
    Output::item("URL", url);
    println!();

    Output::spinner_start("Extracting images from page");

    // Fetch HTML
    let client = HttpClient::new();
    let response = client.get(url)?;
    let html = String::from_utf8_lossy(&response.body);

    // Parse and extract images
    let doc = Document::parse(&html);
    let images = extractors::images(&doc);

    Output::spinner_done();

    if images.is_empty() {
        Output::warning("No images found on page");
        return Ok(());
    }

    Output::success(&format!("Found {} images", images.len()));
    println!();

    // Display images grouped by type
    let mut with_alt: Vec<&extractors::ExtractedImage> = Vec::new();
    let mut without_alt: Vec<&extractors::ExtractedImage> = Vec::new();

    for img in &images {
        if img.alt.is_some() {
            with_alt.push(img);
        } else {
            without_alt.push(img);
        }
    }

    // Images with alt text (accessible)
    if !with_alt.is_empty() {
        println!(
            "\x1b[1m\x1b[32m● Images with Alt Text\x1b[0m ({} images)",
            with_alt.len()
        );
        for (i, img) in with_alt.iter().take(10).enumerate() {
            println!("  {:3}. {}", i + 1, img.url);
            if let Some(ref alt) = img.alt {
                println!("       Alt: {}", alt);
            }
        }
        if with_alt.len() > 10 {
            println!("  \x1b[90m... and {} more\x1b[0m", with_alt.len() - 10);
        }
        println!();
    }

    // Images without alt text (accessibility issue)
    if !without_alt.is_empty() {
        println!(
            "\x1b[1m\x1b[33m● Images Without Alt Text\x1b[0m ({} images - accessibility issue)",
            without_alt.len()
        );
        for (i, img) in without_alt.iter().take(10).enumerate() {
            println!("  {:3}. {}", i + 1, img.url);
        }
        if without_alt.len() > 10 {
            println!("  \x1b[90m... and {} more\x1b[0m", without_alt.len() - 10);
        }
        println!();
    }

    // Statistics
    println!("\x1b[1mStatistics:\x1b[0m");
    println!("  Total images: {}", images.len());
    println!(
        "  With alt text: {} ({:.0}%)",
        with_alt.len(),
        (with_alt.len() as f64 / images.len() as f64) * 100.0
    );
    println!(
        "  Without alt text: {} ({:.0}%)",
        without_alt.len(),
        (without_alt.len() as f64 / images.len() as f64) * 100.0
    );

    Ok(())
}

/// Extract meta tags and OpenGraph data
pub fn meta(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset meta <URL>\nExample: rb web asset meta http://example.com",
    )?;

    Validator::validate_url(url)?;

    Output::header("Meta Tag & OpenGraph Extractor");
    Output::item("URL", url);
    println!();

    Output::spinner_start("Extracting meta information");

    // Fetch HTML
    let client = HttpClient::new();
    let response = client.get(url)?;
    let html = String::from_utf8_lossy(&response.body);

    // Parse DOM
    let doc = Document::parse(&html);

    // Extract meta information
    let meta_data = extractors::meta(&doc);

    // Extract OpenGraph data
    let og_data = extractors::open_graph(&doc);

    Output::spinner_done();

    // Display title
    println!("\x1b[1m\x1b[36m● Page Title\x1b[0m");
    println!("  {}", meta_data.title.as_deref().unwrap_or("(no title)"));
    println!();

    // Display standard meta tags
    println!("\x1b[1m\x1b[32m● Meta Tags\x1b[0m");
    if let Some(ref desc) = meta_data.description {
        println!("  \x1b[1mdescription\x1b[0m: {}", desc);
    }
    if !meta_data.keywords.is_empty() {
        println!(
            "  \x1b[1mkeywords\x1b[0m: {}",
            meta_data.keywords.join(", ")
        );
    }
    if let Some(ref author) = meta_data.author {
        println!("  \x1b[1mauthor\x1b[0m: {}", author);
    }
    if let Some(ref canonical) = meta_data.canonical {
        println!("  \x1b[1mcanonical\x1b[0m: {}", canonical);
    }
    if let Some(ref robots) = meta_data.robots {
        println!("  \x1b[1mrobots\x1b[0m: {}", robots);
    }
    if let Some(ref viewport) = meta_data.viewport {
        println!("  \x1b[1mviewport\x1b[0m: {}", viewport);
    }
    if let Some(ref charset) = meta_data.charset {
        println!("  \x1b[1mcharset\x1b[0m: {}", charset);
    }
    if let Some(ref lang) = meta_data.language {
        println!("  \x1b[1mlanguage\x1b[0m: {}", lang);
    }
    // Display other meta tags
    for (key, value) in &meta_data.other {
        println!("  \x1b[1m{}\x1b[0m: {}", key, value);
    }
    println!();

    // Display OpenGraph data
    let has_og = og_data.title.is_some()
        || og_data.description.is_some()
        || og_data.image.is_some()
        || og_data.url.is_some()
        || og_data.og_type.is_some();

    if has_og {
        println!("\x1b[1m\x1b[35m● OpenGraph Data\x1b[0m");
        if let Some(ref t) = og_data.title {
            println!("  \x1b[1mog:title\x1b[0m: {}", t);
        }
        if let Some(ref d) = og_data.description {
            println!("  \x1b[1mog:description\x1b[0m: {}", d);
        }
        if let Some(ref i) = og_data.image {
            println!("  \x1b[1mog:image\x1b[0m: {}", i);
        }
        if let Some(ref u) = og_data.url {
            println!("  \x1b[1mog:url\x1b[0m: {}", u);
        }
        if let Some(ref ot) = og_data.og_type {
            println!("  \x1b[1mog:type\x1b[0m: {}", ot);
        }
        if let Some(ref s) = og_data.site_name {
            println!("  \x1b[1mog:site_name\x1b[0m: {}", s);
        }
        println!();
    }

    // Statistics
    println!("\x1b[1mStatistics:\x1b[0m");
    let meta_count = meta_data.other.len()
        + if meta_data.description.is_some() {
            1
        } else {
            0
        };
    println!("  Meta tags: {}", meta_count);
    println!(
        "  OpenGraph: {}",
        if has_og { "Present" } else { "Not found" }
    );
    println!(
        "  SEO-ready: {}",
        if meta_data.title.is_some() && meta_data.description.is_some() {
            "Yes"
        } else {
            "Needs improvement"
        }
    );

    Ok(())
}

/// Extract all forms and inputs from a page
pub fn forms(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset forms <URL>\nExample: rb web asset forms http://example.com/login",
    )?;

    Validator::validate_url(url)?;

    Output::header("Form Extractor");
    Output::item("URL", url);
    println!();

    Output::spinner_start("Extracting forms from page");

    // Fetch HTML
    let client = HttpClient::new();
    let response = client.get(url)?;
    let html = String::from_utf8_lossy(&response.body);

    // Parse and extract forms
    let doc = Document::parse(&html);
    let forms = extractors::forms(&doc);

    Output::spinner_done();

    if forms.is_empty() {
        Output::warning("No forms found on page");
        return Ok(());
    }

    Output::success(&format!("Found {} forms", forms.len()));
    println!();

    for (i, form) in forms.iter().enumerate() {
        let action = if form.action.is_empty() {
            "(current page)"
        } else {
            &form.action
        };

        println!(
            "\x1b[1m\x1b[36m● Form #{}\x1b[0m [{} {}]",
            i + 1,
            form.method,
            action
        );

        if let Some(ref id) = form.id {
            println!("  ID: {}", id);
        }
        if let Some(ref name) = form.name {
            println!("  Name: {}", name);
        }

        // Display fields
        if !form.fields.is_empty() {
            println!("  \x1b[1mFields:\x1b[0m");
            for field in &form.fields {
                let name = field.name.as_deref().unwrap_or("(unnamed)");
                let required = if field.required { " *" } else { "" };

                print!("    - [{}] {}{}", field.field_type, name, required);

                if let Some(ref placeholder) = field.placeholder {
                    print!(" (placeholder: {})", placeholder);
                }
                if let Some(ref value) = field.value {
                    if !value.is_empty() {
                        print!(" = \"{}\"", value);
                    }
                }
                println!();
            }
        }

        println!();
    }

    // Security analysis
    println!("\x1b[1m\x1b[33m● Security Notes\x1b[0m");

    let has_password = forms
        .iter()
        .any(|f| f.fields.iter().any(|field| field.field_type == "password"));
    let uses_post = forms.iter().any(|f| f.method == "POST");

    if has_password && !url.starts_with("https://") {
        Output::warning("Password field found on non-HTTPS page!");
    }
    if has_password && !uses_post {
        Output::warning("Password form using GET method (credentials in URL)!");
    }
    if !has_password {
        println!("  No password fields detected");
    } else {
        println!("  Password fields present - ensure HTTPS and POST method");
    }

    Ok(())
}

/// Extract tables as structured data
pub fn tables(ctx: &CliContext) -> Result<(), String> {
    let url = ctx.target.as_ref().ok_or(
        "Missing URL. Usage: rb web asset tables <URL> [--select SELECTOR]\nExample: rb web asset tables http://example.com/data",
    )?;

    Validator::validate_url(url)?;

    Output::header("Table Extractor");
    Output::item("URL", url);

    let selector = ctx.get_flag("select").or_else(|| ctx.get_flag("S"));
    if let Some(ref sel) = selector {
        Output::item("Selector", sel);
    }
    println!();

    Output::spinner_start("Extracting tables from page");

    // Fetch HTML
    let client = HttpClient::new();
    let response = client.get(url)?;
    let html = String::from_utf8_lossy(&response.body);

    // Parse and extract tables
    let doc = Document::parse(&html);
    let tables = extractors::tables(&doc);

    Output::spinner_done();

    if tables.is_empty() {
        Output::warning("No tables found on page");
        return Ok(());
    }

    Output::success(&format!("Found {} tables", tables.len()));
    println!();

    for (i, table) in tables.iter().enumerate() {
        println!(
            "\x1b[1m\x1b[36m● Table #{}\x1b[0m ({} rows × {} cols)",
            i + 1,
            table.rows.len(),
            table
                .headers
                .len()
                .max(table.rows.first().map(|r| r.len()).unwrap_or(0))
        );

        // Display headers if present
        if !table.headers.is_empty() {
            print!("  \x1b[1m");
            for (j, header) in table.headers.iter().enumerate() {
                if j > 0 {
                    print!(" | ");
                }
                print!("{}", header);
            }
            println!("\x1b[0m");
            println!("  {}", "-".repeat(60));
        }

        // Display first few rows
        for (row_idx, row) in table.rows.iter().take(5).enumerate() {
            print!("  ");
            for (col_idx, cell) in row.iter().enumerate() {
                if col_idx > 0 {
                    print!(" | ");
                }
                // Truncate long cells
                if cell.len() > 20 {
                    print!("{}...", &cell[..17]);
                } else {
                    print!("{}", cell);
                }
            }
            println!();

            if row_idx == 4 && table.rows.len() > 5 {
                println!(
                    "  \x1b[90m... and {} more rows\x1b[0m",
                    table.rows.len() - 5
                );
            }
        }

        println!();
    }

    // Statistics
    println!("\x1b[1mStatistics:\x1b[0m");
    println!("  Total tables: {}", tables.len());
    let total_rows: usize = tables.iter().map(|t| t.rows.len()).sum();
    println!("  Total rows: {}", total_rows);
    let with_headers = tables.iter().filter(|t| !t.headers.is_empty()).count();
    println!("  Tables with headers: {}", with_headers);

    Ok(())
}
