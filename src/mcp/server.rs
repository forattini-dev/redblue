use crate::cli::commands;
use crate::mcp::categories::{CategoryConfig, CategoryPreset, ToolCategory};
use crate::mcp::embeddings::{load_embeddings, EmbeddingsData, EmbeddingsLoaderConfig};
use crate::mcp::orchestrator::{Orchestrator, StepResult};
use crate::mcp::prompts::PromptRegistry;
use crate::mcp::resources::ResourceRegistry;
use crate::mcp::search::{hybrid_search, SearchConfig, SearchMode};
use crate::modules::recon::dnsdumpster::DnsDumpsterClient;
use crate::modules::recon::massdns::{
    common_subdomains, load_wordlist, MassDnsConfig, MassDnsScanner,
};
use crate::modules::recon::vuln::osv::{Ecosystem, OsvClient};
use crate::modules::recon::vuln::{
    calculate_risk_score, generate_cpe, ExploitDbClient, KevClient, NvdClient, VulnCollection,
};
use crate::modules::web::crawler::WebCrawler;
use crate::modules::web::dom::Document;
use crate::modules::web::extractors;
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::protocols::har::Har;
use crate::protocols::http::HttpClient;
use crate::utils::json::{parse_json, JsonValue};
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Network scanning
use crate::modules::network::scanner::PortScanner;

// DNS
use crate::protocols::dns::DnsClient;

// Recon
use crate::modules::recon::crtsh::CrtShClient;
use crate::protocols::whois::WhoisClient;

// Intel
use crate::modules::intel::ioc::{IocCollection, IocExtractor};
use crate::modules::intel::mapper::TechniqueMapper;
use crate::modules::intel::navigator::create_layer_from_techniques;

// Evasion - use functions directly
use crate::modules::evasion::antidebug::AntiDebug;
use crate::modules::evasion::sandbox;

type ToolHandler = fn(&mut McpServer, &JsonValue) -> Result<ToolResult, String>;

struct ToolField {
    name: &'static str,
    field_type: &'static str,
    description: &'static str,
    required: bool,
}

struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    fields: &'static [ToolField],
    handler: ToolHandler,
}

struct DocHit {
    path: String,
    line: usize,
    snippet: String,
}

struct ToolResult {
    text: String,
    data: JsonValue,
}

pub struct McpServer {
    tools: Vec<ToolDefinition>,
    initialized: bool,
    embeddings: Option<EmbeddingsData>,
    embeddings_loaded: bool,
    resources: ResourceRegistry,
    prompts: PromptRegistry,
    categories: CategoryConfig,
    orchestrator: Orchestrator,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            tools: vec![
                ToolDefinition {
                    name: "rb.list-domains",
                    description: "List available RedBlue CLI domains.",
                    fields: &[],
                    handler: Self::tool_list_domains,
                },
                ToolDefinition {
                    name: "rb.list-resources",
                    description:
                        "List resources and verbs for a given RedBlue CLI domain (e.g. network).",
                    fields: &[ToolField {
                        name: "domain",
                        field_type: "string",
                        description: "Domain name to inspect (network, dns, web, ...).",
                        required: true,
                    }],
                    handler: Self::tool_list_resources,
                },
                ToolDefinition {
                    name: "rb.describe-command",
                    description: "Get detailed help for a domain/resource combination.",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain name to describe.",
                            required: true,
                        },
                        ToolField {
                            name: "resource",
                            field_type: "string",
                            description: "Resource name inside the domain.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_describe_command,
                },
                ToolDefinition {
                    name: "rb.search-docs",
                    description:
                        "Search the RedBlue documentation for a keyword or phrase (case-insensitive).",
                    fields: &[ToolField {
                        name: "query",
                        field_type: "string",
                        description: "Search term to look for inside docs/ and README.md.",
                        required: true,
                    }],
                    handler: Self::tool_search_docs,
                },
                ToolDefinition {
                    name: "rb.docs.index",
                    description: "Return a structured index of project documentation.",
                    fields: &[],
                    handler: Self::tool_docs_index,
                },
                ToolDefinition {
                    name: "rb.docs.get",
                    description: "Fetch documentation content by path and optional section.",
                    fields: &[
                        ToolField {
                            name: "path",
                            field_type: "string",
                            description: "Relative documentation path (e.g. docs/cli-semantics.md).",
                            required: true,
                        },
                        ToolField {
                            name: "section",
                            field_type: "string",
                            description:
                                "Optional heading to extract (exact text match, case-insensitive).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_docs_get,
                },
                ToolDefinition {
                    name: "rb.targets.list",
                    description: "List all MCP-tracked targets with metadata.",
                    fields: &[],
                    handler: Self::tool_targets_list,
                },
                ToolDefinition {
                    name: "rb.targets.save",
                    description: "Create or update a tracked target entry.",
                    fields: &[
                        ToolField {
                            name: "name",
                            field_type: "string",
                            description: "Human-friendly identifier (unique).",
                            required: true,
                        },
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target expression (host, URL, CIDR, etc.).",
                            required: true,
                        },
                        ToolField {
                            name: "notes",
                            field_type: "string",
                            description: "Optional notes or task context.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_targets_save,
                },
                ToolDefinition {
                    name: "rb.targets.remove",
                    description: "Delete a tracked target by name.",
                    fields: &[ToolField {
                        name: "name",
                        field_type: "string",
                        description: "Identifier to remove.",
                        required: true,
                    }],
                    handler: Self::tool_targets_remove,
                },
                ToolDefinition {
                    name: "rb.command.run",
                    description: "Execute a RedBlue CLI command and capture the output.",
                    fields: &[
                        ToolField {
                            name: "argv",
                            field_type: "array",
                            description: "Explicit argument vector (domain resource verb ...).",
                            required: false,
                        },
                        ToolField {
                            name: "command",
                            field_type: "string",
                            description: "Command string to split into argv when 'argv' is omitted.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_command_run,
                },
                // Web scraping tools
                ToolDefinition {
                    name: "rb.web.crawl",
                    description: "Crawl a website discovering pages, links, forms and assets.",
                    fields: &[
                        ToolField {
                            name: "url",
                            field_type: "string",
                            description: "URL to start crawling from.",
                            required: true,
                        },
                        ToolField {
                            name: "max_depth",
                            field_type: "number",
                            description: "Maximum depth to crawl (default: 2).",
                            required: false,
                        },
                        ToolField {
                            name: "max_pages",
                            field_type: "number",
                            description: "Maximum pages to crawl (default: 50).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_web_crawl,
                },
                ToolDefinition {
                    name: "rb.web.scrape",
                    description: "Scrape data from a URL using CSS selectors.",
                    fields: &[
                        ToolField {
                            name: "url",
                            field_type: "string",
                            description: "URL to scrape.",
                            required: true,
                        },
                        ToolField {
                            name: "selector",
                            field_type: "string",
                            description: "CSS selector to extract elements.",
                            required: true,
                        },
                        ToolField {
                            name: "attr",
                            field_type: "string",
                            description: "Optional attribute to extract from selected elements.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_web_scrape,
                },
                ToolDefinition {
                    name: "rb.html.select",
                    description: "Parse HTML content and extract elements using CSS selectors (no HTTP).",
                    fields: &[
                        ToolField {
                            name: "html",
                            field_type: "string",
                            description: "HTML content to parse.",
                            required: true,
                        },
                        ToolField {
                            name: "selector",
                            field_type: "string",
                            description: "CSS selector to extract elements.",
                            required: true,
                        },
                        ToolField {
                            name: "attr",
                            field_type: "string",
                            description: "Optional attribute to extract from selected elements.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_html_select,
                },
                ToolDefinition {
                    name: "rb.web.links",
                    description: "Extract all links from a webpage.",
                    fields: &[
                        ToolField {
                            name: "url",
                            field_type: "string",
                            description: "URL to extract links from.",
                            required: true,
                        },
                        ToolField {
                            name: "link_type",
                            field_type: "string",
                            description: "Filter by type: internal, external, or all (default: all).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_web_links,
                },
                ToolDefinition {
                    name: "rb.web.tables",
                    description: "Extract tables from a webpage as structured data.",
                    fields: &[
                        ToolField {
                            name: "url",
                            field_type: "string",
                            description: "URL to extract tables from.",
                            required: true,
                        },
                        ToolField {
                            name: "selector",
                            field_type: "string",
                            description: "Optional CSS selector to target specific table.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_web_tables,
                },
                ToolDefinition {
                    name: "rb.har.record",
                    description: "Crawl a website and record HTTP traffic to HAR format.",
                    fields: &[
                        ToolField {
                            name: "url",
                            field_type: "string",
                            description: "URL to start crawling from.",
                            required: true,
                        },
                        ToolField {
                            name: "max_depth",
                            field_type: "number",
                            description: "Maximum depth to crawl (default: 2).",
                            required: false,
                        },
                        ToolField {
                            name: "max_pages",
                            field_type: "number",
                            description: "Maximum pages to crawl (default: 20).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_har_record,
                },
                ToolDefinition {
                    name: "rb.har.analyze",
                    description: "Analyze a HAR file and return statistics.",
                    fields: &[
                        ToolField {
                            name: "content",
                            field_type: "string",
                            description: "HAR file content as JSON string.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_har_analyze,
                },
                // Vulnerability Intelligence Tools
                ToolDefinition {
                    name: "rb.vuln.search",
                    description: "Search vulnerabilities for a technology by name and optional version. Queries NVD, OSV, and enriches with CISA KEV data.",
                    fields: &[
                        ToolField {
                            name: "tech",
                            field_type: "string",
                            description: "Technology name (e.g., nginx, wordpress, lodash).",
                            required: true,
                        },
                        ToolField {
                            name: "version",
                            field_type: "string",
                            description: "Version number to search (e.g., 1.18.0).",
                            required: false,
                        },
                        ToolField {
                            name: "source",
                            field_type: "string",
                            description: "Data source: nvd, osv, or all (default: nvd).",
                            required: false,
                        },
                        ToolField {
                            name: "limit",
                            field_type: "number",
                            description: "Maximum results to return (default: 10).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_vuln_search,
                },
                ToolDefinition {
                    name: "rb.vuln.cve",
                    description: "Get detailed information about a specific CVE, including CVSS scores, KEV status, and known exploits.",
                    fields: &[
                        ToolField {
                            name: "cve_id",
                            field_type: "string",
                            description: "CVE identifier (e.g., CVE-2021-44228).",
                            required: true,
                        },
                    ],
                    handler: Self::tool_vuln_cve,
                },
                ToolDefinition {
                    name: "rb.vuln.kev",
                    description: "Query CISA Known Exploited Vulnerabilities catalog. Returns actively exploited CVEs with remediation deadlines.",
                    fields: &[
                        ToolField {
                            name: "vendor",
                            field_type: "string",
                            description: "Filter by vendor name (e.g., Microsoft, Apache).",
                            required: false,
                        },
                        ToolField {
                            name: "product",
                            field_type: "string",
                            description: "Filter by product name (e.g., Windows Server, Log4j).",
                            required: false,
                        },
                        ToolField {
                            name: "stats",
                            field_type: "boolean",
                            description: "Return catalog statistics instead of entries.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_vuln_kev,
                },
                ToolDefinition {
                    name: "rb.vuln.exploit",
                    description: "Search Exploit-DB for public exploits and proof-of-concepts.",
                    fields: &[
                        ToolField {
                            name: "query",
                            field_type: "string",
                            description: "Search query (e.g., 'Apache Struts', 'privilege escalation linux').",
                            required: true,
                        },
                        ToolField {
                            name: "limit",
                            field_type: "number",
                            description: "Maximum results to return (default: 10).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_vuln_exploit,
                },
                ToolDefinition {
                    name: "rb.vuln.fingerprint",
                    description: "Fingerprint a URL to detect technologies, then search for vulnerabilities affecting them.",
                    fields: &[
                        ToolField {
                            name: "url",
                            field_type: "string",
                            description: "URL to fingerprint (e.g., http://example.com).",
                            required: true,
                        },
                        ToolField {
                            name: "source",
                            field_type: "string",
                            description: "Vulnerability source: nvd, osv, or all (default: nvd).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_vuln_fingerprint,
                },
                // Recon tools
                ToolDefinition {
                    name: "rb.recon.dnsdumpster",
                    description: "Query DNSDumpster for DNS intelligence including MX, TXT, DNS hosts, and subdomains.",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain to query (e.g., example.com).",
                            required: true,
                        },
                    ],
                    handler: Self::tool_recon_dnsdumpster,
                },
                ToolDefinition {
                    name: "rb.recon.massdns",
                    description: "High-performance DNS bruteforce subdomain enumeration.",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain to enumerate subdomains for (e.g., example.com).",
                            required: true,
                        },
                        ToolField {
                            name: "threads",
                            field_type: "integer",
                            description: "Number of concurrent threads (default: 10).",
                            required: false,
                        },
                        ToolField {
                            name: "wordlist",
                            field_type: "string",
                            description: "Path to custom wordlist file. Uses built-in if not specified.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_recon_massdns,
                },
                // ================================================================
                // NETWORK TOOLS
                // ================================================================
                ToolDefinition {
                    name: "rb.network.scan",
                    description: "Scan ports on a target host. Returns open ports with service detection.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target IP address or hostname to scan.",
                            required: true,
                        },
                        ToolField {
                            name: "ports",
                            field_type: "string",
                            description: "Ports to scan: 'common' (top 1000), 'web' (80,443,8080...), 'full' (1-65535), or custom range like '1-1000' or '22,80,443'.",
                            required: false,
                        },
                        ToolField {
                            name: "timeout",
                            field_type: "integer",
                            description: "Timeout per port in milliseconds (default: 1000).",
                            required: false,
                        },
                        ToolField {
                            name: "threads",
                            field_type: "integer",
                            description: "Number of concurrent threads (default: 100).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_network_scan,
                },
                ToolDefinition {
                    name: "rb.network.ping",
                    description: "Check if a host is reachable using TCP connect to common ports.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target IP address or hostname to ping.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_network_ping,
                },
                ToolDefinition {
                    name: "rb.network.health",
                    description: "Check health status of specific ports on a target.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target IP address or hostname.",
                            required: true,
                        },
                        ToolField {
                            name: "ports",
                            field_type: "string",
                            description: "Comma-separated list of ports to check (e.g., '22,80,443').",
                            required: true,
                        },
                    ],
                    handler: Self::tool_network_health,
                },
                // ================================================================
                // DNS TOOLS
                // ================================================================
                ToolDefinition {
                    name: "rb.dns.lookup",
                    description: "Perform DNS lookup for various record types (A, AAAA, MX, NS, TXT, CNAME, SOA).",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain name to lookup.",
                            required: true,
                        },
                        ToolField {
                            name: "type",
                            field_type: "string",
                            description: "Record type: A, AAAA, MX, NS, TXT, CNAME, SOA (default: A).",
                            required: false,
                        },
                        ToolField {
                            name: "server",
                            field_type: "string",
                            description: "DNS server to use (default: 8.8.8.8).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_dns_lookup,
                },
                ToolDefinition {
                    name: "rb.dns.resolve",
                    description: "Quick DNS resolution - returns IP addresses for a domain.",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain name to resolve.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_dns_resolve,
                },
                // ================================================================
                // TLS TOOLS
                // ================================================================
                ToolDefinition {
                    name: "rb.tls.cert",
                    description: "Inspect TLS certificate of a host. Returns subject, issuer, validity, SANs.",
                    fields: &[
                        ToolField {
                            name: "host",
                            field_type: "string",
                            description: "Hostname to inspect (optionally with :port).",
                            required: true,
                        },
                    ],
                    handler: Self::tool_tls_cert,
                },
                ToolDefinition {
                    name: "rb.tls.audit",
                    description: "Full TLS security audit - checks protocols, ciphers, vulnerabilities.",
                    fields: &[
                        ToolField {
                            name: "host",
                            field_type: "string",
                            description: "Hostname to audit (optionally with :port).",
                            required: true,
                        },
                    ],
                    handler: Self::tool_tls_audit,
                },
                // ================================================================
                // RECON TOOLS
                // ================================================================
                ToolDefinition {
                    name: "rb.recon.whois",
                    description: "Perform WHOIS lookup for a domain. Returns registrar, dates, nameservers.",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain to lookup.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_recon_whois,
                },
                ToolDefinition {
                    name: "rb.recon.subdomains",
                    description: "Enumerate subdomains using multiple sources (CT logs, DNS bruteforce).",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain to enumerate subdomains for.",
                            required: true,
                        },
                        ToolField {
                            name: "passive",
                            field_type: "boolean",
                            description: "Use only passive sources (no DNS bruteforce). Default: true.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_recon_subdomains,
                },
                ToolDefinition {
                    name: "rb.recon.crtsh",
                    description: "Query Certificate Transparency logs via crt.sh for subdomains.",
                    fields: &[
                        ToolField {
                            name: "domain",
                            field_type: "string",
                            description: "Domain to search in CT logs.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_recon_crtsh,
                },
                // ================================================================
                // INTEL TOOLS (MITRE ATT&CK)
                // ================================================================
                ToolDefinition {
                    name: "rb.intel.mitre.map",
                    description: "Map security findings to MITRE ATT&CK techniques.",
                    fields: &[
                        ToolField {
                            name: "ports",
                            field_type: "string",
                            description: "Comma-separated list of open ports (e.g., '22,80,443,3389').",
                            required: false,
                        },
                        ToolField {
                            name: "cves",
                            field_type: "string",
                            description: "Comma-separated list of CVE IDs (e.g., 'CVE-2021-44228,CVE-2022-22965').",
                            required: false,
                        },
                        ToolField {
                            name: "technologies",
                            field_type: "string",
                            description: "Comma-separated list of detected technologies (e.g., 'wordpress,apache,mysql').",
                            required: false,
                        },
                    ],
                    handler: Self::tool_intel_mitre_map,
                },
                ToolDefinition {
                    name: "rb.intel.mitre.layer",
                    description: "Generate MITRE ATT&CK Navigator layer JSON from techniques.",
                    fields: &[
                        ToolField {
                            name: "techniques",
                            field_type: "string",
                            description: "Comma-separated list of technique IDs (e.g., 'T1021.001,T1059.001').",
                            required: true,
                        },
                        ToolField {
                            name: "name",
                            field_type: "string",
                            description: "Layer name for the Navigator (default: 'RedBlue Assessment').",
                            required: false,
                        },
                    ],
                    handler: Self::tool_intel_mitre_layer,
                },
                ToolDefinition {
                    name: "rb.intel.ioc.extract",
                    description: "Extract Indicators of Compromise (IOCs) from scan results.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target that was scanned.",
                            required: true,
                        },
                        ToolField {
                            name: "ports",
                            field_type: "string",
                            description: "Comma-separated list of open ports.",
                            required: false,
                        },
                        ToolField {
                            name: "technologies",
                            field_type: "string",
                            description: "Comma-separated list of detected technologies.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_intel_ioc_extract,
                },
                // ================================================================
                // EVASION TOOLS
                // ================================================================
                ToolDefinition {
                    name: "rb.evasion.sandbox",
                    description: "Check if running in a sandbox/VM environment. Returns detection score and indicators.",
                    fields: &[],
                    handler: Self::tool_evasion_sandbox,
                },
                ToolDefinition {
                    name: "rb.evasion.obfuscate",
                    description: "Obfuscate a string using various encoding methods.",
                    fields: &[
                        ToolField {
                            name: "input",
                            field_type: "string",
                            description: "String to obfuscate.",
                            required: true,
                        },
                        ToolField {
                            name: "method",
                            field_type: "string",
                            description: "Obfuscation method: xor, base64, rot13, hex (default: base64).",
                            required: false,
                        },
                        ToolField {
                            name: "key",
                            field_type: "string",
                            description: "Key for XOR encoding (default: 0x42).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_evasion_obfuscate,
                },
                ToolDefinition {
                    name: "rb.evasion.antidebug",
                    description: "Check for debugger presence using various techniques.",
                    fields: &[],
                    handler: Self::tool_evasion_antidebug,
                },
                // ================================================================
                // FINGERPRINT TOOLS
                // ================================================================
                ToolDefinition {
                    name: "rb.fingerprint.service",
                    description: "Detect services running on specific ports by analyzing banners.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target IP or hostname.",
                            required: true,
                        },
                        ToolField {
                            name: "port",
                            field_type: "integer",
                            description: "Port to fingerprint.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_fingerprint_service,
                },
                // Category management tools
                ToolDefinition {
                    name: "rb.config.categories",
                    description: "List, enable, or disable tool categories. Without args, shows current status.",
                    fields: &[
                        ToolField {
                            name: "action",
                            field_type: "string",
                            description: "Action: list, enable, disable, toggle (optional, default: list).",
                            required: false,
                        },
                        ToolField {
                            name: "category",
                            field_type: "string",
                            description: "Category name (discovery, docs, targets, network, dns, web, har, tls, recon, vuln, intel, evasion, fingerprint, command).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_config_categories,
                },
                ToolDefinition {
                    name: "rb.config.preset",
                    description: "Apply a category preset (all, core, blue-team, red-team, web-security, minimal).",
                    fields: &[
                        ToolField {
                            name: "preset",
                            field_type: "string",
                            description: "Preset name: all, core, blue-team, red-team, web-security, minimal.",
                            required: false,
                        },
                    ],
                    handler: Self::tool_config_preset,
                },
                // Autonomous operation tools
                ToolDefinition {
                    name: "rb.auto.recon",
                    description: "Start an autonomous reconnaissance operation on a target. Uses LLM guidance for decision-making.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target host, IP, or domain to assess.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_auto_recon,
                },
                ToolDefinition {
                    name: "rb.auto.vulnscan",
                    description: "Start an autonomous vulnerability scan. Combines port discovery with vuln intel.",
                    fields: &[
                        ToolField {
                            name: "target",
                            field_type: "string",
                            description: "Target to scan for vulnerabilities.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_auto_vulnscan,
                },
                ToolDefinition {
                    name: "rb.auto.step",
                    description: "Execute next step of an autonomous operation. Returns guidance request if LLM input needed.",
                    fields: &[
                        ToolField {
                            name: "operation_id",
                            field_type: "string",
                            description: "Operation ID (from rb.auto.recon or rb.auto.vulnscan).",
                            required: true,
                        },
                    ],
                    handler: Self::tool_auto_step,
                },
                ToolDefinition {
                    name: "rb.auto.guide",
                    description: "Provide LLM guidance response for a pending operation request.",
                    fields: &[
                        ToolField {
                            name: "operation_id",
                            field_type: "string",
                            description: "Operation ID awaiting guidance.",
                            required: true,
                        },
                        ToolField {
                            name: "response",
                            field_type: "string",
                            description: "LLM guidance response (JSON with recommended actions).",
                            required: true,
                        },
                    ],
                    handler: Self::tool_auto_guide,
                },
                ToolDefinition {
                    name: "rb.auto.status",
                    description: "Get status of an autonomous operation or list all operations.",
                    fields: &[
                        ToolField {
                            name: "operation_id",
                            field_type: "string",
                            description: "Operation ID (optional, lists all if omitted).",
                            required: false,
                        },
                    ],
                    handler: Self::tool_auto_status,
                },
                ToolDefinition {
                    name: "rb.auto.stop",
                    description: "Stop an autonomous operation.",
                    fields: &[
                        ToolField {
                            name: "operation_id",
                            field_type: "string",
                            description: "Operation ID to stop.",
                            required: true,
                        },
                    ],
                    handler: Self::tool_auto_stop,
                },
            ],
            initialized: false,
            embeddings: None,
            embeddings_loaded: false,
            resources: ResourceRegistry::new(),
            prompts: PromptRegistry::new(),
            categories: CategoryConfig::new(),
            orchestrator: Orchestrator::new(),
        }
    }

    /// Load embeddings for hybrid search (lazy initialization)
    fn ensure_embeddings_loaded(&mut self) {
        if self.embeddings_loaded {
            return;
        }
        self.embeddings_loaded = true;

        let config = EmbeddingsLoaderConfig::default();
        match load_embeddings(&config) {
            Ok(data) => {
                eprintln!(
                    "[MCP] Loaded {} documents with embeddings (has_vectors: {})",
                    data.documents.len(),
                    data.has_vectors
                );
                self.embeddings = Some(data);
            }
            Err(e) => {
                eprintln!("[MCP] Warning: Could not load embeddings: {}", e);
                eprintln!("[MCP] Falling back to basic text search");
            }
        }
    }

    pub fn run_stdio(core: Arc<Mutex<McpServer>>) -> Result<(), String> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            let payload = match read_payload(&mut reader)? {
                Some(p) => p,
                None => break,
            };
            let message = match parse_json(&payload) {
                Ok(value) => value,
                Err(err) => {
                    let response =
                        build_error_message(None, -32700, &format!("invalid JSON: {}", err));
                    write_message(response)?;
                    continue;
                }
            };
            let response = {
                let mut guard = core
                    .lock()
                    .map_err(|_| "MCP server state poisoned".to_string())?;
                guard.process_message(message)
            };
            if let Some(response) = response {
                write_message(response)?;
            }
        }
        Ok(())
    }

    pub fn process_message(&mut self, message: JsonValue) -> Option<JsonValue> {
        self.handle_message(message)
    }

    fn handle_message(&mut self, message: JsonValue) -> Option<JsonValue> {
        let obj = match message {
            JsonValue::Object(entries) => entries,
            _ => {
                return Some(build_error_message(
                    None,
                    -32600,
                    "top-level message must be an object",
                ))
            }
        };

        let mut id: Option<JsonValue> = None;
        let mut method: Option<String> = None;
        let mut params = JsonValue::Null;

        for (key, value) in obj {
            match key.as_str() {
                "id" => {
                    id = Some(value);
                }
                "method" => {
                    if let JsonValue::String(s) = value {
                        method = Some(s);
                    }
                }
                "params" => {
                    params = value;
                }
                _ => {}
            }
        }

        let method_name = match method {
            Some(name) => name,
            None => return Some(build_error_message(id, -32600, "missing method field")),
        };

        let response = match method_name.as_str() {
            "initialize" => match self.handle_initialize(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("initialize failed: {}", err),
                )),
            },
            "tools/list" => match self.handle_list_tools(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("list failed: {}", err),
                )),
            },
            "tools/call" => match self.handle_tool_call(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("tool call failed: {}", err),
                )),
            },
            "resources/list" => match self.handle_list_resources(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("resources list failed: {}", err),
                )),
            },
            "resources/read" => match self.handle_read_resource(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("resource read failed: {}", err),
                )),
            },
            "prompts/list" => match self.handle_list_prompts(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("prompts list failed: {}", err),
                )),
            },
            "prompts/get" => match self.handle_get_prompt(params) {
                Ok(result) => Some(build_result_message(id, result)),
                Err(err) => Some(build_error_message(
                    id,
                    -32001,
                    &format!("prompt get failed: {}", err),
                )),
            },
            "notifications/initialized" => None,
            other => Some(build_error_message(
                id,
                -32601,
                &format!("unsupported method '{}'", other),
            )),
        };

        response
    }

    fn handle_initialize(&mut self, _params: JsonValue) -> Result<JsonValue, String> {
        let capabilities = JsonValue::object(vec![
            (
                "tools".to_string(),
                JsonValue::object(vec![
                    ("list".to_string(), JsonValue::Bool(true)),
                    ("call".to_string(), JsonValue::Bool(true)),
                ]),
            ),
            (
                "resources".to_string(),
                JsonValue::object(vec![
                    ("list".to_string(), JsonValue::Bool(true)),
                    ("read".to_string(), JsonValue::Bool(true)),
                    ("subscribe".to_string(), JsonValue::Bool(false)),
                ]),
            ),
            (
                "prompts".to_string(),
                JsonValue::object(vec![
                    ("list".to_string(), JsonValue::Bool(true)),
                    ("get".to_string(), JsonValue::Bool(true)),
                ]),
            ),
        ]);

        let result = JsonValue::object(vec![
            (
                "protocolVersion".to_string(),
                JsonValue::String("2024-11-05".to_string()),
            ),
            (
                "serverInfo".to_string(),
                JsonValue::object(vec![
                    (
                        "name".to_string(),
                        JsonValue::String("redblue-mcp".to_string()),
                    ),
                    (
                        "version".to_string(),
                        JsonValue::String(env!("CARGO_PKG_VERSION").to_string()),
                    ),
                ]),
            ),
            ("capabilities".to_string(), capabilities),
        ]);

        self.initialized = true;

        Ok(result)
    }

    fn handle_list_tools(&mut self, _params: JsonValue) -> Result<JsonValue, String> {
        if !self.initialized {
            return Err("call initialize before listing tools".to_string());
        }

        let mut tools_json = Vec::new();
        for tool in &self.tools {
            // Filter by enabled categories (config tools are always available)
            if tool.name.starts_with("rb.config.") || self.categories.is_tool_enabled(tool.name) {
                let entry = vec![
                    ("name".to_string(), JsonValue::String(tool.name.to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String(tool.description.to_string()),
                    ),
                    ("inputSchema".to_string(), build_input_schema(tool.fields)),
                ];
                tools_json.push(JsonValue::Object(entry));
            }
        }

        let result = JsonValue::object(vec![
            ("tools".to_string(), JsonValue::array(tools_json)),
            ("nextCursor".to_string(), JsonValue::Null),
        ]);

        Ok(result)
    }

    fn handle_tool_call(&mut self, params: JsonValue) -> Result<JsonValue, String> {
        if !self.initialized {
            return Err("call initialize before invoking tools".to_string());
        }

        let name = params
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "tool invocation missing name".to_string())?;

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(JsonValue::Object(vec![]));

        for tool in &self.tools {
            if tool.name == name {
                let output = (tool.handler)(self, &arguments)?;
                let content = JsonValue::array(vec![JsonValue::object(vec![
                    ("type".to_string(), JsonValue::String("text".to_string())),
                    ("text".to_string(), JsonValue::String(output.text)),
                ])]);
                let result = JsonValue::object(vec![
                    ("content".to_string(), content),
                    ("data".to_string(), output.data),
                ]);
                return Ok(result);
            }
        }

        Err(format!("unknown tool '{}'", name))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MCP RESOURCES HANDLERS
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_list_resources(&self, _params: JsonValue) -> Result<JsonValue, String> {
        let mut resources_json = Vec::new();

        // Add static resources
        for resource in self.resources.list_resources() {
            resources_json.push(JsonValue::object(vec![
                ("uri".to_string(), JsonValue::String(resource.uri.clone())),
                ("name".to_string(), JsonValue::String(resource.name.clone())),
                (
                    "description".to_string(),
                    JsonValue::String(resource.description.clone()),
                ),
                (
                    "mimeType".to_string(),
                    JsonValue::String(resource.mime_type.clone()),
                ),
            ]));
        }

        // Add resource templates
        let mut templates_json = Vec::new();
        for template in self.resources.list_templates() {
            templates_json.push(JsonValue::object(vec![
                (
                    "uriTemplate".to_string(),
                    JsonValue::String(template.uri_template.clone()),
                ),
                ("name".to_string(), JsonValue::String(template.name.clone())),
                (
                    "description".to_string(),
                    JsonValue::String(template.description.clone()),
                ),
                (
                    "mimeType".to_string(),
                    JsonValue::String(template.mime_type.clone()),
                ),
            ]));
        }

        Ok(JsonValue::object(vec![
            ("resources".to_string(), JsonValue::array(resources_json)),
            (
                "resourceTemplates".to_string(),
                JsonValue::array(templates_json),
            ),
        ]))
    }

    fn handle_read_resource(&self, params: JsonValue) -> Result<JsonValue, String> {
        let uri = params
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'uri' parameter".to_string())?;

        let content = self.resources.read_resource(uri)?;

        let mut content_obj = vec![
            ("uri".to_string(), JsonValue::String(content.uri)),
            ("mimeType".to_string(), JsonValue::String(content.mime_type)),
        ];

        if let Some(text) = content.text {
            content_obj.push(("text".to_string(), JsonValue::String(text)));
        }
        if let Some(blob) = content.blob {
            content_obj.push(("blob".to_string(), JsonValue::String(blob)));
        }

        Ok(JsonValue::object(vec![(
            "contents".to_string(),
            JsonValue::array(vec![JsonValue::object(content_obj)]),
        )]))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MCP PROMPTS HANDLERS
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_list_prompts(&self, _params: JsonValue) -> Result<JsonValue, String> {
        let mut prompts_json = Vec::new();

        for prompt in self.prompts.list_prompts() {
            let mut args_json = Vec::new();
            for arg in &prompt.arguments {
                args_json.push(JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(arg.name.clone())),
                    (
                        "description".to_string(),
                        JsonValue::String(arg.description.clone()),
                    ),
                    ("required".to_string(), JsonValue::Bool(arg.required)),
                ]));
            }

            prompts_json.push(JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(prompt.name.clone())),
                (
                    "description".to_string(),
                    JsonValue::String(prompt.description.clone()),
                ),
                ("arguments".to_string(), JsonValue::array(args_json)),
            ]));
        }

        Ok(JsonValue::object(vec![(
            "prompts".to_string(),
            JsonValue::array(prompts_json),
        )]))
    }

    fn handle_get_prompt(&self, params: JsonValue) -> Result<JsonValue, String> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'name' parameter".to_string())?;

        // Extract arguments from params
        let mut args = std::collections::HashMap::new();
        if let Some(arguments) = params.get("arguments") {
            if let JsonValue::Object(entries) = arguments {
                for (key, value) in entries {
                    if let JsonValue::String(s) = value {
                        args.insert(key.clone(), s.clone());
                    }
                }
            }
        }

        let result = self.prompts.get_prompt(name, &args)?;

        let mut messages_json = Vec::new();
        for msg in result.messages {
            messages_json.push(JsonValue::object(vec![
                ("role".to_string(), JsonValue::String(msg.role)),
                (
                    "content".to_string(),
                    JsonValue::object(vec![
                        ("type".to_string(), JsonValue::String("text".to_string())),
                        ("text".to_string(), JsonValue::String(msg.content)),
                    ]),
                ),
            ]));
        }

        Ok(JsonValue::object(vec![
            (
                "description".to_string(),
                JsonValue::String(result.description),
            ),
            ("messages".to_string(), JsonValue::array(messages_json)),
        ]))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TOOL IMPLEMENTATIONS
    // ═══════════════════════════════════════════════════════════════════════

    fn tool_list_domains(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        let mut domains = HashSet::new();
        for command in commands::all_commands() {
            domains.insert(command.domain().to_string());
        }

        let mut sorted_domains: Vec<String> = domains.into_iter().collect();
        sorted_domains.sort();

        let values = sorted_domains
            .into_iter()
            .map(JsonValue::from)
            .collect::<Vec<JsonValue>>();

        let domain_strings: Vec<String> = values
            .iter()
            .filter_map(|value| value.as_str().map(|s| s.to_string()))
            .collect();
        let text = if domain_strings.is_empty() {
            "No RedBlue CLI domains were found.".to_string()
        } else {
            format!(
                "Available domains ({}): {}",
                domain_strings.len(),
                domain_strings.join(", ")
            )
        };

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![("domains".to_string(), JsonValue::array(values))]),
        })
    }

    fn tool_list_resources(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'domain' is required".to_string())?;

        let mut resources = Vec::new();
        for command in commands::all_commands() {
            if command.domain() != domain {
                continue;
            }

            let mut entry = Vec::new();
            entry.push((
                "resource".to_string(),
                JsonValue::String(command.resource().to_string()),
            ));
            entry.push((
                "description".to_string(),
                JsonValue::String(command.description().to_string()),
            ));

            let routes = command
                .routes()
                .into_iter()
                .map(|route| {
                    JsonValue::object(vec![
                        (
                            "verb".to_string(),
                            JsonValue::String(route.verb.to_string()),
                        ),
                        (
                            "summary".to_string(),
                            JsonValue::String(route.summary.to_string()),
                        ),
                        (
                            "usage".to_string(),
                            JsonValue::String(route.usage.to_string()),
                        ),
                    ])
                })
                .collect::<Vec<JsonValue>>();

            entry.push(("verbs".to_string(), JsonValue::array(routes)));
            resources.push(JsonValue::Object(entry));
        }

        if resources.is_empty() {
            return Err(format!("no resources found for domain '{}'", domain));
        }

        let mut summary_lines = vec![format!("Resources in '{}':", domain)];
        for element in &resources {
            if let JsonValue::Object(fields) = element {
                let resource_name = fields
                    .iter()
                    .find(|(key, _)| key == "resource")
                    .and_then(|(_, value)| value.as_str())
                    .unwrap_or_default();
                let verbs = fields
                    .iter()
                    .find(|(key, _)| key == "verbs")
                    .and_then(|(_, verbs_value)| verbs_value.as_array());
                let mut verb_names = Vec::new();
                if let Some(verbs_list) = verbs {
                    for verb in verbs_list {
                        if let Some(name) = verb.get("verb").and_then(|v| v.as_str()) {
                            verb_names.push(name.to_string());
                        }
                    }
                }
                if verb_names.is_empty() {
                    summary_lines.push(format!("  - {}", resource_name));
                } else {
                    summary_lines.push(format!(
                        "  - {} -> {}",
                        resource_name,
                        verb_names.join(", ")
                    ));
                }
            }
        }

        Ok(ToolResult {
            text: summary_lines.join("\n"),
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                ("resources".to_string(), JsonValue::array(resources)),
            ]),
        })
    }

    fn tool_describe_command(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'domain' is required".to_string())?;
        let resource = args
            .get("resource")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'resource' is required".to_string())?;

        let command = commands::command_for(domain, resource)
            .ok_or_else(|| format!("unknown command '{} {}'", domain, resource))?;

        let mut result = Vec::new();
        result.push(("domain".to_string(), JsonValue::String(domain.to_string())));
        result.push((
            "resource".to_string(),
            JsonValue::String(resource.to_string()),
        ));
        result.push((
            "description".to_string(),
            JsonValue::String(command.description().to_string()),
        ));

        let routes = command
            .routes()
            .into_iter()
            .map(|route| {
                JsonValue::object(vec![
                    (
                        "verb".to_string(),
                        JsonValue::String(route.verb.to_string()),
                    ),
                    (
                        "summary".to_string(),
                        JsonValue::String(route.summary.to_string()),
                    ),
                    (
                        "usage".to_string(),
                        JsonValue::String(route.usage.to_string()),
                    ),
                ])
            })
            .collect::<Vec<JsonValue>>();
        result.push(("verbs".to_string(), JsonValue::array(routes)));

        let flags = command
            .flags()
            .into_iter()
            .map(|flag| {
                JsonValue::object(vec![
                    ("long".to_string(), JsonValue::String(flag.long.to_string())),
                    (
                        "short".to_string(),
                        flag.short
                            .map(|c| JsonValue::String(c.to_string()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "description".to_string(),
                        JsonValue::String(flag.description.to_string()),
                    ),
                    (
                        "default".to_string(),
                        flag.default.map(JsonValue::from).unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect::<Vec<JsonValue>>();
        result.push(("flags".to_string(), JsonValue::array(flags)));

        let mut lines = vec![format!(
            "`rb {} {} <verb>` -- {}",
            domain,
            resource,
            command.description()
        )];
        if let Some(JsonValue::Array(verbs)) = result
            .iter()
            .find(|(key, _)| key == "verbs")
            .map(|(_, value)| value)
        {
            for verb in verbs {
                if let Some(verb_name) = verb.get("verb").and_then(|v| v.as_str()) {
                    let summary = verb.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                    lines.push(format!("  - {} -> {}", verb_name, summary));
                }
            }
        }
        if let Some(JsonValue::Array(flag_items)) = result
            .iter()
            .find(|(key, _)| key == "flags")
            .map(|(_, value)| value)
        {
            if !flag_items.is_empty() {
                lines.push("Supported flags:".to_string());
                for flag in flag_items {
                    if let Some(long) = flag.get("long").and_then(|v| v.as_str()) {
                        let desc = flag
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let short = flag
                            .get("short")
                            .and_then(|v| v.as_str())
                            .map(|s| format!("-{}, ", s))
                            .unwrap_or_default();
                        lines.push(format!("  - {}--{} {}", short, long, desc));
                    }
                }
            }
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::Object(result),
        })
    }

    fn tool_search_docs(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let query = args
            .get("query")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'query' is required".to_string())?;

        if query.trim().is_empty() {
            return Err("query must not be empty".to_string());
        }

        // Try hybrid search with embeddings first
        self.ensure_embeddings_loaded();

        if let Some(ref embeddings) = self.embeddings {
            // Use hybrid search
            let config = SearchConfig {
                max_results: 10,
                min_score: 0.1,
                fuzzy_weight: 0.4,
                semantic_weight: 0.6,
                mode: SearchMode::Hybrid,
            };

            let results = hybrid_search(query, &embeddings.documents, &config);

            let json_hits: Vec<JsonValue> = results
                .iter()
                .map(|result| {
                    JsonValue::object(vec![
                        (
                            "path".to_string(),
                            JsonValue::String(result.document.path.clone()),
                        ),
                        (
                            "title".to_string(),
                            JsonValue::String(result.document.title.clone()),
                        ),
                        (
                            "section".to_string(),
                            result
                                .document
                                .section
                                .as_ref()
                                .map(|s| JsonValue::String(s.clone()))
                                .unwrap_or(JsonValue::Null),
                        ),
                        ("score".to_string(), JsonValue::Number(result.score as f64)),
                        (
                            "match_type".to_string(),
                            JsonValue::String(format!("{:?}", result.match_type)),
                        ),
                        (
                            "highlights".to_string(),
                            JsonValue::array(
                                result
                                    .highlights
                                    .iter()
                                    .map(|h| JsonValue::String(h.clone()))
                                    .collect(),
                            ),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(result.document.category.clone()),
                        ),
                    ])
                })
                .collect();

            let mut lines = vec![format!(
                "Hybrid search results for '{}' ({} docs indexed):",
                query,
                embeddings.documents.len()
            )];
            if json_hits.is_empty() {
                lines.push("  - No matches found.".to_string());
            } else {
                for result in &results {
                    let section_str = result
                        .document
                        .section
                        .as_ref()
                        .map(|s| format!(" > {}", s))
                        .unwrap_or_default();
                    lines.push(format!(
                        "  - [{}] {} ({}{}) - score: {:.2}",
                        result.document.category,
                        result.document.title,
                        result.document.path,
                        section_str,
                        result.score
                    ));
                    for highlight in result.highlights.iter().take(2) {
                        lines.push(format!("      {}", highlight));
                    }
                }
            }

            return Ok(ToolResult {
                text: lines.join("\n"),
                data: JsonValue::object(vec![
                    ("query".to_string(), JsonValue::String(query.to_string())),
                    ("mode".to_string(), JsonValue::String("hybrid".to_string())),
                    (
                        "indexed_docs".to_string(),
                        JsonValue::Number(embeddings.documents.len() as f64),
                    ),
                    ("hits".to_string(), JsonValue::array(json_hits)),
                ]),
            });
        }

        // Fallback to basic text search
        let hits = search_documentation(query, 10);
        let json_hits = hits
            .into_iter()
            .map(|hit| {
                JsonValue::object(vec![
                    ("path".to_string(), JsonValue::String(hit.path)),
                    ("line".to_string(), JsonValue::Number(hit.line as f64)),
                    ("snippet".to_string(), JsonValue::String(hit.snippet)),
                ])
            })
            .collect::<Vec<JsonValue>>();

        let mut lines = vec![format!("Search results for '{}' (basic mode):", query)];
        if json_hits.is_empty() {
            lines.push("  - No matches found.".to_string());
        } else {
            for hit in &json_hits {
                let path = hit.get("path").and_then(|v| v.as_str()).unwrap_or_default();
                let line = hit
                    .get("line")
                    .and_then(|v| v.as_f64())
                    .map(|n| n as usize)
                    .unwrap_or(0);
                let snippet = hit
                    .get("snippet")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                lines.push(format!("  - {}:{} -> {}", path, line, snippet));
            }
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::object(vec![
                ("query".to_string(), JsonValue::String(query.to_string())),
                ("mode".to_string(), JsonValue::String("basic".to_string())),
                ("hits".to_string(), JsonValue::array(json_hits)),
            ]),
        })
    }

    fn tool_docs_index(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        let index = build_document_index(8);
        let mut preview = Vec::new();
        for entry in index.iter().take(3) {
            if let Some(path) = entry.get("path").and_then(|v| v.as_str()) {
                let title = entry
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled");
                preview.push(format!("  - {} ({})", title, path));
            }
        }
        let mut lines = vec![format!("Indexed {} documentation files.", index.len())];
        if preview.is_empty() {
            lines.push("No documents located.".to_string());
        } else {
            lines.push("Sample:".to_string());
            lines.extend(preview);
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::object(vec![("documents".to_string(), JsonValue::array(index))]),
        })
    }

    fn tool_docs_get(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let path = args
            .get("path")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'path' is required".to_string())?;
        let section = args.get("section").and_then(|v| v.as_str());

        let doc_path = resolve_doc_path(path)
            .ok_or_else(|| format!("documentation path '{}' is not recognized", path))?;

        let content = fs::read_to_string(&doc_path)
            .map_err(|e| format!("failed to read '{}': {}", doc_path.display(), e))?;

        let output = if let Some(section_name) = section {
            extract_markdown_section(&content, section_name)
                .ok_or_else(|| format!("section '{}' not found in {}", section_name, path))?
        } else {
            content
        };

        let text = if let Some(section_name) = section {
            format!(
                "Returned section '{}' from {} ({} bytes).",
                section_name,
                path,
                output.len()
            )
        } else {
            format!(
                "Returned entire document {} ({} bytes).",
                path,
                output.len()
            )
        };

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("path".to_string(), JsonValue::String(path.to_string())),
                (
                    "section".to_string(),
                    section
                        .map(|s| JsonValue::String(s.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                ("content".to_string(), JsonValue::String(output)),
            ]),
        })
    }

    fn tool_targets_list(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        let db = TargetDatabase::load(default_target_db_path());
        let entries = db
            .targets
            .iter()
            .map(|entry| entry.to_json())
            .collect::<Vec<JsonValue>>();

        let mut lines = vec![format!("Tracked targets: {}", entries.len())];
        for entry in db.targets.iter().take(5) {
            lines.push(format!("  - {} -> {}", entry.name, entry.target));
        }
        if db.targets.len() > 5 {
            lines.push(format!("  ... and {} more.", db.targets.len() - 5));
        }

        Ok(ToolResult {
            text: lines.join("\n"),
            data: JsonValue::object(vec![("targets".to_string(), JsonValue::array(entries))]),
        })
    }

    fn tool_targets_save(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'name' is required".to_string())?;
        let target = args
            .get("target")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'target' is required".to_string())?;
        let notes = args.get("notes").and_then(|value| value.as_str());

        let path = default_target_db_path();
        let mut db = TargetDatabase::load(path.clone());
        let (created, entry) = db.upsert(name, target, notes);
        db.persist()?;

        let action = if created { "Created" } else { "Updated" };
        let text = format!("{} target '{}' -> {}.", action, entry.name, entry.target);

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("created".to_string(), JsonValue::Bool(created)),
                ("target".to_string(), entry.to_json()),
            ]),
        })
    }

    fn tool_targets_remove(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let name = args
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "argument 'name' is required".to_string())?;

        let path = default_target_db_path();
        let mut db = TargetDatabase::load(path.clone());
        let removed = db.remove(name);
        if removed.is_none() {
            return Err(format!("target '{}' not found", name));
        }
        db.persist()?;

        let entry = removed.unwrap();
        Ok(ToolResult {
            text: format!("Removed target '{}' -> {}.", entry.name, entry.target),
            data: JsonValue::object(vec![
                ("removed".to_string(), JsonValue::Bool(true)),
                ("target".to_string(), entry.to_json()),
            ]),
        })
    }

    fn tool_command_run(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let argv = parse_command_arguments(args)?;
        if argv.is_empty() {
            return Err("command requires at least one argument (domain)".to_string());
        }

        if argv.len() >= 2
            && argv[0].eq_ignore_ascii_case("mcp")
            && argv[1].eq_ignore_ascii_case("server")
        {
            return Err(
                "running 'rb mcp server ...' inside MCP is blocked to avoid recursion".to_string(),
            );
        }

        let exe = std::env::current_exe()
            .map_err(|e| format!("failed to resolve current executable: {}", e))?;

        let output = Command::new(exe)
            .args(&argv)
            .env("RB_MCP_BRIDGE", "1")
            .output()
            .map_err(|e| format!("failed to execute command: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let status = output.status.code().unwrap_or(-1);

        let preview = if stdout.trim().is_empty() {
            if stderr.trim().is_empty() {
                "(no output)".to_string()
            } else {
                format!("stderr: {}", truncate_preview(&stderr))
            }
        } else {
            truncate_preview(&stdout)
        };

        let text = format!(
            "Command exited with status {}. Preview: {}",
            status, preview
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "argv".to_string(),
                    JsonValue::array(
                        argv.iter()
                            .map(|arg| JsonValue::String(arg.clone()))
                            .collect(),
                    ),
                ),
                ("status".to_string(), JsonValue::Number(status as f64)),
                ("stdout".to_string(), JsonValue::String(stdout)),
                ("stderr".to_string(), JsonValue::String(stderr)),
            ]),
        })
    }

    // ========== Web Scraping Tool Handlers ==========

    fn tool_web_crawl(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let max_depth = args
            .get("max_depth")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(2);

        let max_pages = args
            .get("max_pages")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(50);

        let mut crawler = WebCrawler::new()
            .with_max_depth(max_depth)
            .with_max_pages(max_pages)
            .with_same_origin(true);

        let result = crawler
            .crawl(url)
            .map_err(|e| format!("crawl failed: {}", e))?;

        let pages_json: Vec<JsonValue> = result
            .pages
            .iter()
            .map(|page| {
                JsonValue::object(vec![
                    ("url".to_string(), JsonValue::String(page.url.clone())),
                    (
                        "title".to_string(),
                        page.meta
                            .title
                            .as_ref()
                            .map(|t| JsonValue::String(t.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "status".to_string(),
                        JsonValue::Number(page.status_code as f64),
                    ),
                    (
                        "links_count".to_string(),
                        JsonValue::Number(page.links.len() as f64),
                    ),
                ])
            })
            .collect();

        let text = format!(
            "Crawled {} pages from '{}' (max depth: {}, links found: {})",
            result.total_urls, url, result.max_depth_reached, result.total_links
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                (
                    "total_pages".to_string(),
                    JsonValue::Number(result.total_urls as f64),
                ),
                (
                    "total_links".to_string(),
                    JsonValue::Number(result.total_links as f64),
                ),
                (
                    "max_depth_reached".to_string(),
                    JsonValue::Number(result.max_depth_reached as f64),
                ),
                ("pages".to_string(), JsonValue::array(pages_json)),
            ]),
        })
    }

    fn tool_web_scrape(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let selector = args
            .get("selector")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'selector' is required".to_string())?;

        let attr = args.get("attr").and_then(|v| v.as_str());

        // Fetch the page
        let client = HttpClient::new();
        let response = client
            .get(url)
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        // Parse HTML
        let body_str = String::from_utf8_lossy(&response.body);
        let doc = Document::parse(&body_str);

        // Select elements
        let elements = doc.select(selector);

        let results: Vec<JsonValue> = elements
            .iter()
            .map(|el| {
                if let Some(attr_name) = attr {
                    el.attr(attr_name)
                        .map(|v| JsonValue::String(v.to_string()))
                        .unwrap_or(JsonValue::Null)
                } else {
                    JsonValue::String(el.text())
                }
            })
            .collect();

        let text = format!(
            "Extracted {} elements from '{}' using selector '{}'",
            results.len(),
            url,
            selector
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                (
                    "selector".to_string(),
                    JsonValue::String(selector.to_string()),
                ),
                ("count".to_string(), JsonValue::Number(results.len() as f64)),
                ("results".to_string(), JsonValue::array(results)),
            ]),
        })
    }

    fn tool_html_select(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let html = args
            .get("html")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'html' is required".to_string())?;

        let selector = args
            .get("selector")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'selector' is required".to_string())?;

        let attr = args.get("attr").and_then(|v| v.as_str());

        // Parse HTML
        let doc = Document::parse(html);

        // Select elements
        let elements = doc.select(selector);

        let results: Vec<JsonValue> = elements
            .iter()
            .map(|el| {
                if let Some(attr_name) = attr {
                    el.attr(attr_name)
                        .map(|v| JsonValue::String(v.to_string()))
                        .unwrap_or(JsonValue::Null)
                } else {
                    JsonValue::String(el.text())
                }
            })
            .collect();

        let text = format!("Selected {} elements using '{}'", results.len(), selector);

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "selector".to_string(),
                    JsonValue::String(selector.to_string()),
                ),
                ("count".to_string(), JsonValue::Number(results.len() as f64)),
                ("results".to_string(), JsonValue::array(results)),
            ]),
        })
    }

    fn tool_web_links(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        use crate::modules::web::extractors::LinkType;

        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let link_type_filter = args
            .get("link_type")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        // Fetch the page
        let client = HttpClient::new();
        let response = client
            .get(url)
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        // Parse HTML
        let body_str = String::from_utf8_lossy(&response.body);
        let doc = Document::parse(&body_str);

        // Extract links
        let all_links = extractors::links(&doc);

        // Filter by type
        let filtered_links: Vec<_> = all_links
            .iter()
            .filter(|link| {
                let is_internal = matches!(link.link_type, LinkType::Internal);
                match link_type_filter {
                    "internal" => is_internal,
                    "external" => !is_internal,
                    _ => true,
                }
            })
            .collect();

        let links_json: Vec<JsonValue> = filtered_links
            .iter()
            .map(|link| {
                let is_internal = matches!(link.link_type, LinkType::Internal);
                JsonValue::object(vec![
                    ("url".to_string(), JsonValue::String(link.url.clone())),
                    ("text".to_string(), JsonValue::String(link.text.clone())),
                    ("is_internal".to_string(), JsonValue::Bool(is_internal)),
                ])
            })
            .collect();

        let text = format!(
            "Extracted {} {} links from '{}'",
            links_json.len(),
            link_type_filter,
            url
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                (
                    "link_type".to_string(),
                    JsonValue::String(link_type_filter.to_string()),
                ),
                (
                    "count".to_string(),
                    JsonValue::Number(links_json.len() as f64),
                ),
                ("links".to_string(), JsonValue::array(links_json)),
            ]),
        })
    }

    fn tool_web_tables(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        // Selector is noted but tables() extracts all tables
        let _selector = args.get("selector").and_then(|v| v.as_str());

        // Fetch the page
        let client = HttpClient::new();
        let response = client
            .get(url)
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        // Parse HTML
        let body_str = String::from_utf8_lossy(&response.body);
        let doc = Document::parse(&body_str);

        // Extract tables
        let tables = extractors::tables(&doc);

        let tables_json: Vec<JsonValue> = tables
            .iter()
            .map(|table| {
                let headers_json: Vec<JsonValue> = table
                    .headers
                    .iter()
                    .map(|h| JsonValue::String(h.clone()))
                    .collect();

                let rows_json: Vec<JsonValue> = table
                    .rows
                    .iter()
                    .map(|row| {
                        JsonValue::array(
                            row.iter()
                                .map(|cell| JsonValue::String(cell.clone()))
                                .collect(),
                        )
                    })
                    .collect();

                JsonValue::object(vec![
                    ("headers".to_string(), JsonValue::array(headers_json)),
                    ("rows".to_string(), JsonValue::array(rows_json)),
                    (
                        "row_count".to_string(),
                        JsonValue::Number(table.rows.len() as f64),
                    ),
                ])
            })
            .collect();

        let text = format!("Extracted {} tables from '{}'", tables_json.len(), url);

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                (
                    "count".to_string(),
                    JsonValue::Number(tables_json.len() as f64),
                ),
                ("tables".to_string(), JsonValue::array(tables_json)),
            ]),
        })
    }

    fn tool_har_record(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let max_depth = args
            .get("max_depth")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(2);

        let max_pages = args
            .get("max_pages")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(20);

        let mut crawler = WebCrawler::new()
            .with_max_depth(max_depth)
            .with_max_pages(max_pages)
            .with_same_origin(true)
            .with_har_recording(true);

        let result = crawler
            .crawl(url)
            .map_err(|e| format!("crawl failed: {}", e))?;

        // Get HAR data
        let har_json = if let Some(recorder) = crawler.har_recorder() {
            let guard = recorder.lock().unwrap();
            let har = &guard.har;

            let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
            let total_response_size: i64 =
                har.log.entries.iter().map(|e| e.response.body_size).sum();

            JsonValue::object(vec![
                (
                    "version".to_string(),
                    JsonValue::String(har.log.version.clone()),
                ),
                (
                    "entries_count".to_string(),
                    JsonValue::Number(har.log.entries.len() as f64),
                ),
                ("total_time_ms".to_string(), JsonValue::Number(total_time)),
                (
                    "total_response_bytes".to_string(),
                    JsonValue::Number(total_response_size.max(0) as f64),
                ),
                ("har_content".to_string(), JsonValue::String(har.to_json())),
            ])
        } else {
            JsonValue::Null
        };

        let text = format!(
            "Recorded HTTP traffic for {} pages from '{}' (HAR entries: {})",
            result.total_urls,
            url,
            if let Some(entries) = har_json.get("entries_count").and_then(|v| v.as_f64()) {
                entries as usize
            } else {
                0
            }
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                (
                    "pages_crawled".to_string(),
                    JsonValue::Number(result.total_urls as f64),
                ),
                ("har".to_string(), har_json),
            ]),
        })
    }

    fn tool_har_analyze(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'content' is required".to_string())?;

        let har = Har::from_json(content).map_err(|e| format!("failed to parse HAR: {}", e))?;

        let total_entries = har.log.entries.len();
        let total_time: f64 = har.log.entries.iter().map(|e| e.time).sum();
        let total_request_size: i64 = har.log.entries.iter().map(|e| e.request.body_size).sum();
        let total_response_size: i64 = har.log.entries.iter().map(|e| e.response.body_size).sum();

        // Count status codes
        let mut status_counts: Vec<(u16, usize)> = Vec::new();
        for entry in &har.log.entries {
            let status = entry.response.status;
            if let Some(pos) = status_counts.iter().position(|(s, _)| *s == status) {
                status_counts[pos].1 += 1;
            } else {
                status_counts.push((status, 1));
            }
        }

        let status_json: Vec<JsonValue> = status_counts
            .iter()
            .map(|(status, count)| {
                JsonValue::object(vec![
                    ("status".to_string(), JsonValue::Number(*status as f64)),
                    ("count".to_string(), JsonValue::Number(*count as f64)),
                ])
            })
            .collect();

        // Get slowest requests
        let mut sorted_entries: Vec<_> = har.log.entries.iter().collect();
        sorted_entries.sort_by(|a, b| {
            b.time
                .partial_cmp(&a.time)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let slowest_json: Vec<JsonValue> = sorted_entries
            .iter()
            .take(5)
            .map(|entry| {
                JsonValue::object(vec![
                    (
                        "url".to_string(),
                        JsonValue::String(entry.request.url.clone()),
                    ),
                    ("time_ms".to_string(), JsonValue::Number(entry.time)),
                    (
                        "status".to_string(),
                        JsonValue::Number(entry.response.status as f64),
                    ),
                ])
            })
            .collect();

        let text = format!(
            "HAR Analysis: {} entries, {:.2}ms total time, {} bytes transferred",
            total_entries,
            total_time,
            total_response_size.max(0)
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "version".to_string(),
                    JsonValue::String(har.log.version.clone()),
                ),
                (
                    "creator".to_string(),
                    JsonValue::String(format!(
                        "{} {}",
                        har.log.creator.name, har.log.creator.version
                    )),
                ),
                (
                    "total_entries".to_string(),
                    JsonValue::Number(total_entries as f64),
                ),
                ("total_time_ms".to_string(), JsonValue::Number(total_time)),
                (
                    "total_request_bytes".to_string(),
                    JsonValue::Number(total_request_size.max(0) as f64),
                ),
                (
                    "total_response_bytes".to_string(),
                    JsonValue::Number(total_response_size.max(0) as f64),
                ),
                ("status_codes".to_string(), JsonValue::array(status_json)),
                (
                    "slowest_requests".to_string(),
                    JsonValue::array(slowest_json),
                ),
            ]),
        })
    }

    // ==================== Vulnerability Intelligence Handlers ====================

    fn tool_vuln_search(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let tech = args
            .get("tech")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'tech' is required".to_string())?;

        let version = args.get("version").and_then(|v| v.as_str());
        let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("nvd");
        let limit = args
            .get("limit")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(10);

        let mut collection = VulnCollection::new();

        // Generate CPE for NVD query
        let cpe = generate_cpe(tech, version);

        // Query NVD
        if source == "nvd" || source == "all" {
            if let Some(ref cpe_str) = cpe {
                let mut nvd_client = NvdClient::new();
                if let Ok(vulns) = nvd_client.query_by_cpe(cpe_str) {
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                }
            }
        }

        // Query OSV for package ecosystems
        if source == "osv" || source == "all" {
            let osv_client = OsvClient::new();
            let ecosystem = map_tech_to_ecosystem(tech);
            if let Ok(vulns) = osv_client.query_package(tech, version, ecosystem) {
                for vuln in vulns {
                    collection.add(vuln);
                }
            }
        }

        // Enrich with KEV data
        let mut kev_client = KevClient::new();
        for vuln in collection.iter_mut() {
            let _ = kev_client.enrich_vulnerability(vuln);
            vuln.risk_score = Some(calculate_risk_score(vuln));
        }

        // Sort and limit results
        let vulns: Vec<_> = collection.into_sorted().into_iter().take(limit).collect();

        let vulns_json: Vec<JsonValue> = vulns.iter().map(vuln_to_json).collect();

        let text = format!(
            "Found {} vulnerabilities for '{}'{} from {}",
            vulns.len(),
            tech,
            version.map(|v| format!(" {}", v)).unwrap_or_default(),
            source
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("tech".to_string(), JsonValue::String(tech.to_string())),
                (
                    "version".to_string(),
                    version
                        .map(|v| JsonValue::String(v.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                ("source".to_string(), JsonValue::String(source.to_string())),
                ("count".to_string(), JsonValue::Number(vulns.len() as f64)),
                ("vulnerabilities".to_string(), JsonValue::array(vulns_json)),
            ]),
        })
    }

    fn tool_vuln_cve(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let cve_id = args
            .get("cve_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'cve_id' is required".to_string())?;

        // Validate CVE format
        if !cve_id.starts_with("CVE-") {
            return Err(format!(
                "Invalid CVE ID format: {}. Expected format: CVE-YYYY-NNNNN",
                cve_id
            ));
        }

        let mut nvd_client = NvdClient::new();
        let mut vuln = nvd_client
            .query_by_cve(cve_id)?
            .ok_or_else(|| format!("CVE not found: {}", cve_id))?;

        // Enrich with KEV
        let mut kev_client = KevClient::new();
        let _ = kev_client.enrich_vulnerability(&mut vuln);

        // Enrich with exploit info
        let exploit_client = ExploitDbClient::new();
        let _ = exploit_client.enrich_vulnerability(&mut vuln);

        // Calculate risk score
        vuln.risk_score = Some(calculate_risk_score(&vuln));

        let text = format!(
            "{} - {} (CVSS: {}, Risk: {}/100{}{})",
            vuln.id,
            if vuln.title.is_empty() {
                "No title"
            } else {
                &vuln.title
            },
            vuln.best_cvss()
                .map(|s| format!("{:.1}", s))
                .unwrap_or_else(|| "N/A".to_string()),
            vuln.risk_score.unwrap_or(0),
            if vuln.cisa_kev { " [KEV]" } else { "" },
            if vuln.has_exploit() { " [EXPLOIT]" } else { "" }
        );

        Ok(ToolResult {
            text,
            data: vuln_to_json(&vuln),
        })
    }

    fn tool_vuln_kev(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let vendor = args.get("vendor").and_then(|v| v.as_str());
        let product = args.get("product").and_then(|v| v.as_str());
        let stats = args.get("stats").and_then(|v| v.as_bool()).unwrap_or(false);

        let mut kev_client = KevClient::new();

        if stats {
            let kev_stats = kev_client.stats()?;

            let top_vendors_json: Vec<JsonValue> = kev_stats
                .top_vendors
                .iter()
                .map(|(vendor, count)| {
                    JsonValue::object(vec![
                        ("vendor".to_string(), JsonValue::String(vendor.clone())),
                        ("count".to_string(), JsonValue::Number(*count as f64)),
                    ])
                })
                .collect();

            let text = format!(
                "CISA KEV Statistics: {} total CVEs, {} used in ransomware campaigns",
                kev_stats.total, kev_stats.ransomware_count
            );

            return Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    (
                        "total".to_string(),
                        JsonValue::Number(kev_stats.total as f64),
                    ),
                    (
                        "ransomware_count".to_string(),
                        JsonValue::Number(kev_stats.ransomware_count as f64),
                    ),
                    (
                        "top_vendors".to_string(),
                        JsonValue::array(top_vendors_json),
                    ),
                ]),
            });
        }

        let entries = if let Some(v) = vendor {
            kev_client.get_by_vendor(v)?
        } else if let Some(p) = product {
            kev_client.get_by_product(p)?
        } else {
            kev_client.get_all()?
        };

        let entries_json: Vec<JsonValue> = entries
            .iter()
            .take(50) // Limit to 50 entries
            .map(|e| {
                JsonValue::object(vec![
                    ("cve_id".to_string(), JsonValue::String(e.cve_id.clone())),
                    (
                        "vendor".to_string(),
                        JsonValue::String(e.vendor_project.clone()),
                    ),
                    ("product".to_string(), JsonValue::String(e.product.clone())),
                    (
                        "name".to_string(),
                        JsonValue::String(e.vulnerability_name.clone()),
                    ),
                    (
                        "date_added".to_string(),
                        JsonValue::String(e.date_added.clone()),
                    ),
                    (
                        "due_date".to_string(),
                        JsonValue::String(e.due_date.clone()),
                    ),
                    (
                        "ransomware".to_string(),
                        JsonValue::Bool(e.known_ransomware_use),
                    ),
                    (
                        "description".to_string(),
                        JsonValue::String(e.short_description.clone()),
                    ),
                ])
            })
            .collect();

        let filter_desc = vendor
            .map(|v| format!(" for vendor '{}'", v))
            .or_else(|| product.map(|p| format!(" for product '{}'", p)))
            .unwrap_or_default();

        let text = format!("CISA KEV Catalog: {} entries{}", entries.len(), filter_desc);

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("count".to_string(), JsonValue::Number(entries.len() as f64)),
                ("entries".to_string(), JsonValue::array(entries_json)),
            ]),
        })
    }

    fn tool_vuln_exploit(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'query' is required".to_string())?;

        let limit = args
            .get("limit")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize)
            .unwrap_or(10);

        let exploit_client = ExploitDbClient::new();
        let exploits = exploit_client.search(query)?;

        let exploits_json: Vec<JsonValue> = exploits
            .iter()
            .take(limit)
            .map(|e| {
                let exploit_ref = e.to_exploit_ref();
                JsonValue::object(vec![
                    ("id".to_string(), JsonValue::String(e.id.clone())),
                    ("title".to_string(), JsonValue::String(e.title.clone())),
                    (
                        "platform".to_string(),
                        e.platform
                            .as_ref()
                            .map(|p| JsonValue::String(p.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "exploit_type".to_string(),
                        e.exploit_type
                            .as_ref()
                            .map(|t| JsonValue::String(t.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "date".to_string(),
                        e.date
                            .as_ref()
                            .map(|d| JsonValue::String(d.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    ("url".to_string(), JsonValue::String(exploit_ref.url)),
                    ("verified".to_string(), JsonValue::Bool(e.verified)),
                ])
            })
            .collect();

        let text = format!(
            "Exploit-DB: Found {} exploits for '{}'",
            exploits.len().min(limit),
            query
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("query".to_string(), JsonValue::String(query.to_string())),
                (
                    "count".to_string(),
                    JsonValue::Number(exploits.len().min(limit) as f64),
                ),
                ("exploits".to_string(), JsonValue::array(exploits_json)),
            ]),
        })
    }

    fn tool_vuln_fingerprint(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "argument 'url' is required".to_string())?;

        let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("nvd");

        // Fingerprint the URL
        let fingerprinter = WebFingerprinter::new();
        let result = fingerprinter.fingerprint(url)?;
        let techs = &result.technologies;

        if techs.is_empty() {
            return Ok(ToolResult {
                text: format!("No technologies detected for '{}'", url),
                data: JsonValue::object(vec![
                    ("url".to_string(), JsonValue::String(url.to_string())),
                    ("technologies".to_string(), JsonValue::array(vec![])),
                    ("vulnerabilities".to_string(), JsonValue::array(vec![])),
                ]),
            });
        }

        let mut collection = VulnCollection::new();
        let mut kev_client = KevClient::new();

        // For each detected technology, search for vulnerabilities
        for tech in techs {
            let cpe = generate_cpe(&tech.name, tech.version.as_deref());

            // Query NVD
            if source == "nvd" || source == "all" {
                if let Some(ref cpe_str) = cpe {
                    let mut nvd_client = NvdClient::new();
                    if let Ok(vulns) = nvd_client.query_by_cpe(cpe_str) {
                        for vuln in vulns {
                            collection.add(vuln);
                        }
                    }
                }
            }

            // Query OSV for packages
            if source == "osv" || source == "all" {
                let osv_client = OsvClient::new();
                let ecosystem = map_tech_to_ecosystem(&tech.name);
                if let Ok(vulns) =
                    osv_client.query_package(&tech.name, tech.version.as_deref(), ecosystem)
                {
                    for vuln in vulns {
                        collection.add(vuln);
                    }
                }
            }
        }

        // Enrich with KEV and calculate risk scores
        for vuln in collection.iter_mut() {
            let _ = kev_client.enrich_vulnerability(vuln);
            vuln.risk_score = Some(calculate_risk_score(vuln));
        }

        let vulns: Vec<_> = collection.into_sorted().into_iter().take(20).collect();

        let techs_json: Vec<JsonValue> = techs
            .iter()
            .map(|t| {
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(t.name.clone())),
                    (
                        "version".to_string(),
                        t.version
                            .as_ref()
                            .map(|v| JsonValue::String(v.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "confidence".to_string(),
                        JsonValue::String(format!("{}", t.confidence)),
                    ),
                    (
                        "category".to_string(),
                        JsonValue::String(format!("{:?}", t.category)),
                    ),
                ])
            })
            .collect();

        let vulns_json: Vec<JsonValue> = vulns.iter().map(vuln_to_json).collect();

        let text = format!(
            "Fingerprint of '{}': {} technologies detected, {} vulnerabilities found",
            url,
            techs.len(),
            vulns.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("url".to_string(), JsonValue::String(url.to_string())),
                ("technologies".to_string(), JsonValue::array(techs_json)),
                (
                    "vulnerability_count".to_string(),
                    JsonValue::Number(vulns.len() as f64),
                ),
                ("vulnerabilities".to_string(), JsonValue::array(vulns_json)),
            ]),
        })
    }

    /// Query DNSDumpster for DNS intelligence
    fn tool_recon_dnsdumpster(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        let client = DnsDumpsterClient::new();
        let result = client.query(domain)?;

        let unique_subdomains = result.unique_subdomains();

        // Build JSON for DNS records
        let dns_records_json: Vec<JsonValue> = result
            .dns_records
            .iter()
            .map(|r| {
                JsonValue::object(vec![
                    ("host".to_string(), JsonValue::String(r.host.clone())),
                    ("type".to_string(), JsonValue::String(r.record_type.clone())),
                    ("value".to_string(), JsonValue::String(r.value.clone())),
                    (
                        "ip".to_string(),
                        r.ip.as_ref()
                            .map(|i| JsonValue::String(i.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "country".to_string(),
                        r.country
                            .as_ref()
                            .map(|c| JsonValue::String(c.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect();

        // Build JSON for MX records
        let mx_records_json: Vec<JsonValue> = result
            .mx_records
            .iter()
            .map(|r| {
                JsonValue::object(vec![
                    ("host".to_string(), JsonValue::String(r.host.clone())),
                    ("value".to_string(), JsonValue::String(r.value.clone())),
                    (
                        "ip".to_string(),
                        r.ip.as_ref()
                            .map(|i| JsonValue::String(i.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect();

        // Build text summary
        let text = format!(
            "DNSDumpster results for {}:\n- DNS Records: {}\n- MX Records: {}\n- TXT Records: {}\n- Subdomains: {}",
            domain,
            result.dns_records.len(),
            result.mx_records.len(),
            result.txt_records.len(),
            unique_subdomains.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                (
                    "dns_records".to_string(),
                    JsonValue::array(dns_records_json),
                ),
                ("mx_records".to_string(), JsonValue::array(mx_records_json)),
                (
                    "txt_records".to_string(),
                    JsonValue::array(
                        result
                            .txt_records
                            .iter()
                            .map(|t| JsonValue::String(t.clone()))
                            .collect(),
                    ),
                ),
                (
                    "subdomains".to_string(),
                    JsonValue::array(
                        unique_subdomains
                            .iter()
                            .map(|s| JsonValue::String(s.clone()))
                            .collect(),
                    ),
                ),
            ]),
        })
    }

    /// High-performance Mass DNS bruteforce
    fn tool_recon_massdns(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        // Build scanner config
        let mut config = MassDnsConfig::default();

        if let Some(threads) = args.get("threads").and_then(|v| v.as_f64()) {
            config.threads = (threads as usize).max(1).min(100);
        }

        // Load wordlist
        let wordlist = if let Some(path) = args.get("wordlist").and_then(|v| v.as_str()) {
            load_wordlist(path)?
        } else {
            common_subdomains()
        };

        let scanner = MassDnsScanner::with_config(config);
        let result = scanner.bruteforce(domain, &wordlist)?;

        // Build JSON for resolved subdomains
        let resolved_json: Vec<JsonValue> = result
            .resolved
            .iter()
            .map(|r| {
                JsonValue::object(vec![
                    (
                        "subdomain".to_string(),
                        JsonValue::String(r.subdomain.clone()),
                    ),
                    (
                        "ips".to_string(),
                        JsonValue::array(
                            r.ips
                                .iter()
                                .map(|ip| JsonValue::String(ip.clone()))
                                .collect(),
                        ),
                    ),
                    (
                        "cname".to_string(),
                        r.cname
                            .as_ref()
                            .map(|c| JsonValue::String(c.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "resolve_time_ms".to_string(),
                        JsonValue::Number(r.resolve_time_ms as f64),
                    ),
                ])
            })
            .collect();

        // Build text summary
        let text = format!(
            "MassDNS bruteforce for {}:\n- Total attempts: {}\n- Resolved: {}\n- Wildcard detected: {}\n- Duration: {}ms",
            domain,
            result.total_attempts,
            result.resolved.len(),
            result.wildcard_detected,
            result.duration_ms
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(result.domain)),
                (
                    "total_attempts".to_string(),
                    JsonValue::Number(result.total_attempts as f64),
                ),
                (
                    "resolved_count".to_string(),
                    JsonValue::Number(result.resolved.len() as f64),
                ),
                (
                    "wildcard_detected".to_string(),
                    JsonValue::Bool(result.wildcard_detected),
                ),
                (
                    "wildcard_ips".to_string(),
                    JsonValue::array(
                        result
                            .wildcard_ips
                            .iter()
                            .map(|ip| JsonValue::String(ip.clone()))
                            .collect(),
                    ),
                ),
                (
                    "duration_ms".to_string(),
                    JsonValue::Number(result.duration_ms as f64),
                ),
                ("resolved".to_string(), JsonValue::array(resolved_json)),
            ]),
        })
    }

    // ========================================================================
    // NETWORK TOOL HANDLERS
    // ========================================================================

    fn tool_network_scan(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target_str = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        // Resolve hostname to IP if needed
        let target_ip: IpAddr = target_str.parse().or_else(|_| {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            format!("{}:80", target_str)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .ok_or_else(|| format!("Could not resolve hostname: {}", target_str))
        })?;

        let mut scanner = PortScanner::new(target_ip);

        // Configure timeout
        if let Some(timeout) = args.get("timeout").and_then(|v| v.as_f64()) {
            scanner = scanner.with_timeout(timeout as u64);
        }

        // Configure threads
        if let Some(threads) = args.get("threads").and_then(|v| v.as_f64()) {
            scanner = scanner.with_threads(threads as usize);
        }

        // Determine ports to scan
        let ports_arg = args
            .get("ports")
            .and_then(|v| v.as_str())
            .unwrap_or("common");
        let ports: Vec<u16> = match ports_arg {
            "common" => PortScanner::get_common_ports(),
            "web" => vec![80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
            "full" => (1..=65535).collect(),
            custom => {
                // Parse custom port specification
                let mut result = Vec::new();
                for part in custom.split(',') {
                    let part = part.trim();
                    if part.contains('-') {
                        // Range like "1-1000"
                        let bounds: Vec<&str> = part.split('-').collect();
                        if bounds.len() == 2 {
                            if let (Ok(start), Ok(end)) =
                                (bounds[0].parse::<u16>(), bounds[1].parse::<u16>())
                            {
                                result.extend(start..=end);
                            }
                        }
                    } else if let Ok(port) = part.parse::<u16>() {
                        result.push(port);
                    }
                }
                if result.is_empty() {
                    PortScanner::get_common_ports()
                } else {
                    result
                }
            }
        };

        let results = scanner.scan_ports(&ports);

        // Filter open ports
        let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();

        // Build JSON response
        let ports_json: Vec<JsonValue> = open_ports
            .iter()
            .map(|r| {
                JsonValue::object(vec![
                    ("port".to_string(), JsonValue::Number(r.port as f64)),
                    ("state".to_string(), JsonValue::String("open".to_string())),
                    (
                        "service".to_string(),
                        r.service
                            .as_ref()
                            .map(|s| JsonValue::String(s.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                    (
                        "banner".to_string(),
                        r.banner
                            .as_ref()
                            .map(|b| JsonValue::String(b.clone()))
                            .unwrap_or(JsonValue::Null),
                    ),
                ])
            })
            .collect();

        let text = format!(
            "Port scan of {}: {} open ports found out of {} scanned",
            target_str,
            open_ports.len(),
            ports.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "target".to_string(),
                    JsonValue::String(target_str.to_string()),
                ),
                (
                    "target_ip".to_string(),
                    JsonValue::String(target_ip.to_string()),
                ),
                (
                    "ports_scanned".to_string(),
                    JsonValue::Number(ports.len() as f64),
                ),
                (
                    "open_count".to_string(),
                    JsonValue::Number(open_ports.len() as f64),
                ),
                ("open_ports".to_string(), JsonValue::array(ports_json)),
            ]),
        })
    }

    fn tool_network_ping(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        // Try to connect to common ports to check if host is up
        let common_ports = [80, 443, 22, 21, 25, 8080];
        let timeout = Duration::from_millis(2000);

        let mut reachable = false;
        let mut open_port = None;
        let mut response_time = Duration::ZERO;

        for port in &common_ports {
            let start = std::time::Instant::now();
            let addr = format!("{}:{}", target, port);
            if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                if std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
                    reachable = true;
                    open_port = Some(*port);
                    response_time = start.elapsed();
                    break;
                }
            } else {
                // Try resolving hostname
                use std::net::ToSocketAddrs;
                if let Ok(mut addrs) = addr.to_socket_addrs() {
                    if let Some(socket_addr) = addrs.next() {
                        if std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
                            reachable = true;
                            open_port = Some(*port);
                            response_time = start.elapsed();
                            break;
                        }
                    }
                }
            }
        }

        let text = if reachable {
            format!(
                "Host {} is UP (port {} responded in {}ms)",
                target,
                open_port.unwrap_or(0),
                response_time.as_millis()
            )
        } else {
            format!("Host {} appears to be DOWN or filtered", target)
        };

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("target".to_string(), JsonValue::String(target.to_string())),
                ("reachable".to_string(), JsonValue::Bool(reachable)),
                (
                    "responding_port".to_string(),
                    open_port
                        .map(|p| JsonValue::Number(p as f64))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "response_time_ms".to_string(),
                    JsonValue::Number(response_time.as_millis() as f64),
                ),
            ]),
        })
    }

    fn tool_network_health(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        let ports_str = args
            .get("ports")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: ports")?;

        let ports: Vec<u16> = ports_str
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();

        if ports.is_empty() {
            return Err("No valid ports provided".to_string());
        }

        let timeout = Duration::from_millis(2000);
        let mut results = Vec::new();

        for port in &ports {
            let start = std::time::Instant::now();
            let addr = format!("{}:{}", target, port);
            let is_open = if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
            } else {
                use std::net::ToSocketAddrs;
                addr.to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|sa| std::net::TcpStream::connect_timeout(&sa, timeout).is_ok())
                    .unwrap_or(false)
            };
            let elapsed = start.elapsed();

            results.push(JsonValue::object(vec![
                ("port".to_string(), JsonValue::Number(*port as f64)),
                (
                    "status".to_string(),
                    JsonValue::String(if is_open { "open" } else { "closed" }.to_string()),
                ),
                (
                    "response_time_ms".to_string(),
                    JsonValue::Number(elapsed.as_millis() as f64),
                ),
            ]));
        }

        let open_count = results
            .iter()
            .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("open"))
            .count();

        let text = format!(
            "Health check for {}: {}/{} ports open",
            target,
            open_count,
            ports.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("target".to_string(), JsonValue::String(target.to_string())),
                (
                    "total_ports".to_string(),
                    JsonValue::Number(ports.len() as f64),
                ),
                (
                    "open_count".to_string(),
                    JsonValue::Number(open_count as f64),
                ),
                ("results".to_string(), JsonValue::array(results)),
            ]),
        })
    }

    // ========================================================================
    // DNS TOOL HANDLERS
    // ========================================================================

    fn tool_dns_lookup(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        let record_type = args
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("A")
            .to_uppercase();

        let server = args
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or("8.8.8.8");

        let client = DnsClient::new(server);

        let query_type = match record_type.as_str() {
            "A" => crate::protocols::dns::DnsRecordType::A,
            "AAAA" => crate::protocols::dns::DnsRecordType::AAAA,
            "MX" => crate::protocols::dns::DnsRecordType::MX,
            "NS" => crate::protocols::dns::DnsRecordType::NS,
            "TXT" => crate::protocols::dns::DnsRecordType::TXT,
            "CNAME" => crate::protocols::dns::DnsRecordType::CNAME,
            "SOA" => crate::protocols::dns::DnsRecordType::SOA,
            _ => return Err(format!("Unsupported record type: {}", record_type)),
        };

        let answers = client.query(domain, query_type)?;

        let records_json: Vec<JsonValue> = answers
            .iter()
            .map(|r| {
                // Format DnsRdata as string
                let data_str = match &r.data {
                    crate::protocols::dns::DnsRdata::A(ip) => ip.clone(),
                    crate::protocols::dns::DnsRdata::AAAA(ip) => ip.clone(),
                    crate::protocols::dns::DnsRdata::NS(ns) => ns.clone(),
                    crate::protocols::dns::DnsRdata::CNAME(name) => name.clone(),
                    crate::protocols::dns::DnsRdata::PTR(ptr) => ptr.clone(),
                    crate::protocols::dns::DnsRdata::MX {
                        preference,
                        exchange,
                    } => {
                        format!("{} {}", preference, exchange)
                    }
                    crate::protocols::dns::DnsRdata::TXT(texts) => texts.join(" "),
                    crate::protocols::dns::DnsRdata::SOA {
                        mname,
                        rname,
                        serial,
                        ..
                    } => {
                        format!("{} {} {}", mname, rname, serial)
                    }
                    crate::protocols::dns::DnsRdata::Raw(bytes) => {
                        format!(
                            "0x{}",
                            bytes
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>()
                        )
                    }
                };
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(r.name.clone())),
                    (
                        "type".to_string(),
                        JsonValue::String(format!("{}", r.record_type)),
                    ),
                    ("ttl".to_string(), JsonValue::Number(r.ttl as f64)),
                    ("data".to_string(), JsonValue::String(data_str)),
                ])
            })
            .collect();

        let text = format!(
            "DNS {} lookup for {}: {} records found",
            record_type,
            domain,
            records_json.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                ("type".to_string(), JsonValue::String(record_type)),
                ("server".to_string(), JsonValue::String(server.to_string())),
                (
                    "record_count".to_string(),
                    JsonValue::Number(records_json.len() as f64),
                ),
                ("records".to_string(), JsonValue::array(records_json)),
            ]),
        })
    }

    fn tool_dns_resolve(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        let client = DnsClient::new("8.8.8.8");
        let answers = client.query(domain, crate::protocols::dns::DnsRecordType::A)?;

        let ips: Vec<String> = answers
            .iter()
            .filter_map(|r| {
                if let crate::protocols::dns::DnsRdata::A(ip) = &r.data {
                    Some(ip.clone())
                } else {
                    None
                }
            })
            .collect();

        let text = if ips.is_empty() {
            format!("No IP addresses found for {}", domain)
        } else {
            format!("{} resolves to: {}", domain, ips.join(", "))
        };

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                (
                    "ips".to_string(),
                    JsonValue::array(ips.iter().map(|ip| JsonValue::String(ip.clone())).collect()),
                ),
            ]),
        })
    }

    // ========================================================================
    // TLS TOOL HANDLERS
    // ========================================================================

    fn tool_tls_cert(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let host = args
            .get("host")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: host")?;

        // Parse host:port
        let (hostname, port) = if host.contains(':') {
            let parts: Vec<&str> = host.splitn(2, ':').collect();
            (
                parts[0],
                parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443),
            )
        } else {
            (host, 443)
        };

        // Use openssl s_client to get certificate (fallback since we don't have full TLS impl)
        let output = Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("{}:{}", hostname, port),
                "-servername",
                hostname,
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("Failed to execute openssl: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Parse basic certificate info
        let mut subject = String::new();
        let mut issuer = String::new();
        let mut not_before = String::new();
        let mut not_after = String::new();

        for line in combined.lines() {
            let line = line.trim();
            if line.starts_with("subject=") {
                subject = line.trim_start_matches("subject=").trim().to_string();
            } else if line.starts_with("issuer=") {
                issuer = line.trim_start_matches("issuer=").trim().to_string();
            } else if line.starts_with("notBefore=") {
                not_before = line.trim_start_matches("notBefore=").trim().to_string();
            } else if line.starts_with("notAfter=") {
                not_after = line.trim_start_matches("notAfter=").trim().to_string();
            }
        }

        let text = format!(
            "TLS Certificate for {}:{}\nSubject: {}\nIssuer: {}\nValid: {} to {}",
            hostname, port, subject, issuer, not_before, not_after
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("host".to_string(), JsonValue::String(hostname.to_string())),
                ("port".to_string(), JsonValue::Number(port as f64)),
                ("subject".to_string(), JsonValue::String(subject)),
                ("issuer".to_string(), JsonValue::String(issuer)),
                ("not_before".to_string(), JsonValue::String(not_before)),
                ("not_after".to_string(), JsonValue::String(not_after)),
            ]),
        })
    }

    fn tool_tls_audit(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let host = args
            .get("host")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: host")?;

        // Parse host:port
        let (hostname, port) = if host.contains(':') {
            let parts: Vec<&str> = host.splitn(2, ':').collect();
            (
                parts[0],
                parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443),
            )
        } else {
            (host, 443)
        };

        // Get certificate info first
        let cert_result = self.tool_tls_cert(args)?;

        // Check supported TLS versions
        let mut supported_versions = Vec::new();
        for version in &["tls1", "tls1_1", "tls1_2", "tls1_3"] {
            let output = Command::new("openssl")
                .args([
                    "s_client",
                    "-connect",
                    &format!("{}:{}", hostname, port),
                    &format!("-{}", version),
                    "-servername",
                    hostname,
                ])
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output();

            if let Ok(out) = output {
                if out.status.success()
                    || String::from_utf8_lossy(&out.stdout).contains("Certificate chain")
                {
                    supported_versions.push(version.replace("_", ".").replace("tls", "TLS "));
                }
            }
        }

        let mut issues = Vec::new();
        if supported_versions
            .iter()
            .any(|v| v.contains("1.0") || v.contains("1.1"))
        {
            issues.push("Deprecated TLS versions supported (TLS 1.0/1.1)");
        }

        let issues_str = if issues.is_empty() {
            "None".to_string()
        } else {
            issues.join(", ")
        };
        let text = format!(
            "TLS Audit for {}:{}\nSupported versions: {}\nIssues: {}",
            hostname,
            port,
            supported_versions.join(", "),
            issues_str
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("host".to_string(), JsonValue::String(hostname.to_string())),
                ("port".to_string(), JsonValue::Number(port as f64)),
                (
                    "supported_versions".to_string(),
                    JsonValue::array(
                        supported_versions
                            .iter()
                            .map(|v| JsonValue::String(v.clone()))
                            .collect(),
                    ),
                ),
                (
                    "issues".to_string(),
                    JsonValue::array(
                        issues
                            .iter()
                            .map(|i| JsonValue::String(i.to_string()))
                            .collect(),
                    ),
                ),
                ("certificate".to_string(), cert_result.data),
            ]),
        })
    }

    // ========================================================================
    // RECON TOOL HANDLERS
    // ========================================================================

    fn tool_recon_whois(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        let client = WhoisClient::new();
        let result = client.query(domain)?;

        let text = format!(
            "WHOIS for {}:\nRegistrar: {}\nCreated: {}\nExpires: {}\nNameservers: {}",
            domain,
            result.registrar.as_deref().unwrap_or("Unknown"),
            result.creation_date.as_deref().unwrap_or("Unknown"),
            result.expiration_date.as_deref().unwrap_or("Unknown"),
            result.name_servers.join(", ")
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                (
                    "registrar".to_string(),
                    result
                        .registrar
                        .map(|r| JsonValue::String(r))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "creation_date".to_string(),
                    result
                        .creation_date
                        .map(|d| JsonValue::String(d))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "expiration_date".to_string(),
                    result
                        .expiration_date
                        .map(|d| JsonValue::String(d))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "updated_date".to_string(),
                    result
                        .updated_date
                        .map(|d| JsonValue::String(d))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "name_servers".to_string(),
                    JsonValue::array(
                        result
                            .name_servers
                            .iter()
                            .map(|ns| JsonValue::String(ns.clone()))
                            .collect(),
                    ),
                ),
                (
                    "status".to_string(),
                    JsonValue::array(
                        result
                            .status
                            .iter()
                            .map(|s| JsonValue::String(s.clone()))
                            .collect(),
                    ),
                ),
            ]),
        })
    }

    fn tool_recon_subdomains(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        let passive_only = args
            .get("passive")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let mut all_subdomains = HashSet::new();

        // Use CT logs via crt.sh
        if let Ok(crtsh_result) = CrtShClient::new().query_subdomains(domain) {
            for sub in crtsh_result {
                all_subdomains.insert(sub);
            }
        }

        // If not passive only, use DNS bruteforce
        if !passive_only {
            let config = MassDnsConfig::default();
            let scanner = MassDnsScanner::with_config(config);
            let wordlist = common_subdomains();
            if let Ok(result) = scanner.bruteforce(domain, &wordlist) {
                for r in result.resolved {
                    all_subdomains.insert(r.subdomain);
                }
            }
        }

        let subdomains: Vec<String> = all_subdomains.into_iter().collect();

        let text = format!(
            "Subdomain enumeration for {}: {} subdomains found{}",
            domain,
            subdomains.len(),
            if passive_only { " (passive only)" } else { "" }
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                (
                    "count".to_string(),
                    JsonValue::Number(subdomains.len() as f64),
                ),
                ("passive_only".to_string(), JsonValue::Bool(passive_only)),
                (
                    "subdomains".to_string(),
                    JsonValue::array(
                        subdomains
                            .iter()
                            .map(|s| JsonValue::String(s.clone()))
                            .collect(),
                    ),
                ),
            ]),
        })
    }

    fn tool_recon_crtsh(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let domain = args
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: domain")?;

        let client = CrtShClient::new();
        let subdomains = client.query_subdomains(domain)?;

        let text = format!(
            "crt.sh query for {}: {} unique subdomains found in CT logs",
            domain,
            subdomains.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("domain".to_string(), JsonValue::String(domain.to_string())),
                (
                    "count".to_string(),
                    JsonValue::Number(subdomains.len() as f64),
                ),
                (
                    "subdomains".to_string(),
                    JsonValue::array(
                        subdomains
                            .iter()
                            .map(|s| JsonValue::String(s.clone()))
                            .collect(),
                    ),
                ),
            ]),
        })
    }

    // ========================================================================
    // INTEL TOOL HANDLERS (MITRE ATT&CK)
    // ========================================================================

    fn tool_intel_mitre_map(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let mapper = TechniqueMapper::new();

        let mut all_techniques = Vec::new();

        // Map ports
        if let Some(ports_str) = args.get("ports").and_then(|v| v.as_str()) {
            let ports: Vec<u16> = ports_str
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();

            for port in ports {
                let techniques = mapper.map_port(port);
                all_techniques.extend(techniques);
            }
        }

        // Map CVEs
        if let Some(cves_str) = args.get("cves").and_then(|v| v.as_str()) {
            for cve in cves_str.split(',').map(|s| s.trim()) {
                // map_cve requires (cve_id, description) - use cve as description placeholder
                let techniques = mapper.map_cve(cve, cve);
                all_techniques.extend(techniques);
            }
        }

        // Map technologies/fingerprints
        if let Some(techs_str) = args.get("technologies").and_then(|v| v.as_str()) {
            for tech in techs_str.split(',').map(|s| s.trim()) {
                let techniques = mapper.map_fingerprint(tech);
                all_techniques.extend(techniques);
            }
        }

        // Deduplicate by technique_id
        all_techniques.sort_by(|a, b| a.technique_id.cmp(&b.technique_id));
        all_techniques.dedup_by(|a, b| a.technique_id == b.technique_id);

        let techniques_json: Vec<JsonValue> = all_techniques
            .iter()
            .map(|t| {
                JsonValue::object(vec![
                    ("id".to_string(), JsonValue::String(t.technique_id.clone())),
                    ("name".to_string(), JsonValue::String(t.name.clone())),
                    ("tactic".to_string(), JsonValue::String(t.tactic.clone())),
                    ("reason".to_string(), JsonValue::String(t.reason.clone())),
                    (
                        "confidence".to_string(),
                        JsonValue::String(format!("{:?}", t.confidence)),
                    ),
                ])
            })
            .collect();

        let text = format!(
            "MITRE ATT&CK mapping: {} techniques identified",
            all_techniques.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "technique_count".to_string(),
                    JsonValue::Number(all_techniques.len() as f64),
                ),
                ("techniques".to_string(), JsonValue::array(techniques_json)),
            ]),
        })
    }

    fn tool_intel_mitre_layer(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let techniques_str = args
            .get("techniques")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: techniques")?;

        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("RedBlue Assessment");

        let technique_ids: Vec<String> = techniques_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        // Create MappedTechnique structs for the given IDs
        let techniques: Vec<crate::modules::intel::mapper::MappedTechnique> = technique_ids
            .iter()
            .map(|id| crate::modules::intel::mapper::MappedTechnique {
                technique_id: id.clone(),
                name: id.clone(), // Use ID as name placeholder
                reason: "User provided".to_string(),
                tactic: "unknown".to_string(),
                confidence: crate::modules::intel::mapper::Confidence::Medium,
                source: crate::modules::intel::mapper::MappingSource::Port,
                original_value: id.clone(),
            })
            .collect();

        let layer = create_layer_from_techniques(&techniques, name, "manual");
        let layer_json = layer.to_json();

        let text = format!(
            "Generated ATT&CK Navigator layer '{}' with {} techniques",
            name,
            technique_ids.len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "layer_name".to_string(),
                    JsonValue::String(name.to_string()),
                ),
                (
                    "technique_count".to_string(),
                    JsonValue::Number(technique_ids.len() as f64),
                ),
                ("layer_json".to_string(), JsonValue::String(layer_json)),
            ]),
        })
    }

    fn tool_intel_ioc_extract(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        let extractor = IocExtractor::new(target);
        let mut collection = IocCollection::new();

        // Extract from ports if provided
        if let Some(ports_str) = args.get("ports").and_then(|v| v.as_str()) {
            let ports: Vec<u16> = ports_str
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect();

            let iocs = extractor.extract_from_port_scan(target, &ports);
            for ioc in iocs {
                collection.add(ioc);
            }
        }

        // Add basic IOC for the target itself
        let target_ioc = crate::modules::intel::ioc::Ioc::new(
            crate::modules::intel::ioc::IocType::Domain,
            target,
            crate::modules::intel::ioc::IocSource::DnsQuery,
            100,
            target,
        );
        collection.add(target_ioc);

        let iocs_json: Vec<JsonValue> = collection
            .all()
            .iter()
            .map(|ioc| {
                JsonValue::object(vec![
                    (
                        "type".to_string(),
                        JsonValue::String(format!("{:?}", ioc.ioc_type)),
                    ),
                    ("value".to_string(), JsonValue::String(ioc.value.clone())),
                    (
                        "confidence".to_string(),
                        JsonValue::Number(ioc.confidence_score as f64),
                    ),
                    (
                        "source".to_string(),
                        JsonValue::String(format!("{:?}", ioc.source)),
                    ),
                    (
                        "tags".to_string(),
                        JsonValue::array(
                            ioc.tags
                                .iter()
                                .map(|t| JsonValue::String(t.clone()))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect();

        let text = format!(
            "IOC extraction for {}: {} indicators collected",
            target,
            collection.all().len()
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("target".to_string(), JsonValue::String(target.to_string())),
                (
                    "ioc_count".to_string(),
                    JsonValue::Number(collection.all().len() as f64),
                ),
                ("iocs".to_string(), JsonValue::array(iocs_json)),
            ]),
        })
    }

    // ========================================================================
    // EVASION TOOL HANDLERS
    // ========================================================================

    fn tool_evasion_sandbox(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        // Run individual checks
        let vm_files = sandbox::check_vm_files();
        let sandbox_processes = sandbox::check_sandbox_processes();
        let timing_anomaly = sandbox::check_timing_anomaly();
        let low_resources = sandbox::check_low_resources();
        let suspicious_username = sandbox::check_suspicious_username();
        let debugger = sandbox::check_debugger();

        // Get overall score and detection status
        let score = sandbox::sandbox_score();
        let is_sandbox = sandbox::detect_sandbox();

        // Build indicators list
        let indicators_json = vec![
            JsonValue::object(vec![
                (
                    "name".to_string(),
                    JsonValue::String("VM Files".to_string()),
                ),
                ("detected".to_string(), JsonValue::Bool(vm_files)),
                ("weight".to_string(), JsonValue::Number(30.0)),
            ]),
            JsonValue::object(vec![
                (
                    "name".to_string(),
                    JsonValue::String("Sandbox Processes".to_string()),
                ),
                ("detected".to_string(), JsonValue::Bool(sandbox_processes)),
                ("weight".to_string(), JsonValue::Number(25.0)),
            ]),
            JsonValue::object(vec![
                (
                    "name".to_string(),
                    JsonValue::String("Timing Anomaly".to_string()),
                ),
                ("detected".to_string(), JsonValue::Bool(timing_anomaly)),
                ("weight".to_string(), JsonValue::Number(40.0)),
            ]),
            JsonValue::object(vec![
                (
                    "name".to_string(),
                    JsonValue::String("Low Resources".to_string()),
                ),
                ("detected".to_string(), JsonValue::Bool(low_resources)),
                ("weight".to_string(), JsonValue::Number(15.0)),
            ]),
            JsonValue::object(vec![
                (
                    "name".to_string(),
                    JsonValue::String("Suspicious Username".to_string()),
                ),
                ("detected".to_string(), JsonValue::Bool(suspicious_username)),
                ("weight".to_string(), JsonValue::Number(20.0)),
            ]),
            JsonValue::object(vec![
                (
                    "name".to_string(),
                    JsonValue::String("Debugger".to_string()),
                ),
                ("detected".to_string(), JsonValue::Bool(debugger)),
                ("weight".to_string(), JsonValue::Number(35.0)),
            ]),
        ];

        let text = format!(
            "Sandbox detection: Score {}/165 - {}",
            score,
            if is_sandbox {
                "SANDBOX DETECTED"
            } else {
                "Likely real system"
            }
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("is_sandbox".to_string(), JsonValue::Bool(is_sandbox)),
                ("score".to_string(), JsonValue::Number(score as f64)),
                ("threshold".to_string(), JsonValue::Number(50.0)),
                ("indicators".to_string(), JsonValue::array(indicators_json)),
            ]),
        })
    }

    fn tool_evasion_obfuscate(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let input = args
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: input")?;

        let method = args
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("base64");

        let key = args
            .get("key")
            .and_then(|v| v.as_str())
            .and_then(|k| {
                if k.starts_with("0x") {
                    u8::from_str_radix(&k[2..], 16).ok()
                } else {
                    k.parse().ok()
                }
            })
            .unwrap_or(0x42);

        let output = match method {
            "xor" => {
                let bytes: Vec<u8> = input.bytes().map(|b| b ^ key).collect();
                format!(
                    "0x{}",
                    bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>()
                )
            }
            "base64" => {
                use crate::crypto::encoding::base64::base64_encode;
                base64_encode(input.as_bytes())
            }
            "rot13" => input
                .chars()
                .map(|c| match c {
                    'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
                    'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
                    _ => c,
                })
                .collect(),
            "hex" => input
                .bytes()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            _ => return Err(format!("Unknown obfuscation method: {}", method)),
        };

        let text = format!("Obfuscated with {}: {}", method, output);

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("input".to_string(), JsonValue::String(input.to_string())),
                ("method".to_string(), JsonValue::String(method.to_string())),
                ("output".to_string(), JsonValue::String(output)),
            ]),
        })
    }

    fn tool_evasion_antidebug(&mut self, _args: &JsonValue) -> Result<ToolResult, String> {
        // sensitivity: 0-100, aggressive: whether to take action
        let antidebug = AntiDebug::new(50, false);
        let result = antidebug.check_all();

        // checks is Vec<(String, bool)> - (check_name, was_triggered)
        let checks_json: Vec<JsonValue> = result
            .checks
            .iter()
            .map(|(name, detected)| {
                JsonValue::object(vec![
                    ("name".to_string(), JsonValue::String(name.clone())),
                    ("detected".to_string(), JsonValue::Bool(*detected)),
                ])
            })
            .collect();

        let text = format!(
            "Anti-debug check: {} (score: {}/100)",
            if result.debugger_detected {
                "DEBUGGER DETECTED"
            } else {
                "No debugger detected"
            },
            result.score
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                (
                    "debugger_detected".to_string(),
                    JsonValue::Bool(result.debugger_detected),
                ),
                ("score".to_string(), JsonValue::Number(result.score as f64)),
                ("checks".to_string(), JsonValue::array(checks_json)),
            ]),
        })
    }

    // ========================================================================
    // FINGERPRINT TOOL HANDLERS
    // ========================================================================

    fn tool_fingerprint_service(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        let port = args
            .get("port")
            .and_then(|v| v.as_f64())
            .map(|p| p as u16)
            .ok_or("Missing required field: port")?;

        // Try to grab banner
        let timeout = Duration::from_secs(5);
        let addr = format!("{}:{}", target, port);

        let banner = if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
            if let Ok(mut stream) = std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                let mut buf = [0u8; 1024];
                // Send a simple probe for HTTP
                if port == 80 || port == 8080 || port == 443 || port == 8443 {
                    use std::io::Write;
                    let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");
                }
                use std::io::Read;
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        // Guess service from port number (inline simple version)
        let service_guess: Option<String> = match port {
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 | 587 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 | 8080 | 8000 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            443 | 8443 => Some("HTTPS".to_string()),
            3306 => Some("MySQL".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            6379 => Some("Redis".to_string()),
            27017 => Some("MongoDB".to_string()),
            _ => None,
        };

        // Try to detect service from banner
        let detected_service = banner.as_ref().and_then(|b| {
            let b_lower = b.to_lowercase();
            if b_lower.contains("ssh") {
                Some("SSH")
            } else if b_lower.contains("http") {
                Some("HTTP")
            } else if b_lower.contains("ftp") {
                Some("FTP")
            } else if b_lower.contains("smtp") || b_lower.contains("mail") {
                Some("SMTP")
            } else if b_lower.contains("mysql") {
                Some("MySQL")
            } else if b_lower.contains("postgresql") || b_lower.contains("postgres") {
                Some("PostgreSQL")
            } else if b_lower.contains("redis") {
                Some("Redis")
            } else {
                None
            }
        });

        let text = format!(
            "Service fingerprint for {}:{}: {}",
            target,
            port,
            detected_service
                .or(service_guess.as_deref())
                .unwrap_or("Unknown")
        );

        Ok(ToolResult {
            text,
            data: JsonValue::object(vec![
                ("target".to_string(), JsonValue::String(target.to_string())),
                ("port".to_string(), JsonValue::Number(port as f64)),
                (
                    "service".to_string(),
                    detected_service
                        .or(service_guess.as_deref())
                        .map(|s| JsonValue::String(s.to_string()))
                        .unwrap_or(JsonValue::Null),
                ),
                (
                    "banner".to_string(),
                    banner
                        .map(|b| JsonValue::String(b.chars().take(200).collect()))
                        .unwrap_or(JsonValue::Null),
                ),
            ]),
        })
    }

    // ========================================================================
    // CATEGORY CONFIGURATION HANDLERS
    // ========================================================================

    fn tool_config_categories(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("list");

        let category_name = args.get("category").and_then(|v| v.as_str());

        match action {
            "list" => {
                // List all categories and their status
                let status = self.categories.status_summary();
                let mut lines = Vec::new();
                lines.push(format!(
                    "Current preset: {}",
                    self.categories.current_preset().as_str()
                ));
                lines.push(format!(
                    "Enabled tools: {}/44",
                    self.categories.enabled_tool_count()
                ));
                lines.push(String::new());
                lines.push("Category Status:".to_string());

                for (cat, enabled, count) in &status {
                    let marker = if *enabled { "[x]" } else { "[ ]" };
                    lines.push(format!(
                        "  {} {:15} ({:2} tools) - {}",
                        marker,
                        cat.as_str(),
                        count,
                        cat.description()
                    ));
                }

                let categories_json: Vec<JsonValue> = status
                    .iter()
                    .map(|(cat, enabled, count)| {
                        JsonValue::object(vec![
                            (
                                "name".to_string(),
                                JsonValue::String(cat.as_str().to_string()),
                            ),
                            ("enabled".to_string(), JsonValue::Bool(*enabled)),
                            ("tool_count".to_string(), JsonValue::Number(*count as f64)),
                            (
                                "description".to_string(),
                                JsonValue::String(cat.description().to_string()),
                            ),
                        ])
                    })
                    .collect();

                Ok(ToolResult {
                    text: lines.join("\n"),
                    data: JsonValue::object(vec![
                        (
                            "preset".to_string(),
                            JsonValue::String(
                                self.categories.current_preset().as_str().to_string(),
                            ),
                        ),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                        ("categories".to_string(), JsonValue::Array(categories_json)),
                    ]),
                })
            }
            "enable" => {
                let cat_str = category_name.ok_or("Missing category name for enable action")?;
                let category = ToolCategory::from_str(cat_str)
                    .ok_or_else(|| format!("Unknown category: {}", cat_str))?;

                self.categories.enable(category);
                let text = format!(
                    "Enabled category '{}'. Now exposing {} tools.",
                    cat_str,
                    self.categories.enabled_tool_count()
                );

                Ok(ToolResult {
                    text,
                    data: JsonValue::object(vec![
                        (
                            "action".to_string(),
                            JsonValue::String("enabled".to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(cat_str.to_string()),
                        ),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                    ]),
                })
            }
            "disable" => {
                let cat_str = category_name.ok_or("Missing category name for disable action")?;
                let category = ToolCategory::from_str(cat_str)
                    .ok_or_else(|| format!("Unknown category: {}", cat_str))?;

                self.categories.disable(category);
                let text = format!(
                    "Disabled category '{}'. Now exposing {} tools.",
                    cat_str,
                    self.categories.enabled_tool_count()
                );

                Ok(ToolResult {
                    text,
                    data: JsonValue::object(vec![
                        (
                            "action".to_string(),
                            JsonValue::String("disabled".to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(cat_str.to_string()),
                        ),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                    ]),
                })
            }
            "toggle" => {
                let cat_str = category_name.ok_or("Missing category name for toggle action")?;
                let category = ToolCategory::from_str(cat_str)
                    .ok_or_else(|| format!("Unknown category: {}", cat_str))?;

                let now_enabled = self.categories.toggle(category);
                let action_str = if now_enabled { "enabled" } else { "disabled" };
                let text = format!(
                    "Toggled category '{}' -> {}. Now exposing {} tools.",
                    cat_str,
                    action_str,
                    self.categories.enabled_tool_count()
                );

                Ok(ToolResult {
                    text,
                    data: JsonValue::object(vec![
                        (
                            "action".to_string(),
                            JsonValue::String(action_str.to_string()),
                        ),
                        (
                            "category".to_string(),
                            JsonValue::String(cat_str.to_string()),
                        ),
                        ("enabled".to_string(), JsonValue::Bool(now_enabled)),
                        (
                            "enabled_count".to_string(),
                            JsonValue::Number(self.categories.enabled_tool_count() as f64),
                        ),
                    ]),
                })
            }
            _ => Err(format!(
                "Unknown action: {}. Use list, enable, disable, or toggle.",
                action
            )),
        }
    }

    fn tool_config_preset(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let preset_name = args.get("preset").and_then(|v| v.as_str());

        if let Some(name) = preset_name {
            let preset = CategoryPreset::from_str(name)
                .ok_or_else(|| format!("Unknown preset: {}. Available: all, core, blue-team, red-team, web-security, minimal", name))?;

            self.categories.apply_preset(preset);

            let text = format!(
                "Applied preset '{}': {}. Now exposing {} tools.",
                name,
                preset.description(),
                self.categories.enabled_tool_count()
            );

            Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    ("preset".to_string(), JsonValue::String(name.to_string())),
                    (
                        "description".to_string(),
                        JsonValue::String(preset.description().to_string()),
                    ),
                    (
                        "enabled_count".to_string(),
                        JsonValue::Number(self.categories.enabled_tool_count() as f64),
                    ),
                ]),
            })
        } else {
            // List available presets
            let mut lines = Vec::new();
            lines.push(format!(
                "Current preset: {}",
                self.categories.current_preset().as_str()
            ));
            lines.push(String::new());
            lines.push("Available presets:".to_string());

            for preset in CategoryPreset::all_presets() {
                let marker = if preset == self.categories.current_preset() {
                    ">"
                } else {
                    " "
                };
                lines.push(format!(
                    "{} {:15} - {}",
                    marker,
                    preset.as_str(),
                    preset.description()
                ));
            }

            let presets_json: Vec<JsonValue> = CategoryPreset::all_presets()
                .iter()
                .map(|p| {
                    JsonValue::object(vec![
                        (
                            "name".to_string(),
                            JsonValue::String(p.as_str().to_string()),
                        ),
                        (
                            "description".to_string(),
                            JsonValue::String(p.description().to_string()),
                        ),
                        (
                            "active".to_string(),
                            JsonValue::Bool(*p == self.categories.current_preset()),
                        ),
                    ])
                })
                .collect();

            Ok(ToolResult {
                text: lines.join("\n"),
                data: JsonValue::object(vec![
                    (
                        "current".to_string(),
                        JsonValue::String(self.categories.current_preset().as_str().to_string()),
                    ),
                    ("presets".to_string(), JsonValue::Array(presets_json)),
                ]),
            })
        }
    }

    // ========================================================================
    // AUTONOMOUS OPERATION HANDLERS
    // ========================================================================

    fn tool_auto_recon(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        let op_id = self.orchestrator.start_recon(target);

        Ok(ToolResult {
            text: format!(
                "Started autonomous reconnaissance operation on '{}'.\n\
                 Operation ID: {}\n\n\
                 Use rb.auto.step with this ID to advance the operation.\n\
                 The operation will request LLM guidance at decision points.",
                target, op_id
            ),
            data: JsonValue::object(vec![
                ("operation_id".to_string(), JsonValue::String(op_id.clone())),
                ("target".to_string(), JsonValue::String(target.to_string())),
                ("state".to_string(), JsonValue::String("Idle".to_string())),
            ]),
        })
    }

    fn tool_auto_vulnscan(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: target")?;

        let op_id = self.orchestrator.start_vuln_scan(target);

        Ok(ToolResult {
            text: format!(
                "Started autonomous vulnerability scan on '{}'.\n\
                 Operation ID: {}\n\n\
                 This combines port discovery with vulnerability intelligence.\n\
                 Use rb.auto.step to advance the operation.",
                target, op_id
            ),
            data: JsonValue::object(vec![
                ("operation_id".to_string(), JsonValue::String(op_id.clone())),
                ("target".to_string(), JsonValue::String(target.to_string())),
                (
                    "type".to_string(),
                    JsonValue::String("vuln_scan".to_string()),
                ),
            ]),
        })
    }

    fn tool_auto_step(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let op_id = args
            .get("operation_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: operation_id")?;

        match self.orchestrator.step(op_id)? {
            StepResult::Progress { message, findings } => Ok(ToolResult {
                text: format!("Progress: {}", message),
                data: JsonValue::object(vec![
                    (
                        "status".to_string(),
                        JsonValue::String("progress".to_string()),
                    ),
                    ("message".to_string(), JsonValue::String(message)),
                    ("findings".to_string(), JsonValue::Number(findings as f64)),
                ]),
            }),
            StepResult::NeedsGuidance { request } => {
                let request_json = if let Some(req) = &request {
                    crate::mcp::orchestrator::sampling_request_to_json(req)
                } else {
                    "null".to_string()
                };

                Ok(ToolResult {
                    text: format!(
                        "Operation needs LLM guidance.\n\n\
                         A sampling request has been generated. The LLM should analyze the\n\
                         findings and provide guidance using rb.auto.guide with a JSON response.\n\n\
                         Sampling Request:\n{}",
                        request_json
                    ),
                    data: JsonValue::object(vec![
                        ("status".to_string(), JsonValue::String("needs_guidance".to_string())),
                        ("sampling_request".to_string(), JsonValue::String(request_json)),
                    ]),
                })
            }
            StepResult::PausedForReview { reason } => Ok(ToolResult {
                text: format!("Operation paused: {}", reason),
                data: JsonValue::object(vec![
                    (
                        "status".to_string(),
                        JsonValue::String("paused".to_string()),
                    ),
                    ("reason".to_string(), JsonValue::String(reason)),
                ]),
            }),
            StepResult::Paused => Ok(ToolResult {
                text: "Operation is paused. Use rb.auto.status to see details.".to_string(),
                data: JsonValue::object(vec![(
                    "status".to_string(),
                    JsonValue::String("paused".to_string()),
                )]),
            }),
            StepResult::Completed { findings, actions } => Ok(ToolResult {
                text: format!(
                    "Operation completed!\n\
                         Total findings: {}\n\
                         Actions taken: {}",
                    findings, actions
                ),
                data: JsonValue::object(vec![
                    (
                        "status".to_string(),
                        JsonValue::String("completed".to_string()),
                    ),
                    ("findings".to_string(), JsonValue::Number(findings as f64)),
                    ("actions".to_string(), JsonValue::Number(actions as f64)),
                ]),
            }),
        }
    }

    fn tool_auto_guide(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let op_id = args
            .get("operation_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: operation_id")?;

        let response_str = args
            .get("response")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: response")?;

        // Create sampling response from the string
        let response = crate::mcp::sampling::SamplingResponse {
            content: response_str.to_string(),
            model: "user-provided".to_string(),
            stop_reason: crate::mcp::sampling::StopReason::EndTurn,
        };

        self.orchestrator.provide_guidance(op_id, response)?;

        Ok(ToolResult {
            text: format!(
                "Guidance accepted for operation {}.\n\
                 Use rb.auto.step to continue the operation.",
                op_id
            ),
            data: JsonValue::object(vec![
                (
                    "status".to_string(),
                    JsonValue::String("guidance_accepted".to_string()),
                ),
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
            ]),
        })
    }

    fn tool_auto_status(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let op_id = args.get("operation_id").and_then(|v| v.as_str());

        if let Some(id) = op_id {
            // Single operation status
            if let Some(status) = self.orchestrator.get_status(id) {
                Ok(ToolResult {
                    text: format!(
                        "Operation: {}\n\
                         Target: {}\n\
                         State: {}\n\
                         Findings: {}\n\
                         Actions: {}\n\
                         Iteration: {}/{}",
                        status.id,
                        status.target,
                        status.state,
                        status.findings,
                        status.actions,
                        status.iteration,
                        status.max_iterations
                    ),
                    data: JsonValue::object(vec![
                        ("id".to_string(), JsonValue::String(status.id)),
                        ("target".to_string(), JsonValue::String(status.target)),
                        ("state".to_string(), JsonValue::String(status.state)),
                        (
                            "findings".to_string(),
                            JsonValue::Number(status.findings as f64),
                        ),
                        (
                            "actions".to_string(),
                            JsonValue::Number(status.actions as f64),
                        ),
                        (
                            "iteration".to_string(),
                            JsonValue::Number(status.iteration as f64),
                        ),
                        (
                            "max_iterations".to_string(),
                            JsonValue::Number(status.max_iterations as f64),
                        ),
                    ]),
                })
            } else {
                Err(format!("Operation not found: {}", id))
            }
        } else {
            // List all operations
            let operations = self.orchestrator.list_operations();

            if operations.is_empty() {
                return Ok(ToolResult {
                    text: "No active operations.".to_string(),
                    data: JsonValue::object(vec![(
                        "operations".to_string(),
                        JsonValue::Array(vec![]),
                    )]),
                });
            }

            let mut text = format!("Active operations ({}):\n\n", operations.len());
            let ops_json: Vec<JsonValue> = operations
                .iter()
                .map(|op| {
                    text.push_str(&format!(
                        "  {} - {} ({}): {} findings, {} actions\n",
                        op.id, op.target, op.state, op.findings, op.actions
                    ));
                    JsonValue::object(vec![
                        ("id".to_string(), JsonValue::String(op.id.clone())),
                        ("target".to_string(), JsonValue::String(op.target.clone())),
                        ("state".to_string(), JsonValue::String(op.state.clone())),
                        (
                            "findings".to_string(),
                            JsonValue::Number(op.findings as f64),
                        ),
                        ("actions".to_string(), JsonValue::Number(op.actions as f64)),
                    ])
                })
                .collect();

            Ok(ToolResult {
                text,
                data: JsonValue::object(vec![
                    (
                        "count".to_string(),
                        JsonValue::Number(operations.len() as f64),
                    ),
                    ("operations".to_string(), JsonValue::Array(ops_json)),
                ]),
            })
        }
    }

    fn tool_auto_stop(&mut self, args: &JsonValue) -> Result<ToolResult, String> {
        let op_id = args
            .get("operation_id")
            .and_then(|v| v.as_str())
            .ok_or("Missing required field: operation_id")?;

        self.orchestrator.stop(op_id)?;

        Ok(ToolResult {
            text: format!("Operation {} has been stopped.", op_id),
            data: JsonValue::object(vec![
                (
                    "status".to_string(),
                    JsonValue::String("stopped".to_string()),
                ),
                (
                    "operation_id".to_string(),
                    JsonValue::String(op_id.to_string()),
                ),
            ]),
        })
    }
}

/// Convert a Vulnerability to JSON
fn vuln_to_json(vuln: &crate::modules::recon::vuln::Vulnerability) -> JsonValue {
    let exploits_json: Vec<JsonValue> = vuln
        .exploits
        .iter()
        .map(|e| {
            JsonValue::object(vec![
                ("source".to_string(), JsonValue::String(e.source.clone())),
                ("url".to_string(), JsonValue::String(e.url.clone())),
                (
                    "title".to_string(),
                    e.title
                        .as_ref()
                        .map(|t| JsonValue::String(t.clone()))
                        .unwrap_or(JsonValue::Null),
                ),
            ])
        })
        .collect();

    JsonValue::object(vec![
        ("id".to_string(), JsonValue::String(vuln.id.clone())),
        ("title".to_string(), JsonValue::String(vuln.title.clone())),
        (
            "description".to_string(),
            JsonValue::String(vuln.description.clone()),
        ),
        (
            "cvss_v3".to_string(),
            vuln.cvss_v3
                .map(|s| JsonValue::Number(s as f64))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "severity".to_string(),
            JsonValue::String(vuln.severity.as_str().to_string()),
        ),
        (
            "risk_score".to_string(),
            vuln.risk_score
                .map(|s| JsonValue::Number(s as f64))
                .unwrap_or(JsonValue::Null),
        ),
        ("cisa_kev".to_string(), JsonValue::Bool(vuln.cisa_kev)),
        (
            "kev_due_date".to_string(),
            vuln.kev_due_date
                .as_ref()
                .map(|d| JsonValue::String(d.clone()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "has_exploit".to_string(),
            JsonValue::Bool(vuln.has_exploit()),
        ),
        ("exploits".to_string(), JsonValue::array(exploits_json)),
        (
            "published".to_string(),
            vuln.published
                .as_ref()
                .map(|p| JsonValue::String(p.clone()))
                .unwrap_or(JsonValue::Null),
        ),
        (
            "cwes".to_string(),
            JsonValue::array(
                vuln.cwes
                    .iter()
                    .map(|c| JsonValue::String(c.clone()))
                    .collect(),
            ),
        ),
    ])
}

/// Map technology name to OSV ecosystem
fn map_tech_to_ecosystem(tech_name: &str) -> Ecosystem {
    let name_lower = tech_name.to_lowercase();
    if name_lower.contains("node")
        || name_lower.contains("npm")
        || name_lower.contains("express")
        || name_lower.contains("react")
        || name_lower.contains("vue")
        || name_lower.contains("angular")
        || name_lower.contains("jquery")
        || name_lower.contains("lodash")
    {
        Ecosystem::Npm
    } else if name_lower.contains("python")
        || name_lower.contains("django")
        || name_lower.contains("flask")
        || name_lower.contains("fastapi")
    {
        Ecosystem::PyPI
    } else if name_lower.contains("rust") || name_lower.contains("cargo") {
        Ecosystem::Cargo
    } else if name_lower.contains("ruby") || name_lower.contains("rails") {
        Ecosystem::RubyGems
    } else if name_lower.contains("go") || name_lower.contains("golang") {
        Ecosystem::Go
    } else if name_lower.contains("java")
        || name_lower.contains("maven")
        || name_lower.contains("spring")
    {
        Ecosystem::Maven
    } else if name_lower.contains("nuget")
        || name_lower.contains(".net")
        || name_lower.contains("dotnet")
    {
        Ecosystem::NuGet
    } else if name_lower.contains("php")
        || name_lower.contains("composer")
        || name_lower.contains("laravel")
        || name_lower.contains("wordpress")
        || name_lower.contains("drupal")
    {
        Ecosystem::Packagist
    } else {
        Ecosystem::Npm // Default to npm for JS-related technologies
    }
}

fn build_input_schema(fields: &[ToolField]) -> JsonValue {
    let mut properties = Vec::new();
    let mut required = Vec::new();

    for field in fields {
        let mut descriptor = Vec::new();
        descriptor.push((
            "type".to_string(),
            JsonValue::String(field.field_type.to_string()),
        ));
        if !field.description.is_empty() {
            descriptor.push((
                "description".to_string(),
                JsonValue::String(field.description.to_string()),
            ));
        }
        properties.push((field.name.to_string(), JsonValue::Object(descriptor)));
        if field.required {
            required.push(JsonValue::String(field.name.to_string()));
        }
    }

    JsonValue::object(vec![
        ("type".to_string(), JsonValue::String("object".to_string())),
        ("properties".to_string(), JsonValue::Object(properties)),
        ("required".to_string(), JsonValue::Array(required)),
        ("additionalProperties".to_string(), JsonValue::Bool(false)),
    ])
}

fn read_payload<R: BufRead>(reader: &mut R) -> Result<Option<String>, String> {
    let mut content_length: Option<usize> = None;
    let mut header = String::new();

    loop {
        header.clear();
        let bytes = reader
            .read_line(&mut header)
            .map_err(|e| format!("failed to read header: {}", e))?;
        if bytes == 0 {
            return Ok(None);
        }

        let trimmed = header.trim_end_matches(|c| matches!(c, '\n' | '\r'));
        if trimmed.is_empty() {
            break;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let value = trimmed["Content-Length:".len()..].trim();
            let length = value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length header".to_string())?;
            content_length = Some(length);
        }
    }

    let length = content_length.ok_or_else(|| "missing Content-Length header".to_string())?;
    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .map_err(|e| format!("failed to read payload: {}", e))?;

    let to_consume = match reader.fill_buf() {
        Ok(buf) => {
            if buf.starts_with(b"\r\n") {
                Some(2)
            } else if buf.starts_with(b"\n") {
                Some(1)
            } else {
                None
            }
        }
        Err(_) => None,
    };

    if let Some(count) = to_consume {
        reader.consume(count);
    }

    String::from_utf8(buffer)
        .map(Some)
        .map_err(|_| "payload is not UTF-8".to_string())
}

fn write_message(payload: JsonValue) -> Result<(), String> {
    let body = payload.to_json_string();
    let mut stdout = io::stdout().lock();
    write!(
        &mut stdout,
        "Content-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    )
    .map_err(|e| format!("failed to write response: {}", e))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush stdout: {}", e))
}

fn build_result_message(id: Option<JsonValue>, result: JsonValue) -> JsonValue {
    let mut entries = Vec::new();
    entries.push(("jsonrpc".to_string(), JsonValue::String("2.0".to_string())));
    if let Some(identifier) = id {
        entries.push(("id".to_string(), identifier));
    } else {
        entries.push(("id".to_string(), JsonValue::Null));
    }
    entries.push(("result".to_string(), result));
    JsonValue::Object(entries)
}

fn build_error_message(id: Option<JsonValue>, code: i64, message: &str) -> JsonValue {
    let mut entries = Vec::new();
    entries.push(("jsonrpc".to_string(), JsonValue::String("2.0".to_string())));
    if let Some(identifier) = id {
        entries.push(("id".to_string(), identifier));
    } else {
        entries.push(("id".to_string(), JsonValue::Null));
    }
    let error = JsonValue::object(vec![
        ("code".to_string(), JsonValue::Number(code as f64)),
        (
            "message".to_string(),
            JsonValue::String(message.to_string()),
        ),
    ]);
    entries.push(("error".to_string(), error));
    JsonValue::Object(entries)
}

fn parse_command_arguments(args: &JsonValue) -> Result<Vec<String>, String> {
    if let Some(array) = args.get("argv").and_then(|value| value.as_array()) {
        let mut result = Vec::with_capacity(array.len());
        for value in array {
            let s = value
                .as_str()
                .ok_or_else(|| "argv elements must be strings".to_string())?;
            result.push(s.to_string());
        }
        if !result.is_empty() {
            return Ok(result);
        }
    }

    if let Some(command) = args.get("command").and_then(|value| value.as_str()) {
        let parts = split_command_line(command);
        if !parts.is_empty() {
            return Ok(parts);
        }
        return Err("command string did not yield any arguments".to_string());
    }

    Err("provide either 'argv' (array of strings) or 'command' (string)".to_string())
}

fn split_command_line(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut quote_char = '\0';

    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => {
                if in_quotes {
                    if ch == quote_char {
                        in_quotes = false;
                    } else {
                        current.push(ch);
                    }
                } else {
                    in_quotes = true;
                    quote_char = ch;
                }
            }
            '\\' => {
                if let Some(next_ch) = chars.next() {
                    current.push(next_ch);
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            c => current.push(c),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn truncate_preview(text: &str) -> String {
    let trimmed = text.trim();
    const MAX_PREVIEW: usize = 160;
    if trimmed.len() <= MAX_PREVIEW {
        trimmed.replace('\n', " ⏎ ")
    } else {
        let mut snippet = trimmed[..MAX_PREVIEW].to_string();
        snippet.push_str(" …");
        snippet.replace('\n', " ⏎ ")
    }
}

fn build_document_index(max_sections: usize) -> Vec<JsonValue> {
    let mut documents = Vec::new();
    for path in all_document_paths() {
        let content = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(_) => continue,
        };
        let (title, sections) = summarize_markdown(&content, max_sections);
        let section_values = sections
            .into_iter()
            .map(|(level, heading, line)| {
                JsonValue::object(vec![
                    ("level".to_string(), JsonValue::Number(level as f64)),
                    ("title".to_string(), JsonValue::String(heading.clone())),
                    ("line".to_string(), JsonValue::Number(line as f64)),
                    ("slug".to_string(), JsonValue::String(slugify(&heading))),
                ])
            })
            .collect::<Vec<JsonValue>>();

        documents.push(JsonValue::object(vec![
            (
                "path".to_string(),
                JsonValue::String(path.to_string_lossy().to_string()),
            ),
            ("title".to_string(), JsonValue::String(title)),
            ("sections".to_string(), JsonValue::array(section_values)),
        ]));
    }
    documents
}

fn summarize_markdown(content: &str, max_sections: usize) -> (String, Vec<(usize, String, usize)>) {
    let mut title = None;
    let mut sections = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        if let Some((level, heading)) = parse_heading(line) {
            if level == 1 && title.is_none() {
                title = Some(heading.to_string());
            }
            if sections.len() < max_sections {
                sections.push((level, heading.to_string(), idx + 1));
            }
        }
    }

    let doc_title = title.unwrap_or_else(|| "Untitled".to_string());
    (doc_title, sections)
}

fn parse_heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let mut level = 0;
    for ch in trimmed.chars() {
        if ch == '#' {
            level += 1;
        } else {
            break;
        }
    }
    if level == 0 {
        return None;
    }
    let after = trimmed[level..].trim_start();
    if after.is_empty() {
        return None;
    }
    Some((level, after))
}

fn slugify(input: &str) -> String {
    let mut slug = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if (ch.is_ascii_whitespace() || ch == '-') && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_string()
}

fn extract_markdown_section(content: &str, heading_name: &str) -> Option<String> {
    let mut collecting = false;
    let mut target_level = 0usize;
    let mut buffer: Vec<String> = Vec::new();

    for line in content.lines() {
        if let Some((level, heading)) = parse_heading(line) {
            if collecting && level <= target_level {
                break;
            }
            if heading.eq_ignore_ascii_case(heading_name.trim()) {
                collecting = true;
                target_level = level;
                buffer.push(line.to_string());
                continue;
            }
        }

        if collecting {
            buffer.push(line.to_string());
        }
    }

    if collecting {
        Some(buffer.join("\n"))
    } else {
        None
    }
}

fn resolve_doc_path(requested: &str) -> Option<PathBuf> {
    let candidate = Path::new(requested);
    if candidate.is_absolute() {
        return None;
    }
    if candidate
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }

    let normalized = candidate.to_string_lossy().to_string();
    for path in all_document_paths() {
        if path.to_string_lossy() == normalized {
            return Some(path);
        }
    }
    None
}

fn all_document_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("README.md"),
        PathBuf::from("AGENTS.md"),
        PathBuf::from("CLAUDE.md"),
    ];
    collect_doc_paths(Path::new("docs"), &mut paths);
    paths
}

fn default_target_db_path() -> PathBuf {
    PathBuf::from("mcp-targets.json")
}

#[derive(Clone)]
struct TargetEntry {
    name: String,
    target: String,
    notes: Option<String>,
    created_at: u64,
    updated_at: u64,
}

impl TargetEntry {
    fn to_json(&self) -> JsonValue {
        let fields = vec![
            ("name".to_string(), JsonValue::String(self.name.clone())),
            ("target".to_string(), JsonValue::String(self.target.clone())),
            (
                "created_at".to_string(),
                JsonValue::Number(self.created_at as f64),
            ),
            (
                "updated_at".to_string(),
                JsonValue::Number(self.updated_at as f64),
            ),
            (
                "notes".to_string(),
                self.notes
                    .as_ref()
                    .map(|n| JsonValue::String(n.clone()))
                    .unwrap_or(JsonValue::Null),
            ),
        ];
        JsonValue::object(fields)
    }
}

struct TargetDatabase {
    path: PathBuf,
    targets: Vec<TargetEntry>,
    dirty: bool,
}

impl TargetDatabase {
    fn load(path: PathBuf) -> Self {
        let mut db = TargetDatabase {
            path,
            targets: Vec::new(),
            dirty: false,
        };

        if let Ok(contents) = fs::read_to_string(&db.path) {
            if let Ok(json) = parse_json(&contents) {
                if let Some(array) = json.get("targets").and_then(|value| value.as_array()) {
                    for item in array {
                        if let Some(entry) = TargetDatabase::entry_from_json(item) {
                            db.targets.push(entry);
                        }
                    }
                }
            }
        }

        db
    }

    fn entry_from_json(value: &JsonValue) -> Option<TargetEntry> {
        let name = value.get("name")?.as_str()?;
        let target = value.get("target")?.as_str()?;
        let notes = value
            .get("notes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let created_at = value
            .get("created_at")
            .and_then(|v| v.as_f64())
            .map(|v| v as u64)
            .unwrap_or_else(current_timestamp);
        let updated_at = value
            .get("updated_at")
            .and_then(|v| v.as_f64())
            .map(|v| v as u64)
            .unwrap_or(created_at);

        Some(TargetEntry {
            name: name.to_string(),
            target: target.to_string(),
            notes,
            created_at,
            updated_at,
        })
    }

    fn upsert(&mut self, name: &str, target: &str, notes: Option<&str>) -> (bool, TargetEntry) {
        let normalized_notes = notes.map(|n| n.trim()).filter(|s| !s.is_empty());
        let now = current_timestamp();

        for entry in &mut self.targets {
            if entry.name.eq_ignore_ascii_case(name) {
                entry.name = name.to_string();
                entry.target = target.to_string();
                entry.notes = normalized_notes.map(|n| n.to_string());
                entry.updated_at = now;
                self.dirty = true;
                return (false, entry.clone());
            }
        }

        let new_entry = TargetEntry {
            name: name.to_string(),
            target: target.to_string(),
            notes: normalized_notes.map(|n| n.to_string()),
            created_at: now,
            updated_at: now,
        };
        self.targets.push(new_entry.clone());
        self.dirty = true;
        (true, new_entry)
    }

    fn remove(&mut self, name: &str) -> Option<TargetEntry> {
        let index = self
            .targets
            .iter()
            .position(|entry| entry.name.eq_ignore_ascii_case(name));
        if let Some(idx) = index {
            self.dirty = true;
            Some(self.targets.remove(idx))
        } else {
            None
        }
    }

    fn persist(&mut self) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }

        let records = self
            .targets
            .iter()
            .map(|entry| entry.to_json())
            .collect::<Vec<JsonValue>>();

        let payload = JsonValue::object(vec![("targets".to_string(), JsonValue::array(records))])
            .to_json_string();

        fs::write(&self.path, payload)
            .map_err(|e| format!("failed to write {}: {}", self.path.display(), e))?;
        self.dirty = false;
        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn search_documentation(query: &str, max_hits: usize) -> Vec<DocHit> {
    let mut hits = Vec::new();
    let lowercase_query = query.to_lowercase();

    for path in all_document_paths() {
        if hits.len() >= max_hits {
            break;
        }
        if let Some(hit) = search_file_for_query(&path, &lowercase_query, max_hits - hits.len()) {
            hits.extend(hit);
        }
    }

    hits
}

fn collect_doc_paths(root: &Path, accumulator: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_doc_paths(&path, accumulator);
        } else if let Some(ext) = path.extension() {
            if ext == "md" || ext == "txt" {
                accumulator.push(path);
            }
        }
    }
}

fn search_file_for_query(path: &Path, query: &str, remaining: usize) -> Option<Vec<DocHit>> {
    if remaining == 0 {
        return Some(Vec::new());
    }
    let content = fs::read_to_string(path).ok()?;
    let mut hits = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.to_lowercase().contains(query) {
            hits.push(DocHit {
                path: path.to_string_lossy().to_string(),
                line: index + 1,
                snippet: line.trim().to_string(),
            });
            if hits.len() >= remaining {
                break;
            }
        }
    }
    if hits.is_empty() {
        None
    } else {
        Some(hits)
    }
}
