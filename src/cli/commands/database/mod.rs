//! Database commands - RedDb inspection, new engine operations, vector search.
//!
//! This module provides four distinct modes for database operations:
//!
//! - **data**: Legacy interface for querying .rdb files
//! - **query**: Resource-first filtering (ports, dns, subdomains, etc.)
//! - **engine**: Page-based storage engine operations
//! - **vector**: Vector similarity search using IVF/Flat indexes
//!
//! # Examples
//!
//! ```bash
//! # Legacy data mode
//! rb database data query scan.rdb
//! rb database data export scan.rdb --output results.csv
//!
//! # Query mode with filters
//! rb database query ports --db scan.rdb --ip-range 192.168.1.1-192.168.1.255
//! rb database query dns --db scan.rdb --dns-prefix mail.
//!
//! # Engine operations
//! rb database engine open mydata.rdb
//! rb database engine info mydata.rdb
//! rb database engine checkpoint mydata.rdb
//!
//! # Vector search
//! rb database vector search --query 0.1,0.2,0.3 --k 10
//! rb database vector index --type ivf --n-lists 100
//! ```

mod engine;
mod helpers;
mod legacy;
mod query;
mod vector;

use crate::cli::commands::{Command, Flag, Route};
use crate::cli::CliContext;

// Re-export helpers for use by submodules
pub use helpers::*;

/// Database command modes:
/// - `data`: legacy interface (`rb database data query file.rdb`)
/// - `query`: resource-first query interface (`rb database query dns --db file.rdb`)
/// - `engine`: new page-based storage engine operations
/// - `vector`: vector similarity search
#[derive(Clone, Copy)]
pub enum DatabaseMode {
    Data,
    Query,
    Engine,
    Vector,
}

pub struct DatabaseCommand {
    mode: DatabaseMode,
}

impl DatabaseCommand {
    pub const fn new(mode: DatabaseMode) -> Self {
        Self { mode }
    }

    const fn mode_label(&self) -> &'static str {
        match self.mode {
            DatabaseMode::Data => "data",
            DatabaseMode::Query => "query",
            DatabaseMode::Engine => "engine",
            DatabaseMode::Vector => "vector",
        }
    }
}

/// Create all database command variants
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(DatabaseCommand::new(DatabaseMode::Data)),
        Box::new(DatabaseCommand::new(DatabaseMode::Query)),
        Box::new(DatabaseCommand::new(DatabaseMode::Engine)),
        Box::new(DatabaseCommand::new(DatabaseMode::Vector)),
    ]
}

impl Command for DatabaseCommand {
    fn domain(&self) -> &str {
        "database"
    }

    fn resource(&self) -> &str {
        match self.mode {
            DatabaseMode::Data => "data",
            DatabaseMode::Query => "query",
            DatabaseMode::Engine => "engine",
            DatabaseMode::Vector => "vector",
        }
    }

    fn description(&self) -> &str {
        match self.mode {
            DatabaseMode::Data => "Query and export binary database files (.rdb)",
            DatabaseMode::Query => "Filter RedDb contents by dataset (ports, dns, subdomains, ...)",
            DatabaseMode::Engine => "Page-based storage engine operations (open, info, migrate)",
            DatabaseMode::Vector => "Vector similarity search using IVF/Flat indexes",
        }
    }

    fn routes(&self) -> Vec<Route> {
        match self.mode {
            DatabaseMode::Data => vec![
                Route {
                    verb: "query",
                    summary: "Display database contents and statistics",
                    usage: "rb database data query <file.rdb>",
                },
                Route {
                    verb: "export",
                    summary: "Export database to CSV format",
                    usage: "rb database data export <file.rdb> [--output file.csv]",
                },
                Route {
                    verb: "list",
                    summary: "List .rdb files in the current directory",
                    usage: "rb database data list",
                },
                Route {
                    verb: "subnets",
                    summary: "List discovered subnets with host counts",
                    usage: "rb database data subnets",
                },
                Route {
                    verb: "doctor",
                    summary: "Validate RedDb structure and show segment health",
                    usage: "rb database data doctor <file.rdb>",
                },
            ],
            DatabaseMode::Query => vec![
                Route {
                    verb: "summary",
                    summary: "Show RedDb summary (size, record counts)",
                    usage: "rb database query summary --db scan.rdb",
                },
                Route {
                    verb: "ports",
                    summary: "List ports, optionally constrained by IP range",
                    usage:
                        "rb database query ports --db scan.rdb [--ip-range 192.0.2.1-192.0.2.200]",
                },
                Route {
                    verb: "dns",
                    summary: "List DNS records (supports --dns-prefix)",
                    usage: "rb database query dns --db scan.rdb [--dns-prefix mail.]",
                },
                Route {
                    verb: "subdomains",
                    summary: "List subdomains (supports --subdomain-prefix)",
                    usage: "rb database query subdomains --db scan.rdb [--subdomain-prefix api.]",
                },
                Route {
                    verb: "http",
                    summary: "List HTTP captures (supports --host)",
                    usage: "rb database query http --db scan.rdb [--host example.com]",
                },
                Route {
                    verb: "tls",
                    summary: "List TLS scan results (supports --host)",
                    usage: "rb database query tls --db scan.rdb [--host example.com]",
                },
                Route {
                    verb: "whois",
                    summary: "List WHOIS records (supports --domain)",
                    usage: "rb database query whois --db scan.rdb [--domain example.com]",
                },
                Route {
                    verb: "hosts",
                    summary: "List host fingerprints (supports --ip)",
                    usage: "rb database query hosts --db scan.rdb [--ip 192.0.2.10]",
                },
            ],
            DatabaseMode::Engine => vec![
                Route {
                    verb: "open",
                    summary: "Open or create a new page-based database",
                    usage: "rb database engine open <path> [--password secret]",
                },
                Route {
                    verb: "info",
                    summary: "Display database metadata and statistics",
                    usage: "rb database engine info <path>",
                },
                Route {
                    verb: "stats",
                    summary: "Show detailed cache and transaction statistics",
                    usage: "rb database engine stats <path>",
                },
                Route {
                    verb: "checkpoint",
                    summary: "Force a WAL checkpoint to flush pending writes",
                    usage: "rb database engine checkpoint <path>",
                },
                Route {
                    verb: "migrate",
                    summary: "Migrate legacy .rdb format to new page-based engine",
                    usage: "rb database engine migrate <legacy.rdb> --to <new.rdb>",
                },
            ],
            DatabaseMode::Vector => vec![
                Route {
                    verb: "search",
                    summary: "Perform k-nearest neighbor similarity search",
                    usage: "rb database vector search --db <path> --query <vector> [--k 10]",
                },
                Route {
                    verb: "index",
                    summary: "Build or rebuild vector index (flat or IVF)",
                    usage: "rb database vector index --db <path> --type flat|ivf [--n-lists 100]",
                },
                Route {
                    verb: "info",
                    summary: "Display vector index statistics",
                    usage: "rb database vector info --db <path>",
                },
            ],
        }
    }

    fn flags(&self) -> Vec<Flag> {
        match self.mode {
            DatabaseMode::Data => vec![
                Flag::new("output", "Output file path for export").with_short('o'),
                Flag::new("format", "Output format (text, json)").with_default("text"),
            ],
            DatabaseMode::Query => vec![
                Flag::new("db", "Path to the RedDb file to query"),
                Flag::new("database", "Alias for --db"),
                Flag::new("ip-range", "Filter ports by inclusive IP range (start-end)"),
                Flag::new(
                    "subdomain-prefix",
                    "Only include subdomains that start with the provided prefix",
                ),
                Flag::new(
                    "dns-prefix",
                    "Only include DNS records whose domain starts with the provided prefix",
                ),
                Flag::new("host", "Filter HTTP/TLS/host intel by hostname"),
                Flag::new("domain", "Filter WHOIS/DNS by domain"),
                Flag::new("ip", "Filter host intel by IP address"),
                Flag::new(
                    "segment",
                    "Filter partition listings by segment (ports|dns|http|tls|subdomains|whois|host)",
                ),
                Flag::new(
                    "attr",
                    "Filter partition listings by attribute key=value (e.g., category=target)",
                ),
                Flag::new("format", "Output format (text, json)").with_default("text"),
            ],
            DatabaseMode::Engine => vec![
                Flag::new("password", "Password for encrypted database").with_short('p'),
                Flag::new("to", "Destination path for migration"),
                Flag::new("read-only", "Open database in read-only mode"),
                Flag::new("format", "Output format (text, json)").with_default("text"),
            ],
            DatabaseMode::Vector => vec![
                Flag::new("db", "Path to the database file"),
                Flag::new(
                    "query",
                    "Query vector as comma-separated floats (e.g., 0.1,0.2,0.3)",
                ),
                Flag::new("k", "Number of nearest neighbors to return").with_default("10"),
                Flag::new("distance", "Distance metric (cosine, l2, dot)").with_default("cosine"),
                Flag::new("type", "Index type (flat, ivf)").with_default("flat"),
                Flag::new("n-lists", "Number of IVF clusters").with_default("100"),
                Flag::new("n-probes", "Number of IVF probes for search").with_default("10"),
                Flag::new("format", "Output format (text, json)").with_default("text"),
            ],
        }
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        match self.mode {
            DatabaseMode::Data => vec![
                ("Query database", "rb database data query 192.168.1.1.rdb"),
                (
                    "Export to CSV",
                    "rb database data export 192.168.1.1.rdb --output scan.csv",
                ),
                ("List databases", "rb database data list"),
                ("List subnets", "rb database data subnets"),
                ("Validate database", "rb database data doctor recon.rdb"),
            ],
            DatabaseMode::Query => vec![
                ("Summary", "rb database query summary --db recon.rdb"),
                (
                    "Ports in a CIDR window",
                    "rb database query ports --db recon.rdb --ip-range 10.0.0.1-10.0.0.255",
                ),
                (
                    "DNS prefix match",
                    "rb database query dns --db recon.rdb --dns-prefix mail.",
                ),
                (
                    "Subdomain prefix match",
                    "rb database query subdomains --db recon.rdb --subdomain-prefix api.",
                ),
                (
                    "TLS scans for host",
                    "rb database query tls --db recon.rdb --host example.com",
                ),
                (
                    "Partition overview",
                    "rb database query partitions --db recon.rdb --segment tls",
                ),
            ],
            DatabaseMode::Engine => vec![
                ("Create database", "rb database engine open mydata.rdb"),
                (
                    "Open encrypted",
                    "rb database engine open secure.rdb --password mysecret",
                ),
                ("Show info", "rb database engine info mydata.rdb"),
                ("View stats", "rb database engine stats mydata.rdb"),
                (
                    "Force checkpoint",
                    "rb database engine checkpoint mydata.rdb",
                ),
                (
                    "Migrate legacy",
                    "rb database engine migrate old.rdb --to new.rdb",
                ),
            ],
            DatabaseMode::Vector => vec![
                (
                    "Similarity search",
                    "rb database vector search --db vectors.rdb --query 0.1,0.2,0.3 --k 5",
                ),
                (
                    "Build IVF index",
                    "rb database vector index --db vectors.rdb --type ivf --n-lists 100",
                ),
                ("Index info", "rb database vector info --db vectors.rdb"),
            ],
        }
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        match self.mode {
            DatabaseMode::Data => self.execute_legacy(ctx),
            DatabaseMode::Query => self.execute_query(ctx),
            DatabaseMode::Engine => self.execute_engine(ctx),
            DatabaseMode::Vector => self.execute_vector(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_modes() {
        let data_cmd = DatabaseCommand::new(DatabaseMode::Data);
        assert_eq!(data_cmd.domain(), "database");
        assert_eq!(data_cmd.resource(), "data");

        let query_cmd = DatabaseCommand::new(DatabaseMode::Query);
        assert_eq!(query_cmd.resource(), "query");

        let engine_cmd = DatabaseCommand::new(DatabaseMode::Engine);
        assert_eq!(engine_cmd.resource(), "engine");

        let vector_cmd = DatabaseCommand::new(DatabaseMode::Vector);
        assert_eq!(vector_cmd.resource(), "vector");
    }

    #[test]
    fn test_commands_creates_all_modes() {
        let cmds = commands();
        assert_eq!(cmds.len(), 4);

        let resources: Vec<&str> = cmds.iter().map(|c| c.resource()).collect();
        assert!(resources.contains(&"data"));
        assert!(resources.contains(&"query"));
        assert!(resources.contains(&"engine"));
        assert!(resources.contains(&"vector"));
    }

    #[test]
    fn test_parse_ip_range_valid() {
        let (start, end) = parse_ip_range("192.168.1.1-192.168.1.255").unwrap();
        assert_eq!(start.to_string(), "192.168.1.1");
        assert_eq!(end.to_string(), "192.168.1.255");
    }

    #[test]
    fn test_parse_ip_range_invalid() {
        assert!(parse_ip_range("192.168.1.1").is_err());
        assert!(parse_ip_range("192.168.1.255-192.168.1.1").is_err());
        assert!(parse_ip_range("invalid-192.168.1.1").is_err());
    }

    #[test]
    fn test_segment_label() {
        use crate::storage::layout::SegmentKind;

        assert_eq!(segment_label(SegmentKind::Ports), "ports");
        assert_eq!(segment_label(SegmentKind::Dns), "dns");
        assert_eq!(segment_label(SegmentKind::Host), "hosts");
    }

    #[test]
    fn test_parse_segment_kind() {
        use crate::storage::layout::SegmentKind;

        assert!(matches!(
            parse_segment_kind("ports").unwrap(),
            SegmentKind::Ports
        ));
        assert!(matches!(
            parse_segment_kind("DNS").unwrap(),
            SegmentKind::Dns
        ));
        assert!(matches!(
            parse_segment_kind("HOST").unwrap(),
            SegmentKind::Host
        ));
        assert!(parse_segment_kind("invalid").is_err());
    }
}
