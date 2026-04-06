//! Graph Intelligence Command
//!
//! Graph algorithms and intelligence for attack path analysis:
//! - pagerank: Identify critical nodes by influence
//! - components: Find connected components (network segments)
//! - centrality: Betweenness centrality (choke points)
//! - communities: Community detection (related assets)
//! - cycles: Detect circular dependencies
//! - paths: Find attack paths between nodes
//! - summary: Overall graph statistics and insights
//!
//! ## Submodules
//! - `helpers`: Shared utilities (load_graph, truncation, timestamps)
//! - `algorithms`: Graph analysis (PageRank, centrality, communities)
//! - `operations`: Core operations (summary, export, import, query)
//! - `viz`: Visualization (SVG, ASCII tree)
//! - `intel`: Entity-centric intelligence commands

mod algorithms;
mod helpers;
mod intel;
mod operations;
mod viz;

use crate::cli::commands::{Command, Flag, Route};
use crate::cli::{output::Output, CliContext};

// Re-export key functions for testing
pub use algorithms::{
  cmd_centrality, cmd_communities, cmd_components, cmd_cycles, cmd_pagerank, cmd_paths, find_paths,
};
pub use helpers::{chrono_lite_now, load_graph, truncate_str};
pub use intel::{
  cmd_intel_cert, cmd_intel_credential, cmd_intel_domain, cmd_intel_host, cmd_intel_network,
  cmd_intel_service, cmd_intel_tech, cmd_intel_user, cmd_intel_vuln,
};
pub use operations::{
  cmd_export, cmd_import, cmd_insights, cmd_query, cmd_report, cmd_rql_help, cmd_stats, cmd_summary,
};
pub use viz::{
  cmd_viz, find_path_bfs, get_node_type_icon, print_tree_node, print_tree_node_highlighted,
};

pub struct IntelGraphCommand;

impl Command for IntelGraphCommand {
  fn domain(&self) -> &str {
    "intelligence"
  }

  fn resource(&self) -> &str {
    "graph"
  }

  fn description(&self) -> &str {
    "Graph intelligence - algorithms for attack path and network analysis"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "pagerank",
        summary: "Calculate PageRank to find influential nodes",
        usage: "rb intel graph pagerank [--alpha 0.85] [--limit 20]",
      },
      Route {
        verb: "components",
        summary: "Find connected components (network segments)",
        usage: "rb intel graph components [--min-size 2]",
      },
      Route {
        verb: "centrality",
        summary: "Calculate betweenness centrality (choke points)",
        usage: "rb intel graph centrality [--normalize] [--limit 20]",
      },
      Route {
        verb: "communities",
        summary: "Detect communities using label propagation",
        usage: "rb intel graph communities [--iterations 10]",
      },
      Route {
        verb: "cycles",
        summary: "Detect cycles in the graph",
        usage: "rb intel graph cycles [--max-length 10] [--limit 50]",
      },
      Route {
        verb: "paths",
        summary: "Find paths between two nodes",
        usage: "rb intel graph paths <from> <to> [--max-depth 5]",
      },
      Route {
        verb: "summary",
        summary: "Show graph summary and statistics",
        usage: "rb intel graph summary",
      },
      Route {
        verb: "insights",
        summary: "Generate strategic intelligence insights",
        usage: "rb intel graph insights",
      },
      Route {
        verb: "export",
        summary: "Export graph data to file",
        usage: "rb intel graph export [--format json|graphml|dot]",
      },
      Route {
        verb: "report",
        summary: "Generate comprehensive intelligence report",
        usage: "rb intel graph report [--output report.md]",
      },
      Route {
        verb: "viz",
        summary: "Visualize graph with optional path/vuln highlighting",
        usage: "rb intel graph viz [--path 'FROM x TO y'] [--vulns] [--svg out.svg] [--limit 20]",
      },
      Route {
        verb: "query",
        summary: "Execute RQL query on the graph",
        usage: "rb intel graph query \"MATCH (h:Host) RETURN h\"",
      },
      Route {
        verb: "rql",
        summary: "Show RQL (Redblue Query Language) syntax reference",
        usage: "rb intel graph rql",
      },
      Route {
        verb: "stats",
        summary: "Show detailed graph statistics",
        usage: "rb intel graph stats",
      },
      Route {
        verb: "import",
        summary: "Import graph from file",
        usage: "rb intel graph import <file> [--format json|graphml]",
      },
      // Phase 2: Intelligence-specific commands
      Route {
        verb: "host",
        summary: "Host-centric intelligence - what do we know about this host?",
        usage: "rb intel graph host <ip> [--services|--vulns|--users]",
      },
      Route {
        verb: "credential",
        summary: "Credential-centric intelligence - where can this credential access?",
        usage: "rb intel graph credential <name> [--reach|--reuse]",
      },
      Route {
        verb: "user",
        summary: "User-centric intelligence - where does this user exist?",
        usage: "rb intel graph user <username> [--hosts|--credentials]",
      },
      Route {
        verb: "service",
        summary: "Service-centric intelligence - who runs this service?",
        usage: "rb intel graph service <name> [--hosts|--vulns]",
      },
      Route {
        verb: "vuln",
        summary: "Vulnerability-centric intelligence - what is affected?",
        usage: "rb intel graph vuln <cve> [--affected|--critical]",
      },
      Route {
        verb: "tech",
        summary: "Technology-centric intelligence - who uses this technology?",
        usage: "rb intel graph tech <name> [--hosts|--outdated]",
      },
      Route {
        verb: "network",
        summary: "Network topology intelligence - segments and gateways",
        usage: "rb intel graph network [--segments|--gateways]",
      },
      Route {
        verb: "domain",
        summary: "Domain-centric intelligence - DNS and subdomains",
        usage: "rb intel graph domain <name> [--subdomains|--records]",
      },
      Route {
        verb: "cert",
        summary: "Certificate-centric intelligence - certificates and their usage",
        usage: "rb intel graph cert <subject> [--expiring|--hosts]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json)")
        .with_short('o')
        .with_default("text"),
      Flag::new("alpha", "PageRank damping factor (0-1)").with_default("0.85"),
      Flag::new("limit", "Maximum results to show").with_default("20"),
      Flag::new("min-size", "Minimum component size").with_default("2"),
      Flag::new("normalize", "Normalize centrality scores"),
      Flag::new("iterations", "Max iterations for algorithms").with_default("100"),
      Flag::new("max-length", "Maximum cycle length").with_default("10"),
      Flag::new("max-depth", "Maximum path depth").with_default("5"),
      Flag::new("db", "Database path").with_default(".redblue/graph.db"),
      Flag::new("format", "Export format (json, graphml, dot, mermaid)").with_default("json"),
      Flag::new("report-output", "Report output file path").with_default("intelligence-report.md"),
      Flag::new("layout", "Visualization layout (tree, list)").with_default("tree"),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Find most influential nodes", "rb intel graph pagerank"),
      ("Top 10 by PageRank", "rb intel graph pagerank --limit 10"),
      ("Find network segments", "rb intel graph components"),
      ("Find choke points", "rb intel graph centrality"),
      ("Detect communities", "rb intel graph communities"),
      ("Find cycles", "rb intel graph cycles"),
      (
        "Find attack path",
        "rb intel graph paths host:10.0.0.1 host:10.0.0.5",
      ),
      ("Graph summary", "rb intel graph summary"),
      ("Strategic insights", "rb intel graph insights"),
      ("Export to JSON", "rb intel graph export --format json"),
      (
        "Export to DOT/GraphViz",
        "rb intel graph export --format dot",
      ),
      (
        "Export to Mermaid",
        "rb intel graph export --format mermaid",
      ),
      ("Generate report", "rb intel graph report"),
      ("Visualize graph", "rb intel graph viz"),
      (
        "Execute RQL query",
        "rb intel graph query \"MATCH (h:Host) RETURN h\"",
      ),
      ("RQL syntax reference", "rb intel graph rql"),
      (
        "Gremlin query",
        "rb intel graph query \"g.V().hasLabel('Host').out().toList()\"",
      ),
      (
        "Path query",
        "rb intel graph query \"PATH FROM host:10.0.0.1 TO host:10.0.0.50\"",
      ),
      (
        "SQL query",
        "rb intel graph query \"SELECT * FROM hosts WHERE cvss >= 7.0\"",
      ),
      ("Show graph stats", "rb intel graph stats"),
      ("Import graph", "rb intel graph import data.json"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("summary");
    let output_format = ctx
      .flags
      .get("output")
      .map(|s| s.as_str())
      .unwrap_or("text");
    let db_path = ctx
      .flags
      .get("db")
      .map(|s| s.as_str())
      .unwrap_or(".redblue/graph.db");

    // Load graph store
    let graph = match load_graph(db_path) {
      Ok(g) => g,
      Err(e) => {
        Output::error(&format!("Failed to load graph: {}", e));
        return Err(e);
      }
    };

    match verb {
      // Algorithm commands
      "pagerank" => cmd_pagerank(ctx, &graph, output_format),
      "components" => cmd_components(ctx, &graph, output_format),
      "centrality" => cmd_centrality(ctx, &graph, output_format),
      "communities" => cmd_communities(ctx, &graph, output_format),
      "cycles" => cmd_cycles(ctx, &graph, output_format),
      "paths" => cmd_paths(ctx, &graph, output_format),

      // Core operation commands
      "summary" => cmd_summary(&graph, output_format),
      "insights" => cmd_insights(&graph, output_format),
      "export" => cmd_export(ctx, &graph),
      "report" => cmd_report(ctx, &graph),
      "query" => cmd_query(ctx, &graph, output_format),
      "rql" => cmd_rql_help(),
      "stats" => cmd_stats(&graph, output_format),
      "import" => cmd_import(ctx),

      // Visualization commands
      "viz" => cmd_viz(ctx, &graph),

      // Entity-centric intelligence commands
      "host" => cmd_intel_host(ctx, &graph, output_format),
      "credential" => cmd_intel_credential(ctx, &graph, output_format),
      "user" => cmd_intel_user(ctx, &graph, output_format),
      "service" => cmd_intel_service(ctx, &graph, output_format),
      "vuln" => cmd_intel_vuln(ctx, &graph, output_format),
      "tech" => cmd_intel_tech(ctx, &graph, output_format),
      "network" => cmd_intel_network(ctx, &graph, output_format),
      "domain" => cmd_intel_domain(ctx, &graph, output_format),
      "cert" => cmd_intel_cert(ctx, &graph, output_format),

      _ => {
        Output::error(&format!("Unknown verb: {}", verb));
        Err(format!("Unknown verb: {}", verb))
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::storage::engine::GraphStore;

  #[test]
  fn test_command_metadata() {
    let cmd = IntelGraphCommand;
    assert_eq!(cmd.domain(), "intelligence");
    assert_eq!(cmd.resource(), "graph");
    assert!(!cmd.routes().is_empty());
    assert!(!cmd.flags().is_empty());
    assert!(!cmd.examples().is_empty());
  }

  #[test]
  fn test_find_paths_empty_graph() {
    let graph = GraphStore::new();
    let paths = find_paths(&graph, "a", "b", 5);
    assert!(paths.is_empty());
  }

  #[test]
  fn test_find_paths_direct() {
    use crate::storage::engine::{GraphEdgeType, GraphNodeType};

    let graph = GraphStore::new();
    let _ = graph.add_node("a", "A", GraphNodeType::Host);
    let _ = graph.add_node("b", "B", GraphNodeType::Host);
    let _ = graph.add_edge("a", "b", GraphEdgeType::ConnectsTo, 1.0);

    let paths = find_paths(&graph, "a", "b", 5);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec!["a", "b"]);
  }

  #[test]
  fn test_truncate_str() {
    assert_eq!(truncate_str("hello", 10), "hello");
    assert_eq!(truncate_str("hello world", 8), "hello...");
  }
}
