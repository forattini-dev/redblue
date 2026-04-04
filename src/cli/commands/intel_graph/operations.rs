//! Graph Operation Commands
//!
//! Core operations for graph intelligence:
//! - Summary: Overview statistics
//! - Insights: Strategic analysis
//! - Export: JSON, GraphML, DOT, Mermaid
//! - Report: Comprehensive markdown reports
//! - Query: RQL execution
//! - Stats: Detailed statistics
//! - Import: Load graph data

use super::helpers::{chrono_lite_now, load_graph, truncate_str};
use crate::cli::{output::Output, CliContext};
use crate::serde_json::{from_str, Value};
use crate::storage::engine::{
    BetweennessCentrality, ConnectedComponents, CycleDetector, GraphEdgeType, GraphNodeType,
    GraphStore, LabelPropagation, PageRank,
};
use crate::storage::query::{parse, UnifiedExecutor};
use std::path::Path;

/// Graph summary command
pub fn cmd_summary(graph: &GraphStore, format: &str) -> Result<(), String> {
    let stats = graph.stats();

    // Run quick analysis
    let components = ConnectedComponents::find(graph);
    let pr = PageRank::default();
    let pr_result = pr.run(graph);

    // Count isolated nodes (components of size 1)
    let isolated_count = components.components.iter().filter(|c| c.size == 1).count();

    if format == "json" {
        println!(
            r#"{{"nodes":{},"edges":{},"components":{},"isolated":{}}}"#,
            stats.node_count, stats.edge_count, components.count, isolated_count
        );
    } else {
        Output::header("Graph Intelligence Summary");
        println!();
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│ Basic Statistics                                            │");
        println!("├─────────────────────────────────────────────────────────────┤");
        println!(
            "│  Nodes:          {:>10}                                 │",
            stats.node_count
        );
        println!(
            "│  Edges:          {:>10}                                 │",
            stats.edge_count
        );
        println!(
            "│  Density:        {:>10.4}                                 │",
            if stats.node_count > 1 {
                stats.edge_count as f64
                    / (stats.node_count as f64 * (stats.node_count as f64 - 1.0))
            } else {
                0.0
            }
        );
        println!("├─────────────────────────────────────────────────────────────┤");
        println!("│ Connectivity                                                │");
        println!("├─────────────────────────────────────────────────────────────┤");
        println!(
            "│  Components:     {:>10}                                 │",
            components.count
        );
        println!(
            "│  Isolated nodes: {:>10}                                 │",
            isolated_count
        );
        println!("├─────────────────────────────────────────────────────────────┤");
        println!("│ PageRank Analysis                                           │");
        println!("├─────────────────────────────────────────────────────────────┤");

        if !pr_result.scores.is_empty() {
            let mut ranked: Vec<_> = pr_result.scores.iter().collect();
            ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

            println!("│  Top influential nodes:                                     │");
            for (node, score) in ranked.iter().take(5) {
                println!(
                    "│    {:<35} {:>8.4}            │",
                    truncate_str(node, 35),
                    score
                );
            }
        } else {
            println!("│  No nodes to analyze                                        │");
        }

        println!("└─────────────────────────────────────────────────────────────┘");
    }

    Ok(())
}

/// Strategic insights command
pub fn cmd_insights(graph: &GraphStore, format: &str) -> Result<(), String> {
    let stats = graph.stats();

    if stats.node_count == 0 {
        Output::warning("Graph is empty - no insights to generate");
        return Ok(());
    }

    // Run all analyses
    let components = ConnectedComponents::find(graph);
    let centrality = BetweennessCentrality::compute(graph, true);
    let pr = PageRank::default();
    let pr_result = pr.run(graph);
    let lp = LabelPropagation::default();
    let communities = lp.run(graph);
    let detector = CycleDetector::new().max_length(10).max_cycles(50);
    let cycles = detector.find(graph);

    let mut insights: Vec<(String, String, String)> = Vec::new(); // (severity, category, message)

    // Count isolated nodes (components of size 1)
    let isolated_count = components.components.iter().filter(|c| c.size == 1).count();

    // Analyze isolated nodes
    if isolated_count > 0 {
        let pct = (isolated_count as f64 / stats.node_count as f64) * 100.0;
        if pct > 30.0 {
            insights.push((
                "HIGH".into(),
                "Connectivity".into(),
                format!(
                    "{:.0}% of nodes are isolated - potential segmentation issues",
                    pct
                ),
            ));
        } else if pct > 10.0 {
            insights.push((
                "MEDIUM".into(),
                "Connectivity".into(),
                format!(
                    "{} isolated nodes ({:.0}%) - review connectivity",
                    isolated_count, pct
                ),
            ));
        }
    }

    // Analyze components
    if components.count > 1 {
        insights.push((
            "INFO".into(),
            "Segmentation".into(),
            format!("Network has {} separate segments", components.count),
        ));
    }

    // Analyze choke points
    let max_centrality = centrality.scores.values().cloned().fold(0.0_f64, f64::max);
    let mut high_centrality: Vec<_> = centrality
        .scores
        .iter()
        .filter(|(_, &score)| score > max_centrality * 0.7)
        .collect();
    high_centrality.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

    if !high_centrality.is_empty() {
        let nodes: Vec<_> = high_centrality
            .iter()
            .take(3)
            .map(|(n, _)| n.as_str())
            .collect();
        insights.push((
            "CRITICAL".into(),
            "Choke Points".into(),
            format!(
                "Critical choke points: {} - single points of failure",
                nodes.join(", ")
            ),
        ));
    }

    // Analyze influential nodes
    let mut top_pr: Vec<_> = pr_result.scores.iter().collect();
    top_pr.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

    if let Some((top_node, top_score)) = top_pr.first() {
        if **top_score > 0.1 {
            insights.push((
                "HIGH".into(),
                "Influence".into(),
                format!(
                    "'{}' has disproportionate influence (score: {:.4})",
                    top_node, top_score
                ),
            ));
        }
    }

    // Analyze communities
    let community_count = communities.communities.len();
    if community_count > 1 {
        let largest = communities
            .communities
            .iter()
            .map(|c| c.size)
            .max()
            .unwrap_or(0);
        insights.push((
            "INFO".into(),
            "Communities".into(),
            format!(
                "{} distinct communities detected (largest: {} nodes)",
                community_count, largest
            ),
        ));
    }

    // Analyze cycles
    let cycle_count = cycles.cycles.len();
    if cycle_count > 0 {
        insights.push((
            "WARNING".into(),
            "Cycles".into(),
            format!(
                "{} cycles detected - potential circular dependencies",
                cycle_count
            ),
        ));
    }

    if format == "json" {
        let json_output: Vec<_> = insights
            .iter()
            .map(|(sev, cat, msg)| {
                format!(
                    r#"{{"severity":"{}","category":"{}","message":"{}"}}"#,
                    sev, cat, msg
                )
            })
            .collect();
        println!("[{}]", json_output.join(","));
    } else {
        Output::header("Strategic Intelligence Insights");
        println!();

        if insights.is_empty() {
            println!("  ✓ No significant issues detected");
        } else {
            for (severity, category, message) in &insights {
                let icon = match severity.as_str() {
                    "CRITICAL" => "🔴",
                    "HIGH" => "🟠",
                    "WARNING" => "🟡",
                    "MEDIUM" => "🟡",
                    "INFO" => "🔵",
                    _ => "⚪",
                };
                println!("{} [{}] {}: {}", icon, severity, category, message);
            }
        }

        println!();
        println!("Run specific commands for detailed analysis:");
        println!("  rb intel graph pagerank     - Influential nodes");
        println!("  rb intel graph centrality   - Choke points");
        println!("  rb intel graph communities  - Asset groupings");
        println!("  rb intel graph cycles       - Circular dependencies");
    }

    Output::success(&format!("Generated {} insights", insights.len()));
    Ok(())
}

/// Export graph command
pub fn cmd_export(ctx: &CliContext, graph: &GraphStore) -> Result<(), String> {
    let format = ctx
        .flags
        .get("format")
        .map(|s| s.as_str())
        .unwrap_or("json");
    let output_path = ctx
        .flags
        .get("report-output")
        .map(|s| s.replace("intelligence-report.md", &format!("graph.{}", format)))
        .unwrap_or_else(|| format!("graph.{}", format));

    Output::info(&format!("Exporting graph to {} format...", format));

    let nodes: Vec<_> = graph.iter_nodes().collect();
    let edges = graph.iter_all_edges();

    let content = match format {
        "json" => {
            let nodes_json: Vec<String> = nodes
                .iter()
                .map(|n| {
                    format!(
                        r#"{{"id":"{}","label":"{}","type":"{}"}}"#,
                        n.id,
                        n.label,
                        format!("{:?}", n.node_type)
                    )
                })
                .collect();
            let edges_json: Vec<String> = edges
                .iter()
                .map(|e| {
                    format!(
                        r#"{{"from":"{}","to":"{}","type":"{}","weight":{}}}"#,
                        e.source_id,
                        e.target_id,
                        format!("{:?}", e.edge_type),
                        e.weight
                    )
                })
                .collect();
            format!(
                r#"{{"nodes":[{}],"edges":[{}]}}"#,
                nodes_json.join(","),
                edges_json.join(",")
            )
        }
        "graphml" => {
            let mut s = String::new();
            s.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
            s.push('\n');
            s.push_str(r#"<graphml xmlns="http://graphml.graphdrawing.org/xmlns">"#);
            s.push('\n');
            s.push_str(r#"  <key id="label" for="node" attr.name="label" attr.type="string"/>"#);
            s.push('\n');
            s.push_str(r#"  <key id="type" for="node" attr.name="type" attr.type="string"/>"#);
            s.push('\n');
            s.push_str(r#"  <key id="weight" for="edge" attr.name="weight" attr.type="double"/>"#);
            s.push('\n');
            s.push_str(r#"  <graph id="G" edgedefault="directed">"#);
            s.push('\n');
            for node in &nodes {
                s.push_str(&format!(r#"    <node id="{}">"#, node.id));
                s.push('\n');
                s.push_str(&format!(r#"      <data key="label">{}</data>"#, node.label));
                s.push('\n');
                s.push_str(&format!(
                    r#"      <data key="type">{:?}</data>"#,
                    node.node_type
                ));
                s.push('\n');
                s.push_str("    </node>\n");
            }
            for (i, edge) in edges.iter().enumerate() {
                s.push_str(&format!(
                    r#"    <edge id="e{}" source="{}" target="{}">"#,
                    i, edge.source_id, edge.target_id
                ));
                s.push('\n');
                s.push_str(&format!(
                    r#"      <data key="weight">{}</data>"#,
                    edge.weight
                ));
                s.push('\n');
                s.push_str("    </edge>\n");
            }
            s.push_str("  </graph>\n");
            s.push_str("</graphml>\n");
            s
        }
        "dot" => {
            let mut s = String::new();
            s.push_str("digraph G {\n");
            s.push_str("  rankdir=LR;\n");
            s.push_str("  node [shape=box];\n");
            for node in &nodes {
                let color = match format!("{:?}", node.node_type).as_str() {
                    "Host" => "lightblue",
                    "Service" => "lightgreen",
                    "Credential" => "lightyellow",
                    "Vulnerability" => "lightcoral",
                    _ => "white",
                };
                s.push_str(&format!(
                    "  \"{}\" [label=\"{}\" style=filled fillcolor={}];\n",
                    node.id, node.label, color
                ));
            }
            for edge in &edges {
                let style = if edge.weight > 1.0 { "bold" } else { "solid" };
                s.push_str(&format!(
                    "  \"{}\" -> \"{}\" [label=\"{:?}\" style={}];\n",
                    edge.source_id, edge.target_id, edge.edge_type, style
                ));
            }
            s.push_str("}\n");
            s
        }
        "mermaid" => {
            let mut s = String::new();
            s.push_str("```mermaid\n");
            s.push_str("flowchart LR\n");

            for node in &nodes {
                let shape = match format!("{:?}", node.node_type).as_str() {
                    "Host" => format!("{}[{}]", node.id, node.label),
                    "Service" => format!("{}([{}])", node.id, node.label),
                    "Credential" => format!("{}{{{{{}}}}}", node.id, node.label),
                    "Vulnerability" => format!("{}>{{{}}}", node.id, node.label),
                    "User" => format!("{}(({}))", node.id, node.label),
                    _ => format!("{}[{}]", node.id, node.label),
                };
                s.push_str(&format!("    {}\n", shape));
            }

            for edge in &edges {
                let arrow = match format!("{:?}", edge.edge_type).as_str() {
                    "ConnectsTo" => "-->",
                    "HasService" => "-.->",
                    "HasCredential" => "==>",
                    "AffectedBy" => "--x",
                    _ => "-->",
                };
                s.push_str(&format!(
                    "    {} {} {}\n",
                    edge.source_id, arrow, edge.target_id
                ));
            }

            s.push_str("```\n");
            s
        }
        _ => {
            return Err(format!(
                "Unknown format: {}. Use json, graphml, dot, or mermaid",
                format
            ));
        }
    };

    // Write to file
    match std::fs::write(&output_path, &content) {
        Ok(_) => {
            Output::success(&format!(
                "Exported {} nodes and {} edges to {}",
                nodes.len(),
                edges.len(),
                output_path
            ));
        }
        Err(e) => {
            // Print to stdout if file write fails
            println!("{}", content);
            Output::warning(&format!(
                "Could not write to file ({}), printed to stdout",
                e
            ));
        }
    }

    Ok(())
}

/// Report generation command
pub fn cmd_report(ctx: &CliContext, graph: &GraphStore) -> Result<(), String> {
    let output_path = ctx
        .flags
        .get("report-output")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "intelligence-report.md".to_string());

    Output::info("Generating comprehensive intelligence report...");

    // Collect data
    let nodes: Vec<_> = graph.iter_nodes().collect();
    let edges = graph.iter_all_edges();
    let node_count = nodes.len();
    let edge_count = edges.len();

    // Run algorithms
    let pr = PageRank::new().alpha(0.85);
    let pr_result = pr.run(graph);

    let components = ConnectedComponents::find(graph);

    let centrality = BetweennessCentrality::compute(graph, true);

    let lp = LabelPropagation::new().max_iterations(100);
    let communities = lp.run(graph);

    let cd = CycleDetector::new().max_length(10).max_cycles(50);
    let cycles = cd.find(graph);

    // Build report
    let mut report = String::new();
    report.push_str("# Graph Intelligence Report\n\n");
    report.push_str(&format!("Generated: {}\n\n", chrono_lite_now()));
    report.push_str("---\n\n");

    // Summary
    report.push_str("## Summary\n\n");
    report.push_str("| Metric | Value |\n");
    report.push_str("|--------|-------|\n");
    report.push_str(&format!("| Total Nodes | {} |\n", node_count));
    report.push_str(&format!("| Total Edges | {} |\n", edge_count));
    report.push_str(&format!(
        "| Connected Components | {} |\n",
        components.count
    ));
    report.push_str(&format!(
        "| Communities | {} |\n",
        communities.communities.len()
    ));
    report.push_str(&format!("| Cycles Detected | {} |\n", cycles.cycles.len()));
    report.push_str("\n");

    // PageRank top nodes
    report.push_str("## Most Influential Nodes (PageRank)\n\n");
    let mut top_pr: Vec<_> = pr_result.scores.iter().collect();
    top_pr.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    report.push_str("| Rank | Node | Score |\n");
    report.push_str("|------|------|-------|\n");
    for (i, (node, score)) in top_pr.iter().take(10).enumerate() {
        report.push_str(&format!("| {} | {} | {:.4} |\n", i + 1, node, score));
    }
    report.push_str("\n");

    // Centrality choke points
    report.push_str("## Critical Choke Points (Betweenness Centrality)\n\n");
    let mut top_bc: Vec<_> = centrality.scores.iter().collect();
    top_bc.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    report.push_str("| Rank | Node | Centrality |\n");
    report.push_str("|------|------|------------|\n");
    for (i, (node, score)) in top_bc.iter().take(10).enumerate() {
        report.push_str(&format!("| {} | {} | {:.4} |\n", i + 1, node, score));
    }
    report.push_str("\n");

    // Components
    report.push_str("## Network Segments (Connected Components)\n\n");
    report.push_str(&format!(
        "Found **{}** connected components.\n\n",
        components.count
    ));
    for (i, comp) in components.components.iter().take(5).enumerate() {
        report.push_str(&format!(
            "### Component {} ({} nodes)\n\n",
            i + 1,
            comp.size
        ));
        let preview: Vec<_> = comp.nodes.iter().take(5).map(|s| s.as_str()).collect();
        report.push_str(&format!("Nodes: {}", preview.join(", ")));
        if comp.nodes.len() > 5 {
            report.push_str(&format!(" ... and {} more", comp.nodes.len() - 5));
        }
        report.push_str("\n\n");
    }

    // Communities
    report.push_str("## Asset Communities\n\n");
    report.push_str(&format!(
        "Detected **{}** communities.\n\n",
        communities.communities.len()
    ));
    for comm in communities.communities.iter().take(5) {
        report.push_str(&format!(
            "- **Community {}**: {} nodes\n",
            comm.label, comm.size
        ));
    }
    report.push_str("\n");

    // Cycles
    if !cycles.cycles.is_empty() {
        report.push_str("## Detected Cycles (Circular Dependencies)\n\n");
        report.push_str(&format!("Found **{}** cycles.\n\n", cycles.cycles.len()));
        for (i, cycle) in cycles.cycles.iter().take(5).enumerate() {
            report.push_str(&format!(
                "{}. {} (length {})\n",
                i + 1,
                cycle.nodes.join(" → "),
                cycle.length
            ));
        }
        report.push_str("\n");
    }

    // Recommendations
    report.push_str("## Recommendations\n\n");
    if let Some((top_node, top_score)) = top_pr.first() {
        if **top_score > 0.1 {
            report.push_str(&format!("- ⚠️ **High Influence**: Node `{}` has disproportionate influence. Consider redundancy.\n", top_node));
        }
    }
    let isolated = components.components.iter().filter(|c| c.size == 1).count();
    if isolated > 0 {
        report.push_str(&format!(
            "- ℹ️ **Isolated Nodes**: {} isolated nodes detected. Review connectivity.\n",
            isolated
        ));
    }
    if !cycles.cycles.is_empty() {
        report.push_str(&format!(
            "- ⚠️ **Cycles**: {} cycles detected. May indicate circular dependencies.\n",
            cycles.cycles.len()
        ));
    }
    report.push_str("\n---\n\n");
    report.push_str("*Report generated by redblue intel graph*\n");

    // Write to file
    match std::fs::write(&output_path, &report) {
        Ok(_) => {
            Output::success(&format!("Report saved to {}", output_path));
        }
        Err(e) => {
            println!("{}", report);
            Output::warning(&format!(
                "Could not write to file ({}), printed to stdout",
                e
            ));
        }
    }

    Ok(())
}

/// RQL query command
pub fn cmd_query(ctx: &CliContext, graph: &GraphStore, format: &str) -> Result<(), String> {
    // Get query from target or first positional arg
    let query_str = ctx
        .target
        .clone()
        .or_else(|| ctx.args.first().cloned())
        .ok_or_else(|| "No query provided. Usage: rb intel graph query \"<RQL>\"".to_string())?;

    Output::info(&format!(
        "Executing query: {}",
        truncate_str(&query_str, 60)
    ));

    // Parse the query
    let query = parse(&query_str).map_err(|e| format!("Parse error: {:?}", e))?;

    // Execute using unified executor (static method for graph reference)
    let result = UnifiedExecutor::execute_on(graph, &query)
        .map_err(|e| format!("Execution error: {:?}", e))?;

    if format == "json" {
        // JSON output
        let records_json: Vec<String> = result
            .records
            .iter()
            .map(|r| {
                let values: Vec<String> = r
                    .values
                    .iter()
                    .map(|(k, v)| format!(r#""{}":{:?}"#, k, v))
                    .collect();
                let nodes: Vec<String> = r
                    .nodes
                    .iter()
                    .map(|(alias, n)| {
                        format!(
                            r#"{{"alias":"{}","id":"{}","label":"{}"}}"#,
                            alias, n.id, n.label
                        )
                    })
                    .collect();
                let edges: Vec<String> = r
                    .edges
                    .iter()
                    .map(|(_, e)| {
                        format!(
                            r#"{{"from":"{}","to":"{}","type":"{:?}"}}"#,
                            e.from, e.to, e.edge_type
                        )
                    })
                    .collect();
                format!(
                    r#"{{"values":{{{}}},"nodes":[{}],"edges":[{}]}}"#,
                    values.join(","),
                    nodes.join(","),
                    edges.join(",")
                )
            })
            .collect();
        println!("[{}]", records_json.join(","));
    } else {
        Output::header("Query Results");
        println!();

        if result.records.is_empty() {
            println!("  No results found.");
        } else {
            for (i, record) in result.records.iter().take(100).enumerate() {
                println!("─── Record {} ───", i + 1);

                // Print values
                if !record.values.is_empty() {
                    for (key, val) in &record.values {
                        println!("  {}: {:?}", key, val);
                    }
                }

                // Print matched nodes
                for (alias, node) in &record.nodes {
                    println!(
                        "  {} → {} ({}) [{:?}]",
                        alias, node.label, node.id, node.node_type
                    );
                }

                // Print matched edges
                for (_, edge) in &record.edges {
                    println!("  {} --[{:?}]--> {}", edge.from, edge.edge_type, edge.to);
                }

                // Print paths
                for path in &record.paths {
                    println!(
                        "  PATH: {} (weight: {:.2})",
                        path.nodes.join(" → "),
                        path.total_weight
                    );
                }
            }

            if result.records.len() > 100 {
                println!("\n... and {} more records", result.records.len() - 100);
            }
        }

        println!();
        println!(
            "Query stats: {} nodes scanned, {} edges scanned",
            result.stats.nodes_scanned, result.stats.edges_scanned
        );
    }

    Output::success(&format!("Returned {} records", result.records.len()));
    Ok(())
}

/// RQL help command
pub fn cmd_rql_help() -> Result<(), String> {
    println!();
    println!("\x1b[1;36m╔═══════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;36m║          RQL - Redblue Query Language Reference                           ║\x1b[0m");
    println!("\x1b[1;36m╚═══════════════════════════════════════════════════════════════════════════╝\x1b[0m");
    println!();

    // Query Modes
    println!("\x1b[1;33m┌─── QUERY MODES ──────────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  RQL auto-detects query syntax. Supported modes:                          │");
    println!("│                                                                           │");
    println!("│  \x1b[1;32mCypher\x1b[0m    MATCH patterns, Neo4j-inspired                                 │");
    println!("│  \x1b[1;32mSQL\x1b[0m       SELECT queries on table data                                   │");
    println!("│  \x1b[1;32mGremlin\x1b[0m   g.V() traversals, TinkerPop-inspired                           │");
    println!("│  \x1b[1;32mSPARQL\x1b[0m    RDF-style triple patterns                                      │");
    println!("│  \x1b[1;32mPath\x1b[0m      Native path-finding queries                                    │");
    println!("│  \x1b[1;32mNatural\x1b[0m   English-like queries (quoted)                                  │");
    println!("\x1b[1;33m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // Cypher Mode
    println!("\x1b[1;35m┌─── CYPHER MODE ──────────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  Pattern matching with nodes and relationships                            │");
    println!("│                                                                           │");
    println!("│  \x1b[1mSyntax:\x1b[0m                                                                   │");
    println!("│    MATCH (alias:Type) WHERE condition RETURN alias                        │");
    println!("│    MATCH (a)-[r:REL]->(b) RETURN a, r, b                                  │");
    println!("│                                                                           │");
    println!("│  \x1b[1mNode Types:\x1b[0m Host, Service, Credential, User, Vulnerability,             │");
    println!("│             Domain, Endpoint, Technology, Certificate, Network            │");
    println!("│                                                                           │");
    println!("│  \x1b[1mEdge Types:\x1b[0m HasService, ConnectsTo, AuthAccess, UsesTech,                │");
    println!("│             AffectedBy, HasUser, ResolvesTo, HasSubdomain                 │");
    println!("│                                                                           │");
    println!("│  \x1b[1mExamples:\x1b[0m                                                                 │");
    println!("│    MATCH (h:Host) RETURN h                                                │");
    println!("│    MATCH (h:Host)-[s:HasService]->(svc) RETURN h, svc                     │");
    println!("│    MATCH (h:Host)-[:AuthAccess]->(c:Credential) WHERE h.ip = '10.0.0.1'   │");
    println!("│    MATCH (a)-[*1..5]->(b) RETURN a, b   # Variable-length path            │");
    println!("\x1b[1;35m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // SQL Mode
    println!("\x1b[1;34m┌─── SQL MODE ─────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  Table queries on RedDB data                                              │");
    println!("│                                                                           │");
    println!("│  \x1b[1mSyntax:\x1b[0m                                                                   │");
    println!("│    SELECT cols FROM table WHERE cond ORDER BY col LIMIT n                 │");
    println!("│                                                                           │");
    println!("│  \x1b[1mOperators:\x1b[0m =, !=, <, >, <=, >=, LIKE, IN, BETWEEN, AND, OR, NOT         │");
    println!("│                                                                           │");
    println!("│  \x1b[1mExamples:\x1b[0m                                                                 │");
    println!("│    SELECT * FROM hosts WHERE ip LIKE '192.168.%'                          │");
    println!("│    SELECT ip, port FROM services WHERE port < 1024                        │");
    println!("│    SELECT * FROM vulns WHERE cvss >= 7.0 ORDER BY cvss DESC               │");
    println!("\x1b[1;34m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // Gremlin Mode
    println!("\x1b[1;32m┌─── GREMLIN MODE ─────────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  Graph traversals with step chains                                        │");
    println!("│                                                                           │");
    println!("│  \x1b[1mEntry Points:\x1b[0m                                                             │");
    println!("│    g.V()         All vertices (nodes)                                     │");
    println!("│    g.V('id')     Specific vertex by ID                                    │");
    println!("│    g.E()         All edges                                                │");
    println!("│                                                                           │");
    println!("│  \x1b[1mTraversal Steps:\x1b[0m                                                          │");
    println!("│    .out('rel')   Follow outgoing edges                                    │");
    println!("│    .in('rel')    Follow incoming edges                                    │");
    println!("│    .both()       Both directions                                          │");
    println!("│    .outE()       Get outgoing edge objects                                │");
    println!("│    .inV()        Target vertex of edge                                    │");
    println!("│                                                                           │");
    println!("│  \x1b[1mFilters:\x1b[0m                                                                  │");
    println!("│    .has('prop', 'value')   Filter by property                             │");
    println!("│    .hasLabel('Type')       Filter by node type                            │");
    println!("│    .hasId('id')            Filter by ID                                   │");
    println!("│    .limit(n)               Limit results                                  │");
    println!("│    .dedup()                Remove duplicates                              │");
    println!("│                                                                           │");
    println!("│  \x1b[1mTerminals:\x1b[0m                                                                │");
    println!("│    .toList()    Return as list                                            │");
    println!("│    .count()     Count results                                             │");
    println!("│    .path()      Show traversal path                                       │");
    println!("│                                                                           │");
    println!("│  \x1b[1mExamples:\x1b[0m                                                                 │");
    println!("│    g.V().hasLabel('Host').out('HasService').toList()                      │");
    println!("│    g.V('host:10.0.0.1').out('AuthAccess').values('name')                  │");
    println!("│    g.V().has('type', 'Host').outE().groupCount()                          │");
    println!("\x1b[1;32m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // Path Mode
    println!("\x1b[1;31m┌─── PATH MODE ────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  Native path-finding between nodes                                        │");
    println!("│                                                                           │");
    println!("│  \x1b[1mSyntax:\x1b[0m                                                                   │");
    println!("│    PATH FROM <source> TO <target> [VIA :Type] [MAX_HOPS n]                │");
    println!("│    PATHS ALL FROM <source> TO <target> LIMIT n                            │");
    println!("│    PATHS FROM <source> REACHABLE                                          │");
    println!("│                                                                           │");
    println!("│  \x1b[1mNode Selectors:\x1b[0m                                                           │");
    println!("│    host(10.0.0.1)      Match by IP                                        │");
    println!("│    host:10.0.0.1       Shorthand                                          │");
    println!("│    credential(admin)   Match credential by name                           │");
    println!("│    user@host           User at specific host                              │");
    println!("│                                                                           │");
    println!("│  \x1b[1mExamples:\x1b[0m                                                                 │");
    println!("│    PATH FROM host:10.0.0.1 TO host:10.0.0.50                              │");
    println!("│    PATHS ALL FROM host:attacker TO host:dc MAX_HOPS 5                     │");
    println!("│    PATH FROM host:external TO host:database VIA :AuthAccess               │");
    println!("\x1b[1;31m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // SPARQL Mode
    println!("\x1b[1;37m┌─── SPARQL MODE ──────────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  RDF-style triple pattern queries                                         │");
    println!("│                                                                           │");
    println!("│  \x1b[1mSyntax:\x1b[0m                                                                   │");
    println!("│    SELECT ?var WHERE {{ ?s :predicate ?o }}                                │");
    println!("│                                                                           │");
    println!("│  \x1b[1mExamples:\x1b[0m                                                                 │");
    println!("│    SELECT ?host WHERE {{ ?host :hasService ?svc }}                         │");
    println!("│    SELECT ?h ?v WHERE {{ ?h :affectedBy ?v . ?v :cvss ?score }}            │");
    println!("\x1b[1;37m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // Natural Language Mode
    println!("\x1b[1;36m┌─── NATURAL LANGUAGE MODE ────────────────────────────────────────────────┐\x1b[0m");
    println!("│  English-like queries (wrap in quotes)                                    │");
    println!("│                                                                           │");
    println!("│  \x1b[1mExamples:\x1b[0m                                                                 │");
    println!("│    \"find all hosts with open ports\"                                       │");
    println!("│    \"show path from 10.0.0.1 to database\"                                  │");
    println!("│    \"list credentials on web servers\"                                      │");
    println!("│    \"count services by type\"                                               │");
    println!("\x1b[1;36m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    // Usage Examples
    println!("\x1b[1;33m┌─── QUICK EXAMPLES ──────────────────────────────────────────────────────┐\x1b[0m");
    println!("│  rb intel graph query \"MATCH (h:Host) RETURN h\"                           │");
    println!("│  rb intel graph query \"g.V().hasLabel('Host').out().toList()\"             │");
    println!("│  rb intel graph query \"PATH FROM host:10.0.0.1 TO host:10.0.0.50\"         │");
    println!("│  rb intel graph query \"SELECT * FROM hosts WHERE cvss >= 7.0\"             │");
    println!("\x1b[1;33m└───────────────────────────────────────────────────────────────────────────┘\x1b[0m");
    println!();

    Ok(())
}

/// Graph stats command
pub fn cmd_stats(graph: &GraphStore, format: &str) -> Result<(), String> {
    let nodes: Vec<_> = graph.iter_nodes().collect();
    let edges = graph.iter_all_edges();

    // Count by type
    let mut node_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut edge_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for node in &nodes {
        let type_name = format!("{:?}", node.node_type);
        *node_types.entry(type_name).or_insert(0) += 1;
    }

    for edge in &edges {
        let type_name = format!("{:?}", edge.edge_type);
        *edge_types.entry(type_name).or_insert(0) += 1;
    }

    // Calculate density
    let n = nodes.len() as f64;
    let e = edges.len() as f64;
    let density = if n > 1.0 { e / (n * (n - 1.0)) } else { 0.0 };

    // Average degree
    let avg_degree = if n > 0.0 { (2.0 * e) / n } else { 0.0 };

    if format == "json" {
        let node_types_json: Vec<String> = node_types
            .iter()
            .map(|(t, c)| format!(r#""{}":{}"#, t, c))
            .collect();
        let edge_types_json: Vec<String> = edge_types
            .iter()
            .map(|(t, c)| format!(r#""{}":{}"#, t, c))
            .collect();

        println!(
            r#"{{"nodes":{},"edges":{},"density":{:.6},"avg_degree":{:.2},"node_types":{{{}}},"edge_types":{{{}}}}}"#,
            nodes.len(),
            edges.len(),
            density,
            avg_degree,
            node_types_json.join(","),
            edge_types_json.join(",")
        );
    } else {
        Output::header("Graph Statistics");
        println!();

        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│  OVERVIEW                                                   │");
        println!("├─────────────────────────────────────────────────────────────┤");
        println!(
            "│  Total Nodes: {:<10}  Total Edges: {:<10}          │",
            nodes.len(),
            edges.len()
        );
        println!(
            "│  Density:     {:<10.4}  Avg Degree:  {:<10.2}          │",
            density, avg_degree
        );
        println!("└─────────────────────────────────────────────────────────────┘");
        println!();

        println!("NODE TYPES:");
        let mut sorted_nodes: Vec<_> = node_types.iter().collect();
        sorted_nodes.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in sorted_nodes {
            let bar_len = (*count as f64 / nodes.len().max(1) as f64 * 30.0) as usize;
            println!("  {:20} {:>6}  {}", type_name, count, "█".repeat(bar_len));
        }

        println!();
        println!("EDGE TYPES:");
        let mut sorted_edges: Vec<_> = edge_types.iter().collect();
        sorted_edges.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in sorted_edges {
            let bar_len = (*count as f64 / edges.len().max(1) as f64 * 30.0) as usize;
            println!("  {:20} {:>6}  {}", type_name, count, "█".repeat(bar_len));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct ImportNode {
    id: String,
    label: String,
    node_type: GraphNodeType,
}

#[derive(Debug, Clone)]
struct ImportEdge {
    source: String,
    target: String,
    edge_type: GraphEdgeType,
    weight: f32,
}

fn parse_node_type(raw: &str) -> GraphNodeType {
    match raw.trim().to_lowercase().as_str() {
        "host" => GraphNodeType::Host,
        "service" => GraphNodeType::Service,
        "credential" => GraphNodeType::Credential,
        "vulnerability" => GraphNodeType::Vulnerability,
        "endpoint" => GraphNodeType::Endpoint,
        "technology" => GraphNodeType::Technology,
        "user" => GraphNodeType::User,
        "domain" => GraphNodeType::Domain,
        "certificate" => GraphNodeType::Certificate,
        _ => GraphNodeType::Host,
    }
}

fn parse_edge_type(raw: &str) -> GraphEdgeType {
    match raw.trim().to_lowercase().as_str() {
        "has_service" | "hasservice" => GraphEdgeType::HasService,
        "has_endpoint" | "hasendpoint" => GraphEdgeType::HasEndpoint,
        "uses_tech" | "usestech" => GraphEdgeType::UsesTech,
        "auth_access" | "authaccess" => GraphEdgeType::AuthAccess,
        "affected_by" | "affectedby" => GraphEdgeType::AffectedBy,
        "contains" => GraphEdgeType::Contains,
        "connects_to" | "connectsto" => GraphEdgeType::ConnectsTo,
        "related_to" | "relatedto" => GraphEdgeType::RelatedTo,
        "has_user" | "hasuser" => GraphEdgeType::HasUser,
        "has_cert" | "hascert" => GraphEdgeType::HasCert,
        "host" => GraphEdgeType::HasService,
        _ => GraphEdgeType::ConnectsTo,
    }
}

fn parse_json_graph(content: &str) -> Result<(Vec<ImportNode>, Vec<ImportEdge>), String> {
    let value =
        from_str::<Value>(content).map_err(|e| format!("Invalid JSON graph format: {}", e))?;
    let root = value.as_object().ok_or("JSON graph must be an object")?;

    let nodes = root
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "JSON graph missing 'nodes' array".to_string())?;

    let edges = root
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| "JSON graph missing 'edges' array".to_string())?;

    let parsed_nodes = nodes
        .iter()
        .map(|node| {
            let node = node
                .as_object()
                .ok_or("Each node entry must be an object")?;
            let id = node
                .get("id")
                .and_then(Value::as_str)
                .ok_or("Node entry missing 'id'")?;
            let label = node
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or(id)
                .to_string();
            let node_type = node
                .get("type")
                .or_else(|| node.get("node_type"))
                .and_then(Value::as_str)
                .map_or(GraphNodeType::Host, parse_node_type);

            Ok::<ImportNode, String>(ImportNode {
                id: id.to_string(),
                label,
                node_type,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let parsed_edges = edges
        .iter()
        .map(|edge| {
            let edge = edge
                .as_object()
                .ok_or("Each edge entry must be an object")?;
            let source = edge
                .get("from")
                .or_else(|| edge.get("source"))
                .and_then(Value::as_str)
                .ok_or("Edge entry missing source (from/source)")?;
            let target = edge
                .get("to")
                .or_else(|| edge.get("target"))
                .and_then(Value::as_str)
                .ok_or("Edge entry missing target (to/target)")?;
            let edge_type = edge
                .get("type")
                .or_else(|| edge.get("edge_type"))
                .and_then(Value::as_str)
                .map_or(GraphEdgeType::ConnectsTo, parse_edge_type);
            let weight = edge.get("weight").map_or(1.0, |value| match value {
                Value::Number(n) => *n as f32,
                Value::String(s) => s.parse::<f32>().unwrap_or(1.0),
                _ => 1.0,
            });

            Ok::<ImportEdge, String>(ImportEdge {
                source: source.to_string(),
                target: target.to_string(),
                edge_type,
                weight,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((parsed_nodes, parsed_edges))
}

fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
    let token_double = format!(r#"{}=""#, attr);
    let token_single = format!(r#"{}='#'"#, attr);
    let (start, quote_char) = if let Some(pos) = line.find(&token_double) {
        (pos + token_double.len(), '"')
    } else if let Some(pos) = line.find(&token_single) {
        (pos + token_single.len(), '\'')
    } else {
        return None;
    };

    let rest = &line[start..];
    let end = rest.find(quote_char)?;
    Some(rest[..end].to_string())
}

fn extract_xml_data(line: &str, key: &str) -> Option<String> {
    let start_token = format!(r#"<data key="{}">"#, key);
    let start = line.find(&start_token)?;
    let rest = &line[start + start_token.len()..];
    let end = rest.find("</data>")?;
    Some(rest[..end].trim().to_string())
}

fn parse_graphml_graph(content: &str) -> Result<(Vec<ImportNode>, Vec<ImportEdge>), String> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    let mut active_node: Option<usize> = None;
    let mut active_edge: Option<ImportEdge> = None;

    for line in content.lines() {
        let line = line.trim();

        if line.contains("<node") {
            if let Some(id) = extract_xml_attr(line, "id") {
                let label = line
                    .find("label=\"")
                    .and_then(|_| extract_xml_attr(line, "label"))
                    .unwrap_or_else(|| id.clone());
                let node_type =
                    extract_xml_attr(line, "type").unwrap_or_else(|| "host".to_string());
                nodes.push(ImportNode {
                    id,
                    label,
                    node_type: parse_node_type(&node_type),
                });
                active_node = Some(nodes.len() - 1);
                if line.contains("</node>") {
                    active_node = None;
                }
            }
            continue;
        }

        if line.contains("</node>") {
            active_node = None;
            continue;
        }

        if let Some(idx) = active_node {
            if let Some(label) = extract_xml_data(line, "label") {
                nodes[idx].label = label;
                continue;
            }
            if let Some(raw_type) = extract_xml_data(line, "type") {
                nodes[idx].node_type = parse_node_type(&raw_type);
                continue;
            }
        }

        if let Some(start_edge) = line.find("<edge") {
            if let Some(source) = extract_xml_attr(&line[start_edge..], "source") {
                if let Some(target) = extract_xml_attr(&line[start_edge..], "target") {
                    let mut edge = ImportEdge {
                        source,
                        target,
                        edge_type: GraphEdgeType::ConnectsTo,
                        weight: 1.0,
                    };

                    if let Some(raw_type) = extract_xml_data(line, "type") {
                        edge.edge_type = parse_edge_type(&raw_type);
                    }
                    if let Some(weight) = extract_xml_data(line, "weight") {
                        edge.weight = weight.parse::<f32>().unwrap_or(1.0);
                    }

                    if line.contains("</edge>") {
                        edges.push(edge);
                    } else {
                        active_edge = Some(edge);
                    }
                }
            }
            continue;
        }

        if let Some(edge) = active_edge.as_mut() {
            if let Some(raw_type) = extract_xml_data(line, "type") {
                edge.edge_type = parse_edge_type(&raw_type);
            }
            if let Some(weight) = extract_xml_data(line, "weight") {
                edge.weight = weight.parse::<f32>().unwrap_or(1.0);
            }

            if line.contains("</edge>") {
                edges.push(active_edge.take().unwrap_or(ImportEdge {
                    source: String::new(),
                    target: String::new(),
                    edge_type: GraphEdgeType::ConnectsTo,
                    weight: 1.0,
                }));
            }
        }
        if line.contains("</edge>") {
            active_edge = None;
        }
    }

    edges.retain(|edge| !edge.source.is_empty() && !edge.target.is_empty());
    if nodes.is_empty() && edges.is_empty() {
        return Err("No valid node/edge entries found in GraphML content".to_string());
    }
    Ok((nodes, edges))
}

/// Import graph command
pub fn cmd_import(ctx: &CliContext) -> Result<(), String> {
    let file_path = ctx
        .target
        .clone()
        .or_else(|| ctx.args.first().cloned())
        .ok_or_else(|| "No file path provided. Usage: rb intel graph import <file>".to_string())?;

    let format = ctx
        .flags
        .get("format")
        .map(|s| s.as_str())
        .unwrap_or("json");
    let format = format.to_lowercase();

    Output::info(&format!(
        "Importing graph from {} (format: {})...",
        file_path, format
    ));

    // Read file
    let content =
        std::fs::read_to_string(&file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let db_path = ctx
        .flags
        .get("db")
        .map(|s| s.as_str())
        .unwrap_or(".redblue/graph.db");

    let mut graph = load_graph(db_path)?;

    let (nodes, edges) = match format.as_str() {
        "json" => parse_json_graph(&content)?,
        "graphml" => parse_graphml_graph(&content)?,
        _ => return Err(format!("Unknown format: {}. Use json or graphml", format)),
    };

    let mut imported_nodes = 0usize;
    let mut skipped_nodes = 0usize;
    let mut imported_edges = 0usize;
    let mut skipped_edges = 0usize;

    for node in nodes {
        if graph.has_node(&node.id) {
            skipped_nodes += 1;
            continue;
        }

        if graph
            .add_node(&node.id, &node.label, node.node_type)
            .is_ok()
        {
            imported_nodes += 1;
        } else {
            skipped_nodes += 1;
        }
    }

    for edge in edges {
        if !graph.has_node(&edge.source) || !graph.has_node(&edge.target) {
            skipped_edges += 1;
            continue;
        }

        let duplicate =
            graph
                .outgoing_edges(&edge.source)
                .iter()
                .any(|(edge_type, target, weight)| {
                    *edge_type == edge.edge_type
                        && target == &edge.target
                        && (*weight - edge.weight).abs() <= f32::EPSILON
                });
        if duplicate {
            skipped_edges += 1;
            continue;
        }

        if graph
            .add_edge(&edge.source, &edge.target, edge.edge_type, edge.weight)
            .is_ok()
        {
            imported_edges += 1;
        } else {
            skipped_edges += 1;
        }
    }

    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!("Failed to create db directory {}: {}", parent.display(), e)
            })?;
        }
    }

    std::fs::write(db_path, graph.serialize())
        .map_err(|e| format!("Failed to write graph database {}: {}", db_path, e))?;

    Output::success(&format!(
        "Imported {} nodes, {} edges from {} (skipped {} nodes, {} edges)",
        imported_nodes, imported_edges, file_path, skipped_nodes, skipped_edges
    ));

    Ok(())
}
