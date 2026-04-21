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

fn graph_summary_payload(
  nodes: u64,
  edges: u64,
  components: usize,
  isolated: usize,
  pr_result: &crate::storage::engine::PageRankResult,
) -> Value {
  let mut ranked: Vec<_> = pr_result.scores.iter().collect();
  ranked.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
  let top_influential: Vec<Value> = ranked
    .iter()
    .take(5)
    .map(|(node, score)| json!({"node": node, "score": score}))
    .collect();

  json!({
    "nodes": nodes,
    "edges": edges,
    "components": components,
    "isolated": isolated,
    "top_influential": top_influential
  })
}

fn graph_insights_payload(
  node_count: u64,
  component_count: usize,
  isolated_count: usize,
  community_count: usize,
  cycle_count: usize,
  insights: &[(String, String, String)],
) -> Value {
  let insights_json: Vec<Value> = insights
    .iter()
    .map(|(severity, category, message)| {
      json!({
        "severity": severity,
        "category": category,
        "message": message
      })
    })
    .collect();

  json!({
    "node_count": node_count,
    "component_count": component_count,
    "isolated_count": isolated_count,
    "community_count": community_count,
    "cycle_count": cycle_count,
    "insights": insights_json
  })
}

fn query_record_payload(record: &crate::storage::query::UnifiedRecord) -> Value {
  let mut values = crate::serde_json::Map::new();
  for (key, value) in &record.values {
    values.insert(key.clone(), json!(format!("{:?}", value)));
  }

  let nodes: Vec<Value> = record
    .nodes
    .iter()
    .map(|(alias, node)| {
      json!({
        "alias": alias,
        "id": node.id,
        "label": node.label,
        "type": format!("{:?}", node.node_type)
      })
    })
    .collect();

  let edges: Vec<Value> = record
    .edges
    .iter()
    .map(|(_, edge)| {
      json!({
        "from": edge.from,
        "to": edge.to,
        "type": format!("{:?}", edge.edge_type),
        "weight": edge.weight
      })
    })
    .collect();

  let paths: Vec<Value> = record
    .paths
    .iter()
    .map(|path| {
      json!({
        "nodes": path.nodes,
        "total_weight": path.total_weight
      })
    })
    .collect();

  json!({
    "values": Value::Object(values),
    "nodes": nodes,
    "edges": edges,
    "paths": paths
  })
}

fn query_result_payload(query: &str, result: &crate::storage::query::UnifiedResult) -> Value {
  let records: Vec<Value> = result.records.iter().map(query_record_payload).collect();
  let stats = json!({
    "nodes_scanned": result.stats.nodes_scanned,
    "edges_scanned": result.stats.edges_scanned
  });
  json!({
    "query": query,
    "records": records,
    "stats": stats,
    "record_count": result.records.len()
  })
}

fn graph_stats_payload(
  nodes: usize,
  edges: usize,
  density: f64,
  avg_degree: f64,
  node_types: &std::collections::HashMap<String, usize>,
  edge_types: &std::collections::HashMap<String, usize>,
) -> Value {
  let mut node_types_json = crate::serde_json::Map::new();
  for (kind, count) in node_types {
    node_types_json.insert(kind.clone(), json!(count));
  }

  let mut edge_types_json = crate::serde_json::Map::new();
  for (kind, count) in edge_types {
    edge_types_json.insert(kind.clone(), json!(count));
  }

  json!({
    "nodes": nodes,
    "edges": edges,
    "density": density,
    "avg_degree": avg_degree,
    "node_types": Value::Object(node_types_json),
    "edge_types": Value::Object(edge_types_json)
  })
}

fn graph_export_payload(
  format: &str,
  output_path: &str,
  node_count: usize,
  edge_count: usize,
  write_error: Option<String>,
  fallback_content: Option<&str>,
) -> Value {
  let status = if write_error.is_some() {
    "stdout_fallback"
  } else {
    "written"
  };
  let mut payload = json!({
    "format": format,
    "output_path": output_path,
    "node_count": node_count,
    "edge_count": edge_count,
    "status": status
  });

  if let Some(err) = write_error {
    payload["write_error"] = json!(err);
  }
  if let Some(content) = fallback_content {
    payload["content"] = json!(content);
  }

  payload
}

fn graph_report_payload(
  output_path: &str,
  node_count: usize,
  edge_count: usize,
  component_count: usize,
  community_count: usize,
  cycle_count: usize,
  write_error: Option<String>,
  fallback_report: Option<&str>,
) -> Value {
  let status = if write_error.is_some() {
    "stdout_fallback"
  } else {
    "written"
  };
  let summary = json!({
    "node_count": node_count,
    "edge_count": edge_count,
    "component_count": component_count,
    "community_count": community_count,
    "cycle_count": cycle_count
  });

  let mut payload = json!({
    "output_path": output_path,
    "status": status,
    "summary": summary
  });

  if let Some(err) = write_error {
    payload["write_error"] = json!(err);
  }
  if let Some(report) = fallback_report {
    payload["report"] = json!(report);
  }

  payload
}

fn graph_import_payload(
  file_path: &str,
  format: &str,
  db_path: &str,
  imported_nodes: usize,
  skipped_nodes: usize,
  imported_edges: usize,
  skipped_edges: usize,
) -> Value {
  let node_summary = json!({
    "imported": imported_nodes,
    "skipped": skipped_nodes
  });
  let edge_summary = json!({
    "imported": imported_edges,
    "skipped": skipped_edges
  });

  json!({
    "file_path": file_path,
    "format": format,
    "db_path": db_path,
    "status": "imported",
    "nodes": node_summary,
    "edges": edge_summary
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn graph_stats_payload_embeds_type_maps() {
    let mut node_types = std::collections::HashMap::new();
    node_types.insert("Host".to_string(), 2);
    let mut edge_types = std::collections::HashMap::new();
    edge_types.insert("ConnectsTo".to_string(), 1);

    let payload = graph_stats_payload(2, 1, 0.5, 1.0, &node_types, &edge_types);
    assert_eq!(payload["nodes"], json!(2));
    assert_eq!(payload["node_types"]["Host"], json!(2));
    assert_eq!(payload["edge_types"]["ConnectsTo"], json!(1));
  }

  #[test]
  fn graph_insights_payload_keeps_messages() {
    let payload = graph_insights_payload(
      10,
      2,
      1,
      3,
      0,
      &[(
        "HIGH".to_string(),
        "Connectivity".to_string(),
        "Too many islands".to_string(),
      )],
    );
    assert_eq!(
      payload["insights"].as_array().unwrap()[0]["severity"],
      json!("HIGH")
    );
    assert_eq!(
      payload["insights"].as_array().unwrap()[0]["message"],
      json!("Too many islands")
    );
  }

  #[test]
  fn graph_import_payload_includes_counts() {
    let payload = graph_import_payload("intel.json", "json", ".redblue/graph.db", 2, 1, 3, 0);
    assert_eq!(payload["status"], json!("imported"));
    assert_eq!(payload["nodes"]["imported"], json!(2));
    assert_eq!(payload["edges"]["imported"], json!(3));
  }
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
        let node_type = extract_xml_attr(line, "type").unwrap_or_else(|| "host".to_string());
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

  let graph = load_graph(db_path)?;

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

    let duplicate = graph
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
      std::fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create db directory {}: {}", parent.display(), e))?;
    }
  }

  std::fs::write(db_path, graph.serialize())
    .map_err(|e| format!("Failed to write graph database {}: {}", db_path, e))?;

  let payload = graph_import_payload(
    &file_path,
    &format,
    db_path,
    imported_nodes,
    skipped_nodes,
    imported_edges,
    skipped_edges,
  );
  if render::render_machine_output(ctx, "rb intel graph import", &payload)? {
    return Ok(());
  }

  Output::success(&format!(
    "Imported {} nodes, {} edges from {} (skipped {} nodes, {} edges)",
    imported_nodes, imported_edges, file_path, skipped_nodes, skipped_edges
  ));

  Ok(())
}
