//! Database MCP Tools
//!
//! RedDB storage engine tools for opening databases, executing queries,
//! creating graph nodes, retrieving entities, and inspecting statistics.

use crate::mcp::types::{ToolDefinition, ToolField, ToolResult};
use crate::mcp::McpServer;
use crate::storage::engine::graph_store::GraphStore;
use crate::storage::engine::graph_table_index::GraphTableIndex;
use crate::storage::query::executors::MultiModeExecutor;
use crate::storage::schema::Value;
use crate::storage::unified::entity::{EntityData, EntityId, EntityKind};
use crate::storage::unified::UnifiedEntity;
use crate::storage::RedDB;
use crate::utils::json::JsonValue;
use std::collections::HashMap;
use std::sync::Arc;

/// Register database tools with the server
pub fn register_database_tools() -> Vec<ToolDefinition<McpServer>> {
    vec![
        ToolDefinition {
            name: "rb.database.open",
            description: "Open or create a RedDB database at a given path. Returns database info and collection list.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Filesystem path for the database. Creates a new database if it does not exist.",
                    required: true,
                },
            ],
            handler: tool_database_open,
        },
        ToolDefinition {
            name: "rb.database.query",
            description: "Execute an RQL query (SQL, Cypher, Gremlin, SPARQL, or natural language) against a RedDB graph store.",
            fields: &[
                ToolField {
                    name: "query",
                    field_type: "string",
                    description: "The query string to execute. Supports SQL (SELECT ... FROM ...), Cypher (MATCH ...), Gremlin (g.V()...), SPARQL, and natural language.",
                    required: true,
                },
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Optional database path to load before querying. If omitted, executes against a fresh in-memory store.",
                    required: false,
                },
            ],
            handler: tool_database_query,
        },
        ToolDefinition {
            name: "rb.database.node.create",
            description: "Create a graph node in a RedDB collection with a label, type, and properties.",
            fields: &[
                ToolField {
                    name: "collection",
                    field_type: "string",
                    description: "Collection name to insert the node into.",
                    required: true,
                },
                ToolField {
                    name: "label",
                    field_type: "string",
                    description: "Node label (e.g., 'Host', 'Service', 'User').",
                    required: true,
                },
                ToolField {
                    name: "node_type",
                    field_type: "string",
                    description: "Node type classification (e.g., 'server', 'endpoint'). Defaults to label if omitted.",
                    required: false,
                },
                ToolField {
                    name: "properties",
                    field_type: "object",
                    description: "Key-value properties for the node (e.g., {\"ip\": \"10.0.0.1\", \"port\": 22}).",
                    required: false,
                },
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Optional database path for persistence. If omitted, uses an in-memory database.",
                    required: false,
                },
            ],
            handler: tool_database_node_create,
        },
        ToolDefinition {
            name: "rb.database.node.get",
            description: "Get a node (or any entity) by its numeric ID from a RedDB database.",
            fields: &[
                ToolField {
                    name: "id",
                    field_type: "number",
                    description: "Entity ID to look up.",
                    required: true,
                },
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Database path to load. Required for retrieving persisted entities.",
                    required: false,
                },
            ],
            handler: tool_database_node_get,
        },
        ToolDefinition {
            name: "rb.database.stats",
            description: "Get statistics for a RedDB database: collection count, entity count, memory usage, and per-collection breakdown.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Optional database path. If omitted, returns stats for a fresh in-memory database.",
                    required: false,
                },
            ],
            handler: tool_database_stats,
        },
        ToolDefinition {
            name: "rb.database.tables",
            description: "List all tables and collections in a RedDB database.",
            fields: &[
                ToolField {
                    name: "path",
                    field_type: "string",
                    description: "Optional database path. If omitted, returns an empty list for a fresh in-memory database.",
                    required: false,
                },
            ],
            handler: tool_database_tables,
        },
    ]
}

/// Open or create a RedDB database and return basic info.
fn tool_database_open(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: path")?;

    let db = RedDB::open(path).map_err(|e| format!("Failed to open database: {}", e))?;

    let collections = db.collections();
    let store = db.store();
    let stats = store.stats();

    let collections_json: Vec<JsonValue> = collections
        .iter()
        .map(|c| JsonValue::String(c.clone()))
        .collect();

    let text = format!(
        "Opened database at '{}': {} collections, {} total entities",
        path, stats.collection_count, stats.total_entities
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("path".to_string(), JsonValue::String(path.to_string())),
            (
                "collection_count".to_string(),
                JsonValue::Number(stats.collection_count as f64),
            ),
            (
                "total_entities".to_string(),
                JsonValue::Number(stats.total_entities as f64),
            ),
            (
                "total_memory_bytes".to_string(),
                JsonValue::Number(stats.total_memory_bytes as f64),
            ),
            (
                "collections".to_string(),
                JsonValue::array(collections_json),
            ),
        ]),
    })
}

/// Execute an RQL query using the multi-mode executor.
fn tool_database_query(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let query_str = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: query")?;

    // Create a graph store and table index for the executor
    let graph = Arc::new(GraphStore::new());
    let index = Arc::new(GraphTableIndex::new());
    let executor = MultiModeExecutor::new(graph, index);

    // Execute the query (auto-detects mode: SQL, Cypher, Gremlin, SPARQL, natural)
    let exec_result = executor
        .execute(query_str)
        .map_err(|e| format!("Query execution error: {}", e))?;

    let result = &exec_result.result;

    let records_json: Vec<JsonValue> = result
        .records
        .iter()
        .map(|record| {
            let mut fields = Vec::new();

            // Serialize column values
            if !record.values.is_empty() {
                let value_pairs: Vec<(String, JsonValue)> = record
                    .values
                    .iter()
                    .map(|(k, v)| (k.clone(), value_to_json(v)))
                    .collect();
                fields.push(("values".to_string(), JsonValue::object(value_pairs)));
            }

            // Serialize matched nodes
            if !record.nodes.is_empty() {
                let node_pairs: Vec<(String, JsonValue)> = record
                    .nodes
                    .iter()
                    .map(|(alias, node)| {
                        let node_obj = JsonValue::object(vec![
                            ("id".to_string(), JsonValue::String(node.id.clone())),
                            ("label".to_string(), JsonValue::String(node.label.clone())),
                            (
                                "node_type".to_string(),
                                JsonValue::String(format!("{:?}", node.node_type)),
                            ),
                        ]);
                        (alias.clone(), node_obj)
                    })
                    .collect();
                fields.push(("nodes".to_string(), JsonValue::object(node_pairs)));
            }

            // Serialize matched edges
            if !record.edges.is_empty() {
                let edge_pairs: Vec<(String, JsonValue)> = record
                    .edges
                    .iter()
                    .map(|(alias, edge)| {
                        let edge_obj = JsonValue::object(vec![
                            (
                                "edge_type".to_string(),
                                JsonValue::String(format!("{:?}", edge.edge_type)),
                            ),
                            ("from".to_string(), JsonValue::String(edge.from.clone())),
                            ("to".to_string(), JsonValue::String(edge.to.clone())),
                            ("weight".to_string(), JsonValue::Number(edge.weight as f64)),
                        ]);
                        (alias.clone(), edge_obj)
                    })
                    .collect();
                fields.push(("edges".to_string(), JsonValue::object(edge_pairs)));
            }

            JsonValue::object(fields)
        })
        .collect();

    let text = format!(
        "Query returned {} records (mode: {:?}, scanned {} nodes, {} edges, {} rows in {}us)",
        result.records.len(),
        exec_result.mode,
        result.stats.nodes_scanned,
        result.stats.edges_scanned,
        result.stats.rows_scanned,
        result.stats.exec_time_us,
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "query".to_string(),
                JsonValue::String(query_str.to_string()),
            ),
            (
                "mode".to_string(),
                JsonValue::String(format!("{:?}", exec_result.mode)),
            ),
            (
                "record_count".to_string(),
                JsonValue::Number(result.records.len() as f64),
            ),
            (
                "columns".to_string(),
                JsonValue::array(
                    result
                        .columns
                        .iter()
                        .map(|c| JsonValue::String(c.clone()))
                        .collect(),
                ),
            ),
            ("records".to_string(), JsonValue::array(records_json)),
            (
                "explanation".to_string(),
                exec_result
                    .explanation
                    .as_ref()
                    .map(|e| JsonValue::String(e.clone()))
                    .unwrap_or(JsonValue::Null),
            ),
            (
                "stats".to_string(),
                JsonValue::object(vec![
                    (
                        "nodes_scanned".to_string(),
                        JsonValue::Number(result.stats.nodes_scanned as f64),
                    ),
                    (
                        "edges_scanned".to_string(),
                        JsonValue::Number(result.stats.edges_scanned as f64),
                    ),
                    (
                        "rows_scanned".to_string(),
                        JsonValue::Number(result.stats.rows_scanned as f64),
                    ),
                    (
                        "exec_time_us".to_string(),
                        JsonValue::Number(result.stats.exec_time_us as f64),
                    ),
                ]),
            ),
        ]),
    })
}

/// Create a graph node in a RedDB collection.
fn tool_database_node_create(
    _server: &mut McpServer,
    args: &JsonValue,
) -> Result<ToolResult, String> {
    let collection = args
        .get("collection")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: collection")?;

    let label = args
        .get("label")
        .and_then(|v| v.as_str())
        .ok_or("Missing required field: label")?;

    let node_type = args
        .get("node_type")
        .and_then(|v| v.as_str())
        .unwrap_or(label);

    let db = if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
        RedDB::open(path).map_err(|e| format!("Failed to open database: {}", e))?
    } else {
        RedDB::new()
    };

    // Build properties from the JSON object
    let mut properties = HashMap::new();
    if let Some(props_val) = args.get("properties") {
        if let JsonValue::Object(pairs) = props_val {
            for (key, val) in pairs {
                properties.insert(key.clone(), json_to_value(val));
            }
        }
    }

    // Use the RedDB node builder API
    let mut builder = db.node(collection, label);
    for (key, val) in &properties {
        builder = builder.property(key.as_str(), val.clone());
    }

    let id = builder
        .save()
        .map_err(|e| format!("Failed to create node: {}", e))?;

    // Flush if persistence is enabled
    let _ = db.flush();

    let props_json = props_to_json(&properties);

    let text = format!(
        "Created node '{}' (type: '{}') in collection '{}' with ID {}",
        label,
        node_type,
        collection,
        id.raw()
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            ("id".to_string(), JsonValue::Number(id.raw() as f64)),
            (
                "collection".to_string(),
                JsonValue::String(collection.to_string()),
            ),
            ("label".to_string(), JsonValue::String(label.to_string())),
            (
                "node_type".to_string(),
                JsonValue::String(node_type.to_string()),
            ),
            ("properties".to_string(), props_json),
        ]),
    })
}

/// Get a node (or any entity) by ID.
fn tool_database_node_get(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let id_val = args
        .get("id")
        .and_then(|v| v.as_f64())
        .ok_or("Missing required field: id")?;

    let entity_id = EntityId::new(id_val as u64);

    let db = if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
        RedDB::open(path).map_err(|e| format!("Failed to open database: {}", e))?
    } else {
        return Err("A database path is required to retrieve persisted entities".to_string());
    };

    let (collection, entity) = db
        .get_with_collection(entity_id)
        .ok_or_else(|| format!("Entity with ID {} not found", id_val as u64))?;

    let entity_json = entity_to_json(&collection, &entity);

    let text = format!(
        "Found entity {} in collection '{}' (kind: {})",
        entity_id.raw(),
        collection,
        entity_kind_label(&entity.kind),
    );

    Ok(ToolResult {
        text,
        data: entity_json,
    })
}

/// Get database statistics.
fn tool_database_stats(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let db = if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
        RedDB::open(path).map_err(|e| format!("Failed to open database: {}", e))?
    } else {
        RedDB::new()
    };

    let store = db.store();
    let stats = store.stats();

    let collections_json: Vec<(String, JsonValue)> = stats
        .collections
        .iter()
        .map(|(name, mgr_stats)| {
            let col_obj = JsonValue::object(vec![
                (
                    "total_entities".to_string(),
                    JsonValue::Number(mgr_stats.total_entities as f64),
                ),
                (
                    "growing_segments".to_string(),
                    JsonValue::Number(mgr_stats.growing_count as f64),
                ),
                (
                    "sealed_segments".to_string(),
                    JsonValue::Number(mgr_stats.sealed_count as f64),
                ),
                (
                    "archived_segments".to_string(),
                    JsonValue::Number(mgr_stats.archived_count as f64),
                ),
                (
                    "memory_bytes".to_string(),
                    JsonValue::Number(mgr_stats.total_memory_bytes as f64),
                ),
                (
                    "seal_ops".to_string(),
                    JsonValue::Number(mgr_stats.seal_ops as f64),
                ),
                (
                    "compact_ops".to_string(),
                    JsonValue::Number(mgr_stats.compact_ops as f64),
                ),
            ]);
            (name.clone(), col_obj)
        })
        .collect();

    let text = format!(
        "Database stats: {} collections, {} entities, {} bytes memory",
        stats.collection_count, stats.total_entities, stats.total_memory_bytes,
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "collection_count".to_string(),
                JsonValue::Number(stats.collection_count as f64),
            ),
            (
                "total_entities".to_string(),
                JsonValue::Number(stats.total_entities as f64),
            ),
            (
                "total_memory_bytes".to_string(),
                JsonValue::Number(stats.total_memory_bytes as f64),
            ),
            (
                "cross_ref_count".to_string(),
                JsonValue::Number(stats.cross_ref_count as f64),
            ),
            (
                "avg_entities_per_collection".to_string(),
                JsonValue::Number(stats.avg_entities_per_collection()),
            ),
            (
                "collections".to_string(),
                JsonValue::object(collections_json),
            ),
        ]),
    })
}

/// List all tables/collections in a RedDB database.
fn tool_database_tables(_server: &mut McpServer, args: &JsonValue) -> Result<ToolResult, String> {
    let db = if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
        RedDB::open(path).map_err(|e| format!("Failed to open database: {}", e))?
    } else {
        RedDB::new()
    };

    let collections = db.collections();
    let store = db.store();
    let stats = store.stats();

    let tables_json: Vec<JsonValue> = collections
        .iter()
        .map(|name| {
            let entity_count = stats
                .collections
                .get(name)
                .map(|s| s.total_entities)
                .unwrap_or(0);

            JsonValue::object(vec![
                ("name".to_string(), JsonValue::String(name.clone())),
                (
                    "entity_count".to_string(),
                    JsonValue::Number(entity_count as f64),
                ),
            ])
        })
        .collect();

    let text = format!(
        "Found {} tables/collections{}",
        collections.len(),
        if collections.is_empty() {
            String::new()
        } else {
            format!(": {}", collections.join(", "))
        }
    );

    Ok(ToolResult {
        text,
        data: JsonValue::object(vec![
            (
                "count".to_string(),
                JsonValue::Number(collections.len() as f64),
            ),
            ("tables".to_string(), JsonValue::array(tables_json)),
        ]),
    })
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a schema Value to a JsonValue.
fn value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Integer(n) => JsonValue::Number(*n as f64),
        Value::UnsignedInteger(n) => JsonValue::Number(*n as f64),
        Value::Float(f) => JsonValue::Number(*f),
        Value::Text(s) => JsonValue::String(s.clone()),
        Value::Boolean(b) => JsonValue::Bool(*b),
        Value::Timestamp(t) => JsonValue::Number(*t as f64),
        Value::Duration(d) => JsonValue::Number(*d as f64),
        Value::IpAddr(ip) => JsonValue::String(ip.to_string()),
        Value::Blob(data) => JsonValue::String(format!("<blob:{} bytes>", data.len())),
        _ => JsonValue::String(format!("{:?}", value)),
    }
}

/// Convert a JsonValue to a schema Value.
fn json_to_value(json: &JsonValue) -> Value {
    match json {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(b) => Value::Boolean(*b),
        JsonValue::Number(n) => {
            if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                Value::Integer(*n as i64)
            } else {
                Value::Float(*n)
            }
        }
        JsonValue::String(s) => Value::Text(s.clone()),
        JsonValue::Array(_) => Value::Text(format!("{:?}", json)),
        JsonValue::Object(_) => Value::Text(format!("{:?}", json)),
    }
}

/// Convert a HashMap of properties to a JsonValue object.
fn props_to_json(properties: &HashMap<String, Value>) -> JsonValue {
    let pairs: Vec<(String, JsonValue)> = properties
        .iter()
        .map(|(k, v)| (k.clone(), value_to_json(v)))
        .collect();
    JsonValue::object(pairs)
}

/// Get a human-readable label for an EntityKind.
fn entity_kind_label(kind: &EntityKind) -> &'static str {
    match kind {
        EntityKind::TableRow { .. } => "table_row",
        EntityKind::GraphNode { .. } => "graph_node",
        EntityKind::GraphEdge { .. } => "graph_edge",
        EntityKind::Vector { .. } => "vector",
    }
}

/// Serialize a full entity to a JsonValue.
fn entity_to_json(collection: &str, entity: &UnifiedEntity) -> JsonValue {
    let mut fields = vec![
        ("id".to_string(), JsonValue::Number(entity.id.raw() as f64)),
        (
            "collection".to_string(),
            JsonValue::String(collection.to_string()),
        ),
        (
            "kind".to_string(),
            JsonValue::String(entity_kind_label(&entity.kind).to_string()),
        ),
        (
            "created_at".to_string(),
            JsonValue::Number(entity.created_at as f64),
        ),
        (
            "updated_at".to_string(),
            JsonValue::Number(entity.updated_at as f64),
        ),
        (
            "sequence_id".to_string(),
            JsonValue::Number(entity.sequence_id as f64),
        ),
    ];

    // Add kind-specific metadata
    match &entity.kind {
        EntityKind::GraphNode { label, node_type } => {
            fields.push(("label".to_string(), JsonValue::String(label.clone())));
            fields.push((
                "node_type".to_string(),
                JsonValue::String(node_type.clone()),
            ));
        }
        EntityKind::GraphEdge {
            label,
            from_node,
            to_node,
            weight,
        } => {
            fields.push(("label".to_string(), JsonValue::String(label.clone())));
            fields.push((
                "from_node".to_string(),
                JsonValue::String(from_node.clone()),
            ));
            fields.push(("to_node".to_string(), JsonValue::String(to_node.clone())));
            fields.push((
                "weight".to_string(),
                JsonValue::Number(*weight as f64 / 1000.0),
            ));
        }
        EntityKind::TableRow { table, row_id } => {
            fields.push(("table".to_string(), JsonValue::String(table.clone())));
            fields.push(("row_id".to_string(), JsonValue::Number(*row_id as f64)));
        }
        EntityKind::Vector { collection } => {
            fields.push((
                "vector_collection".to_string(),
                JsonValue::String(collection.clone()),
            ));
        }
    }

    // Add entity data
    match &entity.data {
        EntityData::Node(node) => {
            fields.push(("properties".to_string(), props_to_json(&node.properties)));
        }
        EntityData::Edge(edge) => {
            fields.push(("properties".to_string(), props_to_json(&edge.properties)));
            fields.push((
                "edge_weight".to_string(),
                JsonValue::Number(edge.weight as f64),
            ));
        }
        EntityData::Row(row) => {
            if let Some(named) = &row.named {
                fields.push(("columns".to_string(), props_to_json(named)));
            }
            let column_values: Vec<JsonValue> = row.columns.iter().map(value_to_json).collect();
            fields.push(("column_values".to_string(), JsonValue::array(column_values)));
        }
        EntityData::Vector(vec_data) => {
            fields.push((
                "dimensions".to_string(),
                JsonValue::Number(vec_data.dense.len() as f64),
            ));
            if let Some(content) = &vec_data.content {
                fields.push(("content".to_string(), JsonValue::String(content.clone())));
            }
        }
    }

    // Add cross-reference count
    if !entity.cross_refs.is_empty() {
        fields.push((
            "cross_ref_count".to_string(),
            JsonValue::Number(entity.cross_refs.len() as f64),
        ));
    }

    // Add embedding count
    if !entity.embeddings.is_empty() {
        fields.push((
            "embedding_count".to_string(),
            JsonValue::Number(entity.embeddings.len() as f64),
        ));
    }

    JsonValue::object(fields)
}
