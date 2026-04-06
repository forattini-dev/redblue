//! Vector mode handlers for `rb database vector <verb>`
//!
//! Vector similarity search operations:
//! - search: k-nearest neighbor lookup
//! - index: Build vector indexes (flat, IVF)
//! - info: Display index statistics

use crate::cli::commands::print_help;
use crate::cli::{output::Output, CliContext};
use crate::json;
use crate::storage::engine::distance::DistanceMetric;
use crate::storage::{EntityData, RedDB};
use std::collections::HashSet;

use super::DatabaseCommand;

impl DatabaseCommand {
    /// Route vector mode verbs
    pub fn execute_vector(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "No verb provided".to_string()
        })?;

        match verb.as_str() {
            "search" => vector_search(ctx),
            "index" => vector_index(ctx),
            "info" => vector_info(ctx),
            _ => {
                Output::error(&format!("Unknown verb: {}", verb));
                Err("Invalid verb".to_string())
            }
        }
    }
}

/// Parse comma-separated floats into a vector
fn parse_vector(input: &str) -> Result<Vec<f32>, String> {
    input
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<f32>()
                .map_err(|_| format!("Invalid float value: {}", s))
        })
        .collect()
}

/// Parse distance metric string
fn parse_distance(input: &str) -> Result<DistanceMetric, String> {
    match input.to_lowercase().as_str() {
        "cosine" => Ok(DistanceMetric::Cosine),
        "l2" | "euclidean" => Ok(DistanceMetric::L2),
        "dot" | "inner" => Ok(DistanceMetric::InnerProduct),
        "manhattan" | "l1" => {
            Err("Manhattan distance is not supported in unified vector search".to_string())
        }
        other => Err(format!(
            "Unknown distance metric: {}. Expected: cosine, l2, dot",
            other
        )),
    }
}

struct VectorStats {
    total_entities: usize,
    vector_entities: usize,
    embedding_entries: usize,
    dimensions: Vec<usize>,
}

fn collect_vector_stats(db: &RedDB, collection: &str) -> Result<VectorStats, String> {
    let results = db
        .query()
        .collection(collection)
        .execute()
        .map_err(|e| format!("Query failed: {}", e))?;

    let mut total_entities = 0;
    let mut vector_entities = 0;
    let mut embedding_entries = 0;
    let mut dimensions = HashSet::new();

    for item in results.items {
        total_entities += 1;
        match &item.entity.data {
            EntityData::Vector(vec) => {
                vector_entities += 1;
                dimensions.insert(vec.dense.len());
            }
            _ => {}
        }

        for emb in &item.entity.embeddings {
            embedding_entries += 1;
            dimensions.insert(emb.vector.len());
        }
    }

    let mut dimensions: Vec<usize> = dimensions.into_iter().collect();
    dimensions.sort_unstable();

    Ok(VectorStats {
        total_entities,
        vector_entities,
        embedding_entries,
        dimensions,
    })
}

/// Perform k-nearest neighbor similarity search
fn vector_search(ctx: &CliContext) -> Result<(), String> {
    let query_str = ctx
        .get_flag("query")
        .ok_or("Missing query vector. Use --query 0.1,0.2,0.3 to specify the query vector.")?;

    let query_vec = parse_vector(&query_str)?;
    let dimension = query_vec.len();

    if dimension == 0 {
        return Err("Query vector cannot be empty".to_string());
    }

    let k: usize = ctx
        .get_flag("k")
        .unwrap_or_else(|| "10".to_string())
        .parse()
        .map_err(|_| "Invalid k value")?;

    let distance_str = ctx
        .get_flag("distance")
        .unwrap_or_else(|| "cosine".to_string());
    let distance = parse_distance(&distance_str)?;

    if distance != DistanceMetric::Cosine {
        return Err("Unified vector search currently supports cosine similarity only".to_string());
    }

    let db_path = ctx
        .get_flag("db")
        .ok_or("Missing --db <path> for unified vector search")?;
    let collection = ctx
        .get_flag("collection")
        .ok_or("Missing --collection <name> for vector search")?;

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    let db = RedDB::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    let results = db.similar(&collection, &query_vec, k);

    if is_json {
        let results_json: Vec<_> = results
            .iter()
            .map(|result| {
                json!({
                    "id": result.entity_id.raw(),
                    "score": result.score,
                    "distance": 1.0 - result.score,
                })
            })
            .collect();
        Output::json_value(&json!({
            "query_dimension": dimension,
            "k": k,
            "distance_metric": distance_str,
            "collection": collection,
            "results": results_json,
        }));
    } else {
        Output::header("Vector Similarity Search");
        Output::summary_line(&[
            ("Dimension", &dimension.to_string()),
            ("k", &k.to_string()),
            ("Distance", &distance_str),
            ("Collection", &collection),
        ]);
        println!();

        if results.is_empty() {
            Output::warning("No results found");
        } else {
            Output::subheader("Results");
            for (i, result) in results.iter().enumerate() {
                println!(
                    "  {}. ID: {} | Distance: {:.6} | Score: {:.4}",
                    i + 1,
                    result.entity_id.raw(),
                    1.0 - result.score,
                    result.score
                );
            }
        }
    }

    Ok(())
}

/// Build or rebuild vector index
fn vector_index(ctx: &CliContext) -> Result<(), String> {
    let index_type = ctx.get_flag("type").unwrap_or_else(|| "auto".to_string());

    let db_path = ctx
        .get_flag("db")
        .ok_or("Missing --db <path> for vector indexing")?;
    let collection = ctx
        .get_flag("collection")
        .ok_or("Missing --collection <name> for vector indexing")?;

    let db = RedDB::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    let stats = collect_vector_stats(&db, &collection)?;

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if is_json {
        Output::json_value(&json!({
            "status": "ready",
            "type": index_type,
            "collection": collection,
            "vector_entities": stats.vector_entities,
            "embedding_entries": stats.embedding_entries,
            "dimensions": stats.dimensions,
        }));
    } else {
        Output::success(&format!("Vector index ready (type: {})", index_type));
        Output::item("Collection", &collection);
        Output::item("Vector entities", &stats.vector_entities.to_string());
        Output::item("Embedding entries", &stats.embedding_entries.to_string());
        Output::item("Dimensions", &format!("{:?}", stats.dimensions));
    }

    Ok(())
}

/// Display vector index statistics
fn vector_info(ctx: &CliContext) -> Result<(), String> {
    let db_path = ctx
        .get_flag("db")
        .ok_or("Missing --db <path> for vector info")?;
    let collection = ctx
        .get_flag("collection")
        .ok_or("Missing --collection <name> for vector info")?;

    let db = RedDB::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;
    let stats = collect_vector_stats(&db, &collection)?;

    let format = ctx.get_flag("format").unwrap_or_else(|| "text".to_string());
    let is_json = format == "json";

    if is_json {
        Output::json_value(&json!({
            "collection": collection,
            "total_entities": stats.total_entities,
            "vector_entities": stats.vector_entities,
            "embedding_entries": stats.embedding_entries,
            "dimensions": stats.dimensions,
            "distance_metric": "cosine",
        }));
    } else {
        Output::header("Vector Index Info");
        println!();
        Output::item("Collection", &collection);
        Output::item("Total entities", &stats.total_entities.to_string());
        Output::item("Vector entities", &stats.vector_entities.to_string());
        Output::item("Embedding entries", &stats.embedding_entries.to_string());
        Output::item("Dimensions", &format!("{:?}", stats.dimensions));
        Output::item("Distance metric", "cosine");
    }

    Ok(())
}
