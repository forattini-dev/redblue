//! TAXII 2.1 Threat Intelligence Command
//!
//! Connect to TAXII servers to fetch STIX data:
//! - List collections
//! - Sync objects (techniques, groups, software)

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::intel::taxii::TaxiiClient;
use crate::serde_json::Value;

pub struct IntelTaxiiCommand;

impl Command for IntelTaxiiCommand {
  fn domain(&self) -> &str {
    "intelligence" // Short alias: "intel"
  }

  fn resource(&self) -> &str {
    "taxii"
  }

  fn description(&self) -> &str {
    "TAXII 2.1 threat intelligence sync"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::BestEffort)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(
        crate::cli::schema::MachineOutputMetadata::new()
          .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
          .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
          .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
      )
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "collections",
        summary: "List available TAXII collections",
        usage: "rb intel taxii collections [url=...]",
      },
      Route {
        verb: "sync",
        summary: "Sync STIX objects from a TAXII collection",
        usage: "rb intel taxii sync [--collection=ID] [--type=TYPE]",
      },
    ]
  }

  fn flags(&self) -> Vec<Flag> {
    vec![
      Flag::new("output", "Output format (text, json, yaml)")
        .with_short('o')
        .with_default("text"),
      Flag::new("url", "TAXII discovery URL").with_default("https://cti-taxii.mitre.org/taxii/"),
      Flag::new("root", "API Root").with_default("enterprise-attack"),
      Flag::new("collection", "Collection ID to sync"),
      Flag::new(
        "type",
        "Filter by STIX object type (e.g., attack-pattern, intrusion-set)",
      ),
      Flag::new(
        "after",
        "Only fetch objects added after this timestamp (ISO 8601)",
      ),
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      (
        "List default MITRE collections",
        "rb intel taxii collections",
      ),
      (
        "List collections as JSON",
        "rb intel taxii collections --output=json",
      ),
      (
        "List from custom server",
        "rb intel taxii collections --url=https://limo.anomali.com/taxii/",
      ),
      ("Sync all objects (interactive)", "rb intel taxii sync"),
      (
        "Sync techniques only",
        "rb intel taxii sync --collection=<ID> --type=attack-pattern",
      ),
      (
        "Sync as JSON",
        "rb intel taxii sync --collection=<ID> --output=json",
      ),
      (
        "Sync groups from MITRE",
        "rb intel taxii sync --collection=<ID> --type=intrusion-set",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_ref().ok_or_else(|| {
      print_help(self);
      "No verb provided".to_string()
    })?;

    match verb.as_str() {
      "collections" => self.list_collections(ctx),
      "sync" => self.sync_objects(ctx),
      _ => {
        print_help(self);
        Err(format!("Unknown verb: {}", verb))
      }
    }
  }
}

impl IntelTaxiiCommand {
  fn create_client(&self, ctx: &CliContext) -> TaxiiClient {
    let url = ctx.get_flag_or("url", "https://cti-taxii.mitre.org/taxii/");
    let root = ctx.get_flag_or("root", "enterprise-attack");
    TaxiiClient::new(&url).with_api_root(&root)
  }

  fn list_collections(&self, ctx: &CliContext) -> Result<(), String> {
    let client = self.create_client(ctx);
    let url = ctx.get_flag_or("url", "https://cti-taxii.mitre.org/taxii/");

    if !ctx.wants_machine_output() {
      Output::header("TAXII Collections");
      println!("URL: {}", url);
      println!();
      Output::spinner_start("Fetching collections...");
    }

    let collections = client.list_collections()?;

    if !ctx.wants_machine_output() {
      Output::spinner_done();
    }

    let payload = taxii_collections_payload(&url, &collections);
    if render::render_machine_output(ctx, "rb intel taxii collections", &payload)? {
      return Ok(());
    }

    if collections.is_empty() {
      Output::info("No collections found.");
      return Ok(());
    }

    Output::success(&format!("Found {} collections", collections.len()));
    println!();

    for col in collections {
      Output::section(&col.title);
      Output::item("ID", &col.id);
      if let Some(desc) = &col.description {
        Output::item("Description", desc);
      }
      Output::item("Can Read", &col.can_read.to_string());
      println!();
    }

    Ok(())
  }

  fn sync_objects(&self, ctx: &CliContext) -> Result<(), String> {
    let client = self.create_client(ctx);
    let collection_id = ctx.get_flag_or("collection", "");

    // If no collection specified, show available ones
    if collection_id.is_empty() {
      let collections = client.list_collections()?;

      let payload = taxii_missing_collection_payload(&collections);
      if render::render_machine_output(ctx, "rb intel taxii sync", &payload)? {
        return Ok(());
      }

      Output::header("TAXII Sync");
      println!();
      Output::warning("No collection specified. Use --collection=<ID>");
      println!();
      Output::info("Fetching available collections...");
      println!();

      if collections.is_empty() {
        Output::info("No collections available.");
        return Ok(());
      }

      println!("Available collections:");
      for col in &collections {
        println!("  \x1b[1;36m{}\x1b[0m - {}", col.id, col.title);
      }
      println!();
      Output::info("Example: rb intel taxii sync --collection=<ID>");
      return Ok(());
    }

    // Get object type filter
    let obj_type = ctx.get_flag("type");
    let added_after = ctx.get_flag("after");

    if !ctx.wants_machine_output() {
      Output::header("TAXII Sync");
      println!();
      Output::spinner_start(&format!(
        "Syncing objects from collection: {}",
        collection_id
      ));
    }

    let envelope =
      client.get_objects(&collection_id, obj_type.as_deref(), added_after.as_deref())?;

    if !ctx.wants_machine_output() {
      Output::spinner_done();
      println!();
    }

    let objects = envelope.objects.unwrap_or_default();

    // Count object types
    let mut type_counts: std::collections::HashMap<String, usize> =
      std::collections::HashMap::new();
    for obj in &objects {
      if let Some(t) = obj.get("type").and_then(|v| v.as_str()) {
        *type_counts.entry(t.to_string()).or_insert(0) += 1;
      }
    }

    let payload = taxii_sync_payload(
      &collection_id,
      obj_type.as_deref(),
      added_after.as_deref(),
      envelope.more.unwrap_or(false),
      &type_counts,
      &objects,
    );
    if render::render_machine_output(ctx, "rb intel taxii sync", &payload)? {
      return Ok(());
    }

    if objects.is_empty() {
      Output::warning("No objects returned from collection.");
      if let Some(m) = envelope.more {
        if m {
          Output::info("There may be more objects. Use --after to paginate.");
        }
      }
      return Ok(());
    }

    Output::success(&format!("Fetched {} objects", objects.len()));
    println!();

    Output::section("Object Types");
    let mut sorted_types: Vec<_> = type_counts.iter().collect();
    sorted_types.sort_by(|a, b| b.1.cmp(a.1));

    for (obj_type, count) in sorted_types {
      let type_color = match obj_type.as_str() {
        "attack-pattern" => "\x1b[1;31m", // Red - techniques
        "intrusion-set" => "\x1b[1;35m",  // Magenta - groups
        "malware" => "\x1b[1;33m",        // Yellow
        "tool" => "\x1b[1;34m",           // Blue
        "relationship" => "\x1b[0;37m",   // Gray
        _ => "\x1b[0m",
      };
      println!("  {}{:<20}\x1b[0m {:>5}", type_color, obj_type, count);
    }
    println!();

    // Show some sample objects
    let show_limit = 5;
    let techniques: Vec<_> = objects
      .iter()
      .filter(|o| o.get("type").and_then(|v| v.as_str()) == Some("attack-pattern"))
      .take(show_limit)
      .collect();

    if !techniques.is_empty() {
      Output::section(&format!("Sample Techniques (first {})", techniques.len()));
      for tech in techniques {
        let name = tech
          .get("name")
          .and_then(|v| v.as_str())
          .unwrap_or("Unknown");
        let ext_refs = tech
          .get("external_references")
          .and_then(|v| v.as_array())
          .and_then(|arr| {
            arr
              .iter()
              .find(|r| r.get("source_name").and_then(|s| s.as_str()) == Some("mitre-attack"))
          })
          .and_then(|r| r.get("external_id"))
          .and_then(|v| v.as_str())
          .unwrap_or("-");
        println!("  \x1b[1;31m{:<12}\x1b[0m {}", ext_refs, name);
      }
      println!();
    }

    let groups: Vec<_> = objects
      .iter()
      .filter(|o| o.get("type").and_then(|v| v.as_str()) == Some("intrusion-set"))
      .take(show_limit)
      .collect();

    if !groups.is_empty() {
      Output::section(&format!("Sample Threat Groups (first {})", groups.len()));
      for grp in groups {
        let name = grp
          .get("name")
          .and_then(|v| v.as_str())
          .unwrap_or("Unknown");
        let ext_refs = grp
          .get("external_references")
          .and_then(|v| v.as_array())
          .and_then(|arr| {
            arr
              .iter()
              .find(|r| r.get("source_name").and_then(|s| s.as_str()) == Some("mitre-attack"))
          })
          .and_then(|r| r.get("external_id"))
          .and_then(|v| v.as_str())
          .unwrap_or("-");
        println!("  \x1b[1;35m{:<8}\x1b[0m {}", ext_refs, name);
      }
      println!();
    }

    if envelope.more.unwrap_or(false) {
      Output::warning("More objects available. Use --after=<timestamp> for pagination.");
    }

    Output::info("Tip: Use --type=attack-pattern to filter by object type");
    Ok(())
  }
}

fn taxii_collection_to_json(
  col: &crate::modules::intel::taxii::Collection,
) -> crate::serde_json::Value {
  json!({
    "id": col.id.clone(),
    "title": col.title.clone(),
    "description": col.description.clone(),
    "can_read": col.can_read,
  })
}

fn taxii_collections_payload(
  url: &str,
  collections: &[crate::modules::intel::taxii::Collection],
) -> Value {
  let collections_json: Vec<Value> = collections.iter().map(taxii_collection_to_json).collect();
  json!({
    "url": url,
    "total": collections.len(),
    "collections": collections_json,
  })
}

fn taxii_missing_collection_payload(
  collections: &[crate::modules::intel::taxii::Collection],
) -> Value {
  let collections_json: Vec<Value> = collections
    .iter()
    .map(|col| {
      json!({
        "id": col.id.clone(),
        "title": col.title.clone(),
      })
    })
    .collect();
  json!({
    "error": "No collection specified",
    "available_collections": collections_json,
  })
}

fn taxii_object_to_json(obj: &Value) -> Value {
  let obj_type = obj
    .get("type")
    .and_then(|v| v.as_str())
    .unwrap_or("unknown");
  let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
  let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
  let ext_id = obj
    .get("external_references")
    .and_then(|v| v.as_array())
    .and_then(|arr| {
      arr
        .iter()
        .find(|r| r.get("source_name").and_then(|s| s.as_str()) == Some("mitre-attack"))
    })
    .and_then(|r| r.get("external_id"))
    .and_then(|v| v.as_str())
    .unwrap_or("");
  json!({
    "type": obj_type,
    "id": id,
    "name": name,
    "external_id": ext_id,
  })
}

fn taxii_sync_payload(
  collection_id: &str,
  obj_type: Option<&str>,
  added_after: Option<&str>,
  more: bool,
  type_counts: &std::collections::HashMap<String, usize>,
  objects: &[Value],
) -> Value {
  let mut sorted_types: Vec<_> = type_counts.iter().collect();
  sorted_types.sort_by(|a, b| a.0.cmp(b.0));
  let by_type = Value::Object(
    sorted_types
      .iter()
      .map(|(obj_type, count)| (obj_type.to_string(), json!(**count)))
      .collect(),
  );
  let objects_json: Vec<Value> = objects.iter().map(taxii_object_to_json).collect();
  let mut fields = vec![
    ("collection_id".to_string(), json!(collection_id)),
    ("total".to_string(), json!(objects.len())),
    ("more".to_string(), json!(more)),
    ("by_type".to_string(), by_type),
    ("objects".to_string(), json!(objects_json)),
  ];
  if let Some(t) = obj_type {
    fields.push(("type_filter".to_string(), json!(t)));
  }
  if let Some(a) = added_after {
    fields.push(("added_after".to_string(), json!(a)));
  }
  Value::Object(fields.into_iter().collect())
}
