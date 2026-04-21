use crate::json;
use crate::modules::intel::{Ioc, IocCollection, IocConfidence, IocType};
use std::collections::HashMap;

/// Format Unix timestamp as ISO 8601
pub(super) fn format_timestamp(ts: u64) -> String {
  // Simple ISO 8601 formatting (YYYY-MM-DDTHH:MM:SSZ)
  let secs_per_day = 86400u64;
  let secs_per_hour = 3600u64;
  let secs_per_min = 60u64;

  // Days since Unix epoch
  let days = ts / secs_per_day;
  let remaining = ts % secs_per_day;

  let hours = remaining / secs_per_hour;
  let remaining = remaining % secs_per_hour;
  let minutes = remaining / secs_per_min;
  let seconds = remaining % secs_per_min;

  // Calculate year/month/day (simplified - doesn't handle leap years perfectly)
  let mut year = 1970u64;
  let mut remaining_days = days;

  loop {
    let days_in_year =
      if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
        366
      } else {
        365
      };
    if remaining_days < days_in_year {
      break;
    }
    remaining_days -= days_in_year;
    year += 1;
  }

  let is_leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
  let days_in_months = if is_leap {
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  } else {
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  };

  let mut month = 0u64;
  for (i, &days_in_month) in days_in_months.iter().enumerate() {
    if remaining_days < days_in_month as u64 {
      month = (i + 1) as u64;
      break;
    }
    remaining_days -= days_in_month as u64;
  }

  let day = remaining_days + 1;

  format!(
    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
    year, month, day, hours, minutes, seconds
  )
}

pub(super) fn ioc_confidence_label(confidence: IocConfidence) -> &'static str {
  match confidence {
    IocConfidence::High => "high",
    IocConfidence::Medium => "medium",
    IocConfidence::Low => "low",
  }
}

fn counts_by_type_to_json(counts: &HashMap<IocType, usize>) -> crate::serde_json::Value {
  let mut map = crate::serde_json::Map::new();
  let mut entries: Vec<_> = counts.iter().collect();
  entries.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
  for (ioc_type, count) in entries {
    map.insert(ioc_type.to_string(), json!(*count));
  }
  crate::serde_json::Value::Object(map)
}

fn counts_by_confidence_to_json(
  counts: &HashMap<IocConfidence, usize>,
) -> crate::serde_json::Value {
  json!({
      "high": *counts.get(&IocConfidence::High).unwrap_or(&0),
      "medium": *counts.get(&IocConfidence::Medium).unwrap_or(&0),
      "low": *counts.get(&IocConfidence::Low).unwrap_or(&0)
  })
}

pub(super) fn extract_ioc_to_json(ioc: &Ioc) -> crate::serde_json::Value {
  json!({
      "type": ioc.ioc_type.to_string(),
      "value": ioc.value.clone(),
      "confidence": ioc_confidence_label(ioc.confidence),
      "source": ioc.source.to_string(),
      "techniques": ioc.mitre_techniques.clone(),
      "tags": ioc.tags.clone()
  })
}

fn import_ioc_to_json(ioc: &Ioc) -> crate::serde_json::Value {
  json!({
      "type": ioc.ioc_type.to_string(),
      "value": ioc.value.clone(),
      "confidence": ioc_confidence_label(ioc.confidence),
      "source": ioc.source.to_string(),
      "tags": ioc.tags.clone()
  })
}

fn search_ioc_to_json(ioc: &Ioc) -> crate::serde_json::Value {
  json!({
      "type": ioc.ioc_type.to_string(),
      "value": ioc.value.clone(),
      "confidence": ioc_confidence_label(ioc.confidence),
      "source": ioc.source.to_string(),
      "context": ioc.context.clone(),
      "techniques": ioc.mitre_techniques.clone(),
      "tags": ioc.tags.clone()
  })
}

pub(super) fn ioc_extract_empty_payload() -> crate::serde_json::Value {
  json!({
    "error": "No IOCs extracted",
    "iocs": []
  })
}

pub(super) fn ioc_extract_payload(
  target: &str,
  collection: &IocCollection,
) -> crate::serde_json::Value {
  let all_iocs = collection.all();
  let iocs_json: Vec<crate::serde_json::Value> = all_iocs
    .iter()
    .map(|ioc| extract_ioc_to_json(ioc))
    .collect();
  let counts = collection.count_by_type();
  json!({
    "target": target,
    "total": collection.len(),
    "by_type": counts_by_type_to_json(&counts),
    "iocs": iocs_json
  })
}

pub(super) fn ioc_export_empty_payload(
  target: &str,
  export_format: &str,
) -> crate::serde_json::Value {
  json!({
    "target": target,
    "format": export_format,
    "exported": false,
    "message": "No IOCs to export. Extract IOCs first with 'rb intel ioc extract'"
  })
}

pub(super) fn ioc_export_payload(
  target: &str,
  export_format: &str,
  output_path: &str,
  size_bytes: usize,
  collection: &IocCollection,
) -> crate::serde_json::Value {
  json!({
    "target": target,
    "format": export_format,
    "file": output_path,
    "size_bytes": size_bytes,
    "exported": true,
    "total": collection.len()
  })
}

pub(super) fn ioc_types_payload(types: &[(&str, &str, &str, &str)]) -> crate::serde_json::Value {
  let types_json: Vec<crate::serde_json::Value> = types
    .iter()
    .map(|(name, desc, example, category)| {
      json!({
        "name": *name,
        "description": *desc,
        "example": *example,
        "category": *category
      })
    })
    .collect();
  json!({
    "types": types_json,
    "total": types.len()
  })
}

pub(super) fn ioc_demo_payload(
  target: &str,
  collection: &IocCollection,
  port_scan_count: usize,
  dns_count: usize,
  tls_count: usize,
  subdomains_count: usize,
) -> crate::serde_json::Value {
  let counts = collection.count_by_type();
  let conf_counts = collection.count_by_confidence();
  let all_iocs = collection.all();
  let iocs_json: Vec<crate::serde_json::Value> = all_iocs
    .iter()
    .map(|ioc| extract_ioc_to_json(ioc))
    .collect();
  let sources_json = json!({
    "port_scan": port_scan_count,
    "dns": dns_count,
    "tls": tls_count,
    "subdomains": subdomains_count
  });
  json!({
    "target": target,
    "sources": sources_json,
    "total": collection.len(),
    "by_type": counts_by_type_to_json(&counts),
    "by_confidence": counts_by_confidence_to_json(&conf_counts),
    "iocs": iocs_json
  })
}

pub(super) fn ioc_import_missing_file_payload() -> crate::serde_json::Value {
  json!({ "error": "No file specified" })
}

pub(super) fn ioc_import_empty_payload(
  file_path: &str,
  file_format: &str,
) -> crate::serde_json::Value {
  json!({
    "file": file_path,
    "format": file_format,
    "imported": 0,
    "iocs": []
  })
}

pub(super) fn ioc_import_payload(
  file_path: &str,
  file_format: &str,
  import_count: usize,
  collection: &IocCollection,
) -> crate::serde_json::Value {
  let counts = collection.count_by_type();
  let all_iocs = collection.all();
  let iocs_json: Vec<crate::serde_json::Value> =
    all_iocs.iter().map(|ioc| import_ioc_to_json(ioc)).collect();
  json!({
    "file": file_path,
    "format": file_format,
    "imported": import_count,
    "by_type": counts_by_type_to_json(&counts),
    "iocs": iocs_json
  })
}

pub(super) fn ioc_search_missing_query_payload() -> crate::serde_json::Value {
  json!({
    "error": "No search query specified",
    "results": []
  })
}

pub(super) fn ioc_search_payload(
  query: &str,
  type_filter: Option<&str>,
  tag_filter: Option<&str>,
  confidence_filter: Option<&str>,
  results: &[&Ioc],
) -> crate::serde_json::Value {
  let results_json: Vec<crate::serde_json::Value> =
    results.iter().map(|ioc| search_ioc_to_json(ioc)).collect();
  let mut payload = crate::serde_json::Map::new();
  payload.insert("query".to_string(), json!(query));
  if let Some(t) = type_filter {
    payload.insert("type_filter".to_string(), json!(t));
  }
  if let Some(t) = tag_filter {
    payload.insert("tag_filter".to_string(), json!(t));
  }
  if let Some(c) = confidence_filter {
    payload.insert("confidence_filter".to_string(), json!(c));
  }
  payload.insert("total".to_string(), json!(results.len()));
  payload.insert("results".to_string(), json!(results_json));
  crate::serde_json::Value::Object(payload)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ioc_extract_payload_serializes_collection() {
    let mut collection = IocCollection::new();
    collection.add(
      Ioc::new(
        IocType::Domain,
        "example.com",
        IocSource::Manual,
        80,
        "target",
      )
      .with_tag("manual"),
    );

    let payload = ioc_extract_payload("example.com", &collection);

    assert_eq!(payload["target"].as_str(), Some("example.com"));
    assert_eq!(payload["total"].as_i64(), Some(1));
    assert_eq!(
      payload["iocs"].as_array().unwrap()[0]["value"].as_str(),
      Some("example.com")
    );
  }

  #[test]
  fn ioc_export_payload_serializes_summary() {
    let mut collection = IocCollection::new();
    collection.add(Ioc::new(
      IocType::IPv4,
      "93.184.216.34",
      IocSource::DnsQuery,
      90,
      "target",
    ));

    let payload = ioc_export_payload("target", "json", "iocs.json", 128, &collection);

    assert_eq!(payload["exported"].as_bool(), Some(true));
    assert_eq!(payload["format"].as_str(), Some("json"));
    assert_eq!(payload["file"].as_str(), Some("iocs.json"));
    assert_eq!(payload["size_bytes"].as_i64(), Some(128));
  }

  #[test]
  fn ioc_search_payload_includes_filters() {
    let ioc = Ioc::new(IocType::IPv4, "192.168.1.1", IocSource::PortScan, 85, "ctx");
    let payload = ioc_search_payload("192.168", Some("ipv4"), Some("scan"), Some("high"), &[&ioc]);

    assert_eq!(payload["query"].as_str(), Some("192.168"));
    assert_eq!(payload["type_filter"].as_str(), Some("ipv4"));
    assert_eq!(payload["tag_filter"].as_str(), Some("scan"));
    assert_eq!(payload["confidence_filter"].as_str(), Some("high"));
    assert_eq!(payload["total"].as_i64(), Some(1));
  }
}
