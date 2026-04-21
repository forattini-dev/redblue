use crate::mcp::server::{map_tech_to_ecosystem, vuln_to_json, McpServer};
use crate::mcp::types::ToolResult;
use crate::modules::recon::vuln::osv::OsvClient;
use crate::modules::recon::vuln::{
  calculate_risk_score, generate_cpe, KevClient, NvdClient, VulnCollection,
};
use crate::modules::web::fingerprinter::WebFingerprinter;
use crate::utils::json::JsonValue;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub fn tool_vuln_fingerprint(
  _server: &mut McpServer,
  args: &JsonValue,
) -> Result<ToolResult, String> {
  let url = args
    .get("url")
    .and_then(|v| v.as_str())
    .ok_or_else(|| "argument 'url' is required".to_string())?;

  let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("nvd");

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

  for tech in techs {
    let cpe = generate_cpe(&tech.name, tech.version.as_deref());

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

    if source == "osv" || source == "all" {
      let osv_client = OsvClient::new();
      let ecosystem = map_tech_to_ecosystem(&tech.name);
      if let Ok(vulns) = osv_client.query_package(&tech.name, tech.version.as_deref(), ecosystem) {
        for vuln in vulns {
          collection.add(vuln);
        }
      }
    }
  }

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
  let _ = _server;

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

pub fn tool_fingerprint_service(
  _server: &mut McpServer,
  args: &JsonValue,
) -> Result<ToolResult, String> {
  let target = args
    .get("target")
    .and_then(|v| v.as_str())
    .ok_or("Missing required field: target")?;

  let port = args
    .get("port")
    .and_then(|v| v.as_f64())
    .map(|p| p as u16)
    .ok_or("Missing required field: port")?;

  let timeout = Duration::from_secs(5);
  let addr = format!("{}:{}", target, port);

  let banner = if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
    if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
      stream.set_read_timeout(Some(timeout)).ok();
      let mut buf = [0u8; 1024];
      if port == 80 || port == 8080 || port == 443 || port == 8443 {
        let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");
      }
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

  let _ = _server;
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
