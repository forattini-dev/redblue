#[cfg(test)]
use super::*;

#[test]
fn test_port_mapping_ssh() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_port(22);

  assert!(!results.is_empty());
  assert!(results.iter().any(|t| t.technique_id == "T1021.004"));
}

#[test]
fn test_port_mapping_rdp() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_port(3389);

  assert!(!results.is_empty());
  assert!(results.iter().any(|t| t.technique_id == "T1021.001"));
}

#[test]
fn test_port_mapping_smb() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_port(445);

  assert!(!results.is_empty());
  assert!(results.iter().any(|t| t.technique_id == "T1021.002"));
}

#[test]
fn test_cve_mapping_rce() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_cve(
    "CVE-2021-44228",
    "Remote code execution vulnerability in Apache Log4j",
  );

  assert!(!results.is_empty());
  assert!(results.iter().any(|t| t.technique_id == "T1203"));
}

#[test]
fn test_cve_mapping_sqli() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_cve(
    "CVE-2024-1234",
    "SQL injection vulnerability allows attackers to execute arbitrary SQL queries",
  );

  assert!(!results.is_empty());
  assert!(results.iter().any(|t| t.technique_id == "T1190"));
}

#[test]
fn test_fingerprint_mapping() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_fingerprint("WordPress");

  assert!(!results.is_empty());
  assert!(results.iter().any(|t| t.technique_id == "T1190"));
}

#[test]
fn test_banner_mapping() {
  let mapper = TechniqueMapper::new();
  let results = mapper.map_banner("Apache/2.4.51 (Ubuntu)");

  assert!(!results.is_empty());
}

#[test]
fn test_full_mapping() {
  let mapper = TechniqueMapper::new();

  let findings = Findings {
    ports: vec![22, 80, 443, 3389],
    cves: vec![(
      "CVE-2021-44228".to_string(),
      "Remote code execution in Log4j".to_string(),
    )],
    fingerprints: vec!["wordpress".to_string(), "nginx".to_string()],
    banners: vec!["Apache/2.4".to_string()],
  };

  let result = mapper.map_findings(&findings);

  assert!(!result.techniques.is_empty());
  assert!(!result.by_tactic.is_empty());
  assert!(!result.coverage.is_empty());
}

#[test]
fn test_mapped_ports_list() {
  let mapper = TechniqueMapper::new();
  let ports = mapper.mapped_ports();

  assert!(ports.contains(&22));
  assert!(ports.contains(&445));
  assert!(ports.contains(&3389));
}

#[test]
fn test_mapped_technologies_list() {
  let mapper = TechniqueMapper::new();
  let techs = mapper.mapped_technologies();

  assert!(techs.contains(&"wordpress"));
  assert!(techs.contains(&"jenkins"));
  assert!(techs.contains(&"exchange"));
}
