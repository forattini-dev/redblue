
fn capability_entry(
  name: &str,
  implemented: bool,
  available: bool,
  source: &str,
  reason: Option<String>,
) -> Value {
  json!({
    "name": name,
    "implemented": implemented,
    "available": available,
    "source": source,
    "reason": reason.unwrap_or_default()
  })
}

fn detect_container_environment() -> Value {
  let mut reasons = Vec::new();
  let mut technology = String::new();
  let mut score = 0u32;

  if Path::new("/.dockerenv").exists() {
    reasons.push("found /.dockerenv marker".to_string());
    technology = "docker".to_string();
    score += 90;
  }

  if Path::new("/run/.containerenv").exists() {
    reasons.push("found /run/.containerenv marker".to_string());
    technology = "podman".to_string();
    score += 90;
  }

  let cgroup_paths = ["/proc/1/cgroup", "/proc/self/cgroup"];
  for cgroup_path in cgroup_paths {
    if let Some(content) = read_trimmed(cgroup_path) {
      let lower = content.to_lowercase();
      let detections = [
        ("docker", "cgroup references docker"),
        ("containerd", "cgroup references containerd"),
        ("kubepods", "cgroup references kubepods"),
        ("podman", "cgroup references podman"),
        ("libpod", "cgroup references libpod"),
        ("lxc", "cgroup references lxc"),
      ];
      for (needle, reason) in detections {
        if lower.contains(needle) {
          if technology.is_empty() {
            technology = needle.to_string();
          }
          reasons.push(format!("{} ({})", reason, cgroup_path));
          score += 40;
        }
      }
    }
  }

  if let Ok(container_var) = std::env::var("container") {
    if !container_var.trim().is_empty() {
      if technology.is_empty() {
        technology = container_var.clone();
      }
      reasons.push(format!("environment variable container={}", container_var));
      score += 30;
    }
  }

  let detected = score >= 40;
  json!({
    "detected": detected,
    "technology": if detected { technology } else { String::new() },
    "confidence": score_to_confidence(score),
    "score": score,
    "reasons": reasons,
  })
}

fn detect_virtual_machine_environment() -> Value {
  let mut reasons = Vec::new();
  let mut technology = String::new();
  let mut score = 0u32;

  #[cfg(target_os = "linux")]
  {
    let dmi_candidates = [
      "/sys/class/dmi/id/product_name",
      "/sys/class/dmi/id/sys_vendor",
      "/sys/class/dmi/id/product_version",
      "/sys/class/dmi/id/board_vendor",
    ];
    for path in dmi_candidates {
      if let Some(value) = read_trimmed(path) {
        if let Some(candidate) = match_virtualization_vendor(&value) {
          if technology.is_empty() {
            technology = candidate.to_string();
          }
          reasons.push(format!("DMI '{}' indicates {}", path, candidate));
          score += 45;
        }
      }
    }

    if let Some(cpuinfo) = read_trimmed("/proc/cpuinfo") {
      if cpuinfo.contains(" hypervisor ") {
        reasons.push("cpuinfo flags include hypervisor".to_string());
        score += 20;
      }
      if let Some(candidate) = cpuinfo.lines().find_map(match_virtualization_vendor) {
        if technology.is_empty() {
          technology = candidate.to_string();
        }
        reasons.push(format!("cpuinfo references {}", candidate));
        score += 20;
      }
    }

    if Path::new("/sys/hypervisor").exists() {
      reasons.push("found /sys/hypervisor".to_string());
      score += 20;
    }
  }

  if let Some(kernel) = read_trimmed("/proc/sys/kernel/osrelease") {
    if kernel.to_lowercase().contains("microsoft") {
      technology = "wsl".to_string();
      reasons.push("kernel release references microsoft (likely WSL)".to_string());
      score += 50;
    }
  }

  let detected = score >= 35;
  json!({
    "detected": detected,
    "technology": if detected { technology } else { String::new() },
    "confidence": score_to_confidence(score),
    "score": score,
    "reasons": reasons,
  })
}

fn detect_sandbox_environment() -> Value {
  let mut reasons = Vec::new();
  let mut score = 0u32;

  if sandbox::check_sandbox_processes() {
    reasons.push("analysis/sandbox-related processes detected".to_string());
    score += 30;
  }
  if sandbox::check_timing_anomaly() {
    reasons.push("timing anomaly detected".to_string());
    score += 25;
  }
  if sandbox::check_low_resources() {
    reasons.push("low-resource profile matches common sandbox defaults".to_string());
    score += 15;
  }
  if sandbox::check_suspicious_username() {
    reasons.push("username resembles common sandbox/lab naming".to_string());
    score += 10;
  }
  if sandbox::check_debugger() {
    reasons.push("debugger/tracer detected".to_string());
    score += 20;
  }

  let detected = score >= 40;
  json!({
    "detected": detected,
    "confidence": score_to_confidence(score),
    "score": score,
    "reasons": reasons,
  })
}

fn collect_inventory_warnings(
  display: &Value,
  battery: &Value,
  pci: &Value,
  usb: &Value,
  camera: &Value,
  thunderbolt: &Value,
  capabilities: &Value,
) -> Vec<String> {
  let mut warnings = Vec::new();

  if let Some(reason) = unavailable_collector_reason(display) {
    warnings.push(format!("display collector unavailable: {}", reason));
  } else if display
    .get("connectors")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("display inventory is empty or unavailable on this host".to_string());
  }

  if let Some(reason) = unavailable_collector_reason(battery) {
    warnings.push(format!("battery collector unavailable: {}", reason));
  } else if battery
    .get("batteries")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push(
      "battery inventory is empty; this may be a desktop, VM, or unsupported platform".to_string(),
    );
  }

  if let Some(reason) = unavailable_collector_reason(pci) {
    warnings.push(format!("pci collector unavailable: {}", reason));
  } else if pci
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("no interesting PCI display/audio/network devices were identified".to_string());
  }

  if let Some(reason) = unavailable_collector_reason(usb) {
    warnings.push(format!("usb collector unavailable: {}", reason));
  } else if usb
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("USB inventory is empty or inaccessible".to_string());
  }

  if let Some(reason) = unavailable_collector_reason(camera) {
    warnings.push(format!("camera collector unavailable: {}", reason));
  } else if camera
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("camera/video4linux inventory is empty".to_string());
  }

  if let Some(reason) = unavailable_collector_reason(thunderbolt) {
    warnings.push(format!("thunderbolt collector unavailable: {}", reason));
  } else if thunderbolt
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("thunderbolt inventory is empty or unsupported".to_string());
  }

  if let Some(unavailable) = capabilities
    .get("unavailable_collectors")
    .and_then(Value::as_i64)
    .map(|value| value.max(0) as u64)
    .filter(|value| *value > 0)
  {
    warnings.push(format!(
      "{} collector(s) are unavailable; inspect capabilities.collectors for details",
      unavailable
    ));
  }

  warnings
}

fn unavailable_collector_reason(section: &Value) -> Option<String> {
  let collector = section.get("collector")?;
  let available = collector
    .get("available")
    .and_then(Value::as_bool)
    .unwrap_or(false);
  if available {
    return None;
  }

  let reason = collector
    .get("reason")
    .and_then(Value::as_str)
    .unwrap_or_default()
    .trim()
    .to_string();
  if reason.is_empty() {
    Some("collector marked unavailable".to_string())
  } else {
    Some(reason)
  }
}

fn parse_key_value_file(path: &str) -> BTreeMap<String, String> {
  let mut values = BTreeMap::new();
  let Ok(content) = fs::read_to_string(path) else {
    return values;
  };

  for line in content.lines() {
    if let Some((key, value)) = line.split_once('=') {
      values.insert(key.to_string(), value.trim_matches('"').to_string());
    }
  }

  values
}

fn parse_meminfo(path: &str) -> BTreeMap<String, u64> {
  let mut values = BTreeMap::new();
  let Ok(content) = fs::read_to_string(path) else {
    return values;
  };

  for line in content.lines() {
    if let Some((key, value)) = line.split_once(':') {
      let numeric = value
        .split_whitespace()
        .next()
        .and_then(|number| number.parse::<u64>().ok());
      if let Some(numeric) = numeric {
        values.insert(key.to_string(), numeric);
      }
    }
  }

  values
}

fn parse_mounts(path: &str) -> BTreeMap<String, Vec<String>> {
  let mut mounts: BTreeMap<String, Vec<String>> = BTreeMap::new();
  let Ok(content) = fs::read_to_string(path) else {
    return mounts;
  };

  for line in content.lines() {
    let mut parts = line.split_whitespace();
    let Some(device) = parts.next() else {
      continue;
    };
    let Some(mountpoint) = parts.next() else {
      continue;
    };
    if let Some(name) = Path::new(device)
      .file_name()
      .and_then(|value| value.to_str())
    {
      mounts
        .entry(name.to_string())
        .or_default()
        .push(mountpoint.to_string());
    }
  }

  mounts
}

#[derive(Clone, Debug)]
struct MountRecord {
  source: String,
  mountpoint: String,
  fs_type: String,
  options: String,
}

fn parse_mount_records(path: &str) -> Vec<MountRecord> {
  let Ok(content) = fs::read_to_string(path) else {
    return Vec::new();
  };

  let mut mounts = Vec::new();
  for line in content.lines() {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 4 {
      continue;
    }
    mounts.push(MountRecord {
      source: parts[0].to_string(),
      mountpoint: parts[1].to_string(),
      fs_type: parts[2].to_string(),
      options: parts[3].to_string(),
    });
  }

  mounts
}

fn tool_exists(program: &str) -> bool {
  if program.contains(std::path::MAIN_SEPARATOR) {
    return Path::new(program).exists();
  }

  let Some(path_value) = std::env::var_os("PATH") else {
    return false;
  };

  #[cfg(target_os = "windows")]
  let exts: Vec<String> = std::env::var("PATHEXT")
    .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
    .split(';')
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
    .collect();

  for directory in std::env::split_paths(&path_value) {
    let direct = directory.join(program);
    if direct.is_file() {
      return true;
    }

    #[cfg(target_os = "windows")]
    {
      if Path::new(program).extension().is_none() {
        for ext in &exts {
          let with_ext = directory.join(format!("{}{}", program, ext));
          if with_ext.is_file() {
            return true;
          }
        }
      }
    }
  }

  false
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
  if !tool_exists(program) {
    return None;
  }

  let output = ProcessCommand::new(program).args(args).output().ok()?;
  if !output.status.success() {
    return None;
  }

  let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
  if stdout.is_empty() {
    None
  } else {
    Some(stdout)
  }
}

fn parse_key_value_lines(text: &str) -> BTreeMap<String, String> {
  let mut values = BTreeMap::new();
  for line in text.lines() {
    let trimmed = line.trim();
    if trimmed.is_empty() {
      continue;
    }
    if let Some((key, value)) = trimmed.split_once('=') {
      values.insert(key.trim().to_string(), value.trim().to_string());
    }
  }
  values
}

fn parse_key_value_records(text: &str) -> Vec<BTreeMap<String, String>> {
  let mut records = Vec::new();
  let mut current = BTreeMap::new();

  for line in text.lines() {
    let trimmed = line.trim();
    if trimmed.is_empty() {
      if !current.is_empty() {
        records.push(current);
        current = BTreeMap::new();
      }
      continue;
    }
    if let Some((key, value)) = trimmed.split_once('=') {
      current.insert(key.trim().to_string(), value.trim().to_string());
    }
  }

  if !current.is_empty() {
    records.push(current);
  }

  records
}

fn parse_u64_relaxed(value: &str) -> Option<u64> {
  let digits = value
    .chars()
    .filter(|ch| ch.is_ascii_digit())
    .collect::<String>();
  if digits.is_empty() {
    None
  } else {
    digits.parse::<u64>().ok()
  }
}

fn parse_f64_relaxed(value: &str) -> Option<f64> {
  let normalized = value
    .chars()
    .filter(|ch| ch.is_ascii_digit() || *ch == '.')
    .collect::<String>();
  if normalized.is_empty() {
    None
  } else {
    normalized.parse::<f64>().ok()
  }
}

fn parse_boolish(value: &str) -> bool {
  matches!(
    value.trim().to_ascii_lowercase().as_str(),
    "1" | "true" | "yes"
  )
}

fn collect_block_partitions(
  path: &Path,
  device_name: &str,
  mountpoints: &BTreeMap<String, Vec<String>>,
) -> Vec<Value> {
  let Ok(entries) = fs::read_dir(path) else {
    return Vec::new();
  };

  let mut partitions = Vec::new();
  for entry in entries.flatten() {
    let partition_name = entry.file_name().to_string_lossy().to_string();
    if !partition_name.starts_with(device_name) {
      continue;
    }
    if !entry.path().join("partition").exists() {
      continue;
    }

    let size_sectors = read_trimmed(entry.path().join("size"))
      .and_then(|value| value.parse::<u64>().ok())
      .unwrap_or(0);
    partitions.push(json!({
      "name": partition_name.clone(),
      "size_bytes": size_sectors.saturating_mul(512),
      "size_gib": bytes_to_gib(size_sectors.saturating_mul(512)),
      "mountpoints": mountpoints.get(&partition_name).cloned().unwrap_or_default(),
    }));
  }

  partitions.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
  partitions
}

fn classify_network_interface(path: &Path) -> &'static str {
  if path.join("wireless").exists() {
    "wireless"
  } else if path.join("bridge").exists() {
    "bridge"
  } else if path.join("tun_flags").exists() {
    "tunnel"
  } else {
    "ethernet"
  }
}

fn interface_type_from_name(name: &str) -> &'static str {
  let lower = name.to_ascii_lowercase();
  if lower.starts_with("lo") || lower.contains("loopback") {
    "loopback"
  } else if lower.starts_with("wl") || lower.contains("wi-fi") || lower.contains("wireless") {
    "wireless"
  } else if lower.starts_with("br") || lower.contains("bridge") {
    "bridge"
  } else if lower.starts_with("tun") || lower.starts_with("tap") || lower.contains("vpn") {
    "tunnel"
  } else {
    "ethernet"
  }
}

fn block_transport(name: &str) -> &'static str {
  if name.starts_with("nvme") {
    "nvme"
  } else if name.starts_with("sd") {
    "scsi"
  } else if name.starts_with("vd") {
    "virtio"
  } else if name.starts_with("mmcblk") {
    "mmc"
  } else {
    "unknown"
  }
}

fn connector_type(path: &Path) -> String {
  path
    .file_name()
    .and_then(|value| value.to_str())
    .and_then(|name| name.split('-').nth(1))
    .unwrap_or("unknown")
    .to_string()
}

fn match_virtualization_vendor(value: &str) -> Option<&'static str> {
  let lower = value.to_lowercase();
  let vendors = [
    ("vmware", "vmware"),
    ("virtualbox", "virtualbox"),
    ("oracle", "virtualbox"),
    ("kvm", "kvm"),
    ("qemu", "qemu"),
    ("hyper-v", "hyper-v"),
    ("microsoft corporation virtual machine", "hyper-v"),
    ("xen", "xen"),
    ("parallels", "parallels"),
    ("bhyve", "bhyve"),
  ];

  vendors
    .into_iter()
    .find_map(|(needle, technology)| lower.contains(needle).then_some(technology))
}

fn interesting_pci_class(class_id: &str) -> bool {
  let normalized = class_id.trim().trim_start_matches("0x");
  normalized.starts_with("02") || normalized.starts_with("03") || normalized.starts_with("04")
}

fn pci_class_name(class_id: &str) -> &'static str {
  let normalized = class_id.trim().trim_start_matches("0x");
  if normalized.starts_with("02") {
    "network"
  } else if normalized.starts_with("03") {
    "display"
  } else if normalized.starts_with("04") {
    "multimedia"
  } else {
    "other"
  }
}

fn should_skip_block_device(name: &str) -> bool {
  name.starts_with("loop") || name.starts_with("ram") || name.starts_with("fd")
}

fn hostname() -> String {
  read_trimmed("/proc/sys/kernel/hostname")
    .or_else(|| read_trimmed("/etc/hostname"))
    .or_else(|| std::env::var("HOSTNAME").ok())
    .or_else(|| std::env::var("COMPUTERNAME").ok())
    .or_else(|| command_stdout("hostname", &[]))
    .unwrap_or_else(|| "unknown".to_string())
}

fn read_trimmed<P>(path: P) -> Option<String>
where
  P: Into<PathBuf>,
{
  fs::read_to_string(path.into())
    .ok()
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

fn read_lines<P>(path: P) -> Vec<String>
where
  P: Into<PathBuf>,
{
  fs::read_to_string(path.into())
    .ok()
    .map(|value| {
      value
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
    })
    .unwrap_or_default()
}

fn symlink_name<P>(path: P) -> Option<String>
where
  P: Into<PathBuf>,
{
  fs::read_link(path.into()).ok().and_then(|link| {
    link
      .file_name()
      .map(|value| value.to_string_lossy().to_string())
  })
}

fn value_after_colon(line: &str) -> String {
  line
    .split_once(':')
    .map(|(_, value)| value.trim().to_string())
    .unwrap_or_default()
}

fn fallback_string(value: String, fallback: &str) -> String {
  if value.is_empty() {
    fallback.to_string()
  } else {
    value
  }
}

fn kib_to_gib(value: u64) -> f64 {
  value as f64 / 1024.0 / 1024.0
}

fn bytes_to_gib(value: u64) -> f64 {
  value as f64 / 1024.0 / 1024.0 / 1024.0
}

fn value_name(value: &Value) -> String {
  value
    .get("name")
    .or_else(|| value.get("slot"))
    .or_else(|| value.get("bus"))
    .or_else(|| value.get("node"))
    .or_else(|| value.get("domain"))
    .and_then(Value::as_str)
    .unwrap_or_default()
    .to_string()
}

fn detector_score(value: &Value) -> u32 {
  value
    .get("score")
    .and_then(Value::as_i64)
    .map(|score| score.max(0) as u32)
    .unwrap_or(0)
}

fn dominant_environment_signal(
  container_score: u32,
  virtualization_score: u32,
  sandbox_score: u32,
) -> &'static str {
  let mut dominant = "none";
  let mut max_score = 0u32;

  if container_score > max_score {
    dominant = "container";
    max_score = container_score;
  }
  if virtualization_score > max_score {
    dominant = "virtualization";
    max_score = virtualization_score;
  }
  if sandbox_score > max_score {
    dominant = "sandbox";
  }

  dominant
}

fn environment_topology(
  container_detected: bool,
  virtualization_detected: bool,
  sandbox_detected: bool,
) -> &'static str {
  match (
    container_detected,
    virtualization_detected,
    sandbox_detected,
  ) {
    (true, true, true) => "sandbox-in-container-in-vm",
    (true, true, false) => "container-in-vm",
    (true, false, true) => "sandbox-in-container",
    (false, true, true) => "sandbox-in-vm",
    (true, false, false) => "container",
    (false, true, false) => "vm",
    (false, false, true) => "sandbox",
    (false, false, false) => "host",
  }
}

fn json_array_strings(value: Option<&Value>) -> Vec<String> {
  value
    .and_then(Value::as_array)
    .map(|items| {
      items
        .iter()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
    })
    .unwrap_or_default()
}

fn score_to_confidence(score: u32) -> &'static str {
  if score >= 80 {
    "high"
  } else if score >= 40 {
    "medium"
  } else {
    "low"
  }
}

fn confidence_max<'a>(left: &'a str, right: &'a str) -> String {
  let rank = |value: &str| match value {
    "high" => 3,
    "medium" => 2,
    "low" => 1,
    _ => 0,
  };

  if rank(right) > rank(left) {
    right.to_string()
  } else {
    left.to_string()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn block_transport_detects_common_linux_names() {
    assert_eq!(block_transport("nvme0n1"), "nvme");
    assert_eq!(block_transport("sda"), "scsi");
    assert_eq!(block_transport("vda"), "virtio");
    assert_eq!(block_transport("mmcblk0"), "mmc");
    assert_eq!(block_transport("dm-0"), "unknown");
  }

  #[test]
  fn match_virtualization_vendor_handles_common_hypervisors() {
    assert_eq!(
      match_virtualization_vendor("VMware Virtual Platform"),
      Some("vmware")
    );
    assert_eq!(match_virtualization_vendor("KVM"), Some("kvm"));
    assert_eq!(
      match_virtualization_vendor("Microsoft Corporation Virtual Machine"),
      Some("hyper-v")
    );
    assert_eq!(match_virtualization_vendor("Dell Inc."), None);
  }

  #[test]
  fn parse_mount_records_extracts_basic_fields() {
    let path = "/tmp/redblue-system-mounts-test.txt";
    fs::write(
      path,
      "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n/dev/nvme0n1p1 /boot/efi vfat rw 0 0\n",
    )
    .unwrap();

    let mounts = parse_mount_records(path);
    fs::remove_file(path).unwrap();

    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[0].source, "/dev/nvme0n1p2");
    assert_eq!(mounts[0].mountpoint, "/");
    assert_eq!(mounts[0].fs_type, "ext4");
    assert_eq!(mounts[1].mountpoint, "/boot/efi");
  }

  #[test]
  fn score_to_confidence_thresholds_are_stable() {
    assert_eq!(score_to_confidence(5), "low");
    assert_eq!(score_to_confidence(40), "medium");
    assert_eq!(score_to_confidence(80), "high");
  }

  #[test]
  fn capability_entry_contains_reason_and_source() {
    let value = capability_entry(
      "display",
      true,
      false,
      "/sys/class/drm",
      Some("source path unavailable: /sys/class/drm".to_string()),
    );
    assert_eq!(value["name"].as_str(), Some("display"));
    assert_eq!(value["implemented"].as_bool(), Some(true));
    assert_eq!(value["available"].as_bool(), Some(false));
    assert_eq!(value["source"].as_str(), Some("/sys/class/drm"));
    assert!(value["reason"]
      .as_str()
      .unwrap_or_default()
      .contains("source path unavailable"));
  }

  #[test]
  fn environment_topology_handles_nested_states() {
    assert_eq!(environment_topology(false, false, false), "host");
    assert_eq!(environment_topology(true, false, false), "container");
    assert_eq!(environment_topology(false, true, false), "vm");
    assert_eq!(environment_topology(false, false, true), "sandbox");
    assert_eq!(environment_topology(true, true, false), "container-in-vm");
    assert_eq!(
      environment_topology(true, false, true),
      "sandbox-in-container"
    );
    assert_eq!(environment_topology(false, true, true), "sandbox-in-vm");
    assert_eq!(
      environment_topology(true, true, true),
      "sandbox-in-container-in-vm"
    );
  }

  #[test]
  fn dominant_environment_signal_prefers_highest_score() {
    assert_eq!(dominant_environment_signal(0, 0, 0), "none");
    assert_eq!(dominant_environment_signal(80, 50, 40), "container");
    assert_eq!(dominant_environment_signal(20, 70, 60), "virtualization");
    assert_eq!(dominant_environment_signal(30, 40, 90), "sandbox");
  }

  #[test]
  fn summarize_inventory_surfaces_capability_counts() {
    let inventory = json!({
      "host": json!({"hostname": "test"}),
      "environment": json!({"kind": "host"}),
      "system": json!({}),
      "runtime": json!({}),
      "cpu": json!({}),
      "memory": json!({}),
      "capabilities": json!({
        "available_collectors": 8,
        "unavailable_collectors": 5,
        "collectors": json!([])
      }),
      "storage": json!({"devices": json!([])}),
      "network": json!({"interfaces": json!([])}),
      "display": json!({"connectors": json!([])}),
      "battery": json!({"batteries": json!([])}),
      "pci": json!({"devices": json!([])}),
      "usb": json!({"devices": json!([])}),
      "camera": json!({"devices": json!([])}),
      "thunderbolt": json!({"devices": json!([])}),
      "sensors": json!({"thermal_zones": json!([])}),
      "warnings": json!([])
    });

    let summary = summarize_inventory(&inventory);
    assert_eq!(summary["counts"]["available_collectors"].as_i64(), Some(8));
    assert_eq!(
      summary["counts"]["unavailable_collectors"].as_i64(),
      Some(5)
    );
    assert_eq!(
      summary["capabilities"]["available_collectors"].as_i64(),
      Some(8)
    );
  }

  #[test]
  fn interface_type_from_name_classifies_common_patterns() {
    assert_eq!(interface_type_from_name("lo0"), "loopback");
    assert_eq!(interface_type_from_name("wlan0"), "wireless");
    assert_eq!(interface_type_from_name("Wi-Fi"), "wireless");
    assert_eq!(interface_type_from_name("br0"), "bridge");
    assert_eq!(interface_type_from_name("tun0"), "tunnel");
    assert_eq!(interface_type_from_name("eth0"), "ethernet");
  }

  #[test]
  fn parse_key_value_records_splits_multiple_blocks() {
    let input = "Name=CPU 0\nVendor=Acme\n\nName=CPU 1\nVendor=Acme\n";
    let records = parse_key_value_records(input);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].get("Name").map(String::as_str), Some("CPU 0"));
    assert_eq!(records[1].get("Name").map(String::as_str), Some("CPU 1"));
  }

  #[test]
  fn unavailable_collector_reason_prefers_explicit_reason() {
    let section = json!({
      "collector": json!({
        "available": false,
        "reason": "collector parser pending"
      })
    });
    assert_eq!(
      unavailable_collector_reason(&section).as_deref(),
      Some("collector parser pending")
    );
  }

  #[test]
  fn collect_inventory_warnings_reports_unavailable_collectors_explicitly() {
    let unavailable = |name: &str| {
      json!({
        "collector": json!({
          "name": name,
          "available": false,
          "reason": format!("{} unavailable in this environment", name)
        }),
        "devices": [],
        "connectors": [],
        "batteries": []
      })
    };

    let warnings = collect_inventory_warnings(
      &unavailable("display"),
      &unavailable("battery"),
      &unavailable("pci"),
      &unavailable("usb"),
      &unavailable("camera"),
      &unavailable("thunderbolt"),
      &json!({
        "unavailable_collectors": 6
      }),
    );

    assert!(warnings
      .iter()
      .any(|item| item.contains("display collector unavailable")));
    assert!(warnings
      .iter()
      .any(|item| item.contains("battery collector unavailable")));
    assert!(warnings
      .iter()
      .any(|item| item.contains("collector(s) are unavailable")));
  }
}
