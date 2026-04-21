use crate::cli::commands::{Command, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::evasion::sandbox;
use crate::serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

pub struct SystemCommand;

impl Command for SystemCommand {
  fn domain(&self) -> &str {
    "system"
  }

  fn resource(&self) -> &str {
    "host"
  }

  fn description(&self) -> &str {
    "Inspect the local host: OS, hardware, storage, displays, battery, USB, PCI, and runtime environment"
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new().with_machine_output(
      crate::cli::schema::MachineOutputMetadata::new()
        .with_json_support(crate::cli::schema::JsonSupport::Guaranteed)
        .with_stdout_policy(crate::cli::schema::StdoutPolicy::JsonOnlyWhenRequested)
        .with_stderr_policy(crate::cli::schema::StderrPolicy::DiagnosticsOnly),
    )
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    let aliases = match verb {
      "inspect" => &["inventory", "inv"][..],
      "summary" => &["sum"][..],
      _ => crate::cli::aliases::verb_aliases_for(verb),
    };

    crate::cli::schema::RouteMetadata::new()
      .with_aliases(aliases)
      .with_machine_output(self.metadata().machine_output)
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "inspect",
        summary: "Full local host inventory with environment inference",
        usage: "rb system host inspect [--json]",
      },
      Route {
        verb: "summary",
        summary: "Short local host summary with environment inference",
        usage: "rb system host summary [--json]",
      },
    ]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Full host inventory", "rb system host inspect"),
      (
        "Full host inventory as JSON",
        "rb system host inspect --json",
      ),
      ("Short host summary", "rb system host summary"),
      (
        "Short host summary as JSON",
        "rb system host summary --json",
      ),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("inspect");
    let inventory = collect_host_inventory();
    let payload = match verb {
      "inspect" => inventory,
      "summary" => summarize_inventory(&inventory),
      "help" => {
        super::print_help(self);
        return Ok(());
      }
      _ => {
        return Err(format!(
          "Unknown verb '{}'. Use 'rb system host help'.",
          verb
        ))
      }
    };

    if render::render_machine_output(ctx, &format!("rb system host {}", verb), &payload)? {
      return Ok(());
    }

    render_human_inventory(&payload, verb == "summary");
    Ok(())
  }
}

fn collect_host_inventory() -> Value {
  let host = collect_host_identity();
  let environment = collect_environment_assessment();
  let capabilities = collect_capabilities_section();
  let system = collect_system_section();
  let runtime = collect_runtime_section();
  let bios = collect_bios_section();
  let cpu = collect_cpu_section();
  let memory = collect_memory_section();
  let storage = collect_storage_section();
  let network = collect_network_section();
  let display = collect_display_section();
  let sensors = collect_sensor_section();
  let battery = collect_battery_section();
  let pci = collect_pci_section();
  let usb = collect_usb_section();
  let camera = collect_camera_section();
  let thunderbolt = collect_thunderbolt_section();
  let warnings = collect_inventory_warnings(
    &display,
    &battery,
    &pci,
    &usb,
    &camera,
    &thunderbolt,
    &capabilities,
  );

  json!({
    "host": host,
    "environment": environment,
    "capabilities": capabilities,
    "system": system,
    "runtime": runtime,
    "bios": bios,
    "cpu": cpu,
    "memory": memory,
    "storage": storage,
    "network": network,
    "display": display,
    "sensors": sensors,
    "battery": battery,
    "pci": pci,
    "usb": usb,
    "camera": camera,
    "thunderbolt": thunderbolt,
    "warnings": warnings,
  })
}

fn summarize_inventory(inventory: &Value) -> Value {
  let storage_devices = inventory
    .get("storage")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let interfaces = inventory
    .get("network")
    .and_then(|value| value.get("interfaces"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let connected_displays = inventory
    .get("display")
    .and_then(|value| value.get("connectors"))
    .and_then(Value::as_array)
    .map(|items| {
      items
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) == Some("connected"))
        .count()
    })
    .unwrap_or(0);
  let battery_count = inventory
    .get("battery")
    .and_then(|value| value.get("batteries"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let pci_devices = inventory
    .get("pci")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let usb_devices = inventory
    .get("usb")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let camera_devices = inventory
    .get("camera")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let thunderbolt_devices = inventory
    .get("thunderbolt")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let thermal_zones = inventory
    .get("sensors")
    .and_then(|value| value.get("thermal_zones"))
    .and_then(Value::as_array)
    .map(|items| items.len())
    .unwrap_or(0);
  let available_collectors = inventory
    .get("capabilities")
    .and_then(|value| value.get("available_collectors"))
    .and_then(Value::as_i64)
    .map(|value| value.max(0) as u64)
    .unwrap_or(0);
  let unavailable_collectors = inventory
    .get("capabilities")
    .and_then(|value| value.get("unavailable_collectors"))
    .and_then(Value::as_i64)
    .map(|value| value.max(0) as u64)
    .unwrap_or(0);

  json!({
    "host": inventory.get("host").cloned().unwrap_or(Value::Null),
    "environment": inventory.get("environment").cloned().unwrap_or(Value::Null),
    "capabilities": inventory.get("capabilities").cloned().unwrap_or(Value::Null),
    "system": inventory.get("system").cloned().unwrap_or(Value::Null),
    "runtime": inventory.get("runtime").cloned().unwrap_or(Value::Null),
    "cpu": inventory.get("cpu").cloned().unwrap_or(Value::Null),
    "memory": inventory.get("memory").cloned().unwrap_or(Value::Null),
    "counts": json!({
      "storage_devices": storage_devices,
      "network_interfaces": interfaces,
      "connected_displays": connected_displays,
      "batteries": battery_count,
      "interesting_pci_devices": pci_devices,
      "usb_devices": usb_devices,
      "camera_devices": camera_devices,
      "thunderbolt_devices": thunderbolt_devices,
      "thermal_zones": thermal_zones,
      "available_collectors": available_collectors,
      "unavailable_collectors": unavailable_collectors
    }),
    "warnings": inventory.get("warnings").cloned().unwrap_or(Value::Null),
  })
}

fn render_human_inventory(payload: &Value, summary_only: bool) {
  Output::header(if summary_only {
    "Local Host Summary"
  } else {
    "Local Host Inventory"
  });

  if let Some(hostname) = payload
    .get("host")
    .and_then(|value| value.get("hostname"))
    .and_then(Value::as_str)
  {
    Output::item("Hostname", hostname);
  }

  if let Some(kind) = payload
    .get("environment")
    .and_then(|value| value.get("kind"))
    .and_then(Value::as_str)
  {
    let confidence = payload
      .get("environment")
      .and_then(|value| value.get("confidence"))
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let topology = payload
      .get("environment")
      .and_then(|value| value.get("topology"))
      .and_then(Value::as_str)
      .unwrap_or(kind);
    Output::item("Environment", &format!("{} ({})", kind, confidence));
    if topology != kind {
      Output::item("Topology", topology);
    }
    if let Some(dominant) = payload
      .get("environment")
      .and_then(|value| value.get("signals"))
      .and_then(|value| value.get("dominant"))
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty() && *value != "none")
    {
      Output::item("Dominant Signal", dominant);
    }
    if let Some(signals) = payload
      .get("environment")
      .and_then(|value| value.get("signals"))
    {
      let aggregate = signals
        .get("aggregate_score")
        .and_then(Value::as_i64)
        .map(|value| value.max(0) as u64)
        .unwrap_or(0);
      let container_score = signals
        .get("container")
        .and_then(|value| value.get("score"))
        .and_then(Value::as_i64)
        .map(|value| value.max(0) as u64)
        .unwrap_or(0);
      let vm_score = signals
        .get("virtualization")
        .and_then(|value| value.get("score"))
        .and_then(Value::as_i64)
        .map(|value| value.max(0) as u64)
        .unwrap_or(0);
      let sandbox_score = signals
        .get("sandbox")
        .and_then(|value| value.get("score"))
        .and_then(Value::as_i64)
        .map(|value| value.max(0) as u64)
        .unwrap_or(0);
      if aggregate > 0 || container_score > 0 || vm_score > 0 || sandbox_score > 0 {
        Output::item("Signal Score", &aggregate.to_string());
        Output::item(
          "Signal Split",
          &format!(
            "container={} vm={} sandbox={}",
            container_score, vm_score, sandbox_score
          ),
        );
      }
    }
  }

  if let Some(pretty_name) = payload
    .get("system")
    .and_then(|value| value.get("os"))
    .and_then(|value| value.get("pretty_name"))
    .and_then(Value::as_str)
  {
    Output::item("OS", pretty_name);
  }

  if let Some(kernel) = payload
    .get("system")
    .and_then(|value| value.get("kernel"))
    .and_then(Value::as_str)
  {
    Output::item("Kernel", kernel);
  }

  if let Some(session_type) = payload
    .get("runtime")
    .and_then(|value| value.get("session_type"))
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
  {
    Output::item("Session", session_type);
  }

  if let Some(model) = payload
    .get("cpu")
    .and_then(|value| value.get("model"))
    .and_then(Value::as_str)
  {
    Output::item("CPU", model);
  }

  if let Some(memory_gib) = payload
    .get("memory")
    .and_then(|value| value.get("total_gib"))
    .and_then(Value::as_f64)
  {
    Output::item("Memory", &format!("{memory_gib:.1} GiB"));
  }

  let reasons = payload
    .get("environment")
    .and_then(|value| value.get("reasons"))
    .and_then(Value::as_array)
    .map(|items| items.to_vec())
    .unwrap_or_default();
  if !reasons.is_empty() {
    Output::subheader("Environment Signals");
    for reason in reasons {
      if let Some(reason) = reason.as_str() {
        println!("  • {}", reason);
      }
    }
  }

  print_capabilities(payload);

  if summary_only {
    if let Some(counts) = payload.get("counts") {
      Output::subheader("Inventory Counts");
      print_optional_item(counts, "storage_devices", "Storage");
      print_optional_item(counts, "network_interfaces", "Interfaces");
      print_optional_item(counts, "connected_displays", "Displays");
      print_optional_item(counts, "batteries", "Batteries");
      print_optional_item(counts, "interesting_pci_devices", "PCI");
      print_optional_item(counts, "usb_devices", "USB");
      print_optional_item(counts, "camera_devices", "Camera");
      print_optional_item(counts, "thunderbolt_devices", "TBT");
      print_optional_item(counts, "thermal_zones", "Thermal");
      print_optional_item(counts, "available_collectors", "Collectors up");
      print_optional_item(counts, "unavailable_collectors", "Collectors down");
    }
  } else {
    print_system_model(payload);
    print_runtime(payload);
    print_storage(payload);
    print_network(payload);
    print_display(payload);
    print_sensors(payload);
    print_battery(payload);
    print_pci(payload);
    print_usb(payload);
    print_camera(payload);
    print_thunderbolt(payload);
  }

  if let Some(warnings) = payload.get("warnings").and_then(Value::as_array) {
    if !warnings.is_empty() {
      Output::subheader("Notes");
      for warning in warnings {
        if let Some(warning) = warning.as_str() {
          println!("  • {}", warning);
        }
      }
    }
  }
}

fn print_capabilities(payload: &Value) {
  let Some(capabilities) = payload.get("capabilities") else {
    return;
  };

  let available = capabilities
    .get("available_collectors")
    .and_then(Value::as_i64)
    .map(|value| value.max(0) as u64)
    .unwrap_or(0);
  let unavailable = capabilities
    .get("unavailable_collectors")
    .and_then(Value::as_i64)
    .map(|value| value.max(0) as u64)
    .unwrap_or(0);
  Output::subheader("Collectors");
  Output::item("Available", &available.to_string());
  Output::item("Unavailable", &unavailable.to_string());

  let Some(collectors) = capabilities.get("collectors").and_then(Value::as_array) else {
    return;
  };

  let unavailable_collectors = collectors
    .iter()
    .filter(|collector| {
      !collector
        .get("available")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    })
    .take(6)
    .collect::<Vec<_>>();

  if unavailable_collectors.is_empty() {
    return;
  }

  println!("  Gaps:");
  for collector in unavailable_collectors {
    let name = collector
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let reason = collector
      .get("reason")
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty())
      .unwrap_or("collector unavailable");
    println!("  • {} - {}", name, reason);
  }
}

fn print_optional_item(section: &Value, key: &str, label: &str) {
  if let Some(value) = section.get(key).and_then(Value::as_i64) {
    Output::item(label, &value.to_string());
  }
}

fn print_system_model(payload: &Value) {
  let vendor = payload
    .get("system")
    .and_then(|value| value.get("vendor"))
    .and_then(Value::as_str)
    .unwrap_or("unknown");
  let product = payload
    .get("system")
    .and_then(|value| value.get("product"))
    .and_then(Value::as_str)
    .unwrap_or("unknown");
  let bios_version = payload
    .get("bios")
    .and_then(|value| value.get("version"))
    .and_then(Value::as_str)
    .unwrap_or("unknown");

  Output::subheader("Platform");
  Output::item("Vendor", vendor);
  Output::item("Product", product);
  Output::item("BIOS", bios_version);
}

fn print_runtime(payload: &Value) {
  let Some(runtime) = payload.get("runtime") else {
    return;
  };

  Output::subheader("Runtime");
  if let Some(shell) = runtime
    .get("shell")
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
  {
    Output::item("Shell", shell);
  }
  if let Some(desktop) = runtime
    .get("desktop")
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
  {
    Output::item("Desktop", desktop);
  }
  if let Some(session_type) = runtime
    .get("session_type")
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
  {
    Output::item("Session", session_type);
  }
  if let Some(root_fs) = runtime.get("root_filesystem").and_then(Value::as_object) {
    let fs_type = root_fs
      .get("fs_type")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let source = root_fs
      .get("source")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    Output::item("Root FS", &format!("{} ({})", fs_type, source));
  }
}

fn print_storage(payload: &Value) {
  let Some(devices) = payload
    .get("storage")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
  else {
    return;
  };

  Output::subheader("Storage");
  for device in devices.iter().take(8) {
    let name = device
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let size = device
      .get("size_gib")
      .and_then(Value::as_f64)
      .map(|value| format!("{value:.1} GiB"))
      .unwrap_or_else(|| "unknown".to_string());
    let model = device
      .get("model")
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty())
      .unwrap_or("unknown");
    let transport = device
      .get("transport")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    println!("  • {}  {}  {}  {}", name, size, transport, model);
  }
}

fn print_network(payload: &Value) {
  let Some(interfaces) = payload
    .get("network")
    .and_then(|value| value.get("interfaces"))
    .and_then(Value::as_array)
  else {
    return;
  };

  Output::subheader("Network Interfaces");
  for interface in interfaces.iter().take(8) {
    let name = interface
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let state = interface
      .get("operstate")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let mac = interface
      .get("mac")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    println!("  • {}  {}  {}", name, state, mac);
  }
}

fn print_display(payload: &Value) {
  let Some(connectors) = payload
    .get("display")
    .and_then(|value| value.get("connectors"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if connectors.is_empty() {
    return;
  }

  Output::subheader("Displays");
  for connector in connectors.iter().take(8) {
    let name = connector
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let status = connector
      .get("status")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let modes = connector
      .get("modes")
      .and_then(Value::as_array)
      .map(|modes| {
        modes
          .iter()
          .filter_map(Value::as_str)
          .take(3)
          .collect::<Vec<_>>()
          .join(", ")
      })
      .unwrap_or_default();
    if modes.is_empty() {
      println!("  • {}  {}", name, status);
    } else {
      println!("  • {}  {}  {}", name, status, modes);
    }
  }
}

fn print_sensors(payload: &Value) {
  let Some(zones) = payload
    .get("sensors")
    .and_then(|value| value.get("thermal_zones"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if zones.is_empty() {
    return;
  }

  Output::subheader("Thermal");
  for zone in zones.iter().take(6) {
    let name = zone
      .get("type")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let temp = zone
      .get("temp_c")
      .and_then(Value::as_f64)
      .map(|value| format!("{value:.1}C"))
      .unwrap_or_else(|| "unknown".to_string());
    println!("  • {}  {}", name, temp);
  }
}

fn print_battery(payload: &Value) {
  let Some(batteries) = payload
    .get("battery")
    .and_then(|value| value.get("batteries"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if batteries.is_empty() {
    return;
  }

  Output::subheader("Battery");
  for battery in batteries.iter().take(4) {
    let name = battery
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let status = battery
      .get("status")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let capacity = battery
      .get("capacity_percent")
      .and_then(Value::as_i64)
      .map(|value| format!("{}%", value))
      .unwrap_or_else(|| "unknown".to_string());
    println!("  • {}  {}  {}", name, status, capacity);
  }
}

fn print_pci(payload: &Value) {
  let Some(devices) = payload
    .get("pci")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if devices.is_empty() {
    return;
  }

  Output::subheader("PCI");
  for device in devices.iter().take(8) {
    let slot = device
      .get("slot")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let class = device
      .get("class_name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let vendor = device
      .get("vendor_id")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let driver = device
      .get("driver")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    println!("  • {}  {}  {}  {}", slot, class, vendor, driver);
  }
}

fn print_usb(payload: &Value) {
  let Some(devices) = payload
    .get("usb")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if devices.is_empty() {
    return;
  }

  Output::subheader("USB");
  for device in devices.iter().take(8) {
    let bus = device
      .get("bus")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let vendor = device
      .get("vendor")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let product = device
      .get("product")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    println!("  • {}  {}  {}", bus, vendor, product);
  }
}

fn print_camera(payload: &Value) {
  let Some(devices) = payload
    .get("camera")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if devices.is_empty() {
    return;
  }

  Output::subheader("Camera");
  for device in devices.iter().take(8) {
    let node = device
      .get("node")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let name = device
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    println!("  • {}  {}", node, name);
  }
}

fn print_thunderbolt(payload: &Value) {
  let Some(devices) = payload
    .get("thunderbolt")
    .and_then(|value| value.get("devices"))
    .and_then(Value::as_array)
  else {
    return;
  };

  if devices.is_empty() {
    return;
  }

  Output::subheader("Thunderbolt");
  for device in devices.iter().take(8) {
    let domain = device
      .get("domain")
      .and_then(Value::as_str)
      .unwrap_or("unknown");
    let vendor = device
      .get("vendor_name")
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty())
      .unwrap_or("unknown");
    let device_name = device
      .get("device_name")
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty())
      .unwrap_or("unknown");
    println!("  • {}  {}  {}", domain, vendor, device_name);
  }
}

fn collect_host_identity() -> Value {
  json!({
    "hostname": hostname(),
    "architecture": std::env::consts::ARCH,
    "family": std::env::consts::FAMILY,
    "platform": std::env::consts::OS,
    "username": std::env::var("USER")
      .or_else(|_| std::env::var("USERNAME"))
      .unwrap_or_else(|_| "unknown".to_string()),
  })
}

fn collect_system_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let os_release = parse_key_value_file("/etc/os-release");
    let uptime_seconds = read_trimmed("/proc/uptime")
      .and_then(|value| value.split_whitespace().next().map(str::to_string))
      .and_then(|value| value.parse::<f64>().ok());

    return json!({
      "os": json!({
        "id": os_release.get("ID").cloned().unwrap_or_else(|| "linux".to_string()),
        "name": os_release.get("NAME").cloned().unwrap_or_else(|| "Linux".to_string()),
        "pretty_name": os_release.get("PRETTY_NAME").cloned().unwrap_or_else(|| "Linux".to_string()),
        "version_id": os_release.get("VERSION_ID").cloned().unwrap_or_default(),
      }),
      "kernel": read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string()),
      "kernel_version": read_trimmed("/proc/version").unwrap_or_else(|| "unknown".to_string()),
      "uptime_seconds": uptime_seconds,
      "vendor": read_trimmed("/sys/class/dmi/id/sys_vendor").unwrap_or_else(|| "unknown".to_string()),
      "product": read_trimmed("/sys/class/dmi/id/product_name").unwrap_or_else(|| "unknown".to_string()),
      "product_version": read_trimmed("/sys/class/dmi/id/product_version").unwrap_or_default(),
      "board_name": read_trimmed("/sys/class/dmi/id/board_name").unwrap_or_default(),
      "collector": capability_entry(
        "system",
        true,
        Path::new("/proc").exists() && Path::new("/etc/os-release").exists(),
        "/proc + /etc/os-release",
        None
      )
    });
  }

  #[cfg(target_os = "macos")]
  {
    let product_name =
      command_stdout("sw_vers", &["-productName"]).unwrap_or_else(|| "macOS".to_string());
    let product_version = command_stdout("sw_vers", &["-productVersion"]).unwrap_or_default();
    let build_version = command_stdout("sw_vers", &["-buildVersion"]).unwrap_or_default();
    let kernel = command_stdout("uname", &["-r"]).unwrap_or_else(|| "unknown".to_string());
    let kernel_version = command_stdout("uname", &["-v"]).unwrap_or_else(|| "unknown".to_string());
    let model = command_stdout("sysctl", &["-n", "hw.model"]).unwrap_or_default();
    let collector_available = tool_exists("sw_vers") && tool_exists("uname");
    let pretty_name = if product_version.is_empty() {
      product_name.clone()
    } else {
      format!("{} {}", product_name, product_version)
    };

    json!({
      "os": json!({
        "id": "macos",
        "name": product_name,
        "pretty_name": pretty_name,
        "version_id": product_version
      }),
      "kernel": kernel,
      "kernel_version": kernel_version,
      "uptime_seconds": Value::Null,
      "vendor": "Apple",
      "product": model,
      "product_version": build_version,
      "board_name": ""
      ,
      "collector": capability_entry(
        "system",
        true,
        collector_available,
        "sw_vers + uname + sysctl",
        (!collector_available).then(|| "required command(s) missing".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    let os_values = command_stdout("wmic", &["os", "get", "Caption,Version", "/value"])
      .map(|value| parse_key_value_lines(&value))
      .unwrap_or_default();
    let version_fallback =
      command_stdout("cmd", &["/C", "ver"]).unwrap_or_else(|| "Windows".to_string());
    let caption = os_values
      .get("Caption")
      .cloned()
      .filter(|value| !value.is_empty())
      .unwrap_or_else(|| version_fallback.clone());
    let version = os_values.get("Version").cloned().unwrap_or_default();
    let product_values = command_stdout(
      "wmic",
      &["csproduct", "get", "Vendor,Name,Version", "/value"],
    )
    .map(|value| parse_key_value_lines(&value))
    .unwrap_or_default();
    let board_values = command_stdout("wmic", &["baseboard", "get", "Product", "/value"])
      .map(|value| parse_key_value_lines(&value))
      .unwrap_or_default();
    let collector_available = tool_exists("cmd");

    json!({
      "os": json!({
        "id": "windows",
        "name": "Windows",
        "pretty_name": caption.clone(),
        "version_id": version
      }),
      "kernel": caption,
      "kernel_version": os_values.get("Version").cloned().unwrap_or_default(),
      "uptime_seconds": Value::Null,
      "vendor": product_values.get("Vendor").cloned().unwrap_or_else(|| "Microsoft".to_string()),
      "product": product_values.get("Name").cloned().unwrap_or_else(|| "Windows Host".to_string()),
      "product_version": product_values.get("Version").cloned().unwrap_or_default(),
      "board_name": board_values.get("Product").cloned().unwrap_or_default(),
      "collector": capability_entry(
        "system",
        true,
        collector_available,
        "wmic + cmd /C ver",
        (!tool_exists("wmic")).then(|| "wmic unavailable; used cmd fallback where possible".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "os": json!({
        "id": std::env::consts::OS,
        "name": std::env::consts::OS,
        "pretty_name": std::env::consts::OS,
        "version_id": ""
      }),
      "kernel": std::env::consts::OS,
      "kernel_version": std::env::consts::ARCH,
      "uptime_seconds": Value::Null,
      "vendor": "unknown",
      "product": "unknown",
      "product_version": "",
      "board_name": "",
      "collector": capability_entry(
        "system",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_bios_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    return json!({
      "vendor": read_trimmed("/sys/class/dmi/id/bios_vendor").unwrap_or_default(),
      "version": read_trimmed("/sys/class/dmi/id/bios_version").unwrap_or_default(),
      "date": read_trimmed("/sys/class/dmi/id/bios_date").unwrap_or_default(),
      "collector": capability_entry("bios", true, Path::new("/sys/class/dmi/id").exists(), "/sys/class/dmi/id", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let hardware = command_stdout("system_profiler", &["SPHardwareDataType"]).unwrap_or_default();
    let mut vendor = "Apple".to_string();
    let mut version = String::new();
    let mut date = String::new();

    for line in hardware.lines() {
      let trimmed = line.trim();
      if let Some((key, value)) = trimmed.split_once(':') {
        let key = key.trim();
        let value = value.trim().to_string();
        if key.eq_ignore_ascii_case("Boot ROM Version") {
          version = value;
        } else if key.eq_ignore_ascii_case("System Firmware Version")
          || key.eq_ignore_ascii_case("SMC Version (system)")
        {
          if version.is_empty() {
            version = value;
          }
        } else if key.eq_ignore_ascii_case("Model Name") && value.contains("Apple") {
          vendor = "Apple".to_string();
        } else if key.eq_ignore_ascii_case("Provisioning UDID") {
          date = String::new();
        }
      }
    }

    json!({
      "vendor": vendor,
      "version": version,
      "date": date,
      "collector": capability_entry(
        "bios",
        true,
        !hardware.is_empty(),
        "system_profiler SPHardwareDataType",
        (hardware.is_empty()).then(|| "system_profiler unavailable or returned empty output".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    let bios_values = command_stdout(
      "wmic",
      &[
        "bios",
        "get",
        "Manufacturer,SMBIOSBIOSVersion,ReleaseDate",
        "/value",
      ],
    )
    .map(|value| parse_key_value_lines(&value))
    .unwrap_or_default();
    let release_date = bios_values
      .get("ReleaseDate")
      .cloned()
      .map(|value| value.chars().take(8).collect::<String>())
      .unwrap_or_default();

    json!({
      "vendor": bios_values.get("Manufacturer").cloned().unwrap_or_default(),
      "version": bios_values.get("SMBIOSBIOSVersion").cloned().unwrap_or_default(),
      "date": release_date,
      "collector": capability_entry(
        "bios",
        true,
        !bios_values.is_empty(),
        "wmic bios",
        bios_values.is_empty().then(|| "wmic unavailable or returned empty output".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "vendor": "",
      "version": "",
      "date": "",
      "collector": capability_entry(
        "bios",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_runtime_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mounts = parse_mount_records("/proc/mounts");
    let root_filesystem = mounts
      .iter()
      .find(|mount| mount.mountpoint == "/")
      .map(|mount| {
        json!({
          "source": mount.source.clone(),
          "mountpoint": mount.mountpoint.clone(),
          "fs_type": mount.fs_type.clone(),
          "options": mount.options.clone(),
        })
      })
      .unwrap_or(Value::Null);

    let home_filesystem = mounts
      .iter()
      .find(|mount| mount.mountpoint == "/home")
      .map(|mount| {
        json!({
          "source": mount.source.clone(),
          "mountpoint": mount.mountpoint.clone(),
          "fs_type": mount.fs_type.clone(),
          "options": mount.options.clone(),
        })
      })
      .unwrap_or(Value::Null);

    let boot_filesystem = mounts
      .iter()
      .find(|mount| mount.mountpoint == "/boot" || mount.mountpoint == "/boot/efi")
      .map(|mount| {
        json!({
          "source": mount.source.clone(),
          "mountpoint": mount.mountpoint.clone(),
          "fs_type": mount.fs_type.clone(),
          "options": mount.options.clone(),
        })
      })
      .unwrap_or(Value::Null);

    return json!({
      "shell": std::env::var("SHELL").unwrap_or_default(),
      "desktop": std::env::var("XDG_CURRENT_DESKTOP")
        .or_else(|_| std::env::var("DESKTOP_SESSION"))
        .unwrap_or_default(),
      "session_type": std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
      "display_server": if std::env::var("WAYLAND_DISPLAY").is_ok() {
        "wayland".to_string()
      } else if std::env::var("DISPLAY").is_ok() {
        "x11".to_string()
      } else {
        String::new()
      },
      "container_env": std::env::var("container").unwrap_or_default(),
      "root_filesystem": root_filesystem,
      "home_filesystem": home_filesystem,
      "boot_filesystem": boot_filesystem,
      "collector": capability_entry("runtime", true, true, "environment variables + /proc/mounts", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let root_filesystem = command_stdout("df", &["-k", "/"])
      .and_then(|output| {
        output.lines().last().map(|line| {
          let parts = line.split_whitespace().collect::<Vec<_>>();
          if parts.len() < 6 {
            return Value::Null;
          }
          json!({
            "source": parts[0],
            "mountpoint": parts[parts.len() - 1],
            "fs_type": "",
            "options": "",
          })
        })
      })
      .unwrap_or(Value::Null);

    json!({
      "shell": std::env::var("SHELL").unwrap_or_default(),
      "desktop": std::env::var("XDG_CURRENT_DESKTOP")
        .or_else(|_| std::env::var("DESKTOP_SESSION"))
        .unwrap_or_default(),
      "session_type": std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
      "display_server": "",
      "container_env": std::env::var("container").unwrap_or_default(),
      "root_filesystem": root_filesystem,
      "home_filesystem": Value::Null,
      "boot_filesystem": Value::Null,
      "collector": capability_entry(
        "runtime",
        true,
        true,
        "environment variables + df -k",
        None
      ),
    })
  }

  #[cfg(target_os = "windows")]
  {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    json!({
      "shell": std::env::var("COMSPEC").unwrap_or_default(),
      "desktop": std::env::var("SESSIONNAME").unwrap_or_default(),
      "session_type": "",
      "display_server": "",
      "container_env": std::env::var("container").unwrap_or_default(),
      "root_filesystem": json!({
        "source": drive.clone(),
        "mountpoint": format!("{}\\", drive),
        "fs_type": "",
        "options": "",
      }),
      "home_filesystem": Value::Null,
      "boot_filesystem": Value::Null,
      "collector": capability_entry(
        "runtime",
        true,
        true,
        "environment variables + SystemDrive",
        None
      ),
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "shell": std::env::var("SHELL").unwrap_or_default(),
      "desktop": "",
      "session_type": "",
      "display_server": "",
      "container_env": std::env::var("container").unwrap_or_default(),
      "root_filesystem": Value::Null,
      "home_filesystem": Value::Null,
      "boot_filesystem": Value::Null,
      "collector": capability_entry(
        "runtime",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      ),
    })
  }
}

fn collect_cpu_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut model = String::new();
    let mut vendor = String::new();
    let mut logical_cpus = 0u64;
    let mut mhz = None;
    let mut hypervisor = false;

    for line in cpuinfo.lines() {
      if line.starts_with("model name") && model.is_empty() {
        model = value_after_colon(line);
      } else if line.starts_with("vendor_id") && vendor.is_empty() {
        vendor = value_after_colon(line);
      } else if line.starts_with("processor") {
        logical_cpus += 1;
      } else if line.starts_with("cpu MHz") && mhz.is_none() {
        mhz = value_after_colon(line).parse::<f64>().ok();
      } else if line.starts_with("flags") && line.contains(" hypervisor ") {
        hypervisor = true;
      }
    }

    return json!({
      "model": fallback_string(model, "unknown"),
      "vendor": fallback_string(vendor, "unknown"),
      "logical_cpus": logical_cpus,
      "frequency_mhz": mhz,
      "hypervisor_flag": hypervisor,
      "collector": capability_entry("cpu", true, Path::new("/proc/cpuinfo").exists(), "/proc/cpuinfo", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let model = command_stdout("sysctl", &["-n", "machdep.cpu.brand_string"])
      .or_else(|| command_stdout("sysctl", &["-n", "hw.model"]))
      .unwrap_or_else(|| "unknown".to_string());
    let vendor = command_stdout("sysctl", &["-n", "machdep.cpu.vendor"])
      .unwrap_or_else(|| "unknown".to_string());
    let logical_cpus = command_stdout("sysctl", &["-n", "hw.logicalcpu"])
      .and_then(|value| value.parse::<u64>().ok())
      .unwrap_or_else(|| {
        std::thread::available_parallelism()
          .map(|value| value.get() as u64)
          .unwrap_or(0)
      });
    let frequency_mhz = command_stdout("sysctl", &["-n", "hw.cpufrequency"])
      .and_then(|value| value.parse::<f64>().ok())
      .map(|hz| hz / 1_000_000.0);
    let hypervisor_flag = command_stdout("sysctl", &["-n", "kern.hv_vmm_present"])
      .map(|value| parse_boolish(&value))
      .unwrap_or(false);

    json!({
      "model": model,
      "vendor": vendor,
      "logical_cpus": logical_cpus,
      "frequency_mhz": frequency_mhz,
      "hypervisor_flag": hypervisor_flag,
      "collector": capability_entry(
        "cpu",
        true,
        tool_exists("sysctl"),
        "sysctl machdep.cpu.*",
        (!tool_exists("sysctl")).then(|| "sysctl unavailable".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    let cpu_values = command_stdout(
      "wmic",
      &[
        "cpu",
        "get",
        "Name,Manufacturer,NumberOfLogicalProcessors,MaxClockSpeed",
        "/value",
      ],
    )
    .map(|value| parse_key_value_lines(&value))
    .unwrap_or_default();
    let hypervisor_values = command_stdout(
      "wmic",
      &["computersystem", "get", "HypervisorPresent", "/value"],
    )
    .map(|value| parse_key_value_lines(&value))
    .unwrap_or_default();

    let logical_cpus = cpu_values
      .get("NumberOfLogicalProcessors")
      .and_then(|value| value.parse::<u64>().ok())
      .unwrap_or_else(|| {
        std::thread::available_parallelism()
          .map(|value| value.get() as u64)
          .unwrap_or(0)
      });
    let frequency_mhz = cpu_values
      .get("MaxClockSpeed")
      .and_then(|value| value.parse::<f64>().ok());
    let hypervisor_flag = hypervisor_values
      .get("HypervisorPresent")
      .map(|value| parse_boolish(value))
      .unwrap_or(false);

    json!({
      "model": cpu_values.get("Name").cloned().unwrap_or_else(|| "unknown".to_string()),
      "vendor": cpu_values.get("Manufacturer").cloned().unwrap_or_else(|| "unknown".to_string()),
      "logical_cpus": logical_cpus,
      "frequency_mhz": frequency_mhz,
      "hypervisor_flag": hypervisor_flag,
      "collector": capability_entry(
        "cpu",
        true,
        !cpu_values.is_empty(),
        "wmic cpu",
        cpu_values.is_empty().then(|| "wmic unavailable or returned empty output".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "model": "unknown",
      "vendor": "unknown",
      "logical_cpus": std::thread::available_parallelism()
        .map(|value| value.get() as u64)
        .unwrap_or(0),
      "frequency_mhz": Value::Null,
      "hypervisor_flag": false,
      "collector": capability_entry(
        "cpu",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_memory_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let meminfo = parse_meminfo("/proc/meminfo");
    let total_kib = meminfo.get("MemTotal").copied().unwrap_or(0);
    let available_kib = meminfo.get("MemAvailable").copied().unwrap_or(0);
    let swap_total_kib = meminfo.get("SwapTotal").copied().unwrap_or(0);

    return json!({
      "total_kib": total_kib,
      "total_gib": kib_to_gib(total_kib),
      "available_kib": available_kib,
      "available_gib": kib_to_gib(available_kib),
      "swap_total_kib": swap_total_kib,
      "swap_total_gib": kib_to_gib(swap_total_kib),
      "collector": capability_entry("memory", true, Path::new("/proc/meminfo").exists(), "/proc/meminfo", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let total_bytes = command_stdout("sysctl", &["-n", "hw.memsize"])
      .and_then(|value| value.parse::<u64>().ok())
      .unwrap_or(0);
    let total_kib = total_bytes / 1024;
    let swap_total_kib = command_stdout("sysctl", &["-n", "vm.swapusage"])
      .and_then(|value| {
        value
          .split("total =")
          .nth(1)
          .and_then(|segment| segment.split_whitespace().next())
          .and_then(parse_f64_relaxed)
          .map(|number| (number * 1024.0 * 1024.0) as u64 / 1024)
      })
      .unwrap_or(0);

    json!({
      "total_kib": total_kib,
      "total_gib": kib_to_gib(total_kib),
      "available_kib": 0,
      "available_gib": 0.0,
      "swap_total_kib": swap_total_kib,
      "swap_total_gib": kib_to_gib(swap_total_kib),
      "collector": capability_entry(
        "memory",
        true,
        tool_exists("sysctl"),
        "sysctl hw.memsize + vm.swapusage",
        (!tool_exists("sysctl")).then(|| "sysctl unavailable".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    let system_values = command_stdout(
      "wmic",
      &["computersystem", "get", "TotalPhysicalMemory", "/value"],
    )
    .map(|value| parse_key_value_lines(&value))
    .unwrap_or_default();
    let os_values = command_stdout("wmic", &["os", "get", "FreePhysicalMemory", "/value"])
      .map(|value| parse_key_value_lines(&value))
      .unwrap_or_default();
    let pagefile_values =
      command_stdout("wmic", &["pagefile", "get", "AllocatedBaseSize", "/value"])
        .map(|value| parse_key_value_lines(&value))
        .unwrap_or_default();

    let total_kib = system_values
      .get("TotalPhysicalMemory")
      .and_then(|value| parse_u64_relaxed(value))
      .map(|bytes| bytes / 1024)
      .unwrap_or(0);
    let available_kib = os_values
      .get("FreePhysicalMemory")
      .and_then(|value| parse_u64_relaxed(value))
      .unwrap_or(0);
    let swap_total_kib = pagefile_values
      .get("AllocatedBaseSize")
      .and_then(|value| parse_u64_relaxed(value))
      .map(|mb| mb.saturating_mul(1024))
      .unwrap_or(0);

    json!({
      "total_kib": total_kib,
      "total_gib": kib_to_gib(total_kib),
      "available_kib": available_kib,
      "available_gib": kib_to_gib(available_kib),
      "swap_total_kib": swap_total_kib,
      "swap_total_gib": kib_to_gib(swap_total_kib),
      "collector": capability_entry(
        "memory",
        true,
        !system_values.is_empty(),
        "wmic computersystem + wmic os",
        system_values.is_empty().then(|| "wmic unavailable or returned empty output".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "total_kib": 0,
      "total_gib": 0.0,
      "available_kib": 0,
      "available_gib": 0.0,
      "swap_total_kib": 0,
      "swap_total_gib": 0.0,
      "collector": capability_entry(
        "memory",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_storage_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mountpoints = parse_mounts("/proc/mounts");
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else {
      return json!({ "devices": devices });
    };

    for entry in entries.flatten() {
      let name = entry.file_name().to_string_lossy().to_string();
      if should_skip_block_device(&name) {
        continue;
      }

      let path = entry.path();
      let size_sectors = read_trimmed(path.join("size"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
      let partitions = collect_block_partitions(&path, &name, &mountpoints);
      devices.push(json!({
        "name": name,
        "model": read_trimmed(path.join("device/model")).unwrap_or_default(),
        "vendor": read_trimmed(path.join("device/vendor")).unwrap_or_default(),
        "serial": read_trimmed(path.join("device/serial")).unwrap_or_default(),
        "transport": block_transport(&name),
        "size_bytes": size_sectors.saturating_mul(512),
        "size_gib": bytes_to_gib(size_sectors.saturating_mul(512)),
        "rotational": read_trimmed(path.join("queue/rotational")).map(|value| value == "1").unwrap_or(false),
        "removable": read_trimmed(path.join("removable")).map(|value| value == "1").unwrap_or(false),
        "partitions": partitions,
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "devices": devices,
      "collector": capability_entry("storage", true, Path::new("/sys/block").exists(), "/sys/block", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let mut devices = Vec::new();
    let mut roots: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();

    if let Some(df_output) = command_stdout("df", &["-k"]) {
      for line in df_output.lines().skip(1) {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 6 {
          continue;
        }
        let source = parts[0].to_string();
        let size_kib = parts[1].parse::<u64>().unwrap_or(0);
        let mountpoint = parts[parts.len() - 1].to_string();

        let entry = roots
          .entry(source)
          .or_insert_with(|| (size_kib.saturating_mul(1024), Vec::new()));
        entry.0 = entry.0.max(size_kib.saturating_mul(1024));
        if !entry.1.contains(&mountpoint) {
          entry.1.push(mountpoint);
        }
      }
    }

    for (name, (size_bytes, mountpoints)) in roots {
      let partition_items = mountpoints
        .iter()
        .map(|mountpoint| {
          json!({
            "name": mountpoint.clone(),
            "size_bytes": size_bytes,
            "size_gib": bytes_to_gib(size_bytes),
            "mountpoints": [mountpoint.clone()],
          })
        })
        .collect::<Vec<_>>();

      devices.push(json!({
        "name": name,
        "model": "",
        "vendor": "Apple",
        "serial": "",
        "transport": "unknown",
        "size_bytes": size_bytes,
        "size_gib": bytes_to_gib(size_bytes),
        "rotational": false,
        "removable": false,
        "partitions": partition_items,
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    json!({
      "devices": devices,
      "collector": capability_entry(
        "storage",
        true,
        tool_exists("df"),
        "df -k",
        (!tool_exists("df")).then(|| "df unavailable".to_string())
      ),
    })
  }

  #[cfg(target_os = "windows")]
  {
    let mut devices = Vec::new();
    let records = command_stdout(
      "wmic",
      &[
        "logicaldisk",
        "get",
        "DeviceID,FileSystem,Size,VolumeName",
        "/format:list",
      ],
    )
    .map(|value| parse_key_value_records(&value))
    .unwrap_or_default();

    for record in records {
      let Some(name) = record
        .get("DeviceID")
        .cloned()
        .filter(|value| !value.is_empty())
      else {
        continue;
      };
      let size_bytes = record
        .get("Size")
        .and_then(|value| parse_u64_relaxed(value))
        .unwrap_or(0);
      let mountpoint = format!("{}\\", name);

      devices.push(json!({
        "name": name.clone(),
        "model": record.get("VolumeName").cloned().unwrap_or_default(),
        "vendor": "",
        "serial": "",
        "transport": "logical-disk",
        "size_bytes": size_bytes,
        "size_gib": bytes_to_gib(size_bytes),
        "rotational": false,
        "removable": false,
        "partitions": [
          json!({
            "name": name.clone(),
            "size_bytes": size_bytes,
            "size_gib": bytes_to_gib(size_bytes),
            "mountpoints": [mountpoint]
          })
        ],
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    let collector_available = !devices.is_empty() || tool_exists("wmic");
    json!({
      "devices": devices,
      "collector": capability_entry(
        "storage",
        true,
        collector_available,
        "wmic logicaldisk",
        (!tool_exists("wmic")).then(|| "wmic unavailable".to_string())
      ),
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "storage",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      ),
    })
  }
}

fn collect_network_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut interfaces = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
      return json!({ "interfaces": interfaces });
    };

    for entry in entries.flatten() {
      let name = entry.file_name().to_string_lossy().to_string();
      let path = entry.path();
      interfaces.push(json!({
        "name": name,
        "mac": read_trimmed(path.join("address")).unwrap_or_default(),
        "operstate": read_trimmed(path.join("operstate")).unwrap_or_else(|| "unknown".to_string()),
        "mtu": read_trimmed(path.join("mtu")).and_then(|value| value.parse::<u64>().ok()),
        "type": classify_network_interface(&path),
      }));
    }

    interfaces.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "interfaces": interfaces,
      "collector": capability_entry("network", true, Path::new("/sys/class/net").exists(), "/sys/class/net", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_mac = String::new();
    let mut current_mtu: Option<u64> = None;

    if let Some(output) = command_stdout("ifconfig", &["-a"]) {
      for line in output.lines() {
        let trimmed = line.trim();
        let starts_interface =
          !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':');

        if starts_interface {
          if !current_name.is_empty() {
            interfaces.push(json!({
              "name": current_name.clone(),
              "mac": current_mac.clone(),
              "operstate": "unknown",
              "mtu": current_mtu,
              "type": interface_type_from_name(&current_name),
            }));
          }

          current_name = line
            .split(':')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
          current_mac = String::new();
          current_mtu = None;

          let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
          for pair in tokens.windows(2) {
            if pair[0] == "mtu" {
              current_mtu = pair[1].parse::<u64>().ok();
            }
          }
          continue;
        }

        if trimmed.starts_with("ether ") {
          current_mac = trimmed.trim_start_matches("ether ").trim().to_string();
        }
      }
    }

    if !current_name.is_empty() {
      interfaces.push(json!({
        "name": current_name.clone(),
        "mac": current_mac.clone(),
        "operstate": "unknown",
        "mtu": current_mtu,
        "type": interface_type_from_name(&current_name),
      }));
    }

    interfaces.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    json!({
      "interfaces": interfaces,
      "collector": capability_entry(
        "network",
        true,
        tool_exists("ifconfig"),
        "ifconfig -a",
        (!tool_exists("ifconfig")).then(|| "ifconfig unavailable".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_mac = String::new();
    let mut current_state = "unknown".to_string();

    if let Some(output) = command_stdout("ipconfig", &["/all"]) {
      for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
          continue;
        }

        if trimmed.contains(" adapter ") && trimmed.ends_with(':') {
          if !current_name.is_empty() {
            interfaces.push(json!({
              "name": current_name.clone(),
              "mac": current_mac.clone(),
              "operstate": current_state.clone(),
              "mtu": Value::Null,
              "type": interface_type_from_name(&current_name),
            }));
          }
          current_name = trimmed
            .split(" adapter ")
            .nth(1)
            .unwrap_or(trimmed)
            .trim_end_matches(':')
            .trim()
            .to_string();
          current_mac = String::new();
          current_state = "unknown".to_string();
          continue;
        }

        if let Some((key, value)) = trimmed.split_once(':') {
          let key_lower = key.to_ascii_lowercase();
          let value = value.trim().to_string();
          if key_lower.contains("physical address") {
            current_mac = value.replace('-', ":");
          } else if key_lower.contains("media state") {
            current_state = if value.to_ascii_lowercase().contains("disconnected") {
              "down".to_string()
            } else {
              "up".to_string()
            };
          }
        }
      }
    }

    if !current_name.is_empty() {
      interfaces.push(json!({
        "name": current_name.clone(),
        "mac": current_mac.clone(),
        "operstate": current_state.clone(),
        "mtu": Value::Null,
        "type": interface_type_from_name(&current_name),
      }));
    }

    interfaces.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    json!({
      "interfaces": interfaces,
      "collector": capability_entry(
        "network",
        true,
        tool_exists("ipconfig"),
        "ipconfig /all",
        (!tool_exists("ipconfig")).then(|| "ipconfig unavailable".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "interfaces": [],
      "collector": capability_entry(
        "network",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_display_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut connectors = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/drm") else {
      return json!({ "connectors": connectors });
    };

    for entry in entries.flatten() {
      let name = entry.file_name().to_string_lossy().to_string();
      if !name.contains('-') {
        continue;
      }

      let path = entry.path();
      let status_path = path.join("status");
      if !status_path.exists() {
        continue;
      }

      let modes = read_lines(path.join("modes"));
      connectors.push(json!({
        "name": name,
        "connector_type": connector_type(&path),
        "status": read_trimmed(status_path).unwrap_or_else(|| "unknown".to_string()),
        "enabled": path.join("enabled").exists().then(|| read_trimmed(path.join("enabled")).unwrap_or_default()),
        "modes": modes,
      }));
    }

    connectors.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "connectors": connectors,
      "collector": capability_entry("display", true, Path::new("/sys/class/drm").exists(), "/sys/class/drm", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let mut connectors = Vec::new();
    let raw = command_stdout("system_profiler", &["SPDisplaysDataType"]).unwrap_or_default();

    let mut index = 0usize;
    for line in raw.lines() {
      let trimmed = line.trim();
      if let Some((key, value)) = trimmed.split_once(':') {
        if key.trim().eq_ignore_ascii_case("Resolution") {
          index += 1;
          connectors.push(json!({
            "name": format!("display{}", index),
            "connector_type": "display",
            "status": "connected",
            "enabled": "enabled",
            "modes": [value.trim().to_string()],
          }));
        }
      }
    }

    if connectors.is_empty() && !raw.is_empty() {
      connectors.push(json!({
        "name": "display0",
        "connector_type": "display",
        "status": "connected",
        "enabled": "enabled",
        "modes": [],
      }));
    }

    connectors.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    json!({
      "connectors": connectors,
      "collector": capability_entry(
        "display",
        true,
        !raw.is_empty(),
        "system_profiler SPDisplaysDataType",
        raw.is_empty().then(|| "system_profiler unavailable or returned empty output".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    let mut connectors = Vec::new();
    let records = command_stdout(
      "wmic",
      &[
        "path",
        "win32_videocontroller",
        "get",
        "Name,CurrentHorizontalResolution,CurrentVerticalResolution",
        "/format:list",
      ],
    )
    .map(|value| parse_key_value_records(&value))
    .unwrap_or_default();

    for (index, record) in records.iter().enumerate() {
      let name = record
        .get("Name")
        .cloned()
        .unwrap_or_else(|| format!("display{}", index));
      let width = record
        .get("CurrentHorizontalResolution")
        .and_then(|value| parse_u64_relaxed(value));
      let height = record
        .get("CurrentVerticalResolution")
        .and_then(|value| parse_u64_relaxed(value));
      let mode = match (width, height) {
        (Some(w), Some(h)) => format!("{}x{}", w, h),
        _ => String::new(),
      };

      connectors.push(json!({
        "name": name,
        "connector_type": "display",
        "status": "connected",
        "enabled": "enabled",
        "modes": if mode.is_empty() { Vec::<String>::new() } else { vec![mode] },
      }));
    }

    connectors.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    json!({
      "connectors": connectors,
      "collector": capability_entry(
        "display",
        true,
        !records.is_empty() || tool_exists("wmic"),
        "wmic win32_videocontroller",
        (!tool_exists("wmic")).then(|| "wmic unavailable".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "connectors": [],
      "collector": capability_entry(
        "display",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_sensor_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut thermal_zones = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/thermal") else {
      return json!({ "thermal_zones": thermal_zones });
    };

    for entry in entries.flatten() {
      let name = entry.file_name().to_string_lossy().to_string();
      if !name.starts_with("thermal_zone") {
        continue;
      }

      let path = entry.path();
      thermal_zones.push(json!({
        "name": name,
        "type": read_trimmed(path.join("type")).unwrap_or_else(|| "unknown".to_string()),
        "temp_millic": read_trimmed(path.join("temp")).and_then(|value| value.parse::<i64>().ok()),
        "temp_c": read_trimmed(path.join("temp"))
          .and_then(|value| value.parse::<f64>().ok())
          .map(|value| value / 1000.0),
      }));
    }

    thermal_zones.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "thermal_zones": thermal_zones,
      "collector": capability_entry("sensors", true, Path::new("/sys/class/thermal").exists(), "/sys/class/thermal", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    json!({
      "thermal_zones": [],
      "collector": capability_entry(
        "sensors",
        false,
        false,
        "powermetrics/SMC",
        Some("collector baseline not implemented on macOS yet".to_string())
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    json!({
      "thermal_zones": [],
      "collector": capability_entry(
        "sensors",
        false,
        false,
        "WMI MSAcpi_ThermalZoneTemperature",
        Some("collector baseline not implemented on Windows yet".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "thermal_zones": [],
      "collector": capability_entry(
        "sensors",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_battery_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut batteries = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/power_supply") else {
      return json!({ "batteries": batteries });
    };

    for entry in entries.flatten() {
      let name = entry.file_name().to_string_lossy().to_string();
      if !name.starts_with("BAT") {
        continue;
      }

      let path = entry.path();
      batteries.push(json!({
        "name": name,
        "status": read_trimmed(path.join("status")).unwrap_or_else(|| "unknown".to_string()),
        "capacity_percent": read_trimmed(path.join("capacity")).and_then(|value| value.parse::<u64>().ok()),
        "manufacturer": read_trimmed(path.join("manufacturer")).unwrap_or_default(),
        "model_name": read_trimmed(path.join("model_name")).unwrap_or_default(),
        "serial_number": read_trimmed(path.join("serial_number")).unwrap_or_default(),
      }));
    }

    batteries.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "batteries": batteries,
      "collector": capability_entry("battery", true, Path::new("/sys/class/power_supply").exists(), "/sys/class/power_supply", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let mut batteries = Vec::new();
    let raw = command_stdout("pmset", &["-g", "batt"]).unwrap_or_default();

    for line in raw.lines() {
      let trimmed = line.trim();
      if !trimmed.contains('%') {
        continue;
      }

      let capacity = trimmed
        .split('%')
        .next()
        .and_then(|value| value.split_whitespace().last())
        .and_then(|value| parse_u64_relaxed(value));
      let status = if trimmed.to_ascii_lowercase().contains("discharging") {
        "Discharging".to_string()
      } else if trimmed.to_ascii_lowercase().contains("charging") {
        "Charging".to_string()
      } else if trimmed.to_ascii_lowercase().contains("charged") {
        "Charged".to_string()
      } else {
        "unknown".to_string()
      };

      batteries.push(json!({
        "name": "InternalBattery",
        "status": status,
        "capacity_percent": capacity,
        "manufacturer": "Apple",
        "model_name": "",
        "serial_number": "",
      }));
    }

    json!({
      "batteries": batteries,
      "collector": capability_entry(
        "battery",
        true,
        !raw.is_empty(),
        "pmset -g batt",
        raw.is_empty().then(|| "pmset unavailable or returned empty output".to_string())
      ),
    })
  }

  #[cfg(target_os = "windows")]
  {
    let mut batteries = Vec::new();
    let records = command_stdout(
      "wmic",
      &[
        "path",
        "Win32_Battery",
        "get",
        "Name,BatteryStatus,EstimatedChargeRemaining",
        "/format:list",
      ],
    )
    .map(|value| parse_key_value_records(&value))
    .unwrap_or_default();

    for record in records {
      let status = match record
        .get("BatteryStatus")
        .and_then(|value| parse_u64_relaxed(value))
      {
        Some(2) => "Charging",
        Some(3) => "Discharging",
        Some(6) => "Charging",
        Some(7) => "Charging",
        Some(8) => "Charging",
        Some(9) => "Charging",
        Some(11) => "Partially Charged",
        _ => "unknown",
      }
      .to_string();

      batteries.push(json!({
        "name": record.get("Name").cloned().unwrap_or_else(|| "Battery".to_string()),
        "status": status,
        "capacity_percent": record
          .get("EstimatedChargeRemaining")
          .and_then(|value| parse_u64_relaxed(value)),
        "manufacturer": "",
        "model_name": "",
        "serial_number": "",
      }));
    }

    let collector_available = !batteries.is_empty() || tool_exists("wmic");
    json!({
      "batteries": batteries,
      "collector": capability_entry(
        "battery",
        true,
        collector_available,
        "wmic Win32_Battery",
        (!tool_exists("wmic")).then(|| "wmic unavailable".to_string())
      ),
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "batteries": [],
      "collector": capability_entry(
        "battery",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_pci_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else {
      return json!({ "devices": devices });
    };

    for entry in entries.flatten() {
      let path = entry.path();
      let class_id = read_trimmed(path.join("class")).unwrap_or_default();
      if !interesting_pci_class(&class_id) {
        continue;
      }

      devices.push(json!({
        "slot": entry.file_name().to_string_lossy().to_string(),
        "class_id": class_id,
        "class_name": pci_class_name(&class_id),
        "vendor_id": read_trimmed(path.join("vendor")).unwrap_or_default(),
        "device_id": read_trimmed(path.join("device")).unwrap_or_default(),
        "driver": symlink_name(path.join("driver")).unwrap_or_default(),
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "devices": devices,
      "collector": capability_entry("pci", true, Path::new("/sys/bus/pci/devices").exists(), "/sys/bus/pci/devices", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let raw = command_stdout("system_profiler", &["SPPCIDataType"]).unwrap_or_default();
    json!({
      "devices": [],
      "collector": capability_entry(
        "pci",
        false,
        false,
        "system_profiler SPPCIDataType",
        Some(if raw.is_empty() {
          "collector baseline not implemented on macOS yet".to_string()
        } else {
          "collector parser pending for macOS".to_string()
        })
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "pci",
        false,
        false,
        "wmic Win32_PnPEntity",
        Some("collector baseline not implemented on Windows yet".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "pci",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_usb_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") else {
      return json!({ "devices": devices });
    };

    for entry in entries.flatten() {
      let path = entry.path();
      let Some(vendor_id) = read_trimmed(path.join("idVendor")) else {
        continue;
      };
      let Some(product_id) = read_trimmed(path.join("idProduct")) else {
        continue;
      };

      devices.push(json!({
        "bus": entry.file_name().to_string_lossy().to_string(),
        "vendor_id": vendor_id,
        "product_id": product_id,
        "vendor": read_trimmed(path.join("manufacturer")).unwrap_or_default(),
        "product": read_trimmed(path.join("product")).unwrap_or_default(),
        "serial": read_trimmed(path.join("serial")).unwrap_or_default(),
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "devices": devices,
      "collector": capability_entry("usb", true, Path::new("/sys/bus/usb/devices").exists(), "/sys/bus/usb/devices", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let raw = command_stdout("system_profiler", &["SPUSBDataType"]).unwrap_or_default();
    json!({
      "devices": [],
      "collector": capability_entry(
        "usb",
        false,
        false,
        "system_profiler SPUSBDataType",
        Some(if raw.is_empty() {
          "collector baseline not implemented on macOS yet".to_string()
        } else {
          "collector parser pending for macOS".to_string()
        })
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "usb",
        false,
        false,
        "wmic Win32_USBController",
        Some("collector baseline not implemented on Windows yet".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "usb",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_camera_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/video4linux") else {
      return json!({ "devices": devices });
    };

    for entry in entries.flatten() {
      let node = entry.file_name().to_string_lossy().to_string();
      let path = entry.path();
      devices.push(json!({
        "node": node.clone(),
        "dev_path": format!("/dev/{}", node),
        "name": read_trimmed(path.join("name")).unwrap_or_default(),
        "index": read_trimmed(path.join("index")).and_then(|value| value.parse::<i64>().ok()),
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "devices": devices,
      "collector": capability_entry("camera", true, Path::new("/sys/class/video4linux").exists(), "/sys/class/video4linux", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let raw = command_stdout("system_profiler", &["SPCameraDataType"]).unwrap_or_default();
    json!({
      "devices": [],
      "collector": capability_entry(
        "camera",
        false,
        false,
        "system_profiler SPCameraDataType",
        Some(if raw.is_empty() {
          "collector baseline not implemented on macOS yet".to_string()
        } else {
          "collector parser pending for macOS".to_string()
        })
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "camera",
        false,
        false,
        "wmic Win32_PnPEntity (Camera class)",
        Some("collector baseline not implemented on Windows yet".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "camera",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_thunderbolt_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut devices = Vec::new();
    let root = Path::new("/sys/bus/thunderbolt/devices");
    let Ok(entries) = fs::read_dir(root) else {
      return json!({ "devices": devices });
    };

    for entry in entries.flatten() {
      let domain = entry.file_name().to_string_lossy().to_string();
      let path = entry.path();
      if !path.join("device_name").exists() && !path.join("vendor_name").exists() {
        continue;
      }

      devices.push(json!({
        "domain": domain,
        "authorized": read_trimmed(path.join("authorized")).map(|value| value == "1"),
        "device_name": read_trimmed(path.join("device_name")).unwrap_or_default(),
        "vendor_name": read_trimmed(path.join("vendor_name")).unwrap_or_default(),
        "unique_id": read_trimmed(path.join("unique_id")).unwrap_or_default(),
        "rx_speed": read_trimmed(path.join("rx_speed")).unwrap_or_default(),
        "tx_speed": read_trimmed(path.join("tx_speed")).unwrap_or_default(),
      }));
    }

    devices.sort_by(|a, b| value_name(a).cmp(&value_name(b)));
    return json!({
      "devices": devices,
      "collector": capability_entry("thunderbolt", true, Path::new("/sys/bus/thunderbolt/devices").exists(), "/sys/bus/thunderbolt/devices", None),
    });
  }

  #[cfg(target_os = "macos")]
  {
    let raw = command_stdout("system_profiler", &["SPThunderboltDataType"]).unwrap_or_default();
    json!({
      "devices": [],
      "collector": capability_entry(
        "thunderbolt",
        false,
        false,
        "system_profiler SPThunderboltDataType",
        Some(if raw.is_empty() {
          "collector baseline not implemented on macOS yet".to_string()
        } else {
          "collector parser pending for macOS".to_string()
        })
      )
    })
  }

  #[cfg(target_os = "windows")]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "thunderbolt",
        false,
        false,
        "WMI / PnP controller inventory",
        Some("collector baseline not implemented on Windows yet".to_string())
      )
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    json!({
      "devices": [],
      "collector": capability_entry(
        "thunderbolt",
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", std::env::consts::OS))
      )
    })
  }
}

fn collect_environment_assessment() -> Value {
  let container = detect_container_environment();
  let virtualization = detect_virtual_machine_environment();
  let sandbox_state = detect_sandbox_environment();
  let container_detected = container
    .get("detected")
    .and_then(Value::as_bool)
    .unwrap_or(false);
  let virtualization_detected = virtualization
    .get("detected")
    .and_then(Value::as_bool)
    .unwrap_or(false);
  let sandbox_detected = sandbox_state
    .get("detected")
    .and_then(Value::as_bool)
    .unwrap_or(false);
  let container_score = detector_score(&container);
  let virtualization_score = detector_score(&virtualization);
  let sandbox_score = detector_score(&sandbox_state);
  let aggregate_score = container_score
    .saturating_add(virtualization_score)
    .saturating_add(sandbox_score);
  let dominant_signal =
    dominant_environment_signal(container_score, virtualization_score, sandbox_score);
  let topology = environment_topology(
    container_detected,
    virtualization_detected,
    sandbox_detected,
  );

  let mut traits = Vec::new();
  let mut reasons = Vec::new();
  let mut confidence = "low".to_string();
  let kind = if container_detected {
    traits.push("container".to_string());
    reasons.extend(json_array_strings(container.get("reasons")));
    confidence = confidence_max(
      &confidence,
      container
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or("medium"),
    );
    if virtualization_detected {
      traits.push("vm".to_string());
      reasons.extend(json_array_strings(virtualization.get("reasons")));
      confidence = confidence_max(
        &confidence,
        virtualization
          .get("confidence")
          .and_then(Value::as_str)
          .unwrap_or("medium"),
      );
    }
    if sandbox_detected {
      traits.push("sandbox".to_string());
      reasons.extend(json_array_strings(sandbox_state.get("reasons")));
      confidence = confidence_max(
        &confidence,
        sandbox_state
          .get("confidence")
          .and_then(Value::as_str)
          .unwrap_or("low"),
      );
    }
    "container"
  } else if sandbox_detected {
    traits.push("sandbox".to_string());
    reasons.extend(json_array_strings(sandbox_state.get("reasons")));
    confidence = confidence_max(
      &confidence,
      sandbox_state
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or("medium"),
    );
    if virtualization_detected {
      traits.push("vm".to_string());
      reasons.extend(json_array_strings(virtualization.get("reasons")));
      confidence = confidence_max(
        &confidence,
        virtualization
          .get("confidence")
          .and_then(Value::as_str)
          .unwrap_or("medium"),
      );
    }
    "sandbox"
  } else if virtualization_detected {
    traits.push("vm".to_string());
    reasons.extend(json_array_strings(virtualization.get("reasons")));
    confidence = confidence_max(
      &confidence,
      virtualization
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or("medium"),
    );
    "vm"
  } else {
    reasons.push("no strong container, VM, or sandbox signals were found".to_string());
    confidence = "medium".to_string();
    "host"
  };

  json!({
    "kind": kind,
    "topology": topology,
    "traits": traits,
    "confidence": confidence,
    "reasons": reasons,
    "signals": json!({
      "aggregate_score": aggregate_score,
      "dominant": dominant_signal,
      "container": json!({
        "detected": container_detected,
        "score": container_score,
        "confidence": container
          .get("confidence")
          .and_then(Value::as_str)
          .unwrap_or("low"),
      }),
      "virtualization": json!({
        "detected": virtualization_detected,
        "score": virtualization_score,
        "confidence": virtualization
          .get("confidence")
          .and_then(Value::as_str)
          .unwrap_or("low"),
      }),
      "sandbox": json!({
        "detected": sandbox_detected,
        "score": sandbox_score,
        "confidence": sandbox_state
          .get("confidence")
          .and_then(Value::as_str)
          .unwrap_or("low"),
      })
    }),
    "container": container,
    "virtualization": virtualization,
    "sandbox": sandbox_state,
  })
}

fn collect_capabilities_section() -> Value {
  #[cfg(target_os = "linux")]
  {
    let mut collectors = vec![
      capability_entry(
        "system",
        true,
        Path::new("/proc").exists() && Path::new("/etc/os-release").exists(),
        "/proc + /etc/os-release",
        Some("host and OS identity from procfs/os-release".to_string()),
      ),
      capability_entry(
        "runtime",
        true,
        true,
        "environment variables + /proc/self/mountinfo",
        Some("runtime session and root filesystem inference".to_string()),
      ),
      capability_entry(
        "cpu",
        true,
        Path::new("/proc/cpuinfo").exists(),
        "/proc/cpuinfo",
        Some("CPU model, cores and frequency hints".to_string()),
      ),
      capability_entry(
        "memory",
        true,
        Path::new("/proc/meminfo").exists(),
        "/proc/meminfo",
        Some("RAM and swap totals".to_string()),
      ),
      capability_entry(
        "storage",
        true,
        Path::new("/sys/block").exists(),
        "/sys/block",
        Some("block devices and mount mapping".to_string()),
      ),
      capability_entry(
        "network",
        true,
        Path::new("/sys/class/net").exists(),
        "/sys/class/net",
        Some("interface inventory".to_string()),
      ),
      capability_entry(
        "display",
        true,
        Path::new("/sys/class/drm").exists(),
        "/sys/class/drm",
        Some("display connector and mode inventory".to_string()),
      ),
      capability_entry(
        "sensors",
        true,
        Path::new("/sys/class/thermal").exists(),
        "/sys/class/thermal",
        Some("thermal zones and temperature readings".to_string()),
      ),
      capability_entry(
        "battery",
        true,
        Path::new("/sys/class/power_supply").exists(),
        "/sys/class/power_supply",
        Some("battery status and capacity".to_string()),
      ),
      capability_entry(
        "pci",
        true,
        Path::new("/sys/bus/pci/devices").exists(),
        "/sys/bus/pci/devices",
        Some("interesting PCI device classes".to_string()),
      ),
      capability_entry(
        "usb",
        true,
        Path::new("/sys/bus/usb/devices").exists(),
        "/sys/bus/usb/devices",
        Some("USB bus and device inventory".to_string()),
      ),
      capability_entry(
        "camera",
        true,
        Path::new("/sys/class/video4linux").exists(),
        "/sys/class/video4linux",
        Some("video4linux camera inventory".to_string()),
      ),
      capability_entry(
        "thunderbolt",
        true,
        Path::new("/sys/bus/thunderbolt/devices").exists(),
        "/sys/bus/thunderbolt/devices",
        Some("thunderbolt controller/device inventory".to_string()),
      ),
    ];

    for collector in &mut collectors {
      let available = collector
        .get("available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
      if !available {
        let source = collector
          .get("source")
          .and_then(Value::as_str)
          .unwrap_or("collector source");
        *collector = json!({
          "name": collector.get("name").and_then(Value::as_str).unwrap_or("unknown"),
          "implemented": collector.get("implemented").and_then(Value::as_bool).unwrap_or(false),
          "available": false,
          "source": source,
          "reason": format!("source path unavailable: {}", source)
        });
      }
    }

    let available_collectors = collectors
      .iter()
      .filter(|collector| {
        collector
          .get("available")
          .and_then(Value::as_bool)
          .unwrap_or(false)
      })
      .count();
    let unavailable_collectors = collectors.len().saturating_sub(available_collectors);

    return json!({
      "platform": std::env::consts::OS,
      "available_collectors": available_collectors,
      "unavailable_collectors": unavailable_collectors,
      "collectors": collectors
    });
  }

  #[cfg(target_os = "macos")]
  {
    let sw_vers = tool_exists("sw_vers");
    let sysctl = tool_exists("sysctl");
    let ifconfig = tool_exists("ifconfig");
    let df = tool_exists("df");
    let profiler = tool_exists("system_profiler");
    let pmset = tool_exists("pmset");

    let collectors = vec![
      capability_entry(
        "system",
        true,
        sw_vers && sysctl,
        "sw_vers + sysctl",
        Some(if sw_vers && sysctl {
          "macOS host and OS identity via sw_vers/sysctl".to_string()
        } else {
          "required command(s) missing: sw_vers/sysctl".to_string()
        }),
      ),
      capability_entry(
        "runtime",
        true,
        true,
        "environment variables + df -k",
        Some("session and filesystem baseline from environment/df".to_string()),
      ),
      capability_entry(
        "cpu",
        true,
        sysctl,
        "sysctl machdep.cpu.*",
        Some(if sysctl {
          "CPU baseline from sysctl".to_string()
        } else {
          "required command missing: sysctl".to_string()
        }),
      ),
      capability_entry(
        "memory",
        true,
        sysctl,
        "sysctl hw.memsize",
        Some(if sysctl {
          "RAM baseline from sysctl".to_string()
        } else {
          "required command missing: sysctl".to_string()
        }),
      ),
      capability_entry(
        "storage",
        true,
        df,
        "df -k",
        Some(if df {
          "filesystem-backed storage baseline from df".to_string()
        } else {
          "required command missing: df".to_string()
        }),
      ),
      capability_entry(
        "network",
        true,
        ifconfig,
        "ifconfig -a",
        Some(if ifconfig {
          "interface baseline from ifconfig".to_string()
        } else {
          "required command missing: ifconfig".to_string()
        }),
      ),
      capability_entry(
        "display",
        true,
        profiler,
        "system_profiler SPDisplaysDataType",
        Some(if profiler {
          "display baseline from system_profiler".to_string()
        } else {
          "required command missing: system_profiler".to_string()
        }),
      ),
      capability_entry(
        "sensors",
        false,
        false,
        "powermetrics/SMC",
        Some("collector baseline not implemented on macOS yet".to_string()),
      ),
      capability_entry(
        "battery",
        true,
        pmset,
        "pmset -g batt",
        Some(if pmset {
          "battery baseline from pmset".to_string()
        } else {
          "required command missing: pmset".to_string()
        }),
      ),
      capability_entry(
        "pci",
        false,
        false,
        "system_profiler SPPCIDataType",
        Some("collector parser pending for macOS".to_string()),
      ),
      capability_entry(
        "usb",
        false,
        false,
        "system_profiler SPUSBDataType",
        Some("collector parser pending for macOS".to_string()),
      ),
      capability_entry(
        "camera",
        false,
        false,
        "system_profiler SPCameraDataType",
        Some("collector parser pending for macOS".to_string()),
      ),
      capability_entry(
        "thunderbolt",
        false,
        false,
        "system_profiler SPThunderboltDataType",
        Some("collector parser pending for macOS".to_string()),
      ),
    ];

    let available_collectors = collectors
      .iter()
      .filter(|collector| {
        collector
          .get("available")
          .and_then(Value::as_bool)
          .unwrap_or(false)
      })
      .count();
    let unavailable_collectors = collectors.len().saturating_sub(available_collectors);

    json!({
      "platform": "macos",
      "available_collectors": available_collectors,
      "unavailable_collectors": unavailable_collectors,
      "collectors": collectors
    })
  }

  #[cfg(target_os = "windows")]
  {
    let cmd = tool_exists("cmd");
    let wmic = tool_exists("wmic");
    let ipconfig = tool_exists("ipconfig");
    let collectors = vec![
      capability_entry(
        "system",
        true,
        cmd,
        "wmic + cmd /C ver",
        Some(if wmic {
          "Windows host and OS identity via wmic/cmd".to_string()
        } else {
          "wmic unavailable; cmd fallback only".to_string()
        }),
      ),
      capability_entry(
        "runtime",
        true,
        true,
        "environment variables + SystemDrive",
        Some("session and root filesystem baseline from environment".to_string()),
      ),
      capability_entry(
        "cpu",
        true,
        wmic,
        "wmic cpu",
        Some(if wmic {
          "CPU baseline from wmic".to_string()
        } else {
          "required command missing: wmic".to_string()
        }),
      ),
      capability_entry(
        "memory",
        true,
        wmic,
        "wmic computersystem + wmic os",
        Some(if wmic {
          "memory baseline from wmic".to_string()
        } else {
          "required command missing: wmic".to_string()
        }),
      ),
      capability_entry(
        "storage",
        true,
        wmic,
        "wmic logicaldisk",
        Some(if wmic {
          "logical disk baseline from wmic".to_string()
        } else {
          "required command missing: wmic".to_string()
        }),
      ),
      capability_entry(
        "network",
        true,
        ipconfig,
        "ipconfig /all",
        Some(if ipconfig {
          "interface baseline from ipconfig".to_string()
        } else {
          "required command missing: ipconfig".to_string()
        }),
      ),
      capability_entry(
        "display",
        true,
        wmic,
        "wmic win32_videocontroller",
        Some(if wmic {
          "display baseline from wmic".to_string()
        } else {
          "required command missing: wmic".to_string()
        }),
      ),
      capability_entry(
        "sensors",
        false,
        false,
        "WMI MSAcpi_ThermalZoneTemperature",
        Some("collector baseline not implemented on Windows yet".to_string()),
      ),
      capability_entry(
        "battery",
        true,
        wmic,
        "wmic Win32_Battery",
        Some(if wmic {
          "battery baseline from wmic".to_string()
        } else {
          "required command missing: wmic".to_string()
        }),
      ),
      capability_entry(
        "pci",
        false,
        false,
        "wmic Win32_PnPEntity",
        Some("collector baseline not implemented on Windows yet".to_string()),
      ),
      capability_entry(
        "usb",
        false,
        false,
        "wmic Win32_USBController",
        Some("collector baseline not implemented on Windows yet".to_string()),
      ),
      capability_entry(
        "camera",
        false,
        false,
        "wmic Win32_PnPEntity (Camera class)",
        Some("collector baseline not implemented on Windows yet".to_string()),
      ),
      capability_entry(
        "thunderbolt",
        false,
        false,
        "WMI / PnP controller inventory",
        Some("collector baseline not implemented on Windows yet".to_string()),
      ),
    ];

    let available_collectors = collectors
      .iter()
      .filter(|collector| {
        collector
          .get("available")
          .and_then(Value::as_bool)
          .unwrap_or(false)
      })
      .count();
    let unavailable_collectors = collectors.len().saturating_sub(available_collectors);

    json!({
      "platform": "windows",
      "available_collectors": available_collectors,
      "unavailable_collectors": unavailable_collectors,
      "collectors": collectors
    })
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
  {
    let os_name = std::env::consts::OS;
    let collectors = [
      "system",
      "runtime",
      "cpu",
      "memory",
      "storage",
      "network",
      "display",
      "sensors",
      "battery",
      "pci",
      "usb",
      "camera",
      "thunderbolt",
    ]
    .iter()
    .map(|name| {
      capability_entry(
        name,
        false,
        false,
        "platform collector",
        Some(format!("collector not implemented on {}", os_name)),
      )
    })
    .collect::<Vec<_>>();

    json!({
      "platform": os_name,
      "available_collectors": 0,
      "unavailable_collectors": collectors.len(),
      "collectors": collectors
    })
  }
}

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
