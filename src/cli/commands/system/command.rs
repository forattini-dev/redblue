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
