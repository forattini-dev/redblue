use crate::cli::commands::{Command, Route};
use crate::cli::{output::Output, render, CliContext};
use crate::json;
use crate::modules::evasion::sandbox;
use crate::serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
  let warnings = collect_inventory_warnings(&display, &battery, &pci, &usb, &camera, &thunderbolt);

  json!({
    "host": host,
    "environment": environment,
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

  json!({
    "host": inventory.get("host").cloned().unwrap_or(Value::Null),
    "environment": inventory.get("environment").cloned().unwrap_or(Value::Null),
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
      "thermal_zones": thermal_zones
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
    Output::item("Environment", &format!("{} ({})", kind, confidence));
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
    });
  }

  #[cfg(not(target_os = "linux"))]
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
      "board_name": ""
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
    });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({
      "vendor": "",
      "version": "",
      "date": ""
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
    });
  }

  #[cfg(not(target_os = "linux"))]
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
    });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({
      "model": "unknown",
      "vendor": "unknown",
      "logical_cpus": std::thread::available_parallelism()
        .map(|value| value.get() as u64)
        .unwrap_or(0),
      "frequency_mhz": Value::Null,
      "hypervisor_flag": false
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
    });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({
      "total_kib": 0,
      "total_gib": 0.0,
      "available_kib": 0,
      "available_gib": 0.0,
      "swap_total_kib": 0,
      "swap_total_gib": 0.0
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
    return json!({ "devices": devices });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "devices": [] })
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
    return json!({ "interfaces": interfaces });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "interfaces": [] })
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
    return json!({ "connectors": connectors });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "connectors": [] })
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
    return json!({ "thermal_zones": thermal_zones });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "thermal_zones": [] })
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
    return json!({ "batteries": batteries });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "batteries": [] })
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
    return json!({ "devices": devices });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "devices": [] })
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
    return json!({ "devices": devices });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "devices": [] })
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
    return json!({ "devices": devices });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "devices": [] })
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
    return json!({ "devices": devices });
  }

  #[cfg(not(target_os = "linux"))]
  {
    json!({ "devices": [] })
  }
}

fn collect_environment_assessment() -> Value {
  let container = detect_container_environment();
  let virtualization = detect_virtual_machine_environment();
  let sandbox_state = detect_sandbox_environment();

  let mut traits = Vec::new();
  let mut reasons = Vec::new();
  let mut confidence = "low".to_string();
  let kind = if container
    .get("detected")
    .and_then(Value::as_bool)
    .unwrap_or(false)
  {
    traits.push("container".to_string());
    reasons.extend(json_array_strings(container.get("reasons")));
    confidence = confidence_max(
      &confidence,
      container
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or("medium"),
    );
    if virtualization
      .get("detected")
      .and_then(Value::as_bool)
      .unwrap_or(false)
    {
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
    if sandbox_state
      .get("detected")
      .and_then(Value::as_bool)
      .unwrap_or(false)
    {
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
  } else if sandbox_state
    .get("detected")
    .and_then(Value::as_bool)
    .unwrap_or(false)
  {
    traits.push("sandbox".to_string());
    reasons.extend(json_array_strings(sandbox_state.get("reasons")));
    confidence = confidence_max(
      &confidence,
      sandbox_state
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or("medium"),
    );
    if virtualization
      .get("detected")
      .and_then(Value::as_bool)
      .unwrap_or(false)
    {
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
  } else if virtualization
    .get("detected")
    .and_then(Value::as_bool)
    .unwrap_or(false)
  {
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
    "traits": traits,
    "confidence": confidence,
    "reasons": reasons,
    "container": container,
    "virtualization": virtualization,
    "sandbox": sandbox_state,
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
) -> Vec<String> {
  let mut warnings = Vec::new();

  if display
    .get("connectors")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("display inventory is empty or unavailable on this host".to_string());
  }

  if battery
    .get("batteries")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push(
      "battery inventory is empty; this may be a desktop, VM, or unsupported platform".to_string(),
    );
  }

  if pci
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("no interesting PCI display/audio/network devices were identified".to_string());
  }

  if usb
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("USB inventory is empty or inaccessible".to_string());
  }

  if camera
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("camera/video4linux inventory is empty".to_string());
  }

  if thunderbolt
    .get("devices")
    .and_then(Value::as_array)
    .is_none_or(|items| items.is_empty())
  {
    warnings.push("thunderbolt inventory is empty or unsupported".to_string());
  }

  warnings
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
}
