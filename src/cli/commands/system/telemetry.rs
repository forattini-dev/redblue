
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
