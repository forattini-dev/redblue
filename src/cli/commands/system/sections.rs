
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
