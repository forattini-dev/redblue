struct SystemStats {
  prev_total: Option<u64>,
  prev_idle: Option<u64>,
  cpu_percent: Option<f64>,
  mem_total_kib: Option<u64>,
  mem_used_kib: Option<u64>,
  mem_percent: Option<f64>,
}

impl SystemStats {
  fn new() -> Self {
    Self {
      prev_total: None,
      prev_idle: None,
      cpu_percent: None,
      mem_total_kib: None,
      mem_used_kib: None,
      mem_percent: None,
    }
  }

  fn refresh(&mut self) {
    self.update_cpu();
    self.update_mem();
  }

  fn update_cpu(&mut self) {
    if let Ok(contents) = fs::read_to_string("/proc/stat") {
      if let Some(line) = contents.lines().next() {
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // skip "cpu"
        let mut values = Vec::new();
        for part in parts {
          if let Ok(val) = part.parse::<u64>() {
            values.push(val);
          }
        }
        if values.len() >= 4 {
          let idle = values[3] + values.get(4).copied().unwrap_or(0);
          let total: u64 = values.iter().sum();
          if let (Some(prev_total), Some(prev_idle)) = (self.prev_total, self.prev_idle) {
            let total_diff = total.saturating_sub(prev_total);
            if total_diff > 0 {
              let idle_diff = idle.saturating_sub(prev_idle);
              let used = total_diff.saturating_sub(idle_diff);
              self.cpu_percent = Some((used as f64 / total_diff as f64) * 100.0);
            }
          }
          self.prev_total = Some(total);
          self.prev_idle = Some(idle);
        }
      }
    }
  }

  fn update_mem(&mut self) {
    self.mem_percent = None;
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
      let mut total = None;
      let mut available = None;
      for line in contents.lines() {
        if line.starts_with("MemTotal:") {
          total = line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok());
        } else if line.starts_with("MemAvailable:") {
          available = line
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok());
        }
        if total.is_some() && available.is_some() {
          break;
        }
      }
      if let (Some(total_kib), Some(avail_kib)) = (total, available) {
        self.mem_total_kib = Some(total_kib);
        self.mem_used_kib = Some(total_kib.saturating_sub(avail_kib));
        if total_kib > 0 {
          let percent = ((total_kib - avail_kib) as f64 / total_kib as f64) * 100.0;
          self.mem_percent = Some(percent);
        }
      }
    }
  }

  fn cpu_percent_value(&self) -> Option<f64> {
    self.cpu_percent
  }

  fn cpu_compact_display(&self) -> String {
    if let Some(percent) = self.cpu_percent {
      format!("{:>5.1}%", percent)
    } else {
      "  n/a".to_string()
    }
  }

  fn mem_percent_value(&self) -> Option<f64> {
    self.mem_percent
  }

  fn mem_compact_display(&self) -> String {
    if let Some(percent) = self.mem_percent {
      format!("{:>5.1}%", percent)
    } else {
      "  n/a".to_string()
    }
  }

  fn mem_detail_display(&self) -> String {
    match (self.mem_used_kib, self.mem_total_kib) {
      (Some(used), Some(total)) if total > 0 => {
        let used_gb = used as f64 / (1024.0 * 1024.0);
        let total_gb = total as f64 / (1024.0 * 1024.0);
        format!("({:.1}/{:.1}G)", used_gb, total_gb)
      }
      _ => String::from("(n/a)"),
    }
  }
}
