impl BenchCommand {
  fn display_results(&self, results: &LoadTestResults) {
    println!();
    Output::subheader("LOAD TEST RESULTS");
    println!();

    // Summary
    Output::item("Total Requests", &results.total_requests.to_string());
    Output::item(
      "Successful",
      &format!(
        "{} ({:.1}%)",
        results.successful_requests, results.success_rate
      ),
    );
    Output::item("Failed", &results.failed_requests.to_string());
    Output::item(
      "Test Duration",
      &format!("{:.2}s", results.test_duration.as_secs_f64()),
    );
    Output::item(
      "Requests/sec",
      &format!("{:.2}", results.requests_per_second),
    );
    Output::item("Protocol", &results.protocol.display_label());
    Output::item("Method", &results.config.method);
    let body_summary = results
      .config
      .body
      .as_ref()
      .map(|b| format!("{} bytes", b.len()))
      .unwrap_or_else(|| "none".to_string());
    Output::item("Body", &body_summary);
    println!();

    // Latency
    Output::subheader("Latency Distribution");
    Output::item(
      "p50 (median)",
      &format!("{:.2}ms", results.latency.p50.as_secs_f64() * 1000.0),
    );
    Output::item(
      "p95",
      &format!("{:.2}ms", results.latency.p95.as_secs_f64() * 1000.0),
    );
    Output::item(
      "p99",
      &format!("{:.2}ms", results.latency.p99.as_secs_f64() * 1000.0),
    );
    Output::item(
      "min",
      &format!("{:.2}ms", results.latency.min.as_secs_f64() * 1000.0),
    );
    Output::item(
      "max",
      &format!("{:.2}ms", results.latency.max.as_secs_f64() * 1000.0),
    );
    Output::item(
      "avg",
      &format!("{:.2}ms", results.latency.avg.as_secs_f64() * 1000.0),
    );
    println!();

    Output::subheader("TTFB Distribution");
    Output::item(
      "p50 (median)",
      &format!("{:.2}ms", results.ttfb.p50.as_secs_f64() * 1000.0),
    );
    Output::item(
      "p95",
      &format!("{:.2}ms", results.ttfb.p95.as_secs_f64() * 1000.0),
    );
    Output::item(
      "p99",
      &format!("{:.2}ms", results.ttfb.p99.as_secs_f64() * 1000.0),
    );
    Output::item(
      "min",
      &format!("{:.2}ms", results.ttfb.min.as_secs_f64() * 1000.0),
    );
    Output::item(
      "max",
      &format!("{:.2}ms", results.ttfb.max.as_secs_f64() * 1000.0),
    );
    Output::item(
      "avg",
      &format!("{:.2}ms", results.ttfb.avg.as_secs_f64() * 1000.0),
    );
    println!();

    // Status codes
    if results.successful_requests > 0 {
      Output::subheader("Status Codes");
      if results.status_2xx > 0 {
        Output::item("2xx (Success)", &results.status_2xx.to_string());
      }
      if results.status_3xx > 0 {
        Output::item("3xx (Redirect)", &results.status_3xx.to_string());
      }
      if results.status_4xx > 0 {
        Output::item("4xx (Client Error)", &results.status_4xx.to_string());
      }
      if results.status_5xx > 0 {
        Output::item("5xx (Server Error)", &results.status_5xx.to_string());
      }
      println!();
    }

    // Throughput
    Output::subheader("Throughput");
    Output::item(
      "Total Data",
      &format!("{:.2} MB", results.total_bytes as f64 / 1_000_000.0),
    );
    Output::item(
      "Throughput",
      &format!("{:.2} Mbps", results.throughput_mbps),
    );
    println!();

    // Errors (first 10)
    if !results.errors.is_empty() {
      Output::warning(&format!("⚠️  {} ERRORS DETECTED:", results.errors.len()));
      for (i, error) in results.errors.iter().take(10).enumerate() {
        println!("  {}. {}", i + 1, error);
      }
      if results.errors.len() > 10 {
        println!("  ... and {} more errors", results.errors.len() - 10);
      }
      println!();
    }

    // Performance rating
    if results.success_rate > 99.0 && results.latency.p95.as_millis() < 500 {
      Output::success("✓ Excellent performance!");
    } else if results.success_rate > 95.0 && results.latency.p95.as_millis() < 1000 {
      Output::success("✓ Good performance");
    } else if results.success_rate > 90.0 {
      Output::warning("⚠  Acceptable performance - consider optimization");
    } else {
      Output::error("✗ Poor performance - check server capacity");
    }
  }
}

fn parse_method_and_body(ctx: &CliContext) -> Result<(String, Option<Vec<u8>>), String> {
  let method_raw = ctx.get_flag("method").unwrap_or_else(|| "GET".to_string());
  let method_trimmed = method_raw.trim();
  if method_trimmed.is_empty() {
    return Err("HTTP method cannot be empty".to_string());
  }
  if method_trimmed.chars().any(|c| c.is_whitespace()) {
    return Err("HTTP method must not contain whitespace characters".to_string());
  }
  let method = method_trimmed.to_ascii_uppercase();

  let body_inline = ctx.get_flag("body");
  let body_file = ctx.get_flag("body-file");
  if body_inline.is_some() && body_file.is_some() {
    return Err("Specify either --body or --body-file, not both.".to_string());
  }

  let body = if let Some(path) = body_file {
    let data =
      fs::read(&path).map_err(|e| format!("Failed to read body file '{}': {}", path, e))?;
    Some(data)
  } else if let Some(inline) = body_inline {
    Some(inline.into_bytes())
  } else {
    None
  };

  Ok((method, body))
}

const LIVE_GRAPH_WIDTH: usize = 60;
const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

struct LiveDashboard {
  capacity: usize,
  rps_history: VecDeque<f64>,
  latency_history: VecDeque<f64>,
  cpu_history: VecDeque<f64>,
  mem_history: VecDeque<f64>,
  last_render_lines: usize,
  cursor_hidden: bool,
  sample_interval: f64,
  graph_height: usize,
  stats: SystemStats,
  colors: ColorTheme,
  protocol_label: String,
  method_label: String,
}

impl LiveDashboard {
  fn new(
    capacity: usize,
    interval: Duration,
    graph_height: usize,
    colors: ColorTheme,
    protocol_label: String,
    method_label: String,
  ) -> Self {
    Self {
      capacity,
      rps_history: VecDeque::with_capacity(capacity),
      latency_history: VecDeque::with_capacity(capacity),
      cpu_history: VecDeque::with_capacity(capacity),
      mem_history: VecDeque::with_capacity(capacity),
      last_render_lines: 0,
      cursor_hidden: false,
      sample_interval: interval.as_secs_f64().max(f64::EPSILON),
      graph_height: graph_height.max(4),
      stats: SystemStats::new(),
      colors,
      protocol_label,
      method_label,
    }
  }

  fn update(&mut self, snapshot: &LiveSnapshot) {
    self.stats.refresh();
    Self::push_sample(
      &mut self.rps_history,
      self.capacity,
      snapshot.requests_per_second,
    );
    Self::push_sample(
      &mut self.latency_history,
      self.capacity,
      snapshot.p95.as_secs_f64() * 1000.0,
    );
    if let Some(cpu) = self.stats.cpu_percent_value() {
      Self::push_sample(&mut self.cpu_history, self.capacity, cpu);
    }
    if let Some(mem) = self.stats.mem_percent_value() {
      Self::push_sample(&mut self.mem_history, self.capacity, mem);
    }
  }

  fn render(&mut self, snapshot: &LiveSnapshot) {
    let lines = self.build_lines(snapshot);
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if !self.cursor_hidden {
      let _ = write!(handle, "\x1b[?25l");
      self.cursor_hidden = true;
    }
    if self.last_render_lines > 0 {
      let _ = write!(handle, "\x1b[{}F", self.last_render_lines);
    }
    for line in &lines {
      let _ = write!(handle, "\x1b[2K\r{}\n", line);
    }
    self.last_render_lines = lines.len();
    if self.last_render_lines == 0 {
      self.last_render_lines = 1;
      let _ = write!(handle, "\n");
    }
    let _ = handle.flush();
  }

  fn finish(&mut self) {
    if !self.cursor_hidden {
      return;
    }
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if self.last_render_lines > 0 {
      let _ = write!(handle, "\x1b[{}E", self.last_render_lines);
    }
    let _ = write!(handle, "\x1b[?25h");
    let _ = handle.flush();
    self.cursor_hidden = false;
    self.last_render_lines = 0;
  }

  fn push_sample(queue: &mut VecDeque<f64>, capacity: usize, value: f64) {
    if queue.len() == capacity {
      queue.pop_front();
    }
    queue.push_back(value);
  }

  fn build_lines(&self, snapshot: &LiveSnapshot) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(self.colors.wrap_summary(&format!(
            "t={:>5.1}s  total={}  ok={}  err={}  rps={:>6.1}  p95={:>6.0}ms  ttfb={:>6.0}ms  succ={:>5.1}%  proto={}  method={}",
            snapshot.elapsed.as_secs_f64(),
            snapshot.total_requests,
            snapshot.successful_requests,
            snapshot.failed_requests,
            snapshot.requests_per_second,
            snapshot.p95.as_secs_f64() * 1000.0,
            snapshot.ttfb_p95.as_secs_f64() * 1000.0,
            snapshot.success_rate,
            self.protocol_label,
            self.method_label
        )));
    let cpu_spark = render_sparkline(&self.cpu_history, LIVE_GRAPH_WIDTH);
    lines.push(self.colors.wrap_cpu_line(&format!(
      " CPU    {}  {:>6}",
      cpu_spark,
      self.stats.cpu_compact_display()
    )));
    let ram_spark = render_sparkline(&self.mem_history, LIVE_GRAPH_WIDTH);
    lines.push(self.colors.wrap_ram_line(&format!(
      " RAM    {}  {:>6} {}",
      ram_spark,
      self.stats.mem_compact_display(),
      self.stats.mem_detail_display()
    )));
    lines.push(String::new());

    let rps_values: Vec<f64> = self.rps_history.iter().copied().collect();
    for line in render_graph(
      " RPS",
      &rps_values,
      "req/s",
      self.sample_interval,
      self.graph_height,
    ) {
      lines.push(self.colors.wrap_rps(&line));
    }
    lines.push(String::new());

    let latency_values: Vec<f64> = self.latency_history.iter().copied().collect();
    for line in render_graph(
      " Latency",
      &latency_values,
      "ms",
      self.sample_interval,
      self.graph_height,
    ) {
      lines.push(self.colors.wrap_latency(&line));
    }
    lines
  }
}
