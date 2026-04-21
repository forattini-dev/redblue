fn render_graph(
  label: &str,
  values: &[f64],
  unit: &str,
  sample_interval: f64,
  graph_height: usize,
) -> Vec<String> {
  if values.is_empty() {
    return vec![format!("{:<10} (awaiting samples)", label)];
  }

  let width = LIVE_GRAPH_WIDTH;
  let height = graph_height.max(4);
  let display_len = values.len().min(width);
  let start = values.len() - display_len;
  let slice = &values[start..];
  let max_value = slice
    .iter()
    .cloned()
    .fold(0.0_f64, f64::max)
    .max(f64::EPSILON);
  let avg = slice.iter().sum::<f64>() / display_len as f64;
  let current = *slice.last().unwrap_or(&0.0);
  let span_seconds = sample_interval * (display_len.saturating_sub(1) as f64);

  let axis_max = if max_value <= f64::EPSILON {
    1.0
  } else {
    let magnitude = 10_f64.powf((max_value.log10()).floor());
    let scaled = max_value / magnitude;
    let factor = if scaled <= 1.0 {
      1.0
    } else if scaled <= 2.0 {
      2.0
    } else if scaled <= 5.0 {
      5.0
    } else {
      10.0
    };
    factor * magnitude
  };

  let mut lines = Vec::new();
  lines.push(format!(
    "{:<10} cur {:>8.1}  avg {:>8.1}  max {:>8.1} {}",
    label, current, avg, max_value, unit
  ));

  let mut grid = vec![vec![' '; width]; height];
  let offset = width - display_len;
  for idx in 0..display_len {
    let value = slice[idx];
    let normalized = normalize_value(value, axis_max);
    let col = offset + idx;
    draw_column(&mut grid, col, normalized);
  }

  for row in 0..height {
    let label_value = if row == 0 {
      Some(axis_max)
    } else if row == height / 2 {
      Some(axis_max * 0.5)
    } else if row == height - 1 {
      Some(0.0)
    } else {
      None
    };

    let label_text = label_value
      .map(format_axis_value)
      .unwrap_or_else(|| "      ".to_string());

    let mut line = String::with_capacity(width + 12);
    line.push_str(&label_text);
    line.push_str(" │");
    for col in 0..width {
      line.push(grid[row][col]);
    }
    line.push('│');
    lines.push(line);
  }

  let mut baseline = String::with_capacity(width + 12);
  baseline.push_str("      ");
  baseline.push_str(" └");
  baseline.push_str(&"─".repeat(width));
  baseline.push('┘');
  lines.push(baseline);
  let axis_span_label = if span_seconds >= 100.0 {
    format!("{:.0}s", span_seconds)
  } else if span_seconds >= 10.0 {
    format!("{:.1}s", span_seconds)
  } else {
    format!("{:.2}s", span_seconds)
  };
  let pad = width
    .saturating_sub(axis_span_label.len().saturating_add(2))
    .saturating_add(1);
  lines.push(format!("      0s{}{}", " ".repeat(pad), axis_span_label));
  lines
}

fn format_axis_value(value: f64) -> String {
  if value >= 1000.0 {
    format!("{:>6.0}", value)
  } else if value >= 10.0 {
    format!("{:>6.1}", value)
  } else if value >= 1.0 {
    format!("{:>6.2}", value)
  } else if value > 0.0 {
    format!("{:>6.3}", value)
  } else {
    "     0".to_string()
  }
}

fn normalize_value(value: f64, axis_max: f64) -> f64 {
  if axis_max <= f64::EPSILON {
    0.0
  } else {
    (value / axis_max).clamp(0.0, 1.0)
  }
}

fn draw_column(grid: &mut Vec<Vec<char>>, col: usize, value: f64) {
  let height = grid.len();
  if height == 0 {
    return;
  }

  for row in 0..height {
    grid[row][col] = ' ';
  }

  let clamped = value.clamp(0.0, 1.0);
  let total_units = clamped * height as f64;
  let mut full_rows = total_units.floor() as isize;
  if full_rows as usize > height {
    full_rows = height as isize;
  }
  let mut remainder = total_units - full_rows as f64;
  if clamped >= 0.999_999 {
    remainder = 1.0;
  }

  for i in 0..full_rows.max(0) {
    let row = height as isize - 1 - i;
    if row < 0 {
      break;
    }
    grid[row as usize][col] = '█';
  }

  if (remainder > f64::EPSILON) && (full_rows as usize) < height {
    let row = height as isize - 1 - full_rows;
    if row >= 0 {
      let idx = (remainder * (SPARK_CHARS.len() as f64 - 1.0)).round() as usize;
      let ch = SPARK_CHARS[idx.min(SPARK_CHARS.len() - 1)];
      if grid[row as usize][col] == ' ' {
        grid[row as usize][col] = ch;
      }
    }
  }
}

fn render_sparkline(history: &VecDeque<f64>, width: usize) -> String {
  if width == 0 {
    return String::new();
  }
  const EMPTY_CHAR: char = '·';
  if history.is_empty() {
    return EMPTY_CHAR.to_string().repeat(width);
  }

  let len = history.len();
  let start = len.saturating_sub(width);
  let slice: Vec<f64> = history.iter().skip(start).copied().collect();

  let min = slice.iter().cloned().fold(f64::INFINITY, f64::min).min(0.0);
  let max = slice
    .iter()
    .cloned()
    .fold(f64::NEG_INFINITY, f64::max)
    .max(0.0);
  let range = (max - min).max(f64::EPSILON);

  let padding = width.saturating_sub(slice.len());
  let mut spark = String::with_capacity(width);
  if padding > 0 {
    spark.push_str(&EMPTY_CHAR.to_string().repeat(padding));
  }

  for value in slice {
    let normalized = ((value - min) / range).clamp(0.0, 1.0);
    let idx = (normalized * (SPARK_CHARS.len() as f64 - 1.0)).round() as usize;
    spark.push(SPARK_CHARS[idx.min(SPARK_CHARS.len() - 1)]);
  }

  spark
}

const ANSI_RESET: &str = "\x1b[0m";

#[derive(Clone)]
struct AnsiColor {
  prefix: String,
}

impl AnsiColor {
  fn plain() -> Self {
    Self {
      prefix: String::new(),
    }
  }

  fn from_rgb(r: u8, g: u8, b: u8) -> Self {
    Self {
      prefix: format!("\x1b[38;2;{};{};{}m", r, g, b),
    }
  }

  fn wrap(&self, text: &str) -> String {
    if self.prefix.is_empty() {
      text.to_string()
    } else {
      format!("{}{}{}", self.prefix, text, ANSI_RESET)
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ColorMode {
  Always,
  Auto,
  Never,
}

impl FromStr for ColorMode {
  type Err = String;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
      "" => Ok(Self::Always),
      "always" | "true" | "yes" | "1" => Ok(Self::Always),
      "auto" | "tty" => Ok(Self::Auto),
      "never" | "false" | "no" | "0" => Ok(Self::Never),
      other => Err(format!(
        "Invalid color mode '{}'. Use always, auto, or never.",
        other
      )),
    }
  }
}

impl ColorMode {
  fn from_context(ctx: &CliContext) -> Result<Self, String> {
    if ctx.has_flag("no-color") {
      return Ok(Self::Never);
    }

    if let Some(flag) = ctx.get_flag("color") {
      return ColorMode::from_str(&flag);
    }

    if env::var("CLICOLOR_FORCE")
      .map(|v| !v.trim().is_empty() && v.trim() != "0")
      .unwrap_or(false)
    {
      return Ok(Self::Always);
    }

    if env::var_os("NO_COLOR").is_some() {
      return Ok(Self::Never);
    }

    if env::var("CLICOLOR")
      .map(|v| v.trim() == "0")
      .unwrap_or(false)
    {
      return Ok(Self::Never);
    }

    Ok(Self::Always)
  }

  fn should_color(self) -> bool {
    match self {
      Self::Always => true,
      Self::Never => false,
      Self::Auto => {
        if env::var_os("NO_COLOR").is_some() {
          return false;
        }
        // Check if stdout is a terminal
        #[cfg(not(target_os = "windows"))]
        {
          unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
        }
        #[cfg(target_os = "windows")]
        {
          // On Windows, check via GetStdHandle
          use std::os::windows::io::AsRawHandle;
          let handle = std::io::stdout().as_raw_handle();
          unsafe {
            #[link(name = "kernel32")]
            extern "system" {
              fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
            }
            let mut mode = 0;
            GetConsoleMode(handle as *mut _, &mut mode) != 0
          }
        }
      }
    }
  }
}

struct ColorTheme {
  rps: AnsiColor,
  latency: AnsiColor,
  cpu: AnsiColor,
  ram: AnsiColor,
  summary: AnsiColor,
}

impl ColorTheme {
  fn default() -> Self {
    Self {
      rps: AnsiColor::from_rgb(179, 136, 255),     // brand purple
      latency: AnsiColor::from_rgb(128, 222, 234), // pastel cyan
      cpu: AnsiColor::from_rgb(255, 171, 145),     // warm coral
      ram: AnsiColor::from_rgb(200, 230, 201),     // mint green
      summary: AnsiColor::from_rgb(171, 71, 188),  // accent purple
    }
  }

  fn monochrome() -> Self {
    let base = AnsiColor::plain();
    Self {
      rps: base.clone(),
      latency: base.clone(),
      cpu: base.clone(),
      ram: base.clone(),
      summary: base,
    }
  }

  fn from_flags(
    rps: Option<&String>,
    latency: Option<&String>,
    cpu: Option<&String>,
    ram: Option<&String>,
    mode: ColorMode,
  ) -> Result<Self, String> {
    if !mode.should_color() {
      return Ok(Self::monochrome());
    }
    let defaults = Self::default();
    Ok(Self {
      rps: parse_color_flag(rps, &defaults.rps)?,
      latency: parse_color_flag(latency, &defaults.latency)?,
      cpu: parse_color_flag(cpu, &defaults.cpu)?,
      ram: parse_color_flag(ram, &defaults.ram)?,
      summary: defaults.summary.clone(),
    })
  }

  fn wrap_rps(&self, text: &str) -> String {
    self.rps.wrap(text)
  }

  fn wrap_latency(&self, text: &str) -> String {
    self.latency.wrap(text)
  }

  fn wrap_cpu(&self, text: &str) -> String {
    self.cpu.wrap(text)
  }

  fn wrap_ram(&self, text: &str) -> String {
    self.ram.wrap(text)
  }

  fn wrap_summary(&self, text: &str) -> String {
    self.summary.wrap(text)
  }

  fn wrap_cpu_line(&self, text: &str) -> String {
    self.cpu.wrap(text)
  }

  fn wrap_ram_line(&self, text: &str) -> String {
    self.ram.wrap(text)
  }
}

fn parse_color_flag(flag: Option<&String>, default: &AnsiColor) -> Result<AnsiColor, String> {
  match flag {
    Some(value) if !value.trim().is_empty() => parse_color_value(value),
    _ => Ok(default.clone()),
  }
}

fn parse_color_value(value: &str) -> Result<AnsiColor, String> {
  let trimmed = value.trim();
  let lower = trimmed.to_ascii_lowercase();
  let rgb = match lower.as_str() {
    "purple" => (179, 136, 255),
    "teal" => (100, 216, 203),
    "coral" => (255, 171, 145),
    "mint" => (165, 214, 167),
    "gold" => (255, 224, 130),
    "royal" => (121, 134, 203),
    _ => {
      let hex = lower.trim_start_matches('#');
      if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
                    "Invalid color value '{}'. Use hex like #RRGGBB or names: purple, teal, coral, mint, gold, royal.",
                    trimmed
                ));
      }
      let r = u8::from_str_radix(&hex[0..2], 16).map_err(|_| {
        format!(
          "Invalid color value '{}'. Unable to parse red channel.",
          trimmed
        )
      })?;
      let g = u8::from_str_radix(&hex[2..4], 16).map_err(|_| {
        format!(
          "Invalid color value '{}'. Unable to parse green channel.",
          trimmed
        )
      })?;
      let b = u8::from_str_radix(&hex[4..6], 16).map_err(|_| {
        format!(
          "Invalid color value '{}'. Unable to parse blue channel.",
          trimmed
        )
      })?;
      (r, g, b)
    }
  };
  Ok(AnsiColor::from_rgb(rgb.0, rgb.1, rgb.2))
}
