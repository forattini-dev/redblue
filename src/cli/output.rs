/// Beautiful output formatting
use crate::modules::network::scanner::ScanProgress;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SPINNER_FRAMES: [&str; 12] = [
    "[      ]", "[=     ]", "[==    ]", "[===   ]", "[====  ]", "[===== ]", "[======]", "[ =====]",
    "[  ====]", "[   ===]", "[    ==]", "[     =]",
];

struct SpinnerState {
    stop_flag: Arc<AtomicBool>,
    message: Arc<Mutex<String>>,
    frame: Arc<AtomicUsize>,
    handle: Option<std::thread::JoinHandle<()>>,
}

static SPINNER_STATE: Mutex<Option<SpinnerState>> = Mutex::new(None);

pub struct Output;

impl Output {
    // Color codes
    const RESET: &'static str = "\x1b[0m";
    const BOLD: &'static str = "\x1b[1m";
    const DIM: &'static str = "\x1b[2m";

    #[allow(dead_code)]
    const RED: &'static str = "\x1b[31m";
    const GREEN: &'static str = "\x1b[32m";
    const YELLOW: &'static str = "\x1b[33m";
    #[allow(dead_code)]
    const BLUE: &'static str = "\x1b[34m";
    #[allow(dead_code)]
    const MAGENTA: &'static str = "\x1b[35m";
    const CYAN: &'static str = "\x1b[36m";

    pub fn success(msg: &str) {
        println!("{}✓{} {}", Self::GREEN, Self::RESET, msg);
    }

    pub fn error(msg: &str) {
        println!("{}✗{} {}", Self::RED, Self::RESET, msg);
    }

    #[allow(dead_code)]
    pub fn info(msg: &str) {
        println!("{}ℹ{} {}", Self::BLUE, Self::RESET, msg);
    }

    pub fn warning(msg: &str) {
        println!("{}⚠{} {}", Self::YELLOW, Self::RESET, msg);
    }

    /// Phase header (for multi-phase scans)
    pub fn phase(title: &str) {
        println!("\n{}{}▸ {}{}", Self::BOLD, Self::CYAN, title, Self::RESET);
    }

    /// Task start (with spinner simulation)
    pub fn task_start(task: &str) {
        print!("  {}⟳{} {} ... ", Self::CYAN, Self::RESET, task);
        io::stdout().flush().unwrap();
    }

    /// Task done (on same line)
    pub fn task_done(result: &str) {
        println!("{}{}{}", Self::GREEN, result, Self::RESET);
    }

    #[allow(dead_code)]
    pub fn step(step: usize, total: usize, msg: &str) {
        println!("{}[{}/{}]{} {}", Self::CYAN, step, total, Self::RESET, msg);
    }

    pub fn header(title: &str) {
        println!("\n{}▸ {}{}", Self::BOLD, title, Self::RESET);
    }

    pub fn subheader(title: &str) {
        println!("{}{}{}", Self::CYAN, title, Self::RESET);
    }

    /// Section header (alias for subheader for compatibility)
    pub fn section(title: &str) {
        Self::subheader(title);
    }

    pub fn item(label: &str, value: &str) {
        println!("  {}{:<12}{} {}", Self::DIM, label, Self::RESET, value);
    }

    /// Compact summary line
    pub fn summary_line(items: &[(&str, &str)]) {
        print!(" ");
        for (i, (label, value)) in items.iter().enumerate() {
            if i > 0 {
                print!(" {}|{} ", Self::DIM, Self::RESET);
            }
            print!("{}{}{} {}", Self::DIM, label, Self::RESET, value);
        }
        println!();
    }

    pub fn table_header(cols: &[&str]) {
        let row = cols.join(" │ ");
        println!("{}{}{}", Self::BOLD, row, Self::RESET);
        println!("{}", "─".repeat(row.len()));
    }

    pub fn table_row(cols: &[&str]) {
        println!("{}", cols.join(" │ "));
    }

    #[allow(dead_code)]
    pub fn json(data: &str) {
        println!("{}", data);
    }

    pub fn spinner_start(msg: &str) {
        let snippet = msg.trim().to_string();
        Self::stop_spinner(false);

        let mut guard = SPINNER_STATE.lock().unwrap();

        let message = Arc::new(Mutex::new(snippet.clone()));
        let frame = Arc::new(AtomicUsize::new(0));
        let line = if snippet.is_empty() {
            format!("{}{}{}", Self::CYAN, SPINNER_FRAMES[0], Self::RESET)
        } else {
            format!(
                "{} {}{}{}",
                snippet,
                Self::CYAN,
                SPINNER_FRAMES[0],
                Self::RESET
            )
        };
        print!("\r{}\x1b[K", line);
        let _ = io::stdout().flush();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_flag = stop_flag.clone();
        let message_clone = Arc::clone(&message);
        let frame_clone = Arc::clone(&frame);
        let handle = thread::spawn(move || {
            let mut idx = 1usize;
            let frame_count = SPINNER_FRAMES.len();
            while !thread_flag.load(Ordering::Relaxed) {
                let frame_idx = idx % frame_count;
                frame_clone.store(frame_idx, Ordering::Relaxed);
                let current_msg = { message_clone.lock().unwrap().clone() };
                let frame_str = SPINNER_FRAMES[frame_idx];
                let line = if current_msg.is_empty() {
                    format!("{}{}{}", Output::CYAN, frame_str, Output::RESET)
                } else {
                    format!(
                        "{} {}{}{}",
                        current_msg,
                        Output::CYAN,
                        frame_str,
                        Output::RESET
                    )
                };
                print!("\r{}\x1b[K", line);
                let _ = io::stdout().flush();
                idx = (idx + 1) % frame_count;
                thread::sleep(Duration::from_millis(60));
            }
        });

        *guard = Some(SpinnerState {
            stop_flag,
            message,
            frame,
            handle: Some(handle),
        });
    }

    pub fn spinner_done() {
        if Self::stop_spinner(true).is_none() {
            println!(" {}✓{}", Self::GREEN, Self::RESET);
        }
    }

    pub fn spinner_status(msg: &str) {
        let trimmed = msg.trim().to_string();
        let line = {
            let guard = SPINNER_STATE.lock().unwrap();
            if let Some(state) = guard.as_ref() {
                {
                    let mut message = state.message.lock().unwrap();
                    *message = trimmed.clone();
                }
                let frame_idx = state.frame.load(Ordering::Relaxed) % SPINNER_FRAMES.len();
                let frame_str = SPINNER_FRAMES[frame_idx];
                if trimmed.is_empty() {
                    format!("{}{}{}", Output::CYAN, frame_str, Output::RESET)
                } else {
                    format!("{} {}{}{}", trimmed, Output::CYAN, frame_str, Output::RESET)
                }
            } else {
                return;
            }
        };
        print!("\r{}\x1b[K", line);
        let _ = io::stdout().flush();
    }

    pub fn progress_bar(label: impl Into<String>, total: u64, enabled: bool) -> ProgressBar {
        ProgressBar::new(label.into(), total, enabled)
    }

    pub fn dim(msg: &str) {
        println!("{}{}{}", Self::DIM, msg, Self::RESET);
    }

    pub fn colorize(text: &str, color: &str) -> String {
        let color_code = match color {
            "red" => Self::RED,
            "green" => Self::GREEN,
            "yellow" => Self::YELLOW,
            "blue" => Self::BLUE,
            "magenta" => Self::MAGENTA,
            "cyan" => Self::CYAN,
            _ => "",
        };
        format!("{}{}{}", color_code, text, Self::RESET)
    }
}

impl Output {
    fn stop_spinner(print_completion: bool) -> Option<String> {
        let mut guard = SPINNER_STATE.lock().unwrap();
        if let Some(mut state) = guard.take() {
            let message = { state.message.lock().unwrap().clone() };
            state.stop_flag.store(true, Ordering::Relaxed);
            if let Some(handle) = state.handle.take() {
                let _ = handle.join();
            }

            if print_completion {
                let line = if message.is_empty() {
                    format!("{}✓{}", Output::GREEN, Output::RESET)
                } else {
                    format!("{} {}✓{}", message, Output::GREEN, Output::RESET)
                };
                print!("\r{}\x1b[K\n", line);
            } else {
                print!("\r\x1b[K");
            }
            let _ = io::stdout().flush();
            return Some(message);
        }
        None
    }
}

const PROGRESS_WIDTH: usize = 20;

struct ProgressInner {
    enabled: bool,
    total: AtomicU64,
    width: usize,
    label: String,
    current: AtomicU64,
    stop_flag: AtomicBool,
    finished: AtomicBool,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
    start: Instant,
}

#[derive(Clone)]
pub struct ProgressBar {
    inner: Arc<ProgressInner>,
}

impl ProgressBar {
    pub fn new(label: String, total: u64, enabled: bool) -> Self {
        let inner = Arc::new(ProgressInner::new(label, total, enabled));

        if enabled {
            inner.render();
            let thread_inner = Arc::clone(&inner);
            let handle = thread::spawn(move || {
                while !thread_inner.stop_flag.load(Ordering::Relaxed) {
                    thread_inner.render();
                    thread::sleep(Duration::from_millis(80));
                }
            });
            *inner.handle.lock().unwrap() = Some(handle);
        }

        ProgressBar { inner }
    }

    pub fn tick(&self, amount: u64) {
        if self.inner.enabled {
            self.inner.current.fetch_add(amount, Ordering::Relaxed);
        }
    }

    pub fn set_total(&self, total: u64) {
        if !self.inner.enabled {
            self.inner.set_total(total);
            return;
        }
        self.inner.set_total(total);
        self.inner.render();
    }

    pub fn finish(&self) {
        if !self.inner.enabled {
            return;
        }

        if self.inner.finished.swap(true, Ordering::SeqCst) {
            return;
        }

        self.inner.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.inner.handle.lock().unwrap().take() {
            let _ = handle.join();
        }

        let total = self.inner.total.load(Ordering::Relaxed).max(1);
        self.inner.current.store(total, Ordering::Relaxed);
        self.inner.render();
        print!(" {}✓{}", Output::GREEN, Output::RESET);
        println!();
        let _ = io::stdout().flush();
    }
}

impl Drop for ProgressBar {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.finish();
        }
    }
}

impl ScanProgress for ProgressBar {
    fn inc(&self, delta: usize) {
        self.tick(delta as u64);
    }
}

impl ProgressInner {
    fn new(label: String, total: u64, enabled: bool) -> Self {
        Self {
            enabled,
            total: AtomicU64::new(total.max(1)),
            width: PROGRESS_WIDTH,
            label,
            current: AtomicU64::new(0),
            stop_flag: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            handle: Mutex::new(None),
            start: Instant::now(),
        }
    }

    fn set_total(&self, total: u64) {
        let total = total.max(1);
        self.total.store(total, Ordering::Relaxed);
        let current = self.current.load(Ordering::Relaxed);
        if current > total {
            self.current.store(total, Ordering::Relaxed);
        }
    }

    fn render(&self) {
        if !self.enabled {
            return;
        }

        let total = self.total.load(Ordering::Relaxed).max(1);
        let current = self.current.load(Ordering::Relaxed).min(total);
        let ratio = current as f64 / total as f64;
        let filled = ((ratio * self.width as f64).round() as usize).clamp(0, self.width);
        let bar = format!(
            "[{}{}]",
            "█".repeat(filled),
            " ".repeat(self.width - filled)
        );
        let percent = (ratio * 100.0).min(100.0);
        let elapsed = self.start.elapsed().as_secs_f64();
        let label = if self.label.chars().count() > 28 {
            let mut truncated = String::new();
            for (idx, ch) in self.label.chars().enumerate() {
                if idx >= 27 {
                    truncated.push('…');
                    break;
                }
                truncated.push(ch);
            }
            truncated
        } else {
            self.label.clone()
        };

        print!(
            "\r{}{}{} {:>5.1}% {}/{} t={:.1}s {}",
            Output::CYAN,
            bar,
            Output::RESET,
            percent,
            current,
            total,
            elapsed,
            label
        );
        let _ = io::stdout().flush();
    }
}
