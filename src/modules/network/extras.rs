/// Extra Features (Rate Limiting, Logging, File Transfer)
///
/// Additional utilities to enhance netcat functionality.
///
/// Features:
/// - Rate limiting (bandwidth throttling)
/// - Connection logging
/// - File transfer optimization
/// - Connection statistics
///
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

/// Rate limiter for bandwidth throttling
pub struct RateLimiter {
    bytes_per_second: usize,
    last_check: Instant,
    bytes_this_second: usize,
}

impl RateLimiter {
    pub fn new(bytes_per_second: usize) -> Self {
        Self {
            bytes_per_second,
            last_check: Instant::now(),
            bytes_this_second: 0,
        }
    }

    /// Check if we can send/receive n bytes
    pub fn check(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_check);

        // Reset counter every second
        if elapsed >= Duration::from_secs(1) {
            self.last_check = now;
            self.bytes_this_second = 0;
        }

        // Check limit
        if self.bytes_this_second + bytes <= self.bytes_per_second {
            self.bytes_this_second += bytes;
            true
        } else {
            false
        }
    }

    /// Wait until we can send/receive n bytes
    pub fn wait_for(&mut self, bytes: usize) {
        while !self.check(bytes) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Get current rate (bytes/sec)
    pub fn current_rate(&self) -> usize {
        let elapsed = Instant::now().duration_since(self.last_check);
        if elapsed >= Duration::from_secs(1) {
            0
        } else {
            self.bytes_this_second
        }
    }
}

/// Connection logger
pub struct ConnectionLogger {
    log_file: Option<File>,
    verbose: bool,
}

impl ConnectionLogger {
    pub fn new(log_path: Option<&Path>, verbose: bool) -> Result<Self, String> {
        let log_file = if let Some(path) = log_path {
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("Failed to open log file: {}", e))?,
            )
        } else {
            None
        };

        Ok(Self { log_file, verbose })
    }

    /// Log connection event
    pub fn log_connection(&mut self, addr: &SocketAddr, event: &str) {
        let timestamp = Self::timestamp();
        let message = format!("[{}] {} - {}\n", timestamp, addr, event);

        if self.verbose {
            eprint!("{}", message);
        }

        if let Some(ref mut file) = self.log_file {
            let _ = file.write_all(message.as_bytes());
            let _ = file.flush();
        }
    }

    /// Log data transfer
    pub fn log_data(&mut self, direction: &str, bytes: usize) {
        let timestamp = Self::timestamp();
        let message = format!("[{}] {} - {} bytes\n", timestamp, direction, bytes);

        if self.verbose {
            eprint!("{}", message);
        }

        if let Some(ref mut file) = self.log_file {
            let _ = file.write_all(message.as_bytes());
            let _ = file.flush();
        }
    }

    /// Log error
    pub fn log_error(&mut self, error: &str) {
        let timestamp = Self::timestamp();
        let message = format!("[{}] ERROR - {}\n", timestamp, error);

        if self.verbose {
            eprint!("{}", message);
        }

        if let Some(ref mut file) = self.log_file {
            let _ = file.write_all(message.as_bytes());
            let _ = file.flush();
        }
    }

    /// Get current timestamp
    fn timestamp() -> String {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let secs = now.as_secs();
        let millis = now.subsec_millis();

        // Format: YYYY-MM-DD HH:MM:SS.mmm
        let datetime = secs / 86400 + 719_162; // Days since Unix epoch to days since 0000-01-01
        let year = (400 * datetime + 292_194) / 146_097;
        let day_of_year = datetime - (365 * year + year / 4 - year / 100 + year / 400);
        let month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month + 2) / 5 + 1;
        let month = month + 3 - 12 * (month / 10);

        let hour = (secs % 86400) / 3600;
        let minute = (secs % 3600) / 60;
        let second = secs % 60;

        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            year, month, day, hour, minute, second, millis
        )
    }
}

/// Connection statistics
pub struct ConnectionStats {
    start_time: Instant,
    bytes_sent: usize,
    bytes_received: usize,
}

impl ConnectionStats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Record sent bytes
    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes;
    }

    /// Record received bytes
    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes;
    }

    /// Get total bytes
    pub fn total_bytes(&self) -> usize {
        self.bytes_sent + self.bytes_received
    }

    /// Get duration
    pub fn duration(&self) -> Duration {
        Instant::now().duration_since(self.start_time)
    }

    /// Get average throughput (bytes/sec)
    pub fn throughput(&self) -> f64 {
        let duration = self.duration().as_secs_f64();
        if duration > 0.0 {
            self.total_bytes() as f64 / duration
        } else {
            0.0
        }
    }

    /// Print statistics
    pub fn print(&self) {
        let duration = self.duration();
        let throughput = self.throughput();

        println!("\n[Connection Statistics]");
        println!("  Duration:        {:.2}s", duration.as_secs_f64());
        println!("  Bytes sent:      {}", Self::format_bytes(self.bytes_sent));
        println!(
            "  Bytes received:  {}",
            Self::format_bytes(self.bytes_received)
        );
        println!(
            "  Total:           {}",
            Self::format_bytes(self.total_bytes())
        );
        println!(
            "  Throughput:      {}/s",
            Self::format_bytes(throughput as usize)
        );
    }

    /// Format bytes with units (KB, MB, GB)
    fn format_bytes(bytes: usize) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = KB * 1024.0;
        const GB: f64 = MB * 1024.0;

        let bytes_f = bytes as f64;

        if bytes_f >= GB {
            format!("{:.2} GB", bytes_f / GB)
        } else if bytes_f >= MB {
            format!("{:.2} MB", bytes_f / MB)
        } else if bytes_f >= KB {
            format!("{:.2} KB", bytes_f / KB)
        } else {
            format!("{} B", bytes)
        }
    }
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// File transfer optimizer
pub struct FileTransfer {
    buffer_size: usize,
    rate_limiter: Option<RateLimiter>,
    stats: ConnectionStats,
}

impl FileTransfer {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            rate_limiter: None,
            stats: ConnectionStats::new(),
        }
    }

    pub fn with_rate_limit(mut self, bytes_per_second: usize) -> Self {
        self.rate_limiter = Some(RateLimiter::new(bytes_per_second));
        self
    }

    /// Send file over stream
    pub fn send_file<W: Write>(&mut self, file_path: &Path, writer: &mut W) -> Result<(), String> {
        let mut file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;

        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            let n = file
                .read(&mut buffer)
                .map_err(|e| format!("Failed to read file: {}", e))?;

            if n == 0 {
                break;
            }

            // Rate limiting
            if let Some(ref mut limiter) = self.rate_limiter {
                limiter.wait_for(n);
            }

            writer
                .write_all(&buffer[..n])
                .map_err(|e| format!("Failed to write data: {}", e))?;

            self.stats.record_sent(n);
        }

        writer
            .flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    /// Receive file from stream
    pub fn receive_file<R: Read>(
        &mut self,
        reader: &mut R,
        file_path: &Path,
    ) -> Result<(), String> {
        let mut file =
            File::create(file_path).map_err(|e| format!("Failed to create file: {}", e))?;

        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    // Rate limiting
                    if let Some(ref mut limiter) = self.rate_limiter {
                        limiter.wait_for(n);
                    }

                    file.write_all(&buffer[..n])
                        .map_err(|e| format!("Failed to write to file: {}", e))?;

                    self.stats.record_received(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(format!("Failed to read data: {}", e)),
            }
        }

        file.flush()
            .map_err(|e| format!("Failed to flush file: {}", e))?;

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(1000); // 1KB/s

        // Should allow first 1000 bytes
        assert!(limiter.check(500));
        assert!(limiter.check(500));

        // Should block next bytes in same second
        assert!(!limiter.check(100));

        // After waiting, should allow again
        std::thread::sleep(Duration::from_secs(1));
        assert!(limiter.check(500));
    }

    #[test]
    fn test_connection_stats() {
        let mut stats = ConnectionStats::new();

        stats.record_sent(1024);
        stats.record_received(2048);

        assert_eq!(stats.bytes_sent, 1024);
        assert_eq!(stats.bytes_received, 2048);
        assert_eq!(stats.total_bytes(), 3072);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(ConnectionStats::format_bytes(500), "500 B");
        assert_eq!(ConnectionStats::format_bytes(1536), "1.50 KB");
        assert_eq!(ConnectionStats::format_bytes(1_572_864), "1.50 MB");
        assert_eq!(ConnectionStats::format_bytes(1_610_612_736), "1.50 GB");
    }

    #[test]
    fn test_file_transfer_memory() {
        let mut transfer = FileTransfer::new(8192);

        // Create fake file data
        let file_data = b"Hello, World! This is test data.";
        let mut reader = Cursor::new(file_data);
        let mut writer = Vec::new();

        // Simulate sending
        let mut buffer = vec![0u8; transfer.buffer_size];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    writer.write_all(&buffer[..n]).unwrap();
                    transfer.stats.record_sent(n);
                }
                Err(_) => break,
            }
        }

        assert_eq!(writer, file_data);
        assert_eq!(transfer.stats.bytes_sent, file_data.len());
    }

    #[test]
    fn test_connection_logger() {
        let logger = ConnectionLogger::new(None, false);
        assert!(logger.is_ok());

        let mut logger = logger.unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Should not panic
        logger.log_connection(&addr, "connected");
        logger.log_data("sent", 1024);
        logger.log_error("test error");
    }
}
