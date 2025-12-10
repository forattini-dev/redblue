//! Linux Service Manager
//!
//! Implements service installation via systemd (preferred) or cron fallback.

use super::{
    dirs, find_rb_binary, InstalledService, ServiceConfig, ServiceManager, ServiceStatus,
    templates,
};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;

/// Linux service manager using systemd or cron
pub struct LinuxServiceManager {
    /// Use user-level systemd (no root required)
    use_user_systemd: bool,
    /// Fallback to cron if systemd unavailable
    cron_fallback: bool,
}

impl LinuxServiceManager {
    pub fn new() -> Self {
        Self {
            use_user_systemd: true,
            cron_fallback: true,
        }
    }

    /// Check if systemd is available
    fn has_systemd(&self) -> bool {
        Command::new("systemctl")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if running as root
    fn is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// Get systemd service directory
    fn systemd_dir(&self) -> PathBuf {
        if self.is_root() {
            PathBuf::from("/etc/systemd/system")
        } else {
            dirs::home_dir()
                .unwrap_or_default()
                .join(".config/systemd/user")
        }
    }

    /// Get service file path
    fn service_path(&self, name: &str) -> PathBuf {
        self.systemd_dir().join(format!("{}.service", name))
    }

    /// Install using systemd
    fn install_systemd(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        let rb_path = find_rb_binary()?;
        let service_content = templates::systemd_service(config, rb_path.to_str().unwrap_or("rb"));

        // Create directory if needed
        let dir = self.systemd_dir();
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create systemd dir: {}", e))?;

        // Write service file
        let service_path = self.service_path(&config.name);
        fs::write(&service_path, &service_content)
            .map_err(|e| format!("Failed to write service file: {}", e))?;

        // Reload systemd
        let reload_cmd = if self.is_root() {
            Command::new("systemctl").arg("daemon-reload").output()
        } else {
            Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .output()
        };

        reload_cmd.map_err(|e| format!("Failed to reload systemd: {}", e))?;

        // Enable if auto-start requested
        if config.auto_start {
            let enable_cmd = if self.is_root() {
                Command::new("systemctl")
                    .args(["enable", &config.name])
                    .output()
            } else {
                Command::new("systemctl")
                    .args(["--user", "enable", &config.name])
                    .output()
            };

            enable_cmd.map_err(|e| format!("Failed to enable service: {}", e))?;
        }

        Ok(InstalledService {
            name: config.name.clone(),
            status: ServiceStatus::Stopped,
            description: config.description.clone(),
            config_path: service_path,
            installed_at: Some(Self::current_timestamp()),
        })
    }

    /// Install using cron @reboot
    fn install_cron(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        let rb_path = find_rb_binary()?;
        let (cmd, args) = config.service_type.to_command(rb_path.to_str().unwrap_or("rb"));
        let full_command = format!("{} {}", cmd, args.join(" "));

        // Read current crontab
        let current = Command::new("crontab")
            .arg("-l")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        // Check if already exists
        let marker = format!("# rb-service: {}", config.name);
        if current.contains(&marker) {
            return Err(format!("Service {} already exists in crontab", config.name));
        }

        // Add new entry
        let new_entry = format!(
            "{}\n@reboot {} # {}\n",
            marker, full_command, config.name
        );

        let new_crontab = format!("{}\n{}", current.trim(), new_entry);

        // Write new crontab
        let mut child = Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn crontab: {}", e))?;

        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(new_crontab.as_bytes())
                .map_err(|e| format!("Failed to write crontab: {}", e))?;
        }

        child
            .wait()
            .map_err(|e| format!("Failed to install crontab: {}", e))?;

        // Create a marker file for tracking
        let marker_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("redblue/services");
        fs::create_dir_all(&marker_dir).ok();
        let marker_path = marker_dir.join(format!("{}.cron", config.name));
        fs::write(&marker_path, &full_command).ok();

        Ok(InstalledService {
            name: config.name.clone(),
            status: ServiceStatus::Stopped,
            description: config.description.clone(),
            config_path: marker_path,
            installed_at: Some(Self::current_timestamp()),
        })
    }

    /// Uninstall cron service
    fn uninstall_cron(&self, name: &str) -> Result<(), String> {
        // Read current crontab
        let current = Command::new("crontab")
            .arg("-l")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        // Filter out lines for this service
        let marker = format!("# rb-service: {}", name);
        let new_crontab: Vec<&str> = current
            .lines()
            .filter(|line| !line.contains(&marker) && !line.ends_with(&format!("# {}", name)))
            .collect();

        let new_content = new_crontab.join("\n");

        // Write new crontab
        let mut child = Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn crontab: {}", e))?;

        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(new_content.as_bytes())
                .map_err(|e| format!("Failed to write crontab: {}", e))?;
        }

        child
            .wait()
            .map_err(|e| format!("Failed to update crontab: {}", e))?;

        // Remove marker file
        let marker_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("redblue/services");
        let marker_path = marker_dir.join(format!("{}.cron", name));
        fs::remove_file(&marker_path).ok();

        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}", secs)
    }

    /// Check if service is a cron-based service
    fn is_cron_service(&self, name: &str) -> bool {
        let marker_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("redblue/services");
        marker_dir.join(format!("{}.cron", name)).exists()
    }

    /// List cron-based services
    fn list_cron_services(&self) -> Vec<InstalledService> {
        let marker_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("redblue/services");

        let mut services = Vec::new();

        if let Ok(entries) = fs::read_dir(&marker_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "cron").unwrap_or(false) {
                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        let desc = fs::read_to_string(&path).ok();
                        services.push(InstalledService {
                            name: name.to_string(),
                            status: ServiceStatus::Unknown, // Cron jobs don't have real status
                            description: desc,
                            config_path: path,
                            installed_at: None,
                        });
                    }
                }
            }
        }

        services
    }
}

impl Default for LinuxServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for LinuxServiceManager {
    fn install(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        if self.has_systemd() {
            self.install_systemd(config)
        } else if self.cron_fallback {
            self.install_cron(config)
        } else {
            Err("systemd not available and cron fallback disabled".to_string())
        }
    }

    fn uninstall(&self, name: &str) -> Result<(), String> {
        // Check if cron-based first
        if self.is_cron_service(name) {
            return self.uninstall_cron(name);
        }

        // Stop service first
        self.stop(name).ok();

        // Disable service
        let disable_cmd = if self.is_root() {
            Command::new("systemctl")
                .args(["disable", name])
                .output()
        } else {
            Command::new("systemctl")
                .args(["--user", "disable", name])
                .output()
        };
        disable_cmd.ok();

        // Remove service file
        let service_path = self.service_path(name);
        if service_path.exists() {
            fs::remove_file(&service_path)
                .map_err(|e| format!("Failed to remove service file: {}", e))?;
        }

        // Reload systemd
        let reload_cmd = if self.is_root() {
            Command::new("systemctl").arg("daemon-reload").output()
        } else {
            Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .output()
        };
        reload_cmd.ok();

        Ok(())
    }

    fn start(&self, name: &str) -> Result<(), String> {
        if self.is_cron_service(name) {
            return Err("Cron services start on reboot only".to_string());
        }

        let output = if self.is_root() {
            Command::new("systemctl")
                .args(["start", name])
                .output()
        } else {
            Command::new("systemctl")
                .args(["--user", "start", name])
                .output()
        };

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
            Err(e) => Err(format!("Failed to start service: {}", e)),
        }
    }

    fn stop(&self, name: &str) -> Result<(), String> {
        if self.is_cron_service(name) {
            return Err("Cron services cannot be stopped (kill process manually)".to_string());
        }

        let output = if self.is_root() {
            Command::new("systemctl").args(["stop", name]).output()
        } else {
            Command::new("systemctl")
                .args(["--user", "stop", name])
                .output()
        };

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
            Err(e) => Err(format!("Failed to stop service: {}", e)),
        }
    }

    fn status(&self, name: &str) -> Result<ServiceStatus, String> {
        if self.is_cron_service(name) {
            return Ok(ServiceStatus::Unknown);
        }

        let output = if self.is_root() {
            Command::new("systemctl")
                .args(["is-active", name])
                .output()
        } else {
            Command::new("systemctl")
                .args(["--user", "is-active", name])
                .output()
        };

        match output {
            Ok(o) => {
                let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
                match status.as_str() {
                    "active" => Ok(ServiceStatus::Running),
                    "inactive" => Ok(ServiceStatus::Stopped),
                    "failed" => Ok(ServiceStatus::Failed),
                    _ => {
                        // Check if service file exists
                        if self.service_path(name).exists() {
                            Ok(ServiceStatus::Unknown)
                        } else {
                            Ok(ServiceStatus::NotFound)
                        }
                    }
                }
            }
            Err(_) => {
                if self.service_path(name).exists() {
                    Ok(ServiceStatus::Unknown)
                } else {
                    Ok(ServiceStatus::NotFound)
                }
            }
        }
    }

    fn list(&self) -> Result<Vec<InstalledService>, String> {
        let mut services = Vec::new();

        // List systemd services
        let dir = self.systemd_dir();
        if dir.exists() {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "service").unwrap_or(false) {
                        if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                            // Only list rb- prefixed services
                            if name.starts_with("rb-") {
                                let status = self.status(name).unwrap_or(ServiceStatus::Unknown);
                                let desc = self.parse_description(&path);
                                services.push(InstalledService {
                                    name: name.to_string(),
                                    status,
                                    description: desc,
                                    config_path: path,
                                    installed_at: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Add cron services
        services.extend(self.list_cron_services());

        Ok(services)
    }
}

impl LinuxServiceManager {
    /// Parse description from systemd service file
    fn parse_description(&self, path: &PathBuf) -> Option<String> {
        if let Ok(file) = fs::File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if line.starts_with("Description=") {
                    return Some(line.trim_start_matches("Description=").to_string());
                }
            }
        }
        None
    }
}
