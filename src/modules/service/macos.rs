//! macOS Service Manager
//!
//! Implements service installation via launchd (LaunchAgents/LaunchDaemons).

use super::{
    dirs, find_rb_binary, templates, InstalledService, ServiceConfig, ServiceManager, ServiceStatus,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// macOS service manager using launchd
pub struct MacOSServiceManager {
    /// Use user-level LaunchAgents (no root required)
    use_user_agents: bool,
}

impl MacOSServiceManager {
    pub fn new() -> Self {
        Self {
            use_user_agents: true,
        }
    }

    /// Check if running as root
    fn is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// Get launchd directory
    fn launchd_dir(&self) -> PathBuf {
        if self.is_root() && !self.use_user_agents {
            PathBuf::from("/Library/LaunchDaemons")
        } else {
            dirs::home_dir()
                .unwrap_or_default()
                .join("Library/LaunchAgents")
        }
    }

    /// Get plist file path
    fn plist_path(&self, name: &str) -> PathBuf {
        self.launchd_dir()
            .join(format!("io.redblue.{}.plist", name))
    }

    /// Get launchd label
    fn label(&self, name: &str) -> String {
        format!("io.redblue.{}", name)
    }
}

impl Default for MacOSServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for MacOSServiceManager {
    fn install(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        let rb_path = find_rb_binary()?;
        let plist_content = templates::launchd_plist(config, rb_path.to_str().unwrap_or("rb"));

        // Create directory if needed
        let dir = self.launchd_dir();
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create LaunchAgents dir: {}", e))?;

        // Write plist file
        let plist_path = self.plist_path(&config.name);
        fs::write(&plist_path, &plist_content)
            .map_err(|e| format!("Failed to write plist file: {}", e))?;

        // Load if auto-start requested
        if config.auto_start {
            let _label = self.label(&config.name);
            Command::new("launchctl")
                .args(["load", "-w"])
                .arg(&plist_path)
                .output()
                .map_err(|e| format!("Failed to load service: {}", e))?;
        }

        Ok(InstalledService {
            name: config.name.clone(),
            status: ServiceStatus::Stopped,
            description: config.description.clone(),
            config_path: plist_path,
            installed_at: Some(Self::current_timestamp()),
        })
    }

    fn uninstall(&self, name: &str) -> Result<(), String> {
        let plist_path = self.plist_path(name);
        let _label = self.label(name);

        // Unload service
        Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&plist_path)
            .output()
            .ok();

        // Remove plist file
        if plist_path.exists() {
            fs::remove_file(&plist_path)
                .map_err(|e| format!("Failed to remove plist file: {}", e))?;
        }

        Ok(())
    }

    fn start(&self, name: &str) -> Result<(), String> {
        let label = self.label(name);

        let output = Command::new("launchctl").args(["start", &label]).output();

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
            Err(e) => Err(format!("Failed to start service: {}", e)),
        }
    }

    fn stop(&self, name: &str) -> Result<(), String> {
        let label = self.label(name);

        let output = Command::new("launchctl").args(["stop", &label]).output();

        match output {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
            Err(e) => Err(format!("Failed to stop service: {}", e)),
        }
    }

    fn status(&self, name: &str) -> Result<ServiceStatus, String> {
        let label = self.label(name);
        let plist_path = self.plist_path(name);

        if !plist_path.exists() {
            return Ok(ServiceStatus::NotFound);
        }

        // Check if service is loaded and running
        let output = Command::new("launchctl").args(["list", &label]).output();

        match output {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // launchctl list shows PID, exit status, label
                // If PID is not "-", service is running
                if stdout.lines().any(|l| {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    parts.len() >= 3 && parts[0] != "-"
                }) {
                    Ok(ServiceStatus::Running)
                } else {
                    Ok(ServiceStatus::Stopped)
                }
            }
            Ok(_) => Ok(ServiceStatus::Stopped),
            Err(_) => Ok(ServiceStatus::Unknown),
        }
    }

    fn list(&self) -> Result<Vec<InstalledService>, String> {
        let mut services = Vec::new();

        let dir = self.launchd_dir();
        if dir.exists() {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "plist").unwrap_or(false) {
                        if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                            // Only list io.redblue.* services
                            if filename.starts_with("io.redblue.") {
                                let name = filename.trim_start_matches("io.redblue.").to_string();
                                let status = self.status(&name).unwrap_or(ServiceStatus::Unknown);
                                services.push(InstalledService {
                                    name,
                                    status,
                                    description: None,
                                    config_path: path,
                                    installed_at: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(services)
    }
}

impl MacOSServiceManager {
    fn current_timestamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}", secs)
    }
}
