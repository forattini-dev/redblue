//! Windows Service Manager
//!
//! Implements service installation via Registry Run keys and Scheduled Tasks.

use super::{
    dirs, find_rb_binary, InstalledService, ServiceConfig, ServiceManager, ServiceStatus,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Windows service manager using Registry and Scheduled Tasks
pub struct WindowsServiceManager {
    /// Use Registry Run keys (simpler, user-level)
    use_registry: bool,
    /// Use Scheduled Tasks (more powerful)
    use_scheduled_tasks: bool,
}

impl WindowsServiceManager {
    pub fn new() -> Self {
        Self {
            use_registry: true,
            use_scheduled_tasks: true,
        }
    }

    /// Get the marker directory for tracking installed services
    fn marker_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("redblue\\services")
    }

    /// Get marker file path for a service
    fn marker_path(name: &str) -> PathBuf {
        Self::marker_dir().join(format!("{}.service", name))
    }

    /// Install via Registry Run key
    fn install_registry(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        let rb_path = find_rb_binary()?;
        let (cmd, args) = config.service_type.to_command(rb_path.to_str().unwrap_or("rb"));
        let full_command = format!("\"{}\" {}", cmd, args.join(" "));

        // Use reg add command
        let output = Command::new("reg")
            .args([
                "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v",
                &config.name,
                "/t",
                "REG_SZ",
                "/d",
                &full_command,
                "/f",
            ])
            .output()
            .map_err(|e| format!("Failed to add registry key: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Registry add failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Create marker file
        let marker_dir = Self::marker_dir();
        fs::create_dir_all(&marker_dir).ok();
        let marker_path = Self::marker_path(&config.name);
        let marker_content = format!(
            "type=registry\ncommand={}\ndescription={}\n",
            full_command,
            config.description.as_deref().unwrap_or("")
        );
        fs::write(&marker_path, &marker_content).ok();

        Ok(InstalledService {
            name: config.name.clone(),
            status: ServiceStatus::Stopped,
            description: config.description.clone(),
            config_path: marker_path,
            installed_at: Some(Self::current_timestamp()),
        })
    }

    /// Install via Scheduled Task
    fn install_scheduled_task(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        let rb_path = find_rb_binary()?;
        let (cmd, args) = config.service_type.to_command(rb_path.to_str().unwrap_or("rb"));

        // Create scheduled task using schtasks
        let task_name = format!("redblue\\{}", config.name);

        let mut schtasks_args = vec![
            "/Create".to_string(),
            "/TN".to_string(),
            task_name.clone(),
            "/TR".to_string(),
            format!("\"{}\" {}", cmd, args.join(" ")),
            "/SC".to_string(),
            "ONLOGON".to_string(), // Run at login
            "/F".to_string(),      // Force overwrite
        ];

        // Add description if provided
        if let Some(desc) = &config.description {
            // schtasks doesn't have a direct description flag, we'll store it in marker
        }

        let output = Command::new("schtasks")
            .args(&schtasks_args)
            .output()
            .map_err(|e| format!("Failed to create scheduled task: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "schtasks failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Create marker file
        let marker_dir = Self::marker_dir();
        fs::create_dir_all(&marker_dir).ok();
        let marker_path = Self::marker_path(&config.name);
        let marker_content = format!(
            "type=scheduled_task\ntask_name={}\ndescription={}\n",
            task_name,
            config.description.as_deref().unwrap_or("")
        );
        fs::write(&marker_path, &marker_content).ok();

        Ok(InstalledService {
            name: config.name.clone(),
            status: ServiceStatus::Stopped,
            description: config.description.clone(),
            config_path: marker_path,
            installed_at: Some(Self::current_timestamp()),
        })
    }

    /// Check service type from marker file
    fn get_service_type(name: &str) -> Option<String> {
        let marker_path = Self::marker_path(name);
        if let Ok(content) = fs::read_to_string(&marker_path) {
            for line in content.lines() {
                if line.starts_with("type=") {
                    return Some(line.trim_start_matches("type=").to_string());
                }
            }
        }
        None
    }

    fn current_timestamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}", secs)
    }
}

impl Default for WindowsServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for WindowsServiceManager {
    fn install(&self, config: &ServiceConfig) -> Result<InstalledService, String> {
        // Prefer scheduled tasks for more control, fallback to registry
        if self.use_scheduled_tasks {
            self.install_scheduled_task(config)
        } else if self.use_registry {
            self.install_registry(config)
        } else {
            Err("No installation method enabled".to_string())
        }
    }

    fn uninstall(&self, name: &str) -> Result<(), String> {
        let service_type = Self::get_service_type(name);

        match service_type.as_deref() {
            Some("registry") => {
                // Remove from registry
                Command::new("reg")
                    .args([
                        "delete",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "/v",
                        name,
                        "/f",
                    ])
                    .output()
                    .ok();
            }
            Some("scheduled_task") => {
                // Remove scheduled task
                let task_name = format!("redblue\\{}", name);
                Command::new("schtasks")
                    .args(["/Delete", "/TN", &task_name, "/F"])
                    .output()
                    .ok();
            }
            _ => {
                // Try both
                Command::new("reg")
                    .args([
                        "delete",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "/v",
                        name,
                        "/f",
                    ])
                    .output()
                    .ok();

                let task_name = format!("redblue\\{}", name);
                Command::new("schtasks")
                    .args(["/Delete", "/TN", &task_name, "/F"])
                    .output()
                    .ok();
            }
        }

        // Remove marker file
        let marker_path = Self::marker_path(name);
        fs::remove_file(&marker_path).ok();

        Ok(())
    }

    fn start(&self, name: &str) -> Result<(), String> {
        let service_type = Self::get_service_type(name);

        match service_type.as_deref() {
            Some("scheduled_task") => {
                let task_name = format!("redblue\\{}", name);
                let output = Command::new("schtasks")
                    .args(["/Run", "/TN", &task_name])
                    .output()
                    .map_err(|e| format!("Failed to run task: {}", e))?;

                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).to_string())
                }
            }
            _ => Err("Registry-based services start on login only".to_string()),
        }
    }

    fn stop(&self, name: &str) -> Result<(), String> {
        let service_type = Self::get_service_type(name);

        match service_type.as_deref() {
            Some("scheduled_task") => {
                let task_name = format!("redblue\\{}", name);
                let output = Command::new("schtasks")
                    .args(["/End", "/TN", &task_name])
                    .output()
                    .map_err(|e| format!("Failed to stop task: {}", e))?;

                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).to_string())
                }
            }
            _ => Err("Registry-based services cannot be stopped (kill process manually)".to_string()),
        }
    }

    fn status(&self, name: &str) -> Result<ServiceStatus, String> {
        let marker_path = Self::marker_path(name);

        if !marker_path.exists() {
            return Ok(ServiceStatus::NotFound);
        }

        let service_type = Self::get_service_type(name);

        match service_type.as_deref() {
            Some("scheduled_task") => {
                let task_name = format!("redblue\\{}", name);
                let output = Command::new("schtasks")
                    .args(["/Query", "/TN", &task_name, "/FO", "LIST"])
                    .output();

                match output {
                    Ok(o) if o.status.success() => {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        if stdout.contains("Running") {
                            Ok(ServiceStatus::Running)
                        } else {
                            Ok(ServiceStatus::Stopped)
                        }
                    }
                    _ => Ok(ServiceStatus::Unknown),
                }
            }
            Some("registry") => {
                // Registry services don't have a running state we can query
                Ok(ServiceStatus::Unknown)
            }
            _ => Ok(ServiceStatus::Unknown),
        }
    }

    fn list(&self) -> Result<Vec<InstalledService>, String> {
        let mut services = Vec::new();

        let marker_dir = Self::marker_dir();
        if marker_dir.exists() {
            if let Ok(entries) = fs::read_dir(&marker_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "service").unwrap_or(false) {
                        if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
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

        Ok(services)
    }
}

impl WindowsServiceManager {
    fn parse_description(&self, path: &PathBuf) -> Option<String> {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if line.starts_with("description=") {
                    let desc = line.trim_start_matches("description=").to_string();
                    if !desc.is_empty() {
                        return Some(desc);
                    }
                }
            }
        }
        None
    }
}
