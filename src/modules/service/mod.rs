//! Service Manager Module
//!
//! Cross-platform service installation for persistent redblue services.
//! Supports Linux (systemd/cron), macOS (launchd), and Windows (Registry/Tasks).
//!
//! # Usage
//! ```bash
//! rb service manage install mitm-proxy --port 8080
//! rb service manage list
//! rb service manage status rb-mitm-proxy
//! rb service manage uninstall rb-mitm-proxy
//! ```

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod templates;
#[cfg(target_os = "windows")]
pub mod windows;

use std::collections::HashMap;
use std::path::PathBuf;

/// Listener protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerProtocol {
    Tcp,
    Udp,
    Http,
    Https,
}

impl ListenerProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ListenerProtocol::Tcp => "tcp",
            ListenerProtocol::Udp => "udp",
            ListenerProtocol::Http => "http",
            ListenerProtocol::Https => "https",
        }
    }
}

/// Service types that can be installed
#[derive(Debug, Clone)]
pub enum ServiceType {
    /// MITM proxy service
    MitmProxy { port: u16, upstream: Option<String> },
    /// HTTP file server
    HttpServer { port: u16, root: PathBuf },
    /// DNS server
    DnsServer { port: u16, upstream: String },
    /// Reverse shell listener
    Listener {
        port: u16,
        protocol: ListenerProtocol,
    },
    /// Hooks/scripts server
    HooksServer { port: u16, scripts_dir: PathBuf },
    /// Custom command
    Custom { command: String, args: Vec<String> },
}

impl ServiceType {
    /// Get the default service name prefix for this type
    pub fn default_name(&self) -> String {
        match self {
            ServiceType::MitmProxy { port, .. } => format!("rb-mitm-{}", port),
            ServiceType::HttpServer { port, .. } => format!("rb-http-{}", port),
            ServiceType::DnsServer { port, .. } => format!("rb-dns-{}", port),
            ServiceType::Listener { port, protocol } => {
                format!("rb-listener-{}-{}", protocol.as_str(), port)
            }
            ServiceType::HooksServer { port, .. } => format!("rb-hooks-{}", port),
            ServiceType::Custom { command, .. } => {
                let name = command.split('/').last().unwrap_or("custom");
                format!("rb-{}", name)
            }
        }
    }

    /// Get the command and arguments to run this service
    pub fn to_command(&self, rb_path: &str) -> (String, Vec<String>) {
        match self {
            ServiceType::MitmProxy { port, upstream } => {
                let mut args = vec![
                    "mitm".to_string(),
                    "intercept".to_string(),
                    "start".to_string(),
                    "--port".to_string(),
                    port.to_string(),
                ];
                if let Some(up) = upstream {
                    args.push("--upstream".to_string());
                    args.push(up.clone());
                }
                (rb_path.to_string(), args)
            }
            ServiceType::HttpServer { port, root } => {
                let args = vec![
                    "web".to_string(),
                    "serve".to_string(),
                    "--port".to_string(),
                    port.to_string(),
                    "--root".to_string(),
                    root.display().to_string(),
                ];
                (rb_path.to_string(), args)
            }
            ServiceType::DnsServer { port, upstream } => {
                let args = vec![
                    "dns".to_string(),
                    "serve".to_string(),
                    "--port".to_string(),
                    port.to_string(),
                    "--upstream".to_string(),
                    upstream.clone(),
                ];
                (rb_path.to_string(), args)
            }
            ServiceType::Listener { port, protocol } => {
                let args = vec![
                    "exploit".to_string(),
                    "payload".to_string(),
                    "listener".to_string(),
                    protocol.as_str().to_string(),
                    port.to_string(),
                ];
                (rb_path.to_string(), args)
            }
            ServiceType::HooksServer { port, scripts_dir } => {
                let args = vec![
                    "hooks".to_string(),
                    "serve".to_string(),
                    "--port".to_string(),
                    port.to_string(),
                    "--scripts".to_string(),
                    scripts_dir.display().to_string(),
                ];
                (rb_path.to_string(), args)
            }
            ServiceType::Custom { command, args } => (command.clone(), args.clone()),
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            ServiceType::MitmProxy { port, upstream } => {
                let up = upstream.as_deref().unwrap_or("direct");
                format!("MITM Proxy on port {} (upstream: {})", port, up)
            }
            ServiceType::HttpServer { port, root } => {
                format!("HTTP Server on port {} serving {}", port, root.display())
            }
            ServiceType::DnsServer { port, upstream } => {
                format!("DNS Server on port {} (upstream: {})", port, upstream)
            }
            ServiceType::Listener { port, protocol } => {
                format!(
                    "{} Listener on port {}",
                    protocol.as_str().to_uppercase(),
                    port
                )
            }
            ServiceType::HooksServer { port, scripts_dir } => {
                format!(
                    "Hooks Server on port {} (scripts: {})",
                    port,
                    scripts_dir.display()
                )
            }
            ServiceType::Custom { command, args } => {
                format!("Custom: {} {}", command, args.join(" "))
            }
        }
    }
}

/// Configuration for a service to be installed
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Unique service name
    pub name: String,
    /// Service type with specific parameters
    pub service_type: ServiceType,
    /// Start service automatically on boot
    pub auto_start: bool,
    /// Restart on failure
    pub restart_on_failure: bool,
    /// Working directory (optional)
    pub working_dir: Option<PathBuf>,
    /// Environment variables
    pub env_vars: HashMap<String, String>,
    /// Description for the service
    pub description: Option<String>,
}

impl ServiceConfig {
    /// Create a new service configuration
    pub fn new(service_type: ServiceType) -> Self {
        let name = service_type.default_name();
        let description = Some(service_type.description());
        Self {
            name,
            service_type,
            auto_start: true,
            restart_on_failure: true,
            working_dir: None,
            env_vars: HashMap::new(),
            description,
        }
    }

    /// Set custom service name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set auto-start on boot
    pub fn with_auto_start(mut self, auto_start: bool) -> Self {
        self.auto_start = auto_start;
        self
    }

    /// Set restart on failure
    pub fn with_restart(mut self, restart: bool) -> Self {
        self.restart_on_failure = restart;
        self
    }

    /// Set working directory
    pub fn with_working_dir(mut self, dir: PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
    }

    /// Add environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Service status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Service is running
    Running,
    /// Service is stopped
    Stopped,
    /// Service failed
    Failed,
    /// Status unknown
    Unknown,
    /// Service not found
    NotFound,
}

impl ServiceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceStatus::Running => "running",
            ServiceStatus::Stopped => "stopped",
            ServiceStatus::Failed => "failed",
            ServiceStatus::Unknown => "unknown",
            ServiceStatus::NotFound => "not found",
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, ServiceStatus::Running)
    }
}

/// Information about an installed service
#[derive(Debug, Clone)]
pub struct InstalledService {
    /// Service name
    pub name: String,
    /// Current status
    pub status: ServiceStatus,
    /// Service description
    pub description: Option<String>,
    /// Path to service file
    pub config_path: PathBuf,
    /// When the service was installed
    pub installed_at: Option<String>,
}

/// Service manager trait - platform-specific implementations
pub trait ServiceManager {
    /// Install a new service
    fn install(&self, config: &ServiceConfig) -> Result<InstalledService, String>;

    /// Uninstall a service by name
    fn uninstall(&self, name: &str) -> Result<(), String>;

    /// Start a service
    fn start(&self, name: &str) -> Result<(), String>;

    /// Stop a service
    fn stop(&self, name: &str) -> Result<(), String>;

    /// Restart a service
    fn restart(&self, name: &str) -> Result<(), String> {
        self.stop(name)?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        self.start(name)
    }

    /// Get service status
    fn status(&self, name: &str) -> Result<ServiceStatus, String>;

    /// List all installed redblue services
    fn list(&self) -> Result<Vec<InstalledService>, String>;

    /// Check if a service exists
    fn exists(&self, name: &str) -> bool {
        !matches!(self.status(name), Ok(ServiceStatus::NotFound) | Err(_))
    }
}

/// Get the appropriate service manager for the current platform
pub fn get_service_manager() -> Box<dyn ServiceManager> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxServiceManager::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSServiceManager::new())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsServiceManager::new())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        compile_error!("Unsupported platform for service manager")
    }
}

/// Find the path to the redblue binary
pub fn find_rb_binary() -> Result<PathBuf, String> {
    // First try current executable
    if let Ok(exe) = std::env::current_exe() {
        if exe.exists() {
            return Ok(exe);
        }
    }

    // Try common installation paths
    let paths = [
        PathBuf::from("/usr/local/bin/rb"),
        PathBuf::from("/usr/bin/rb"),
        dirs::home_dir()
            .map(|h| h.join(".local/bin/rb"))
            .unwrap_or_default(),
        dirs::home_dir()
            .map(|h| h.join(".cargo/bin/rb"))
            .unwrap_or_default(),
    ];

    for path in &paths {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    // Try PATH
    if let Ok(output) = std::process::Command::new("which").arg("rb").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err("Could not find rb binary. Please install it first.".to_string())
}

/// Simple home directory finder without external crates
mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .map(PathBuf::from)
    }

    pub fn config_dir() -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| home_dir().map(|h| h.join(".config")))
        }

        #[cfg(target_os = "macos")]
        {
            home_dir().map(|h| h.join("Library/Application Support"))
        }

        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA").ok().map(PathBuf::from)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            home_dir().map(|h| h.join(".config"))
        }
    }
}
