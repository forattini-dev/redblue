//! Service File Templates
//!
//! Templates for systemd, launchd, and other service configuration files.

use super::ServiceConfig;

/// Generate systemd service file content
pub fn systemd_service(config: &ServiceConfig, rb_path: &str) -> String {
    let (exec_cmd, exec_args) = config.service_type.to_command(rb_path);
    let exec_start = format!("{} {}", exec_cmd, exec_args.join(" "));

    let description = config.description.as_deref().unwrap_or("redblue service");

    let restart = if config.restart_on_failure {
        "Restart=on-failure\nRestartSec=5"
    } else {
        "Restart=no"
    };

    let working_dir = config
        .working_dir
        .as_ref()
        .map(|d| format!("WorkingDirectory={}", d.display()))
        .unwrap_or_default();

    let env_vars: String = config
        .env_vars
        .iter()
        .map(|(k, v)| format!("Environment=\"{}={}\"", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"[Unit]
Description={description}
After=network.target

[Service]
Type=simple
ExecStart={exec_start}
{working_dir}
{env_vars}
{restart}

[Install]
WantedBy=default.target
"#,
        description = description,
        exec_start = exec_start,
        working_dir = working_dir,
        env_vars = env_vars,
        restart = restart,
    )
    .lines()
    .filter(|line| !line.is_empty() || line.starts_with('['))
    .collect::<Vec<_>>()
    .join("\n")
}

/// Generate launchd plist content
pub fn launchd_plist(config: &ServiceConfig, rb_path: &str) -> String {
    let (exec_cmd, exec_args) = config.service_type.to_command(rb_path);

    let label = format!("io.redblue.{}", config.name);

    let _description = config.description.as_deref().unwrap_or("redblue service");

    let keep_alive = if config.restart_on_failure {
        "<key>KeepAlive</key>\n\t<true/>"
    } else {
        ""
    };

    let run_at_load = if config.auto_start {
        "<key>RunAtLoad</key>\n\t<true/>"
    } else {
        ""
    };

    let working_dir = config
        .working_dir
        .as_ref()
        .map(|d| {
            format!(
                "<key>WorkingDirectory</key>\n\t<string>{}</string>",
                d.display()
            )
        })
        .unwrap_or_default();

    let env_vars: String = if config.env_vars.is_empty() {
        String::new()
    } else {
        let vars: String = config
            .env_vars
            .iter()
            .map(|(k, v)| format!("\t\t<key>{}</key>\n\t\t<string>{}</string>", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "<key>EnvironmentVariables</key>\n\t<dict>\n{}\n\t</dict>",
            vars
        )
    };

    // Build program arguments array
    let mut args = vec![format!("<string>{}</string>", exec_cmd)];
    for arg in &exec_args {
        args.push(format!("<string>{}</string>", arg));
    }
    let program_args = args.join("\n\t\t");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		{program_args}
	</array>
	{run_at_load}
	{keep_alive}
	{working_dir}
	{env_vars}
	<key>StandardOutPath</key>
	<string>/tmp/{name}.out.log</string>
	<key>StandardErrorPath</key>
	<string>/tmp/{name}.err.log</string>
</dict>
</plist>
"#,
        label = label,
        program_args = program_args,
        run_at_load = run_at_load,
        keep_alive = keep_alive,
        working_dir = working_dir,
        env_vars = env_vars,
        name = config.name,
    )
}

/// Generate cron @reboot entry
pub fn cron_entry(config: &ServiceConfig, rb_path: &str) -> String {
    let (exec_cmd, exec_args) = config.service_type.to_command(rb_path);
    format!(
        "# rb-service: {}\n@reboot {} {} # {}",
        config.name,
        exec_cmd,
        exec_args.join(" "),
        config.name
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::service::{ListenerProtocol, ServiceType};

    #[test]
    fn test_systemd_service_template() {
        let config = ServiceConfig::new(ServiceType::MitmProxy {
            port: 8080,
            upstream: None,
        });

        let content = systemd_service(&config, "/usr/local/bin/rb");
        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Service]"));
        assert!(content.contains("[Install]"));
        assert!(content.contains("mitm"));
        assert!(content.contains("8080"));
    }

    #[test]
    fn test_launchd_plist_template() {
        let config = ServiceConfig::new(ServiceType::Listener {
            port: 4444,
            protocol: ListenerProtocol::Tcp,
        });

        let content = launchd_plist(&config, "/usr/local/bin/rb");
        assert!(content.contains("<!DOCTYPE plist"));
        assert!(content.contains("io.redblue.rb-listener"));
        assert!(content.contains("4444"));
    }

    #[test]
    fn test_cron_entry() {
        let config = ServiceConfig::new(ServiceType::DnsServer {
            port: 5353,
            upstream: "8.8.8.8".to_string(),
        });

        let entry = cron_entry(&config, "/usr/local/bin/rb");
        assert!(entry.contains("@reboot"));
        assert!(entry.contains("dns serve"));
        assert!(entry.contains("5353"));
    }
}
