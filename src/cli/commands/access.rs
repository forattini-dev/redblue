use crate::cli::commands::{Command, Flag, Route};
use crate::cli::{output::Output, CliContext};
use crate::accessors::Accessor;
use crate::accessors::file::FileAccessor;
use crate::accessors::process::ProcessAccessor;
use crate::accessors::network::NetworkAccessor;
use crate::accessors::service::ServiceAccessor;
use crate::accessors::registry::RegistryAccessor;
use std::collections::HashMap;

pub struct AccessCommand;

impl Command for AccessCommand {
    fn domain(&self) -> &str {
        "access"
    }

    fn resource(&self) -> &str {
        "system"
    }

    fn description(&self) -> &str {
        "System accessors for gathering information and interacting with the host"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "file",
                summary: "File system access (list, read, hash, search)",
                usage: "rb access system file <method> [args]",
            },
            Route {
                verb: "process",
                summary: "Process access (list, tree)",
                usage: "rb access system process <method> [args]",
            },
            Route {
                verb: "network",
                summary: "Network access (netstat, arp, routes, interfaces)",
                usage: "rb access system network <method> [args]",
            },
            Route {
                verb: "service",
                summary: "Service access (list, status)",
                usage: "rb access system service <method> [args]",
            },
            Route {
                verb: "registry",
                summary: "Registry access (Windows only)",
                usage: "rb access system registry <method> [args]",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("path", "Path for file/registry operations").with_short('p').with_arg("PATH"),
            Flag::new("pid", "Process ID").with_arg("PID"),
            Flag::new("pattern", "Search pattern").with_arg("PATTERN"),
            Flag::new("key", "Registry key").with_short('k').with_arg("KEY"),
            Flag::new("value", "Registry value").with_short('v').with_arg("VALUE"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            ("List files", "rb access system file list --path /tmp"),
            ("List processes", "rb access system process list"),
            ("Show network connections", "rb access system network connections"),
            ("List services", "rb access system service list"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().ok_or("Missing verb")?;
        
        // Map verb to accessor
        let accessor: Box<dyn Accessor> = match verb {
            "file" => Box::new(FileAccessor::new()),
            "process" => Box::new(ProcessAccessor::new()),
            "network" => Box::new(NetworkAccessor::new()),
            "service" => Box::new(ServiceAccessor::new()),
            "registry" => Box::new(RegistryAccessor::new()),
            _ => return Err(format!("Unknown accessor: {}", verb)),
        };

        // Method is the first argument after the verb
        let method = ctx.args.get(0).ok_or("Missing method")?;
        
        // Collect args into HashMap
        let mut args = HashMap::new();
        if let Some(path) = ctx.get_flag("path") { args.insert("path".to_string(), path); }
        if let Some(pid) = ctx.get_flag("pid") { args.insert("pid".to_string(), pid); }
        if let Some(pattern) = ctx.get_flag("pattern") { args.insert("pattern".to_string(), pattern); }
        if let Some(key) = ctx.get_flag("key") { args.insert("key".to_string(), key); }
        if let Some(value) = ctx.get_flag("value") { args.insert("value".to_string(), value); }
        
        // Add positional args as "arg0", "arg1", etc.
        for (i, arg) in ctx.args.iter().skip(1).enumerate() {
            args.insert(format!("arg{}", i), arg.clone());
        }

        let result = accessor.execute(method, &args);

        if result.success {
            if let Some(data) = result.data {
                if ctx.get_output_format() == crate::cli::format::OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                } else {
                    // Try to print somewhat nicely
                    if let Some(arr) = data.as_array() {
                        println!("Found {} items:", arr.len());
                        for item in arr.iter().take(20) {
                            println!("  {:?}", item);
                        }
                        if arr.len() > 20 {
                            println!("  ... and {} more", arr.len() - 20);
                        }
                    } else {
                        println!("{:?}", data);
                    }
                }
                Ok(())
            } else {
                Output::success("Operation completed successfully");
                Ok(())
            }
        } else {
            Err(result.error.unwrap_or_else(|| "Unknown error".to_string()))
        }
    }
}