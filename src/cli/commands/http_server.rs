//! HTTP Server CLI Command
//!
//! Built-in HTTP server for file serving and payload hosting.
//!
//! Usage:
//!   rb http server serve [path] [--port 8000] [--cors] [--no-dir-listing]
//!   rb http server list
//!   rb http server stop [port]

use crate::cli::commands::{print_help, Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::http_server::{HttpServer, HttpServerConfig};
use std::path::PathBuf;
use std::sync::Arc;

pub struct HttpServerCommand;

impl Command for HttpServerCommand {
    fn domain(&self) -> &str {
        "http"
    }

    fn resource(&self) -> &str {
        "server"
    }

    fn description(&self) -> &str {
        "Built-in HTTP server for file serving and payload hosting"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "serve",
                summary: "Start HTTP file server",
                usage: "rb http server serve [path] --port 8000",
            },
            Route {
                verb: "payloads",
                summary: "List available embedded payloads",
                usage: "rb http server payloads",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("port", "Port to listen on")
                .with_short('p')
                .with_default("8000"),
            Flag::new("host", "Host to bind to")
                .with_short('H')
                .with_default("0.0.0.0"),
            Flag::new("cors", "Enable CORS headers for all origins"),
            Flag::new("no-dir-listing", "Disable directory listing"),
            Flag::new("serve-self", "Enable /rb endpoint to serve redblue binary"),
            Flag::new("index", "Custom index file").with_default("index.html"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Serve current directory on port 8000",
                "rb http server serve",
            ),
            (
                "Serve specific directory on port 8080",
                "rb http server serve /var/www --port 8080",
            ),
            (
                "Serve with CORS enabled",
                "rb http server serve ./dist --cors",
            ),
            (
                "Serve redblue binary for download",
                "rb http server serve --serve-self",
            ),
            (
                "List available embedded payloads",
                "rb http server payloads",
            ),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_ref().ok_or_else(|| {
            print_help(self);
            "".to_string()
        })?;

        match verb.as_str() {
            "serve" => self.serve(ctx),
            "payloads" => self.list_payloads(ctx),
            "help" => {
                print_help(self);
                Ok(())
            }
            _ => {
                Output::error(&format!(
                    "Unknown verb '{}'. Use 'serve' or 'payloads'",
                    verb
                ));
                print_help(self);
                Err(format!("Unknown verb: {}", verb))
            }
        }
    }
}

impl HttpServerCommand {
    fn serve(&self, ctx: &CliContext) -> Result<(), String> {
        let port: u16 = ctx
            .get_flag_or("port", "8000")
            .parse()
            .map_err(|_| "Invalid port number")?;

        let host = ctx.get_flag_or("host", "0.0.0.0");
        let enable_cors = ctx.has_flag("cors");
        let disable_dir_listing = ctx.has_flag("no-dir-listing");
        let serve_self = ctx.has_flag("serve-self");
        let index_file = ctx.get_flag_or("index", "index.html");

        // Get root directory from target or use current directory
        let root_dir = ctx
            .target
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        // Build configuration
        let mut config = HttpServerConfig::new();
        config = config
            .port(port)
            .host(&host)
            .root_dir(&root_dir)
            .index_file(&index_file);

        if enable_cors {
            config = config.cors_all();
        }

        if disable_dir_listing {
            config = config.disable_dir_listing();
        }

        if serve_self {
            config = config.serve_self();
        }

        Output::header("HTTP Server");
        Output::item("Root", &format!("{}", root_dir.display()));
        Output::item("Address", &format!("http://{}:{}", host, port));
        Output::item("CORS", if enable_cors { "enabled" } else { "disabled" });
        Output::item(
            "Directory listing",
            if disable_dir_listing {
                "disabled"
            } else {
                "enabled"
            },
        );
        Output::item("Serve /rb", if serve_self { "enabled" } else { "disabled" });
        println!();
        Output::info("Built-in payloads:");
        Output::dim("  /hook.js   - Browser hook payload");
        if serve_self {
            Output::dim("  /rb        - redblue binary (self-replication)");
        }
        println!();
        Output::success(&format!("Starting server on http://{}:{} ...", host, port));
        Output::dim("Press Ctrl+C to stop");
        println!();

        // Create and start server
        let server = HttpServer::new(config);
        let server_ref = Arc::new(server);
        let server_for_signal = server_ref.clone();

        // Create shutdown signal handler
        ctrlc_handler(move || {
            server_for_signal.stop();
        });

        // Start server (blocking)
        server_ref
            .run()
            .map_err(|e| format!("Server error: {}", e))?;

        Output::success("Server stopped");
        Ok(())
    }

    fn list_payloads(&self, _ctx: &CliContext) -> Result<(), String> {
        use crate::modules::http_server::EmbeddedFiles;

        Output::header("Embedded Payloads");
        println!();

        for (path, content_type) in EmbeddedFiles::list() {
            println!("  \x1b[36m{:<15}\x1b[0m {}", path, content_type);
        }

        println!();
        Output::info("These payloads are embedded in the binary and always available.");
        Output::dim("Use 'rb http server serve --serve-self' to also serve the redblue binary.");

        Ok(())
    }
}

/// Simple Ctrl+C handler without external dependencies
fn ctrlc_handler<F>(handler: F)
where
    F: Fn() + Send + 'static,
{
    use std::thread;

    thread::spawn(move || {
        // Set up signal handler using libc
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGINT);
            libc::sigaddset(&mut mask, libc::SIGTERM);

            // Block signals in this thread so sigwait works
            libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());

            let mut sig: libc::c_int = 0;
            loop {
                if libc::sigwait(&mask, &mut sig) == 0 {
                    handler();
                    break;
                }
            }
        }
    });
}
