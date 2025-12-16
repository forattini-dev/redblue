// C2 Agent Interactive Shell
// REPL interface for controlling connected agents

use crate::agent::protocol::AgentCommand;
use crate::agent::server::{AgentServer, SessionStatus};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Global command counter for unique IDs
static COMMAND_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique command ID
fn generate_command_id() -> String {
    let count = COMMAND_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("cmd-{}-{}", timestamp, count)
}

/// ANSI color codes
mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const CYAN: &str = "\x1b[36m";
    pub const MAGENTA: &str = "\x1b[35m";
}

/// C2 Agent Shell state
pub struct AgentShell {
    server: Arc<Mutex<AgentServer>>,
    selected_agent: Option<String>,
    command_history: Vec<String>,
    running: bool,
}

impl AgentShell {
    pub fn new(server: Arc<Mutex<AgentServer>>) -> Self {
        Self {
            server,
            selected_agent: None,
            command_history: Vec::new(),
            running: true,
        }
    }

    /// Run the interactive shell
    pub fn run(&mut self) -> Result<(), String> {
        self.print_banner();

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        while self.running {
            // Print prompt
            self.print_prompt(&mut stdout);
            stdout.flush().ok();

            // Read input
            let mut input = String::new();
            if stdin.lock().read_line(&mut input).is_err() {
                break;
            }

            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            // Save to history
            self.command_history.push(input.to_string());

            // Parse and execute command
            if let Err(e) = self.execute_command(input) {
                println!("{}Error: {}{}", colors::RED, e, colors::RESET);
            }
        }

        println!("\n{}Goodbye!{}", colors::CYAN, colors::RESET);
        Ok(())
    }

    fn print_banner(&self) {
        println!(
            "{}",
            r#"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██████╗ ███████╗██████╗ ██████╗ ██╗     ██╗   ██╗███████╗       ║
║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║     ██║   ██║██╔════╝       ║
║   ██████╔╝█████╗  ██║  ██║██████╔╝██║     ██║   ██║█████╗         ║
║   ██╔══██╗██╔══╝  ██║  ██║██╔══██╗██║     ██║   ██║██╔══╝         ║
║   ██║  ██║███████╗██████╔╝██████╔╝███████╗╚██████╔╝███████╗       ║
║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝       ║
║                                                                   ║
║                    C2 Agent Control Shell                         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"#
        );

        println!(
            "{}Type 'help' for available commands{}\n",
            colors::DIM, colors::RESET
        );
    }

    fn print_prompt(&self, stdout: &mut io::Stdout) {
        if let Some(ref agent_id) = self.selected_agent {
            let short_id = if agent_id.len() > 8 {
                &agent_id[..8]
            } else {
                agent_id
            };
            print!(
                "{}[{}{}{}]{}> ",
                colors::CYAN,
                colors::GREEN,
                short_id,
                colors::CYAN,
                colors::RESET
            );
        } else {
            print!("{}rb-c2{}> ", colors::CYAN, colors::RESET);
        }
        stdout.flush().ok();
    }

    fn execute_command(&mut self, input: &str) -> Result<(), String> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        let cmd = parts[0].to_lowercase();
        let args = &parts[1..];

        match cmd.as_str() {
            "help" | "?" | "h" => self.cmd_help(),
            "quit" | "exit" | "q" => {
                self.running = false;
                Ok(())
            }
            "agents" | "list" | "ls" => self.cmd_list_agents(),
            "select" | "use" | "interact" => self.cmd_select_agent(args),
            "deselect" | "back" | "bg" => self.cmd_deselect_agent(),
            "info" => self.cmd_agent_info(args),
            "shell" | "exec" | "!" => self.cmd_shell(args),
            "upload" => self.cmd_upload(args),
            "download" => self.cmd_download(args),
            "ps" | "processes" => self.cmd_processes(),
            "netstat" | "connections" => self.cmd_netstat(),
            "services" => self.cmd_services(),
            "files" | "ls-files" => self.cmd_list_files(args),
            "cat" | "read" => self.cmd_read_file(args),
            "hash" => self.cmd_hash_file(args),
            "kill" => self.cmd_kill_agent(args),
            "responses" | "output" => self.cmd_get_responses(),
            "clear" | "cls" => {
                print!("\x1b[2J\x1b[H");
                Ok(())
            }
            "status" => self.cmd_status(),
            "sleep" => self.cmd_sleep(args),
            "jitter" => self.cmd_jitter(args),
            "playbook" => self.cmd_playbook(args),
            _ => {
                // If agent is selected, treat as shell command
                if self.selected_agent.is_some() {
                    self.cmd_shell(&parts)
                } else {
                    Err(format!("Unknown command: {}. Type 'help' for usage.", cmd))
                }
            }
        }
    }

    fn cmd_help(&self) -> Result<(), String> {
        let b = colors::BOLD;
        let r = colors::RESET;
        let d = colors::DIM;
        let y = colors::YELLOW;
        let g = colors::GREEN;
        let c = colors::CYAN;

        println!(
            "
{b}C2 Agent Shell Commands{r}
{d}════════════════════════{r}

{y}Agent Management:{r}
  {g}agents{r}, {g}list{r}, {g}ls{r}          List all connected agents
  {g}select{r} <id>              Select an agent to interact with
  {g}deselect{r}, {g}back{r}           Deselect current agent
  {g}info{r} [id]                Show detailed agent info
  {g}kill{r} <id>                Disconnect and remove an agent
  {g}status{r}                   Show server status

{y}Command Execution (requires selected agent):{r}
  {g}shell{r} <cmd>, {g}exec{r} <cmd>   Execute shell command on agent
  {g}!{r}<cmd>                    Shorthand for shell command

{y}File Operations:{r}
  {g}files{r} [path]             List files in directory
  {g}cat{r} <path>               Read file contents
  {g}hash{r} <path> [algo]       Calculate file hash (md5/sha1/sha256)
  {g}upload{r} <local> <remote>  Upload file to agent
  {g}download{r} <remote> <local> Download file from agent

{y}System Information:{r}
  {g}ps{r}, {g}processes{r}           List running processes
  {g}netstat{r}, {g}connections{r}    List network connections
  {g}services{r}                 List system services

{y}Agent Configuration:{r}
  {g}sleep{r} <seconds>          Set agent beacon interval
  {g}jitter{r} <0.0-1.0>         Set jitter percentage

{y}Automation:{r}
  {g}playbook{r} <name>          Execute playbook on agent

{y}General:{r}
  {g}responses{r}, {g}output{r}        Show pending responses from agent
  {g}clear{r}, {g}cls{r}               Clear screen
  {g}help{r}, {g}?{r}                  Show this help
  {g}quit{r}, {g}exit{r}, {g}q{r}            Exit the shell

{d}Tips:{r}
  - When an agent is selected, unknown commands are executed as shell commands
  - Use {c}Tab{r} for command completion (coming soon)
  - Agent IDs can be abbreviated to their first 8 characters
"
        );
        Ok(())
    }

    fn cmd_list_agents(&self) -> Result<(), String> {
        let server = self.server.lock().unwrap();
        let agents = server.list_agents();

        if agents.is_empty() {
            println!(
                "{}No agents connected{}",
                colors::YELLOW, colors::RESET
            );
            return Ok(());
        }

        println!(
            "\n{}  {:<12} {:<20} {:<15} {:<12} {:<15}{}",
            colors::BOLD,
            "ID",
            "HOSTNAME",
            "OS",
            "STATUS",
            "LAST SEEN",
            colors::RESET
        );
        println!("{}", "─".repeat(80));

        for agent in agents {
            let short_id = if agent.id.len() > 12 {
                format!("{}...", &agent.id[..9])
            } else {
                agent.id.clone()
            };

            let status_color = match agent.status {
                SessionStatus::Active => colors::GREEN,
                SessionStatus::Dormant => colors::YELLOW,
                SessionStatus::Dead => colors::RED,
            };

            let status_str = match agent.status {
                SessionStatus::Active => "Active",
                SessionStatus::Dormant => "Dormant",
                SessionStatus::Dead => "Dead",
            };

            let last_seen = self.format_last_seen(agent.last_seen);

            let selected_marker = if Some(&agent.id) == self.selected_agent.as_ref() {
                format!("{}*{}", colors::GREEN, colors::RESET)
            } else {
                " ".to_string()
            };

            println!(
                "{} {:<12} {:<20} {:<15} {}{:<12}{} {:<15}",
                selected_marker,
                short_id,
                truncate(&agent.hostname, 20),
                truncate(&agent.os, 15),
                status_color,
                status_str,
                colors::RESET,
                last_seen
            );
        }
        println!();

        Ok(())
    }

    fn cmd_select_agent(&mut self, args: &[&str]) -> Result<(), String> {
        if args.is_empty() {
            return Err("Usage: select <agent_id>".to_string());
        }

        let id_prefix = args[0];
        let server = self.server.lock().unwrap();
        let agents = server.list_agents();

        // Find agent by ID or prefix
        let matching: Vec<_> = agents
            .iter()
            .filter(|a| a.id.starts_with(id_prefix) || a.id == id_prefix)
            .collect();

        match matching.len() {
            0 => Err(format!("No agent found matching '{}'", id_prefix)),
            1 => {
                self.selected_agent = Some(matching[0].id.clone());
                println!(
                    "{}Selected agent: {}{}",
                    colors::GREEN, matching[0].id, colors::RESET
                );
                println!(
                    "  Hostname: {}, OS: {}",
                    matching[0].hostname, matching[0].os
                );
                Ok(())
            }
            _ => {
                println!("Multiple agents match '{}':", id_prefix);
                for a in matching {
                    println!("  - {}", a.id);
                }
                Err("Please provide a more specific ID".to_string())
            }
        }
    }

    fn cmd_deselect_agent(&mut self) -> Result<(), String> {
        if self.selected_agent.is_some() {
            self.selected_agent = None;
            println!("{}Agent deselected{}", colors::YELLOW, colors::RESET);
        }
        Ok(())
    }

    fn cmd_agent_info(&self, args: &[&str]) -> Result<(), String> {
        let agent_id = if !args.is_empty() {
            args[0].to_string()
        } else if let Some(ref id) = self.selected_agent {
            id.clone()
        } else {
            return Err("No agent selected. Use: info <agent_id>".to_string());
        };

        let server = self.server.lock().unwrap();
        let agent = server
            .get_agent(&agent_id)
            .or_else(|| {
                // Try prefix match
                server
                    .list_agents()
                    .into_iter()
                    .find(|a| a.id.starts_with(&agent_id))
            })
            .ok_or_else(|| format!("Agent '{}' not found", agent_id))?;

        println!("\n{}Agent Information{}", colors::BOLD, colors::RESET);
        println!("{}", "─".repeat(40));
        println!("{}ID:{}        {}", colors::CYAN, colors::RESET, agent.id);
        println!(
            "{}Hostname:{} {}",
            colors::CYAN, colors::RESET, agent.hostname
        );
        println!("{}OS:{}        {}", colors::CYAN, colors::RESET, agent.os);

        let status_color = match agent.status {
            SessionStatus::Active => colors::GREEN,
            SessionStatus::Dormant => colors::YELLOW,
            SessionStatus::Dead => colors::RED,
        };
        let status_str = match agent.status {
            SessionStatus::Active => "Active",
            SessionStatus::Dormant => "Dormant",
            SessionStatus::Dead => "Dead",
        };
        println!(
            "{}Status:{}    {}{}{}",
            colors::CYAN, colors::RESET, status_color, status_str, colors::RESET
        );

        println!(
            "{}Last Seen:{} {}",
            colors::CYAN,
            colors::RESET,
            self.format_last_seen(agent.last_seen)
        );
        println!(
            "{}Pending Commands:{} {}",
            colors::CYAN,
            colors::RESET,
            agent.command_queue.len()
        );
        println!(
            "{}Pending Responses:{} {}",
            colors::CYAN,
            colors::RESET,
            agent.response_queue.len()
        );
        println!();

        Ok(())
    }

    fn cmd_shell(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected. Use 'select <id>' first.")?
            .clone();

        if args.is_empty() {
            return Err("Usage: shell <command>".to_string());
        }

        let command = args.join(" ");
        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "shell".to_string(),
            args: vec![command.clone()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Command queued: {}",
            colors::GREEN, colors::RESET, command
        );
        println!(
            "{}    Use 'responses' to see output when agent checks in{}",
            colors::DIM, colors::RESET
        );

        Ok(())
    }

    fn cmd_upload(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.len() < 2 {
            return Err("Usage: upload <local_path> <remote_path>".to_string());
        }

        let local_path = args[0];
        let remote_path = args[1];

        // Read local file and encode as base64
        let data = std::fs::read(local_path)
            .map_err(|e| format!("Failed to read {}: {}", local_path, e))?;

        // Encode data as hex for transport
        let data_hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "upload".to_string(),
            args: vec![remote_path.to_string(), data_hex],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Upload queued: {} -> {}",
            colors::GREEN, colors::RESET, local_path, remote_path
        );

        Ok(())
    }

    fn cmd_download(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.is_empty() {
            return Err("Usage: download <remote_path> [local_path]".to_string());
        }

        let remote_path = args[0];
        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "download".to_string(),
            args: vec![remote_path.to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Download queued: {}",
            colors::GREEN, colors::RESET, remote_path
        );
        println!(
            "{}    File will be in responses when agent checks in{}",
            colors::DIM, colors::RESET
        );

        Ok(())
    }

    fn cmd_processes(&mut self) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "accessor".to_string(),
            args: vec!["process".to_string(), "list".to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Process list requested",
            colors::GREEN, colors::RESET
        );

        Ok(())
    }

    fn cmd_netstat(&mut self) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "accessor".to_string(),
            args: vec!["network".to_string(), "connections".to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Network connections requested",
            colors::GREEN, colors::RESET
        );

        Ok(())
    }

    fn cmd_services(&mut self) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "accessor".to_string(),
            args: vec!["service".to_string(), "list".to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Services list requested",
            colors::GREEN, colors::RESET
        );

        Ok(())
    }

    fn cmd_list_files(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        let path = args.first().copied().unwrap_or(".");

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "accessor".to_string(),
            args: vec!["file".to_string(), "list".to_string(), path.to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} File list requested for: {}",
            colors::GREEN, colors::RESET, path
        );

        Ok(())
    }

    fn cmd_read_file(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.is_empty() {
            return Err("Usage: cat <path>".to_string());
        }

        let path = args[0];

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "accessor".to_string(),
            args: vec!["file".to_string(), "read".to_string(), path.to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} File read requested: {}",
            colors::GREEN, colors::RESET, path
        );

        Ok(())
    }

    fn cmd_hash_file(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.is_empty() {
            return Err("Usage: hash <path> [algorithm]".to_string());
        }

        let path = args[0];
        let algo = args.get(1).copied().unwrap_or("sha256");

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "accessor".to_string(),
            args: vec![
                "file".to_string(),
                "hash".to_string(),
                path.to_string(),
                algo.to_string(),
            ],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Hash requested ({}) for: {}",
            colors::GREEN, colors::RESET, algo, path
        );

        Ok(())
    }

    fn cmd_kill_agent(&mut self, args: &[&str]) -> Result<(), String> {
        if args.is_empty() {
            return Err("Usage: kill <agent_id>".to_string());
        }

        let id_prefix = args[0];
        let server = self.server.lock().unwrap();
        let agents = server.list_agents();

        // Find agent
        let agent = agents
            .iter()
            .find(|a| a.id.starts_with(id_prefix) || a.id == id_prefix)
            .ok_or_else(|| format!("Agent '{}' not found", id_prefix))?;

        let agent_id = agent.id.clone();
        drop(server); // Release lock before re-acquiring

        let server = self.server.lock().unwrap();
        server.remove_agent(&agent_id);

        // Deselect if this was the selected agent
        if self.selected_agent.as_ref() == Some(&agent_id) {
            self.selected_agent = None;
        }

        println!(
            "{}[+]{} Agent {} removed",
            colors::GREEN, colors::RESET, agent_id
        );

        Ok(())
    }

    fn cmd_get_responses(&self) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?;

        let server = self.server.lock().unwrap();
        let responses = server.get_responses(agent_id);

        if responses.is_empty() {
            println!(
                "{}No pending responses from agent{}",
                colors::YELLOW, colors::RESET
            );
            return Ok(());
        }

        println!(
            "\n{}Responses from agent {}{}",
            colors::BOLD, agent_id, colors::RESET
        );
        println!("{}", "─".repeat(60));

        for resp in responses {
            let status_icon = if resp.success {
                format!("{}✓{}", colors::GREEN, colors::RESET)
            } else {
                format!("{}✗{}", colors::RED, colors::RESET)
            };

            println!("{} Command ID: {}", status_icon, resp.command_id);

            if !resp.output.is_empty() {
                println!("{}Output:{}", colors::CYAN, colors::RESET);
                // Try to pretty print if it looks like JSON
                if resp.output.starts_with('{') || resp.output.starts_with('[') {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.output) {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap_or(resp.output.clone()));
                    } else {
                        println!("{}", resp.output);
                    }
                } else {
                    println!("{}", resp.output);
                }
            }

            if let Some(ref err) = resp.error {
                println!("{}Error:{} {}", colors::RED, colors::RESET, err);
            }

            println!();
        }

        Ok(())
    }

    fn cmd_status(&self) -> Result<(), String> {
        let server = self.server.lock().unwrap();
        let agents = server.list_agents();

        let active = agents
            .iter()
            .filter(|a| a.status == SessionStatus::Active)
            .count();
        let dormant = agents
            .iter()
            .filter(|a| a.status == SessionStatus::Dormant)
            .count();
        let dead = agents
            .iter()
            .filter(|a| a.status == SessionStatus::Dead)
            .count();

        println!("\n{}Server Status{}", colors::BOLD, colors::RESET);
        println!("{}", "─".repeat(30));
        println!("Total Agents:   {}", agents.len());
        println!(
            "{}Active:{}         {}",
            colors::GREEN, colors::RESET, active
        );
        println!(
            "{}Dormant:{}        {}",
            colors::YELLOW, colors::RESET, dormant
        );
        println!("{}Dead:{}           {}", colors::RED, colors::RESET, dead);

        if let Some(ref agent_id) = self.selected_agent {
            let short_id = if agent_id.len() > 8 {
                &agent_id[..8]
            } else {
                agent_id
            };
            println!(
                "\n{}Selected:{}       {}",
                colors::CYAN, colors::RESET, short_id
            );
        }

        println!();
        Ok(())
    }

    fn cmd_sleep(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.is_empty() {
            return Err("Usage: sleep <seconds>".to_string());
        }

        let interval: u64 = args[0]
            .parse()
            .map_err(|_| "Invalid interval. Must be a number.")?;

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "config".to_string(),
            args: vec!["interval".to_string(), interval.to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Sleep interval set to {}s",
            colors::GREEN, colors::RESET, interval
        );

        Ok(())
    }

    fn cmd_jitter(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.is_empty() {
            return Err("Usage: jitter <0.0-1.0>".to_string());
        }

        let jitter: f32 = args[0]
            .parse()
            .map_err(|_| "Invalid jitter. Must be a float between 0.0 and 1.0.")?;

        if !(0.0..=1.0).contains(&jitter) {
            return Err("Jitter must be between 0.0 and 1.0".to_string());
        }

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "config".to_string(),
            args: vec!["jitter".to_string(), jitter.to_string()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Jitter set to {}",
            colors::GREEN, colors::RESET, jitter
        );

        Ok(())
    }

    fn cmd_playbook(&mut self, args: &[&str]) -> Result<(), String> {
        let agent_id = self
            .selected_agent
            .as_ref()
            .ok_or("No agent selected")?
            .clone();

        if args.is_empty() {
            return Err("Usage: playbook <name>".to_string());
        }

        let name = args.join(" ");

        let cmd = AgentCommand {
            id: generate_command_id(),
            action: "playbook".to_string(),
            args: vec![name.clone()],
        };

        let server = self.server.lock().unwrap();
        server.add_command_to_session(&agent_id, cmd)?;

        println!(
            "{}[+]{} Playbook '{}' execution queued",
            colors::GREEN, colors::RESET, name
        );

        Ok(())
    }

    fn format_last_seen(&self, time: SystemTime) -> String {
        let now = SystemTime::now();
        match now.duration_since(time) {
            Ok(duration) => {
                let secs = duration.as_secs();
                if secs < 60 {
                    format!("{}s ago", secs)
                } else if secs < 3600 {
                    format!("{}m ago", secs / 60)
                } else if secs < 86400 {
                    format!("{}h ago", secs / 3600)
                } else {
                    format!("{}d ago", secs / 86400)
                }
            }
            Err(_) => "Unknown".to_string(),
        }
    }
}

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}
