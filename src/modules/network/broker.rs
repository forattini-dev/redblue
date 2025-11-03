/// Connection Broker (Multi-client mode)
///
/// Implements chat server mode where multiple clients can connect
/// simultaneously and messages are broadcast to all connected clients.
///
/// Features:
/// - Multiple simultaneous connections
/// - Broadcast messages to all clients
/// - Connection/disconnection events
/// - Optional message logging
///
/// Replaces: ncat --broker
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

/// Connected client information
#[derive(Debug, Clone)]
struct Client {
    id: usize,
    addr: String,
    connected_at: SystemTime,
}

/// Broker configuration
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub port: u16,
    pub verbose: bool,
    pub log_file: Option<String>,
}

impl BrokerConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            verbose: false,
            log_file: None,
        }
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_log_file(mut self, log_file: Option<String>) -> Self {
        self.log_file = log_file;
        self
    }
}

/// Connection broker (chat server)
pub struct Broker {
    config: BrokerConfig,
    clients: Arc<Mutex<Vec<(usize, TcpStream, Client)>>>,
    next_client_id: Arc<Mutex<usize>>,
}

impl Broker {
    pub fn new(config: BrokerConfig) -> Self {
        Self {
            config,
            clients: Arc::new(Mutex::new(Vec::new())),
            next_client_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Run the broker
    pub fn run(&self) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener =
            TcpListener::bind(&addr).map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        if self.config.verbose {
            eprintln!("[+] Broker listening on {}", addr);
            eprintln!("[+] Waiting for connections...");
        }

        // Accept connections in loop
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let client_addr = stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    if self.config.verbose {
                        eprintln!("[+] New connection from {}", client_addr);
                    }

                    // Get client ID
                    let client_id = {
                        let mut id = self.next_client_id.lock().unwrap();
                        let current = *id;
                        *id += 1;
                        current
                    };

                    let client = Client {
                        id: client_id,
                        addr: client_addr.clone(),
                        connected_at: SystemTime::now(),
                    };

                    // Clone stream for sending
                    let send_stream = stream.try_clone().map_err(|e| {
                        format!("Failed to clone stream for {}: {}", client_addr, e)
                    })?;

                    // Add client to list
                    {
                        let mut clients = self.clients.lock().unwrap();
                        clients.push((client_id, send_stream, client.clone()));
                    }

                    // Broadcast join message
                    self.broadcast_system(
                        &format!("[{}] {} joined the chat", client_id, client_addr),
                        None,
                    );

                    // Handle client in new thread
                    let clients_clone = Arc::clone(&self.clients);
                    let verbose = self.config.verbose;
                    let log_file = self.config.log_file.clone();

                    thread::spawn(move || {
                        Self::handle_client(
                            stream,
                            client,
                            clients_clone,
                            verbose,
                            log_file,
                        );
                    });
                }
                Err(e) => {
                    if self.config.verbose {
                        eprintln!("[!] Accept error: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a single client
    fn handle_client(
        stream: TcpStream,
        client: Client,
        clients: Arc<Mutex<Vec<(usize, TcpStream, Client)>>>,
        verbose: bool,
        log_file: Option<String>,
    ) {
        let reader = BufReader::new(stream);

        for line in reader.lines() {
            match line {
                Ok(message) => {
                    if message.is_empty() {
                        continue;
                    }

                    // Format message
                    let formatted = format!("[{}] {}: {}", client.id, client.addr, message);

                    if verbose {
                        println!("{}", formatted);
                    }

                    // Log to file if configured
                    if let Some(ref log_path) = log_file {
                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(log_path)
                        {
                            let timestamp = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            writeln!(file, "[{}] {}", timestamp, formatted).ok();
                        }
                    }

                    // Broadcast to all other clients
                    let mut clients_lock = clients.lock().unwrap();
                    clients_lock.retain(|(id, stream, _)| {
                        if *id == client.id {
                            return true; // Keep self
                        }

                        // Try to send message
                        let msg_bytes = format!("{}\n", formatted).into_bytes();
                        match stream.try_clone() {
                            Ok(mut s) => {
                                if s.write_all(&msg_bytes).is_err() {
                                    if verbose {
                                        eprintln!("[!] Client {} disconnected (send failed)", id);
                                    }
                                    return false; // Remove dead client
                                }
                                true
                            }
                            Err(_) => {
                                if verbose {
                                    eprintln!("[!] Client {} disconnected (clone failed)", id);
                                }
                                false
                            }
                        }
                    });
                }
                Err(_) => {
                    // Client disconnected
                    break;
                }
            }
        }

        // Remove client from list
        {
            let mut clients_lock = clients.lock().unwrap();
            clients_lock.retain(|(id, _, _)| *id != client.id);
        }

        // Broadcast leave message
        let leave_msg = format!("[{}] {} left the chat", client.id, client.addr);
        if verbose {
            eprintln!("{}", leave_msg);
        }

        Self::broadcast_system_static(&leave_msg, Some(client.id), clients);
    }

    /// Broadcast system message to all clients
    fn broadcast_system(&self, message: &str, except_id: Option<usize>) {
        Self::broadcast_system_static(message, except_id, Arc::clone(&self.clients));
    }

    /// Static version for use in threads
    fn broadcast_system_static(
        message: &str,
        except_id: Option<usize>,
        clients: Arc<Mutex<Vec<(usize, TcpStream, Client)>>>,
    ) {
        let msg_bytes = format!("{}\n", message).into_bytes();
        let mut clients_lock = clients.lock().unwrap();

        clients_lock.retain(|(id, stream, _)| {
            if Some(*id) == except_id {
                return true; // Skip self
            }

            match stream.try_clone() {
                Ok(mut s) => {
                    if s.write_all(&msg_bytes).is_err() {
                        return false; // Remove dead client
                    }
                    true
                }
                Err(_) => false,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broker_config() {
        let config = BrokerConfig::new(8080).with_verbose(true);
        assert_eq!(config.port, 8080);
        assert!(config.verbose);
        assert!(config.log_file.is_none());
    }

    #[test]
    fn test_broker_creation() {
        let config = BrokerConfig::new(9000);
        let broker = Broker::new(config);
        assert_eq!(broker.config.port, 9000);
    }
}
