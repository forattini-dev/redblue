use super::server::McpServer;
use crate::utils::json::parse_json;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_ADDR: &str = "127.0.0.1:8787";
const SSE_PING_INTERVAL: Duration = Duration::from_secs(15);
const STREAM_PING_INTERVAL: Duration = Duration::from_secs(15);

pub struct TransportConfig {
    pub http_addr: String,
    pub enable_http: bool,
    pub enable_sse: bool,
    pub enable_stream: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            http_addr: DEFAULT_ADDR.to_string(),
            enable_http: true,
            enable_sse: true,
            enable_stream: true,
        }
    }
}

pub struct HttpServerHandle {
    join_handle: Option<thread::JoinHandle<()>>,
}

impl HttpServerHandle {
    pub fn stop(self) {
        if let Some(handle) = self.join_handle {
            let _ = handle.join();
        }
    }
}

struct HttpSharedState {
    core: Arc<Mutex<McpServer>>,
    sse_sessions: Mutex<HashMap<String, mpsc::Sender<SseEvent>>>,
    stream_sessions: Mutex<HashMap<String, mpsc::Sender<String>>>,
    counter: AtomicU64,
}

impl HttpSharedState {
    fn new(core: Arc<Mutex<McpServer>>) -> Self {
        Self {
            core,
            sse_sessions: Mutex::new(HashMap::new()),
            stream_sessions: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(1),
        }
    }

    fn next_session_id(&self, prefix: &str) -> String {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}", prefix, current_timestamp(), id)
    }

    fn dispatch_sse(&self, session: &str, message: String) {
        if let Some(sender) = self
            .sse_sessions
            .lock()
            .ok()
            .and_then(|map| map.get(session).cloned())
        {
            let _ = sender.send(SseEvent::message(message));
        }
    }

    fn dispatch_stream(&self, session: &str, message: String) {
        if let Some(sender) = self
            .stream_sessions
            .lock()
            .ok()
            .and_then(|map| map.get(session).cloned())
        {
            let _ = sender.send(message);
        }
    }
}

struct SseEvent {
    event: Option<String>,
    data: String,
}

impl SseEvent {
    fn message(data: String) -> Self {
        Self {
            event: Some("message".to_string()),
            data,
        }
    }

    fn endpoint(path: String) -> Self {
        Self {
            event: Some("endpoint".to_string()),
            data: path,
        }
    }

    fn session(id: String) -> Self {
        Self {
            event: Some("session".to_string()),
            data: id,
        }
    }
}

#[derive(Default)]
pub struct TransportHandles {
    http: Option<HttpServerHandle>,
}

impl TransportHandles {
    pub fn stop(self) {
        if let Some(handle) = self.http {
            handle.stop();
        }
    }
}

pub fn start_http_transports(
    core: Arc<Mutex<McpServer>>,
    config: TransportConfig,
) -> Result<TransportHandles, String> {
    if !config.enable_http {
        return Ok(TransportHandles::default());
    }

    let listener = TcpListener::bind(&config.http_addr)
        .map_err(|e| format!("failed to bind HTTP transport {}: {}", config.http_addr, e))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("failed to configure listener: {}", e))?;

    let shared = Arc::new(HttpSharedState::new(core));
    let enable_sse = config.enable_sse;
    let enable_stream = config.enable_stream;
    let addr_display = config.http_addr.clone();
    let shared_loop = shared.clone();

    let join_handle = thread::Builder::new()
        .name("mcp-http-server".to_string())
        .spawn(move || run_http_loop(listener, shared_loop, enable_sse, enable_stream))
        .map_err(|e| format!("failed to spawn HTTP server thread: {}", e))?;

    println!(
        "[MCP] HTTP transports listening on {} (SSE: {}, stream: {})",
        addr_display, enable_sse, enable_stream
    );

    Ok(TransportHandles {
        http: Some(HttpServerHandle {
            join_handle: Some(join_handle),
        }),
    })
}

fn run_http_loop(
    listener: TcpListener,
    shared: Arc<HttpSharedState>,
    enable_sse: bool,
    enable_stream: bool,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let shared_clone = shared.clone();
                thread::spawn(move || {
                    handle_client(stream, shared_clone, enable_sse, enable_stream)
                });
            }
            Err(err) => {
                eprintln!("[MCP] HTTP accept error: {}", err);
                break;
            }
        }
    }
}

fn handle_client(
    stream: TcpStream,
    shared: Arc<HttpSharedState>,
    enable_sse: bool,
    enable_stream: bool,
) {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);

    while let Ok(Some(request)) = read_http_request(&mut reader) {
        match route_request(request.method.as_str(), request.path.as_str()) {
            Route::Sse if enable_sse => {
                let stream = reader.into_inner();
                handle_sse_connection(stream, shared.clone(), request);
                return;
            }
            Route::Sse => {
                write_simple_response(
                    &mut reader.into_inner(),
                    404,
                    "SSE transport disabled".as_bytes(),
                );
                return;
            }
            Route::SseMessage if enable_sse => {
                handle_sse_message(&mut reader, shared.clone(), request);
            }
            Route::SseMessage => {
                write_simple_response(&mut reader.into_inner(), 404, b"SSE transport disabled");
                return;
            }
            Route::Stream if enable_stream => {
                let stream = reader.into_inner();
                handle_stream_connection(stream, shared.clone(), request);
                return;
            }
            Route::Stream => {
                write_simple_response(&mut reader.into_inner(), 404, b"Stream transport disabled");
                return;
            }
            Route::StreamSend if enable_stream => {
                handle_stream_message(&mut reader, shared.clone(), request);
            }
            Route::StreamSend => {
                write_simple_response(&mut reader.into_inner(), 404, b"Stream transport disabled");
                return;
            }
            Route::Status => {
                respond_status(&mut reader, peer, shared.clone());
            }
            Route::Unknown => {
                let mut stream = reader.into_inner();
                write_simple_response(
                    &mut stream,
                    404,
                    b"Endpoint not implemented by redblue MCP transport",
                );
                return;
            }
        }
    }
}

fn handle_sse_connection(
    mut stream: TcpStream,
    shared: Arc<HttpSharedState>,
    request: HttpRequest,
) {
    if request.method != "GET" {
        write_simple_response(&mut stream, 405, b"Method not allowed");
        return;
    }

    let session_id = shared.next_session_id("s");
    let (tx, rx) = mpsc::channel::<SseEvent>();

    if shared
        .sse_sessions
        .lock()
        .map(|mut map| map.insert(session_id.clone(), tx.clone()))
        .is_err()
    {
        write_simple_response(&mut stream, 500, b"Internal server error");
        return;
    }

    if write_sse_headers(&mut stream).is_err() {
        let _ = shared
            .sse_sessions
            .lock()
            .map(|mut map| map.remove(&session_id));
        return;
    }

    let endpoint = format!("/messages?sessionId={}", session_id);
    let _ = tx.send(SseEvent::endpoint(endpoint));
    let _ = tx.send(SseEvent::session(session_id.clone()));

    loop {
        match rx.recv_timeout(SSE_PING_INTERVAL) {
            Ok(event) => {
                if send_sse_event(&mut stream, &event).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if send_sse_ping(&mut stream).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = shared
        .sse_sessions
        .lock()
        .map(|mut map| map.remove(&session_id));
}

fn handle_sse_message(
    reader: &mut BufReader<TcpStream>,
    shared: Arc<HttpSharedState>,
    request: HttpRequest,
) {
    let session_id = match request.query_params.get("sessionId") {
        Some(id) => id.clone(),
        None => {
            write_simple_response(reader.get_mut(), 400, b"sessionId query parameter required");
            return;
        }
    };

    if !shared
        .sse_sessions
        .lock()
        .map(|map| map.contains_key(&session_id))
        .unwrap_or(false)
    {
        write_simple_response(reader.get_mut(), 404, b"unknown session");
        return;
    }

    let body_text = match String::from_utf8(request.body) {
        Ok(text) => text,
        Err(_) => {
            write_simple_response(reader.get_mut(), 415, b"body must be utf-8 JSON");
            return;
        }
    };

    let message = match parse_json(&body_text) {
        Ok(value) => value,
        Err(err) => {
            let payload = format!("invalid JSON: {}", err);
            write_simple_response(reader.get_mut(), 400, payload.as_bytes());
            return;
        }
    };

    let response = {
        let mut guard = match shared.core.lock() {
            Ok(guard) => guard,
            Err(_) => {
                write_simple_response(reader.get_mut(), 500, b"MCP state poisoned");
                return;
            }
        };
        guard.process_message(message)
    };

    if let Some(payload) = response {
        shared.dispatch_sse(&session_id, payload.to_json_string());
    }

    write_simple_response(reader.get_mut(), 202, b"accepted");
}

fn handle_stream_connection(
    mut stream: TcpStream,
    shared: Arc<HttpSharedState>,
    request: HttpRequest,
) {
    if request.method != "GET" {
        write_simple_response(&mut stream, 405, b"Method not allowed");
        return;
    }

    let session_id = shared.next_session_id("h");
    let (tx, rx) = mpsc::channel::<String>();

    if shared
        .stream_sessions
        .lock()
        .map(|mut map| map.insert(session_id.clone(), tx.clone()))
        .is_err()
    {
        write_simple_response(&mut stream, 500, b"Internal server error");
        return;
    }

    if write_stream_headers(&mut stream).is_err() {
        let _ = shared
            .stream_sessions
            .lock()
            .map(|mut map| map.remove(&session_id));
        return;
    }

    let handshake = format!(
        r#"{{"type":"handshake","sessionId":"{}","endpoint":"/stream/send?sessionId={}"}}"#,
        session_id, session_id
    );
    let _ = tx.send(handshake);

    loop {
        match rx.recv_timeout(STREAM_PING_INTERVAL) {
            Ok(message) => {
                if send_chunk(&mut stream, &message).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if send_chunk(&mut stream, r#"{"type":"ping"}"#).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = send_chunk_end(&mut stream);
    let _ = shared
        .stream_sessions
        .lock()
        .map(|mut map| map.remove(&session_id));
}

fn handle_stream_message(
    reader: &mut BufReader<TcpStream>,
    shared: Arc<HttpSharedState>,
    request: HttpRequest,
) {
    let session_id = match request.query_params.get("sessionId") {
        Some(id) => id.clone(),
        None => {
            write_simple_response(reader.get_mut(), 400, b"sessionId query parameter required");
            return;
        }
    };

    if !shared
        .stream_sessions
        .lock()
        .map(|map| map.contains_key(&session_id))
        .unwrap_or(false)
    {
        write_simple_response(reader.get_mut(), 404, b"unknown session");
        return;
    }

    let body_text = match String::from_utf8(request.body) {
        Ok(text) => text,
        Err(_) => {
            write_simple_response(reader.get_mut(), 415, b"body must be utf-8 JSON");
            return;
        }
    };

    let message = match parse_json(&body_text) {
        Ok(value) => value,
        Err(err) => {
            let payload = format!("invalid JSON: {}", err);
            write_simple_response(reader.get_mut(), 400, payload.as_bytes());
            return;
        }
    };

    let response = {
        let mut guard = match shared.core.lock() {
            Ok(guard) => guard,
            Err(_) => {
                write_simple_response(reader.get_mut(), 500, b"MCP state poisoned");
                return;
            }
        };
        guard.process_message(message)
    };

    if let Some(payload) = response {
        shared.dispatch_stream(&session_id, payload.to_json_string());
    }

    write_simple_response(reader.get_mut(), 202, b"accepted");
}

fn respond_status(
    reader: &mut BufReader<TcpStream>,
    peer: Option<std::net::SocketAddr>,
    shared: Arc<HttpSharedState>,
) {
    let sse_count = shared.sse_sessions.lock().map(|map| map.len()).unwrap_or(0);
    let stream_count = shared
        .stream_sessions
        .lock()
        .map(|map| map.len())
        .unwrap_or(0);
    let status = format!(
        "{{\"peer\":\"{:?}\",\"sse\":{},\"stream\":{}}}",
        peer, sse_count, stream_count
    );

    write_simple_response(reader.get_mut(), 200, status.as_bytes());
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query_params: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Sse,
    SseMessage,
    Stream,
    StreamSend,
    Status,
    Unknown,
}

fn route_request(method: &str, path: &str) -> Route {
    match (method, path) {
        ("GET", "/sse") => Route::Sse,
        ("POST", "/messages") => Route::SseMessage,
        ("GET", "/stream") => Route::Stream,
        ("POST", "/stream/send") => Route::StreamSend,
        ("GET", "/status") => Route::Status,
        _ => Route::Unknown,
    }
}

fn read_http_request(reader: &mut BufReader<TcpStream>) -> Result<Option<HttpRequest>, String> {
    let mut request_line = String::new();
    loop {
        request_line.clear();
        if reader
            .read_line(&mut request_line)
            .map_err(|e| e.to_string())?
            == 0
        {
            return Ok(None);
        }
        if !request_line.trim().is_empty() {
            break;
        }
    }

    let mut parts = request_line.trim_end().split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "invalid request line".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "invalid request line".to_string())?;

    let (path, query) = split_path_query(target);

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let mut body = Vec::new();
    if let Some(length) = headers.get("content-length") {
        if let Ok(len) = length.parse::<usize>() {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
            body = buf;
        }
    }

    let query_params = parse_query(&query);

    Ok(Some(HttpRequest {
        method: method.to_string(),
        path,
        query_params,
        body,
    }))
}

fn split_path_query(target: &str) -> (String, String) {
    if let Some(pos) = target.find('?') {
        (target[..pos].to_string(), target[pos + 1..].to_string())
    } else {
        (target.to_string(), String::new())
    }
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut iter = pair.splitn(2, '=');
        let key = iter.next().unwrap_or("").to_string();
        let value = iter.next().unwrap_or("").replace('+', " ");
        params.insert(key, percent_decode(&value));
    }
    params
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                result.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn write_simple_response(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let status_text = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        status_text,
        body.len()
    );
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn write_sse_headers(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
    )?;
    stream.flush()
}

fn send_sse_event(stream: &mut TcpStream, event: &SseEvent) -> Result<(), std::io::Error> {
    if let Some(name) = &event.event {
        stream.write_all(format!("event: {}\r\n", name).as_bytes())?;
    }
    if event.event.is_some() {
        stream.write_all(b"data: ")?;
        stream.write_all(event.data.replace('\n', "\ndata: ").as_bytes())?;
        stream.write_all(b"\r\n\r\n")?;
    } else {
        stream.write_all(event.data.as_bytes())?;
        stream.write_all(b"\r\n\r\n")?;
    }
    stream.flush()
}

fn send_sse_ping(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    stream.write_all(b": ping\r\n\r\n")?;
    stream.flush()
}

fn write_stream_headers(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
    )?;
    stream.flush()
}

fn send_chunk(stream: &mut TcpStream, data: &str) -> Result<(), std::io::Error> {
    let payload = data.as_bytes();
    stream.write_all(format!("{:X}\r\n", payload.len()).as_bytes())?;
    stream.write_all(payload)?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

fn send_chunk_end(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
