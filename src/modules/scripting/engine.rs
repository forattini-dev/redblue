use crate::protocols::http::{HttpClient, HttpRequest};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Script {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub steps: Vec<ScriptStep>,
}

#[derive(Debug, Clone)]
pub enum ScriptStep {
    HttpRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Option<String>,
        match_status: Option<u16>,
        match_body: Option<String>,
    },
    TcpConnect {
        port: u16,
    },
    // Add more step types as needed
}

#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub script_id: String,
    pub success: bool,
    pub output: String,
}

pub struct ScriptEngine {
    http_client: HttpClient,
}

impl ScriptEngine {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
        }
    }

    pub fn execute(&self, script: &Script, target: &str) -> ScriptResult {
        let mut success = true;
        let mut output = String::new();

        for step in &script.steps {
            match step {
                ScriptStep::HttpRequest {
                    method,
                    path,
                    headers,
                    body,
                    match_status,
                    match_body,
                } => {
                    let url = format!("{}{}", target.trim_end_matches('/'), path);
                    let mut req = if method == "POST" {
                        HttpRequest::post(&url)
                            .with_body(body.clone().unwrap_or_default().into_bytes())
                    } else {
                        HttpRequest::get(&url)
                    };

                    for (k, v) in headers {
                        req.headers.insert(k.clone(), v.clone());
                    }

                    match self.http_client.send(&req) {
                        Ok(resp) => {
                            if let Some(status) = match_status {
                                if resp.status_code != *status {
                                    success = false;
                                    output.push_str(&format!(
                                        "Step failed: Status {} != {}\n",
                                        resp.status_code, status
                                    ));
                                    break;
                                }
                            }
                            if let Some(pattern) = match_body {
                                let body_str = String::from_utf8_lossy(&resp.body);
                                if !body_str.contains(pattern) {
                                    success = false;
                                    output.push_str(&format!(
                                        "Step failed: Body does not contain '{}'\n",
                                        pattern
                                    ));
                                    break;
                                }
                            }
                            output.push_str(&format!("HTTP {} {} - OK\n", method, path));
                        }
                        Err(e) => {
                            success = false;
                            output.push_str(&format!("Step failed: Request error {}\n", e));
                            break;
                        }
                    }
                }
                ScriptStep::TcpConnect { port } => {
                    // Placeholder for TCP connect logic
                    output.push_str(&format!("TCP Connect {} - Skipped (Not impl)\n", port));
                }
            }
        }

        ScriptResult {
            script_id: script.id.clone(),
            success,
            output,
        }
    }
}
