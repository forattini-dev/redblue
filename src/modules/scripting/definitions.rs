//! Script definitions for common vulnerability checks
//! These are built-in scripts that ship with redblue

use super::engine::{Script, ScriptStep};
use std::collections::HashMap;

/// Get all built-in vulnerability check scripts
pub fn get_builtin_scripts() -> Vec<Script> {
    vec![
        // Apache Server Status disclosure
        Script {
            id: "apache-server-status".to_string(),
            name: "Apache Server Status".to_string(),
            category: "info-disclosure".to_string(),
            description: "Check for Apache mod_status information disclosure".to_string(),
            steps: vec![
                ScriptStep::HttpRequest {
                    method: "GET".to_string(),
                    path: "/server-status".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    match_status: Some(200),
                    match_body: Some("Apache Server Status".to_string()),
                },
            ],
        },
        // phpinfo disclosure
        Script {
            id: "phpinfo-disclosure".to_string(),
            name: "PHP Info Disclosure".to_string(),
            category: "info-disclosure".to_string(),
            description: "Check for exposed phpinfo() pages".to_string(),
            steps: vec![
                ScriptStep::HttpRequest {
                    method: "GET".to_string(),
                    path: "/phpinfo.php".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    match_status: Some(200),
                    match_body: Some("PHP Version".to_string()),
                },
            ],
        },
        // .git exposure
        Script {
            id: "git-exposure".to_string(),
            name: "Git Repository Exposure".to_string(),
            category: "info-disclosure".to_string(),
            description: "Check for exposed .git directory".to_string(),
            steps: vec![
                ScriptStep::HttpRequest {
                    method: "GET".to_string(),
                    path: "/.git/HEAD".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    match_status: Some(200),
                    match_body: Some("ref:".to_string()),
                },
            ],
        },
        // .env file exposure
        Script {
            id: "env-exposure".to_string(),
            name: "Environment File Exposure".to_string(),
            category: "info-disclosure".to_string(),
            description: "Check for exposed .env file".to_string(),
            steps: vec![
                ScriptStep::HttpRequest {
                    method: "GET".to_string(),
                    path: "/.env".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    match_status: Some(200),
                    match_body: None,
                },
            ],
        },
    ]
}
