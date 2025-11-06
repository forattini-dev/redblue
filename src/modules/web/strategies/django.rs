/// Django framework security scanner
///
/// Enumerates common deployment misconfigurations:
/// - Presence of the Django admin login and static assets
/// - Debug toolbar exposure (__debug__/)
/// - Publicly reachable settings or SQLite database files
/// - Leaked configuration artefacts (.env, settings.py)
///
/// Built without external dependencies and powered by the in-house HTTP stack.
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DjangoScanResult {
    pub url: String,
    pub framework_detected: bool,
    pub version_hint: Option<String>,
    pub admin_login_exposed: bool,
    pub debug_toolbar_exposed: bool,
    pub env_exposed: bool,
    pub sqlite_database_exposed: bool,
    pub settings_exposed: bool,
    pub interesting_endpoints: Vec<String>,
    pub findings: Vec<DjangoFinding>,
}

#[derive(Debug, Clone)]
pub struct DjangoFinding {
    pub severity: DjangoSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DjangoSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub struct DjangoScanner {
    http_client: HttpClient,
}

impl DjangoScanner {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
        }
    }

    pub fn scan(&self, url: &str) -> Result<DjangoScanResult, String> {
        self.scan_with_progress(url, None)
    }

    pub fn scan_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<DjangoScanResult, String> {
        const TOTAL_PHASES: usize = 7;

        fn advance(progress: &Option<Arc<dyn ScanProgress>>, completed: &mut usize, count: usize) {
            if count == 0 {
                return;
            }
            if let Some(p) = progress {
                p.inc(count);
            }
            *completed += count;
        }

        let base_url = url.trim_end_matches('/');
        let mut completed = 0usize;
        let mut result = DjangoScanResult {
            url: base_url.to_string(),
            framework_detected: false,
            version_hint: None,
            admin_login_exposed: false,
            debug_toolbar_exposed: false,
            env_exposed: false,
            sqlite_database_exposed: false,
            settings_exposed: false,
            interesting_endpoints: Vec::new(),
            findings: Vec::new(),
        };

        let fingerprint = self.fingerprint(base_url)?;
        advance(&progress, &mut completed, 1);

        if !fingerprint.detected {
            let remaining = TOTAL_PHASES.saturating_sub(completed);
            if remaining > 0 {
                advance(&progress, &mut completed, remaining);
            }
            return Ok(result);
        }

        result.framework_detected = true;
        result.version_hint = fingerprint.version;
        result.admin_login_exposed = fingerprint.admin_login_exposed;

        if fingerprint.admin_login_exposed {
            result
                .interesting_endpoints
                .push(join_url(base_url, "admin/login/"));
        }
        if let Some(f) = fingerprint.admin_login_finding {
            result.findings.push(f);
        }

        if let Some(debug_toolbar) = self.check_debug_toolbar(base_url)? {
            result.debug_toolbar_exposed = true;
            result.interesting_endpoints.push(
                debug_toolbar
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "__debug__/")),
            );
            result.findings.push(debug_toolbar);
        }
        advance(&progress, &mut completed, 1);

        if let Some(env_finding) = self.check_env(base_url)? {
            result.env_exposed = true;
            result.interesting_endpoints.push(
                env_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, ".env")),
            );
            result.findings.push(env_finding);
        }
        advance(&progress, &mut completed, 1);

        if let Some(sqlite_finding) = self.check_sqlite_database(base_url)? {
            result.sqlite_database_exposed = true;
            result.interesting_endpoints.push(
                sqlite_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "db.sqlite3")),
            );
            result.findings.push(sqlite_finding);
        }
        advance(&progress, &mut completed, 1);

        if let Some(settings_finding) = self.check_settings_files(base_url)? {
            result.settings_exposed = true;
            result.interesting_endpoints.push(
                settings_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "settings.py")),
            );
            result.findings.push(settings_finding);
        }
        advance(&progress, &mut completed, 1);

        if let Some(admin_static) = self.check_admin_static(base_url) {
            result.interesting_endpoints.push(admin_static);
        }
        advance(&progress, &mut completed, 1);

        let remaining = TOTAL_PHASES.saturating_sub(completed);
        if remaining > 0 {
            advance(&progress, &mut completed, remaining);
        }

        Ok(result)
    }

    fn fingerprint(&self, base_url: &str) -> Result<DjangoFingerprint, String> {
        let mut fp = DjangoFingerprint::default();
        let admin_url = join_url(base_url, "admin/login/");

        if let Ok(response) = self.http_client.get(&admin_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("Django administration") || body.contains("csrfmiddlewaretoken") {
                    fp.detected = true;
                    fp.admin_login_exposed = true;
                    fp.version = fp.version.or_else(|| extract_version_from_admin(&body));
                    fp.admin_login_finding = Some(DjangoFinding {
                        severity: DjangoSeverity::Low,
                        title: "Django admin login reachable".to_string(),
                        description: "The Django admin login page is exposed on the default /admin/login/ path.".to_string(),
                        evidence: Some(admin_url.clone()),
                        remediation: "Restrict admin access via IP allow lists, VPN, or custom admin URLs.".to_string(),
                    });
                }
            }
        }

        if !fp.detected {
            // Probe a guaranteed missing route to see if the default Django 404 reveals itself.
            let probe_url = join_url(base_url, "redblue-probe-missing-route");
            if let Ok(response) = self.http_client.get(&probe_url) {
                if response.status_code == 404 {
                    let body = response.body_as_string();
                    if body.contains("Django") || body.contains("csrfmiddlewaretoken") {
                        fp.detected = true;
                        fp.version = fp.version.or_else(|| extract_version_from_text(&body));
                    }
                }
            }
        }

        if !fp.detected {
            if let Ok(response) = self.http_client.get(base_url) {
                let lower_headers: Vec<(String, String)> = response
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.to_ascii_lowercase()))
                    .collect();
                for (key, value) in lower_headers {
                    if key == "set-cookie"
                        && (value.contains("csrftoken") || value.contains("sessionid"))
                    {
                        fp.detected = true;
                    }
                }
            }
        }

        Ok(fp)
    }

    fn check_debug_toolbar(&self, base_url: &str) -> Result<Option<DjangoFinding>, String> {
        let debug_url = join_url(base_url, "__debug__/");
        if let Ok(response) = self.http_client.get(&debug_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("djdt") || body.contains("django-debug-toolbar") {
                    return Ok(Some(DjangoFinding {
                        severity: DjangoSeverity::High,
                        title: "Django debug toolbar exposed".to_string(),
                        description: "The Django debug toolbar responded without protection, leaking SQL queries, settings, and request context.".to_string(),
                        evidence: Some(debug_url),
                        remediation: "Disable DEBUG in production and restrict the debug toolbar middleware to trusted hosts only.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_env(&self, base_url: &str) -> Result<Option<DjangoFinding>, String> {
        let env_url = join_url(base_url, ".env");
        if let Ok(response) = self.http_client.get(&env_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("DJANGO_SETTINGS_MODULE") || body.contains("SECRET_KEY=") {
                    return Ok(Some(DjangoFinding {
                        severity: DjangoSeverity::Critical,
                        title: ".env file exposed".to_string(),
                        description: "The Django environment file is publicly readable, leaking SECRET_KEY and other credentials.".to_string(),
                        evidence: Some(env_url),
                        remediation: "Remove .env from the document root or block access via web server rules.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_sqlite_database(&self, base_url: &str) -> Result<Option<DjangoFinding>, String> {
        let db_url = join_url(base_url, "db.sqlite3");
        if let Ok(response) = self.http_client.get(&db_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("SQLite format 3") {
                    return Ok(Some(DjangoFinding {
                        severity: DjangoSeverity::Critical,
                        title: "SQLite database exposed".to_string(),
                        description: "Downloaded content appears to be the Django SQLite database (SQLite format 3 header detected).".to_string(),
                        evidence: Some(db_url),
                        remediation: "Relocate db.sqlite3 outside the web root and replace with a production-grade database.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_settings_files(&self, base_url: &str) -> Result<Option<DjangoFinding>, String> {
        let settings_candidates = ["settings.py", "config/settings.py", "local_settings.py"]; // common paths
        for candidate in &settings_candidates {
            let target = join_url(base_url, candidate);
            if let Ok(response) = self.http_client.get(&target) {
                if response.status_code == 200 {
                    let body = response.body_as_string();
                    if body.contains("SECRET_KEY") || body.contains("DEBUG = True") {
                        return Ok(Some(DjangoFinding {
                            severity: DjangoSeverity::High,
                            title: format!("{} exposed", candidate),
                            description: "Django settings file is accessible, leaking SECRET_KEY, database credentials, and configuration.".to_string(),
                            evidence: Some(target),
                            remediation: "Place settings modules outside the static root and configure the web server to block direct access.".to_string(),
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    fn check_admin_static(&self, base_url: &str) -> Option<String> {
        let static_url = join_url(base_url, "static/admin/css/base.css");
        if let Ok(response) = self.http_client.get(&static_url) {
            if response.status_code == 200 {
                return Some(static_url);
            }
        }
        None
    }
}

#[derive(Default)]
struct DjangoFingerprint {
    detected: bool,
    version: Option<String>,
    admin_login_exposed: bool,
    admin_login_finding: Option<DjangoFinding>,
}

fn extract_version_from_admin(body: &str) -> Option<String> {
    if let Some(pos) = body.find("Django version") {
        let slice = &body[pos + "Django version".len()..];
        return take_version_prefix(slice);
    }
    extract_version_from_text(body)
}

fn extract_version_from_text(text: &str) -> Option<String> {
    if let Some(pos) = text.find("Django v") {
        return take_version_prefix(&text[pos + "Django v".len()..]);
    }
    None
}

fn take_version_prefix(slice: &str) -> Option<String> {
    let mut version = String::new();
    for ch in slice.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            version.push(ch);
        } else if !version.is_empty() {
            break;
        }
    }
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

fn join_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{}/{}", base, path)
}
