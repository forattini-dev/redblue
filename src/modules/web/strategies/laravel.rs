/// Laravel framework security scanner
///
/// Focus areas:
/// - Framework fingerprinting and version hints
/// - Exposure of sensitive debugging surfaces (Debugbar, Telescope, Horizon)
/// - Leaked configuration artefacts (.env, logs, storage files)
/// - Common misconfigurations that grant unauthenticated insight or access
///
/// The implementation relies solely on the in-house HTTP client and stays
/// dependency free in line with project guardrails.
use crate::modules::network::scanner::ScanProgress;
use crate::protocols::http::HttpClient;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct LaravelScanResult {
    pub url: String,
    pub framework_detected: bool,
    pub version_hint: Option<String>,
    pub debug_signals: bool,
    pub env_exposed: bool,
    pub horizon_exposed: bool,
    pub telescope_exposed: bool,
    pub storage_logs_exposed: bool,
    pub ignition_health_endpoint: bool,
    pub interesting_endpoints: Vec<String>,
    pub vulnerabilities: Vec<LaravelFinding>,
}

#[derive(Debug, Clone)]
pub struct LaravelFinding {
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub struct LaravelScanner {
    http_client: HttpClient,
}

impl LaravelScanner {
    pub fn new() -> Self {
        Self {
            http_client: HttpClient::new(),
        }
    }

    pub fn scan(&self, url: &str) -> Result<LaravelScanResult, String> {
        self.scan_with_progress(url, None)
    }

    pub fn scan_with_progress(
        &self,
        url: &str,
        progress: Option<Arc<dyn ScanProgress>>,
    ) -> Result<LaravelScanResult, String> {
        const TOTAL_PHASES: usize = 8;

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
        let mut result = LaravelScanResult {
            url: base_url.to_string(),
            framework_detected: false,
            version_hint: None,
            debug_signals: false,
            env_exposed: false,
            horizon_exposed: false,
            telescope_exposed: false,
            storage_logs_exposed: false,
            ignition_health_endpoint: false,
            interesting_endpoints: Vec::new(),
            vulnerabilities: Vec::new(),
        };

        let fingerprint = self.fingerprint(base_url)?;
        advance(&progress, &mut completed, 1);

        if !fingerprint.detected {
            // Consume remaining progress so the caller sees a completed task.
            let remaining = TOTAL_PHASES.saturating_sub(completed);
            if remaining > 0 {
                advance(&progress, &mut completed, remaining);
            }
            return Ok(result);
        }

        result.framework_detected = true;
        result.version_hint = fingerprint.version;
        result.debug_signals = fingerprint.debugbar_present;

        if fingerprint.debugbar_present {
            result.vulnerabilities.push(LaravelFinding {
                severity: FindingSeverity::Medium,
                title: "Laravel Debugbar exposure".to_string(),
                description: "The application responded with Laravel Debugbar assets or headers, signalling APP_DEBUG is enabled in production.".to_string(),
                evidence: fingerprint.debugbar_evidence,
                remediation: "Disable debug tooling (APP_DEBUG=false) and ensure the Debugbar package is only loaded in local environments.".to_string(),
            });
        }

        // Check .env exposure
        if let Some(env_finding) = self.check_env_exposure(base_url)? {
            result.env_exposed = true;
            result.interesting_endpoints.push(
                env_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, ".env")),
            );
            result.vulnerabilities.push(env_finding);
        }
        advance(&progress, &mut completed, 1);

        // Horizon dashboard
        if let Some(horizon_finding) = self.check_horizon(base_url)? {
            result.horizon_exposed = true;
            result.interesting_endpoints.push(
                horizon_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "horizon")),
            );
            result.vulnerabilities.push(horizon_finding);
        }
        advance(&progress, &mut completed, 1);

        // Telescope dashboard
        if let Some(telescope_finding) = self.check_telescope(base_url)? {
            result.telescope_exposed = true;
            result.interesting_endpoints.push(
                telescope_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "telescope")),
            );
            result.vulnerabilities.push(telescope_finding);
        }
        advance(&progress, &mut completed, 1);

        // Ignition health endpoint (debug solution executor)
        if let Some(ignition_finding) = self.check_ignition_health(base_url)? {
            result.ignition_health_endpoint = true;
            result.interesting_endpoints.push(
                ignition_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "_ignition/health-check")),
            );
            result.vulnerabilities.push(ignition_finding);
        }
        advance(&progress, &mut completed, 1);

        // Storage/log leaks
        if let Some(log_finding) = self.check_storage_logs(base_url)? {
            result.storage_logs_exposed = true;
            result.interesting_endpoints.push(
                log_finding
                    .evidence
                    .clone()
                    .unwrap_or_else(|| join_url(base_url, "storage/logs/laravel.log")),
            );
            result.vulnerabilities.push(log_finding);
        }
        advance(&progress, &mut completed, 1);

        // Public Mix manifest - not a vulnerability but useful confirmation
        if let Some(manifest_path) = self.check_mix_manifest(base_url) {
            result.interesting_endpoints.push(manifest_path);
        }
        advance(&progress, &mut completed, 1);

        // Final progress sync
        let remaining = TOTAL_PHASES.saturating_sub(completed);
        if remaining > 0 {
            advance(&progress, &mut completed, remaining);
        }

        Ok(result)
    }

    fn fingerprint(&self, base_url: &str) -> Result<LaravelFingerprint, String> {
        let mut fingerprint = LaravelFingerprint::default();

        if let Ok(response) = self.http_client.get(base_url) {
            let body = response.body_as_string();

            // Header based detection
            for (header, value) in &response.headers {
                if header.eq_ignore_ascii_case("set-cookie")
                    && value.to_lowercase().contains("laravel_session")
                {
                    fingerprint.detected = true;
                    fingerprint.cookie_hint = true;
                }
                if header.eq_ignore_ascii_case("x-powered-by")
                    && value.to_lowercase().contains("laravel")
                {
                    fingerprint.detected = true;
                    fingerprint.version = fingerprint
                        .version
                        .or_else(|| extract_version_from_powered_by(value));
                }
                if header.eq_ignore_ascii_case("x-debugbar-id")
                    || header.eq_ignore_ascii_case("x-laravel-debugbar")
                {
                    fingerprint.debugbar_present = true;
                    fingerprint.debugbar_evidence = Some(format!("{}: {}", header, value));
                }
            }

            // Body heuristics
            if body.contains("name=\"csrf-token\"") || body.contains("window.Laravel") {
                fingerprint.detected = true;
            }
            if let Some(version_hint) = extract_version_from_body(&body) {
                fingerprint.version = fingerprint.version.or(Some(version_hint));
            }
            if body.contains("/_debugbar/") {
                fingerprint.debugbar_present = true;
                fingerprint.debugbar_evidence = Some(join_url(base_url, "_debugbar"));
            }
        }

        if !fingerprint.detected {
            // Probe mix-manifest.json which is specific to Laravel Mix deployments
            if let Ok(response) = self
                .http_client
                .get(&join_url(base_url, "mix-manifest.json"))
            {
                if response.is_success() && response.body_as_string().contains("laravel-mix") {
                    fingerprint.detected = true;
                    fingerprint.version = fingerprint
                        .version
                        .or_else(|| extract_version_from_body(&response.body_as_string()));
                }
            }
        }

        Ok(fingerprint)
    }

    fn check_env_exposure(&self, base_url: &str) -> Result<Option<LaravelFinding>, String> {
        let env_url = join_url(base_url, ".env");
        if let Ok(response) = self.http_client.get(&env_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("APP_KEY=") || body.contains("DB_CONNECTION=") {
                    return Ok(Some(LaravelFinding {
                        severity: FindingSeverity::Critical,
                        title: ".env configuration file exposed".to_string(),
                        description: "The application's .env file is accessible without authentication, leaking secrets, database credentials, and APP_KEY.".to_string(),
                        evidence: Some(env_url),
                        remediation: "Reconfigure web server rules to deny access to .env and other dot-files. Ensure deployments keep configuration files outside the web root.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_horizon(&self, base_url: &str) -> Result<Option<LaravelFinding>, String> {
        let api_url = join_url(base_url, "horizon/api/stats");
        if let Ok(response) = self.http_client.get(&api_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("recentJobs") || body.contains("jobsPerMinute") {
                    return Ok(Some(LaravelFinding {
                        severity: FindingSeverity::High,
                        title: "Laravel Horizon dashboard exposed".to_string(),
                        description: "The Horizon metrics API responded without authentication, exposing queue activity and enabling job inspection.".to_string(),
                        evidence: Some(api_url),
                        remediation: "Protect Horizon with authentication (horizon.php middleware), IP restrictions, or disable the dashboard in production.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_telescope(&self, base_url: &str) -> Result<Option<LaravelFinding>, String> {
        let telescope_url = join_url(base_url, "telescope/requests");
        if let Ok(response) = self.http_client.get(&telescope_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("Telescope") {
                    return Ok(Some(LaravelFinding {
                        severity: FindingSeverity::High,
                        title: "Laravel Telescope exposed".to_string(),
                        description: "Telescope responded without restriction, exposing request logs, queued jobs, cache contents, and potential secrets.".to_string(),
                        evidence: Some(telescope_url),
                        remediation: "Register Telescope's authorization gate to restrict production access or disable Telescope outside local environments.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_ignition_health(&self, base_url: &str) -> Result<Option<LaravelFinding>, String> {
        let ignition_url = join_url(base_url, "_ignition/health-check");
        if let Ok(response) = self.http_client.get(&ignition_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("canExecuteSolutions") {
                    return Ok(Some(LaravelFinding {
                        severity: FindingSeverity::Medium,
                        title: "Ignition health-check reachable".to_string(),
                        description: "The Ignition debug endpoint is reachable, signalling debug handlers are still active in production deployments.".to_string(),
                        evidence: Some(ignition_url),
                        remediation: "Disable Ignition solution execution in production by setting IGNITION_ENABLE_SOLUTION_EXECUTION=false and restricting the route.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_storage_logs(&self, base_url: &str) -> Result<Option<LaravelFinding>, String> {
        let log_url = join_url(base_url, "storage/logs/laravel.log");
        if let Ok(response) = self.http_client.get(&log_url) {
            if response.status_code == 200 {
                let body = response.body_as_string();
                if body.contains("Stack trace") || body.contains("[202") {
                    return Ok(Some(LaravelFinding {
                        severity: FindingSeverity::High,
                        title: "Laravel application log exposed".to_string(),
                        description: "The main Laravel log file is publicly accessible, leaking stack traces, environment information, and potentially credentials.".to_string(),
                        evidence: Some(log_url),
                        remediation: "Move storage/logs outside the web root or configure web server rules to block direct access.".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    fn check_mix_manifest(&self, base_url: &str) -> Option<String> {
        let manifest_url = join_url(base_url, "mix-manifest.json");
        if let Ok(response) = self.http_client.get(&manifest_url) {
            if response.status_code == 200 {
                return Some(manifest_url);
            }
        }
        None
    }
}

#[derive(Default)]
struct LaravelFingerprint {
    detected: bool,
    version: Option<String>,
    cookie_hint: bool,
    debugbar_present: bool,
    debugbar_evidence: Option<String>,
}

fn extract_version_from_powered_by(value: &str) -> Option<String> {
    let mut lower = value.to_lowercase();
    if let Some(idx) = lower.find("laravel/") {
        lower = lower[idx + "laravel/".len()..].to_string();
        return take_version_prefix(&lower);
    }
    None
}

fn extract_version_from_body(body: &str) -> Option<String> {
    if let Some(pos) = body.find("Laravel v") {
        let slice = &body[pos + "Laravel v".len()..];
        return take_version_prefix(slice);
    }
    if let Some(pos) = body.find("Laravel version") {
        let slice = &body[pos + "Laravel version".len()..];
        return take_version_prefix(slice);
    }
    None
}

fn take_version_prefix(slice: &str) -> Option<String> {
    let mut collected = String::new();
    for ch in slice.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            collected.push(ch);
        } else if !collected.is_empty() {
            break;
        }
    }
    if collected.is_empty() {
        None
    } else {
        Some(collected)
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
