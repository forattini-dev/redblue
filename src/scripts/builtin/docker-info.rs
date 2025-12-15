/// Docker API Information Script
///
/// Detects exposed Docker APIs and identifies security issues
/// including unauthenticated access to the Docker daemon.
use crate::scripts::types::*;
use crate::scripts::Script;

/// Docker API Information Script
pub struct DockerInfoScript {
    meta: ScriptMetadata,
}

impl DockerInfoScript {
    pub fn new() -> Self {
        Self {
            meta: ScriptMetadata {
                id: "docker-info".to_string(),
                name: "Docker API Detection".to_string(),
                author: "redblue".to_string(),
                version: "1.0".to_string(),
                description: "Detects exposed Docker APIs and identifies security issues"
                    .to_string(),
                categories: vec![
                    ScriptCategory::Discovery,
                    ScriptCategory::Vuln,
                    ScriptCategory::Safe,
                ],
                protocols: vec!["http".to_string(), "https".to_string()],
                ports: vec![2375, 2376, 2377, 4243],
                license: "MIT".to_string(),
                cves: Vec::new(),
                references: vec![
                    "https://docs.docker.com/engine/security/protect-access/".to_string()
                ],
            },
        }
    }
}

impl Default for DockerInfoScript {
    fn default() -> Self {
        Self::new()
    }
}

impl Script for DockerInfoScript {
    fn metadata(&self) -> &ScriptMetadata {
        &self.meta
    }

    fn run(&self, ctx: &ScriptContext) -> Result<ScriptResult, String> {
        let mut result = ScriptResult::new(&self.meta.id);

        let docker_data = ctx.get_data("docker_response").unwrap_or("");
        let docker_version = ctx.get_data("docker_version").unwrap_or("");
        let tls_enabled = ctx.get_data("docker_tls").unwrap_or("");

        if docker_data.is_empty() && docker_version.is_empty() {
            result.add_output("No Docker API data available in context");
            return Ok(result);
        }

        result.success = true;
        let data_lower = docker_data.to_lowercase();

        // Docker API detected - this is always significant
        result.add_finding(
            Finding::new(FindingType::Discovery, "Docker API Detected")
                .with_description(&format!("Docker daemon API exposed on port {}", ctx.port))
                .with_severity(FindingSeverity::Medium),
        );

        // Check TLS status
        let is_tls_port = ctx.port == 2376;
        match tls_enabled.to_lowercase().as_str() {
            "false" | "disabled" | "no" | "0" => {
                result.add_finding(
                    Finding::new(FindingType::Vulnerability, "Docker API Without TLS")
                        .with_description(
                            "Docker API is accessible without TLS encryption. \
                             This allows unauthorized access to the Docker daemon with root privileges."
                        )
                        .with_severity(FindingSeverity::Critical)
                        .with_remediation(
                            "Enable TLS for Docker daemon. Use port 2376 with certificates. \
                             See: https://docs.docker.com/engine/security/protect-access/"
                        ),
                );
            }
            "true" | "enabled" | "yes" | "1" => {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "TLS Enabled")
                        .with_description("Docker API is protected with TLS")
                        .with_severity(FindingSeverity::Info),
                );
            }
            _ => {
                // Infer from port
                if !is_tls_port && ctx.port == 2375 {
                    result.add_finding(
                        Finding::new(FindingType::Vulnerability, "Unencrypted Docker API Port")
                            .with_description(
                                "Port 2375 is the default unencrypted Docker API port. \
                                 This typically indicates no TLS protection.",
                            )
                            .with_severity(FindingSeverity::Critical)
                            .with_remediation("Use port 2376 with TLS certificates"),
                    );
                }
            }
        }

        // Extract version
        if !docker_version.is_empty() {
            result.extract("docker_version", docker_version);
            result.add_finding(
                Finding::new(FindingType::Version, "Docker Version")
                    .with_description(&format!("Docker version: {}", docker_version))
                    .with_severity(FindingSeverity::Info),
            );
        }

        // Check for API version from response
        if let Some(api_version) = self.extract_api_version(&data_lower) {
            result.extract("docker_api_version", &api_version);
        }

        // Check for privileged containers
        if data_lower.contains("\"privileged\":true") || data_lower.contains("\"privileged\": true")
        {
            result.add_finding(
                Finding::new(
                    FindingType::Misconfiguration,
                    "Privileged Containers Running",
                )
                .with_description(
                    "Privileged containers are running. These containers have \
                         full access to the host system.",
                )
                .with_severity(FindingSeverity::High)
                .with_remediation(
                    "Avoid privileged containers. Use specific capabilities instead.",
                ),
            );
        }

        // Check for containers with host mounts
        if data_lower.contains("/var/run/docker.sock") {
            result.add_finding(
                Finding::new(FindingType::Misconfiguration, "Docker Socket Mounted")
                    .with_description(
                        "Container has Docker socket mounted. This allows \
                         container escape and host compromise.",
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation("Remove Docker socket mount unless absolutely necessary"),
            );
        }

        if data_lower.contains("\"type\":\"bind\"")
            && (data_lower.contains("\"/etc\"") || data_lower.contains("\"/root\""))
        {
            result.add_finding(
                Finding::new(
                    FindingType::Misconfiguration,
                    "Sensitive Host Paths Mounted",
                )
                .with_description("Containers have sensitive host paths mounted (/etc, /root)")
                .with_severity(FindingSeverity::High)
                .with_remediation("Review and minimize host path mounts"),
            );
        }

        // Check for running containers count
        if data_lower.contains("containers") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Container Information Accessible")
                    .with_description("Docker API exposes container information")
                    .with_severity(FindingSeverity::Medium),
            );
        }

        // Check for images
        if data_lower.contains("images") {
            result.add_finding(
                Finding::new(FindingType::InfoLeak, "Image Information Accessible")
                    .with_description("Docker API exposes image information")
                    .with_severity(FindingSeverity::Low),
            );
        }

        // Check for swarm mode
        if data_lower.contains("swarm") {
            if data_lower.contains("\"localnodelocked\":false") || data_lower.contains("active") {
                result.add_finding(
                    Finding::new(FindingType::Discovery, "Docker Swarm Mode Active")
                        .with_description("Docker Swarm mode is enabled on this node")
                        .with_severity(FindingSeverity::Info),
                );
            }
        }

        // Internet exposure check
        let is_external = !ctx.host.starts_with("192.168.")
            && !ctx.host.starts_with("10.")
            && !ctx.host.starts_with("172.")
            && ctx.host != "localhost"
            && ctx.host != "127.0.0.1";

        if is_external {
            result.add_finding(
                Finding::new(FindingType::Vulnerability, "Docker API Exposed to Internet")
                    .with_description(
                        "Docker API is exposed to the internet. This is extremely dangerous \
                         as it provides root-level access to the host system.",
                    )
                    .with_severity(FindingSeverity::Critical)
                    .with_remediation(
                        "Never expose Docker API to the internet. \
                         Use VPN or SSH tunneling if remote access is needed.",
                    ),
            );
        }

        result.add_output(&format!(
            "Docker API analysis complete for {}:{}",
            ctx.host, ctx.port
        ));
        Ok(result)
    }
}

impl DockerInfoScript {
    fn extract_api_version(&self, data: &str) -> Option<String> {
        // Look for ApiVersion in JSON response
        if let Some(pos) = data.find("\"apiversion\"") {
            let after = &data[pos..];
            let mut version = String::new();
            let mut in_value = false;
            for ch in after.chars() {
                if ch == '"' {
                    if in_value {
                        break;
                    }
                    in_value = !in_value;
                } else if in_value && (ch.is_ascii_digit() || ch == '.') {
                    version.push(ch);
                }
            }
            if !version.is_empty() {
                return Some(version);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_script() {
        let script = DockerInfoScript::new();
        assert_eq!(script.id(), "docker-info");
    }

    #[test]
    fn test_no_tls() {
        let script = DockerInfoScript::new();
        let mut ctx = ScriptContext::new("10.0.0.1", 2375);
        ctx.set_data("docker_response", "{\"containers\": 5}");
        ctx.set_data("docker_tls", "false");

        let result = script.run(&ctx).unwrap();
        let has_no_tls = result
            .findings
            .iter()
            .any(|f| f.title.contains("Without TLS"));
        assert!(has_no_tls);
    }
}
