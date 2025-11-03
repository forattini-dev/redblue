/// Dependency Scanner - Detect vulnerable dependencies (Snyk/npm audit replacement)
///
/// Scans project dependency files (package.json, requirements.txt, Cargo.toml, etc.)
/// and identifies known vulnerabilities, outdated packages, and security issues.
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum PackageManager {
    Npm,      // package.json
    Pip,      // requirements.txt
    Cargo,    // Cargo.toml
    Composer, // composer.json
    Maven,    // pom.xml
    Gradle,   // build.gradle
    Bundler,  // Gemfile
    Go,       // go.mod
}

impl PackageManager {
    pub fn from_filename(filename: &str) -> Option<Self> {
        match filename {
            "package.json" | "package-lock.json" | "yarn.lock" => Some(PackageManager::Npm),
            "requirements.txt" | "Pipfile" | "Pipfile.lock" => Some(PackageManager::Pip),
            "Cargo.toml" | "Cargo.lock" => Some(PackageManager::Cargo),
            "composer.json" | "composer.lock" => Some(PackageManager::Composer),
            "pom.xml" => Some(PackageManager::Maven),
            "build.gradle" | "build.gradle.kts" => Some(PackageManager::Gradle),
            "Gemfile" | "Gemfile.lock" => Some(PackageManager::Bundler),
            "go.mod" | "go.sum" => Some(PackageManager::Go),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            PackageManager::Npm => "npm/yarn",
            PackageManager::Pip => "pip",
            PackageManager::Cargo => "Cargo",
            PackageManager::Composer => "Composer",
            PackageManager::Maven => "Maven",
            PackageManager::Gradle => "Gradle",
            PackageManager::Bundler => "Bundler",
            PackageManager::Go => "Go",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub package_manager: PackageManager,
    pub file_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl VulnSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            VulnSeverity::Critical => "Critical",
            VulnSeverity::High => "High",
            VulnSeverity::Medium => "Medium",
            VulnSeverity::Low => "Low",
        }
    }

    pub fn color(&self) -> &str {
        match self {
            VulnSeverity::Critical => "red",
            VulnSeverity::High => "red",
            VulnSeverity::Medium => "yellow",
            VulnSeverity::Low => "blue",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub package_name: String,
    pub affected_version: String,
    pub severity: VulnSeverity,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug)]
pub struct DependencyScanResult {
    pub total_dependencies: usize,
    pub vulnerable_dependencies: usize,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub files_scanned: Vec<String>,
}

pub struct DependencyScanner {
    exclude_dirs: Vec<String>,
}

impl Default for DependencyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyScanner {
    pub fn new() -> Self {
        Self {
            exclude_dirs: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                "target".to_string(),
                "vendor".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
            ],
        }
    }

    /// Scan a directory for dependency files and vulnerabilities
    pub fn scan_directory(&self, path: &str) -> Result<DependencyScanResult, String> {
        let path_obj = Path::new(path);
        if !path_obj.exists() {
            return Err(format!("Path does not exist: {}", path));
        }

        let mut dependencies = Vec::new();
        let mut files_scanned = Vec::new();

        self.scan_recursive(path_obj, &mut dependencies, &mut files_scanned)?;

        let vulnerabilities = self.check_vulnerabilities(&dependencies);
        let vulnerable_deps = vulnerabilities.len();

        Ok(DependencyScanResult {
            total_dependencies: dependencies.len(),
            vulnerable_dependencies: vulnerable_deps,
            dependencies,
            vulnerabilities,
            files_scanned,
        })
    }

    fn scan_recursive(
        &self,
        path: &Path,
        dependencies: &mut Vec<Dependency>,
        files_scanned: &mut Vec<String>,
    ) -> Result<(), String> {
        if !path.is_dir() {
            return Ok(());
        }

        // Check if this directory should be excluded
        if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
            if self.exclude_dirs.contains(&dir_name.to_string()) {
                return Ok(());
            }
        }

        let entries = fs::read_dir(path).map_err(|e| format!("Failed to read directory: {}", e))?;

        for entry in entries.flatten() {
            let entry_path = entry.path();

            if entry_path.is_dir() {
                self.scan_recursive(&entry_path, dependencies, files_scanned)?;
            } else if let Some(filename) = entry_path.file_name().and_then(|n| n.to_str()) {
                if let Some(pm) = PackageManager::from_filename(filename) {
                    let path_str = entry_path.to_string_lossy().to_string();
                    files_scanned.push(path_str.clone());

                    let file_deps = self.parse_dependency_file(&entry_path, pm)?;
                    dependencies.extend(file_deps);
                }
            }
        }

        Ok(())
    }

    fn parse_dependency_file(
        &self,
        path: &Path,
        pm: PackageManager,
    ) -> Result<Vec<Dependency>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        let path_str = path.to_string_lossy().to_string();

        match pm {
            PackageManager::Npm => self.parse_package_json(&content, &path_str),
            PackageManager::Pip => self.parse_requirements_txt(&content, &path_str),
            PackageManager::Cargo => self.parse_cargo_toml(&content, &path_str),
            _ => Ok(Vec::new()), // Other package managers not yet implemented
        }
    }

    fn parse_package_json(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Dependency>, String> {
        let mut deps = Vec::new();

        // Simple JSON parsing for dependencies and devDependencies
        for line in content.lines() {
            let trimmed = line.trim();

            // Look for dependency entries like: "package-name": "^1.2.3",
            if trimmed.starts_with('"') && trimmed.contains(':') {
                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() == 2 {
                    let name = parts[0].trim().trim_matches('"');
                    let version = parts[1]
                        .trim()
                        .trim_matches(',')
                        .trim_matches('"')
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .to_string();

                    // Skip section names
                    if name != "dependencies"
                        && name != "devDependencies"
                        && name != "peerDependencies"
                    {
                        deps.push(Dependency {
                            name: name.to_string(),
                            version,
                            package_manager: PackageManager::Npm,
                            file_path: file_path.to_string(),
                        });
                    }
                }
            }
        }

        Ok(deps)
    }

    fn parse_requirements_txt(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Dependency>, String> {
        let mut deps = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse lines like: package==1.2.3 or package>=1.2.3
            let name_version: Vec<&str> = if trimmed.contains("==") {
                trimmed.split("==").collect()
            } else if trimmed.contains(">=") {
                trimmed.split(">=").collect()
            } else if trimmed.contains("<=") {
                trimmed.split("<=").collect()
            } else {
                vec![trimmed, "latest"]
            };

            if !name_version.is_empty() {
                let name = name_version[0].trim();
                let version = name_version.get(1).unwrap_or(&"latest").trim();

                deps.push(Dependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    package_manager: PackageManager::Pip,
                    file_path: file_path.to_string(),
                });
            }
        }

        Ok(deps)
    }

    fn parse_cargo_toml(&self, content: &str, file_path: &str) -> Result<Vec<Dependency>, String> {
        let mut deps = Vec::new();
        let mut in_dependencies = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Check for [dependencies] section
            if trimmed == "[dependencies]" {
                in_dependencies = true;
                continue;
            }

            // Stop if we hit another section
            if trimmed.starts_with('[') && trimmed != "[dependencies]" {
                in_dependencies = false;
                continue;
            }

            if in_dependencies && trimmed.contains('=') {
                let parts: Vec<&str> = trimmed.split('=').collect();
                if parts.len() == 2 {
                    let name = parts[0].trim();
                    let version = parts[1]
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();

                    deps.push(Dependency {
                        name: name.to_string(),
                        version,
                        package_manager: PackageManager::Cargo,
                        file_path: file_path.to_string(),
                    });
                }
            }
        }

        Ok(deps)
    }

    fn check_vulnerabilities(&self, dependencies: &[Dependency]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Known vulnerable packages database (simplified)
        let vuln_db = self.get_vulnerability_database();

        for dep in dependencies {
            let key = format!("{}:{}", dep.package_manager.display_name(), dep.name);

            if let Some(vuln_pattern) = vuln_db.get(&key) {
                if self.version_matches(&dep.version, &vuln_pattern.0) {
                    vulns.push(vuln_pattern.1.clone());
                }
            }
        }

        vulns
    }

    fn version_matches(&self, version: &str, pattern: &str) -> bool {
        // Simple version matching (can be enhanced)
        if pattern == "*" {
            return true;
        }

        if pattern.starts_with('<') {
            let target = pattern.trim_start_matches('<').trim();
            return self.version_less_than(version, target);
        }

        version == pattern
    }

    fn version_less_than(&self, v1: &str, v2: &str) -> bool {
        let parts1: Vec<u32> = v1.split('.').filter_map(|s| s.parse().ok()).collect();
        let parts2: Vec<u32> = v2.split('.').filter_map(|s| s.parse().ok()).collect();

        for i in 0..parts1.len().max(parts2.len()) {
            let p1 = parts1.get(i).unwrap_or(&0);
            let p2 = parts2.get(i).unwrap_or(&0);

            if p1 < p2 {
                return true;
            } else if p1 > p2 {
                return false;
            }
        }

        false
    }

    fn get_vulnerability_database(&self) -> HashMap<String, (String, Vulnerability)> {
        let mut db = HashMap::new();

        // npm packages
        db.insert(
            "npm/yarn:lodash".to_string(),
            (
                "<4.17.21".to_string(),
                Vulnerability {
                    package_name: "lodash".to_string(),
                    affected_version: "<4.17.21".to_string(),
                    severity: VulnSeverity::High,
                    cve_id: Some("CVE-2021-23337".to_string()),
                    title: "Command Injection in lodash".to_string(),
                    description:
                        "Lodash versions before 4.17.21 are vulnerable to command injection"
                            .to_string(),
                    fixed_version: Some("4.17.21".to_string()),
                },
            ),
        );

        db.insert(
            "npm/yarn:axios".to_string(),
            (
                "<0.21.1".to_string(),
                Vulnerability {
                    package_name: "axios".to_string(),
                    affected_version: "<0.21.1".to_string(),
                    severity: VulnSeverity::Medium,
                    cve_id: Some("CVE-2020-28168".to_string()),
                    title: "SSRF in axios".to_string(),
                    description: "Axios versions before 0.21.1 are vulnerable to SSRF".to_string(),
                    fixed_version: Some("0.21.1".to_string()),
                },
            ),
        );

        db.insert(
            "npm/yarn:express".to_string(),
            (
                "<4.17.3".to_string(),
                Vulnerability {
                    package_name: "express".to_string(),
                    affected_version: "<4.17.3".to_string(),
                    severity: VulnSeverity::Medium,
                    cve_id: Some("CVE-2022-24999".to_string()),
                    title: "Open Redirect in express".to_string(),
                    description: "Express versions before 4.17.3 are vulnerable to open redirect"
                        .to_string(),
                    fixed_version: Some("4.17.3".to_string()),
                },
            ),
        );

        // Python packages
        db.insert(
            "pip:django".to_string(),
            (
                "<3.2.13".to_string(),
                Vulnerability {
                    package_name: "django".to_string(),
                    affected_version: "<3.2.13".to_string(),
                    severity: VulnSeverity::High,
                    cve_id: Some("CVE-2022-28346".to_string()),
                    title: "SQL Injection in Django".to_string(),
                    description: "Django versions before 3.2.13 are vulnerable to SQL injection"
                        .to_string(),
                    fixed_version: Some("3.2.13".to_string()),
                },
            ),
        );

        db.insert(
            "pip:flask".to_string(),
            (
                "<2.0.3".to_string(),
                Vulnerability {
                    package_name: "flask".to_string(),
                    affected_version: "<2.0.3".to_string(),
                    severity: VulnSeverity::Medium,
                    cve_id: Some("CVE-2023-30861".to_string()),
                    title: "Cookie Parsing Issue in Flask".to_string(),
                    description: "Flask versions before 2.0.3 have a cookie parsing vulnerability"
                        .to_string(),
                    fixed_version: Some("2.0.3".to_string()),
                },
            ),
        );

        db.insert(
            "pip:requests".to_string(),
            (
                "<2.31.0".to_string(),
                Vulnerability {
                    package_name: "requests".to_string(),
                    affected_version: "<2.31.0".to_string(),
                    severity: VulnSeverity::Medium,
                    cve_id: Some("CVE-2023-32681".to_string()),
                    title: "Proxy Tunnel Validation in Requests".to_string(),
                    description: "Requests versions before 2.31.0 have proxy validation issues"
                        .to_string(),
                    fixed_version: Some("2.31.0".to_string()),
                },
            ),
        );

        db
    }
}
