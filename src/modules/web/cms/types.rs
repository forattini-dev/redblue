//! CMS Types and Data Structures

/// Supported CMS types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmsType {
    WordPress,
    Drupal,
    Joomla,
    Magento,
    Shopify,
    PrestaShop,
    OpenCart,
    TYPO3,
    Concrete5,
    Ghost,
    Hugo,
    Jekyll,
    Gatsby,
    NextJS,
    Strapi,
    Contentful,
    Sanity,
    Squarespace,
    Wix,
    Webflow,
    Unknown,
}

impl CmsType {
    pub fn name(&self) -> &str {
        match self {
            Self::WordPress => "WordPress",
            Self::Drupal => "Drupal",
            Self::Joomla => "Joomla",
            Self::Magento => "Magento",
            Self::Shopify => "Shopify",
            Self::PrestaShop => "PrestaShop",
            Self::OpenCart => "OpenCart",
            Self::TYPO3 => "TYPO3",
            Self::Concrete5 => "Concrete5",
            Self::Ghost => "Ghost",
            Self::Hugo => "Hugo",
            Self::Jekyll => "Jekyll",
            Self::Gatsby => "Gatsby",
            Self::NextJS => "Next.js",
            Self::Strapi => "Strapi",
            Self::Contentful => "Contentful",
            Self::Sanity => "Sanity",
            Self::Squarespace => "Squarespace",
            Self::Wix => "Wix",
            Self::Webflow => "Webflow",
            Self::Unknown => "Unknown",
        }
    }

    pub fn admin_paths(&self) -> Vec<&str> {
        match self {
            Self::WordPress => vec!["/wp-admin/", "/wp-login.php"],
            Self::Drupal => vec!["/user/login", "/admin/"],
            Self::Joomla => vec!["/administrator/", "/admin/"],
            Self::Magento => vec!["/admin/", "/admin_*"],
            Self::Shopify => vec!["/admin"],
            Self::PrestaShop => vec!["/admin*/", "/backoffice/"],
            Self::OpenCart => vec!["/admin/"],
            Self::TYPO3 => vec!["/typo3/"],
            Self::Concrete5 => vec!["/dashboard/"],
            Self::Ghost => vec!["/ghost/"],
            _ => vec!["/admin/"],
        }
    }
}

impl std::fmt::Display for CmsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Detection result from CMS detector
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Detected CMS type
    pub cms_type: CmsType,
    /// Detected version
    pub version: Option<String>,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Detection methods that matched
    pub methods: Vec<String>,
    /// Additional metadata
    pub metadata: Vec<(String, String)>,
}

impl DetectionResult {
    pub fn unknown() -> Self {
        Self {
            cms_type: CmsType::Unknown,
            version: None,
            confidence: 0,
            methods: Vec::new(),
            metadata: Vec::new(),
        }
    }
}

/// Plugin/Module information
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name/slug
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Detected version
    pub version: Option<String>,
    /// Plugin location/path
    pub location: Option<String>,
    /// Is plugin vulnerable?
    pub vulnerable: bool,
    /// Detection method
    pub detection_method: PluginDetectionMethod,
    /// Confidence (0-100)
    pub confidence: u8,
    /// Last update date
    pub last_updated: Option<String>,
    /// Known vulnerabilities
    pub vulnerabilities: Vec<String>,
}

impl PluginInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: None,
            version: None,
            location: None,
            vulnerable: false,
            detection_method: PluginDetectionMethod::DirectAccess,
            confidence: 50,
            last_updated: None,
            vulnerabilities: Vec::new(),
        }
    }
}

/// Plugin detection methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginDetectionMethod {
    /// Direct access to plugin files
    DirectAccess,
    /// Found in HTML source
    HtmlSource,
    /// Found in CSS/JS includes
    AssetIncludes,
    /// Found via API
    ApiEndpoint,
    /// Found in error messages
    ErrorMessage,
    /// Found in readme/changelog
    ReadmeFile,
    /// Found via version probing
    VersionProbe,
    /// Aggressive bruteforce
    Bruteforce,
}

/// Theme/Template information
#[derive(Debug, Clone)]
pub struct ThemeInfo {
    /// Theme name/slug
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Detected version
    pub version: Option<String>,
    /// Theme location/path
    pub location: Option<String>,
    /// Is theme vulnerable?
    pub vulnerable: bool,
    /// Is this the active theme?
    pub is_active: bool,
    /// Parent theme (if child)
    pub parent_theme: Option<String>,
    /// Detection method
    pub detection_method: PluginDetectionMethod,
    /// Known vulnerabilities
    pub vulnerabilities: Vec<String>,
}

impl ThemeInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            display_name: None,
            version: None,
            location: None,
            vulnerable: false,
            is_active: false,
            parent_theme: None,
            detection_method: PluginDetectionMethod::HtmlSource,
            vulnerabilities: Vec::new(),
        }
    }
}

/// User information
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Username
    pub username: String,
    /// User ID
    pub id: Option<u64>,
    /// Display name
    pub display_name: Option<String>,
    /// User role (admin, editor, etc.)
    pub role: Option<String>,
    /// Email (if discovered)
    pub email: Option<String>,
    /// Profile URL
    pub profile_url: Option<String>,
    /// Detection method
    pub detection_method: UserDetectionMethod,
}

impl UserInfo {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            id: None,
            display_name: None,
            role: None,
            email: None,
            profile_url: None,
            detection_method: UserDetectionMethod::AuthorArchive,
        }
    }
}

/// User detection methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDetectionMethod {
    /// Author archive pages (/?author=N)
    AuthorArchive,
    /// REST API (/wp-json/wp/v2/users)
    RestApi,
    /// RSS feed author
    RssFeed,
    /// Login error messages
    LoginError,
    /// XML-RPC
    XmlRpc,
    /// oEmbed discovery
    OEmbed,
    /// Comment author
    CommentAuthor,
    /// Admin AJAX
    AdminAjax,
}

/// Vulnerability information
#[derive(Debug, Clone)]
pub struct Vulnerability {
    /// Vulnerability ID (CVE, WPScan ID, etc.)
    pub id: String,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: VulnSeverity,
    /// CVSS score
    pub cvss: Option<f32>,
    /// Affected component (core, plugin, theme)
    pub component: VulnComponent,
    /// Affected component name
    pub component_name: String,
    /// Affected versions
    pub affected_versions: String,
    /// Fixed in version
    pub fixed_in: Option<String>,
    /// Vulnerability type
    pub vuln_type: VulnType,
    /// References (URLs)
    pub references: Vec<String>,
    /// Exploit available?
    pub exploit_available: bool,
    /// Published date
    pub published: Option<String>,
}

/// Vulnerability severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn from_cvss(cvss: f32) -> Self {
        match cvss {
            x if x >= 9.0 => Self::Critical,
            x if x >= 7.0 => Self::High,
            x if x >= 4.0 => Self::Medium,
            x if x >= 0.1 => Self::Low,
            _ => Self::Info,
        }
    }
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Vulnerability component type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnComponent {
    Core,
    Plugin,
    Theme,
    Server,
    Configuration,
}

/// Vulnerability type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnType {
    SqlInjection,
    Xss,
    Csrf,
    Rce,
    Lfi,
    Rfi,
    PathTraversal,
    AuthBypass,
    PrivilegeEscalation,
    InformationDisclosure,
    Ssrf,
    OpenRedirect,
    FileUpload,
    Deserialization,
    Xxe,
    Dos,
    Other,
}

impl VulnType {
    pub fn name(&self) -> &str {
        match self {
            Self::SqlInjection => "SQL Injection",
            Self::Xss => "Cross-Site Scripting (XSS)",
            Self::Csrf => "Cross-Site Request Forgery (CSRF)",
            Self::Rce => "Remote Code Execution (RCE)",
            Self::Lfi => "Local File Inclusion (LFI)",
            Self::Rfi => "Remote File Inclusion (RFI)",
            Self::PathTraversal => "Path Traversal",
            Self::AuthBypass => "Authentication Bypass",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::InformationDisclosure => "Information Disclosure",
            Self::Ssrf => "Server-Side Request Forgery (SSRF)",
            Self::OpenRedirect => "Open Redirect",
            Self::FileUpload => "Arbitrary File Upload",
            Self::Deserialization => "Insecure Deserialization",
            Self::Xxe => "XML External Entity (XXE)",
            Self::Dos => "Denial of Service (DoS)",
            Self::Other => "Other",
        }
    }
}

impl std::fmt::Display for VulnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Interesting finding
#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding type
    pub finding_type: FindingType,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// URL where found
    pub url: Option<String>,
    /// Evidence
    pub evidence: Option<String>,
    /// Severity
    pub severity: VulnSeverity,
    /// Confidence (0-100)
    pub confidence: u8,
}

/// Finding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingType {
    /// Directory listing enabled
    DirectoryListing,
    /// Sensitive file exposed
    SensitiveFile,
    /// Debug mode enabled
    DebugMode,
    /// Default credentials
    DefaultCredentials,
    /// Backup file found
    BackupFile,
    /// Configuration file exposed
    ConfigFile,
    /// Version disclosure
    VersionDisclosure,
    /// XML-RPC enabled
    XmlRpcEnabled,
    /// REST API exposed
    RestApiExposed,
    /// Registration enabled
    RegistrationEnabled,
    /// Weak password policy
    WeakPasswordPolicy,
    /// Missing security headers
    MissingSecurityHeaders,
    /// SSL/TLS issues
    SslIssues,
    /// Outdated software
    OutdatedSoftware,
    /// Information leak
    InformationLeak,
    /// Other
    Other,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectoryListing => write!(f, "Directory Listing"),
            Self::SensitiveFile => write!(f, "Sensitive File"),
            Self::DebugMode => write!(f, "Debug Mode"),
            Self::DefaultCredentials => write!(f, "Default Credentials"),
            Self::BackupFile => write!(f, "Backup File"),
            Self::ConfigFile => write!(f, "Configuration File"),
            Self::VersionDisclosure => write!(f, "Version Disclosure"),
            Self::XmlRpcEnabled => write!(f, "XML-RPC Enabled"),
            Self::RestApiExposed => write!(f, "REST API Exposed"),
            Self::RegistrationEnabled => write!(f, "Registration Enabled"),
            Self::WeakPasswordPolicy => write!(f, "Weak Password Policy"),
            Self::MissingSecurityHeaders => write!(f, "Missing Security Headers"),
            Self::SslIssues => write!(f, "SSL/TLS Issues"),
            Self::OutdatedSoftware => write!(f, "Outdated Software"),
            Self::InformationLeak => write!(f, "Information Leak"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// HTTP response for internal use
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub url: String,
}

impl HttpResponse {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn contains(&self, pattern: &str) -> bool {
        self.body.contains(pattern)
    }

    pub fn contains_any(&self, patterns: &[&str]) -> bool {
        patterns.iter().any(|p| self.body.contains(p))
    }
}
