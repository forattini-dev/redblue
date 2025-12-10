//! CPE (Common Platform Enumeration) Dictionary
//!
//! Maps detected technology names to CPE 2.3 identifiers for NVD queries.
//! CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//!
//! Reference: https://nvd.nist.gov/products/cpe

/// CPE mapping entry linking technology name to CPE components
#[derive(Debug, Clone)]
pub struct CpeMapping {
    /// Technology name as detected by fingerprinting (lowercase)
    pub tech_name: &'static str,
    /// CPE vendor component
    pub vendor: &'static str,
    /// CPE product component
    pub product: &'static str,
    /// Technology category for grouping
    pub category: TechCategory,
    /// Alternative names/aliases for this technology
    pub aliases: &'static [&'static str],
}

/// Technology categories for organization and filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TechCategory {
    /// Web servers (nginx, Apache, IIS)
    WebServer,
    /// Reverse proxies and load balancers
    Proxy,
    /// Content Delivery Networks
    Cdn,
    /// Web application frameworks
    Framework,
    /// Programming language runtimes
    Runtime,
    /// Content Management Systems
    Cms,
    /// JavaScript libraries
    JsLibrary,
    /// Databases
    Database,
    /// Operating Systems
    OperatingSystem,
    /// Other/uncategorized
    Other,
}

impl CpeMapping {
    /// Generate CPE 2.3 string with version
    pub fn to_cpe(&self, version: Option<&str>) -> String {
        let ver = version.unwrap_or("*");
        format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            self.vendor, self.product, ver
        )
    }

    /// Generate CPE 2.3 string for matching (wildcards)
    pub fn to_cpe_match(&self) -> String {
        format!(
            "cpe:2.3:a:{}:{}:*:*:*:*:*:*:*:*",
            self.vendor, self.product
        )
    }
}

/// Master CPE dictionary - comprehensive mappings for vulnerability lookups
pub static CPE_DICTIONARY: &[CpeMapping] = &[
    // ============================================
    // WEB SERVERS
    // ============================================
    CpeMapping {
        tech_name: "nginx",
        vendor: "f5",
        product: "nginx",
        category: TechCategory::WebServer,
        aliases: &["nginx", "openresty"],
    },
    CpeMapping {
        tech_name: "apache",
        vendor: "apache",
        product: "http_server",
        category: TechCategory::WebServer,
        aliases: &["apache", "httpd", "apache2", "apache http server"],
    },
    CpeMapping {
        tech_name: "iis",
        vendor: "microsoft",
        product: "internet_information_services",
        category: TechCategory::WebServer,
        aliases: &["iis", "microsoft-iis", "microsoft iis"],
    },
    CpeMapping {
        tech_name: "litespeed",
        vendor: "litespeedtech",
        product: "litespeed_web_server",
        category: TechCategory::WebServer,
        aliases: &["litespeed", "lsws"],
    },
    CpeMapping {
        tech_name: "caddy",
        vendor: "caddyserver",
        product: "caddy",
        category: TechCategory::WebServer,
        aliases: &["caddy"],
    },
    CpeMapping {
        tech_name: "tomcat",
        vendor: "apache",
        product: "tomcat",
        category: TechCategory::WebServer,
        aliases: &["tomcat", "apache tomcat"],
    },
    CpeMapping {
        tech_name: "jetty",
        vendor: "eclipse",
        product: "jetty",
        category: TechCategory::WebServer,
        aliases: &["jetty", "eclipse jetty"],
    },
    CpeMapping {
        tech_name: "gunicorn",
        vendor: "gunicorn",
        product: "gunicorn",
        category: TechCategory::WebServer,
        aliases: &["gunicorn"],
    },
    CpeMapping {
        tech_name: "uvicorn",
        vendor: "encode",
        product: "uvicorn",
        category: TechCategory::WebServer,
        aliases: &["uvicorn"],
    },

    // ============================================
    // PROXIES & LOAD BALANCERS
    // ============================================
    CpeMapping {
        tech_name: "haproxy",
        vendor: "haproxy",
        product: "haproxy",
        category: TechCategory::Proxy,
        aliases: &["haproxy"],
    },
    CpeMapping {
        tech_name: "traefik",
        vendor: "traefik",
        product: "traefik",
        category: TechCategory::Proxy,
        aliases: &["traefik"],
    },
    CpeMapping {
        tech_name: "envoy",
        vendor: "envoyproxy",
        product: "envoy",
        category: TechCategory::Proxy,
        aliases: &["envoy"],
    },
    CpeMapping {
        tech_name: "varnish",
        vendor: "varnish-software",
        product: "varnish_cache",
        category: TechCategory::Proxy,
        aliases: &["varnish", "varnish cache"],
    },
    CpeMapping {
        tech_name: "squid",
        vendor: "squid-cache",
        product: "squid",
        category: TechCategory::Proxy,
        aliases: &["squid"],
    },

    // ============================================
    // PROGRAMMING RUNTIMES
    // ============================================
    CpeMapping {
        tech_name: "php",
        vendor: "php",
        product: "php",
        category: TechCategory::Runtime,
        aliases: &["php"],
    },
    CpeMapping {
        tech_name: "node.js",
        vendor: "nodejs",
        product: "node.js",
        category: TechCategory::Runtime,
        aliases: &["node", "nodejs", "node.js"],
    },
    CpeMapping {
        tech_name: "python",
        vendor: "python",
        product: "python",
        category: TechCategory::Runtime,
        aliases: &["python", "cpython"],
    },
    CpeMapping {
        tech_name: "ruby",
        vendor: "ruby-lang",
        product: "ruby",
        category: TechCategory::Runtime,
        aliases: &["ruby", "mri"],
    },
    CpeMapping {
        tech_name: "java",
        vendor: "oracle",
        product: "jdk",
        category: TechCategory::Runtime,
        aliases: &["java", "jdk", "jre", "openjdk"],
    },
    CpeMapping {
        tech_name: "dotnet",
        vendor: "microsoft",
        product: ".net",
        category: TechCategory::Runtime,
        aliases: &[".net", "dotnet", "asp.net"],
    },
    CpeMapping {
        tech_name: "go",
        vendor: "golang",
        product: "go",
        category: TechCategory::Runtime,
        aliases: &["go", "golang"],
    },

    // ============================================
    // WEB FRAMEWORKS
    // ============================================
    CpeMapping {
        tech_name: "express",
        vendor: "expressjs",
        product: "express",
        category: TechCategory::Framework,
        aliases: &["express", "expressjs"],
    },
    CpeMapping {
        tech_name: "django",
        vendor: "djangoproject",
        product: "django",
        category: TechCategory::Framework,
        aliases: &["django"],
    },
    CpeMapping {
        tech_name: "flask",
        vendor: "palletsprojects",
        product: "flask",
        category: TechCategory::Framework,
        aliases: &["flask"],
    },
    CpeMapping {
        tech_name: "rails",
        vendor: "rubyonrails",
        product: "rails",
        category: TechCategory::Framework,
        aliases: &["rails", "ruby on rails", "ror"],
    },
    CpeMapping {
        tech_name: "laravel",
        vendor: "laravel",
        product: "laravel",
        category: TechCategory::Framework,
        aliases: &["laravel"],
    },
    CpeMapping {
        tech_name: "symfony",
        vendor: "symfony",
        product: "symfony",
        category: TechCategory::Framework,
        aliases: &["symfony"],
    },
    CpeMapping {
        tech_name: "spring",
        vendor: "vmware",
        product: "spring_framework",
        category: TechCategory::Framework,
        aliases: &["spring", "spring framework", "spring boot"],
    },
    CpeMapping {
        tech_name: "fastapi",
        vendor: "tiangolo",
        product: "fastapi",
        category: TechCategory::Framework,
        aliases: &["fastapi"],
    },
    CpeMapping {
        tech_name: "nextjs",
        vendor: "vercel",
        product: "next.js",
        category: TechCategory::Framework,
        aliases: &["next", "nextjs", "next.js"],
    },
    CpeMapping {
        tech_name: "nuxt",
        vendor: "nuxt",
        product: "nuxt",
        category: TechCategory::Framework,
        aliases: &["nuxt", "nuxtjs", "nuxt.js"],
    },

    // ============================================
    // CMS (Content Management Systems)
    // ============================================
    CpeMapping {
        tech_name: "wordpress",
        vendor: "wordpress",
        product: "wordpress",
        category: TechCategory::Cms,
        aliases: &["wordpress", "wp"],
    },
    CpeMapping {
        tech_name: "drupal",
        vendor: "drupal",
        product: "drupal",
        category: TechCategory::Cms,
        aliases: &["drupal"],
    },
    CpeMapping {
        tech_name: "joomla",
        vendor: "joomla",
        product: "joomla\\!",
        category: TechCategory::Cms,
        aliases: &["joomla", "joomla!"],
    },
    CpeMapping {
        tech_name: "magento",
        vendor: "adobe",
        product: "magento",
        category: TechCategory::Cms,
        aliases: &["magento", "adobe commerce"],
    },
    CpeMapping {
        tech_name: "shopify",
        vendor: "shopify",
        product: "shopify",
        category: TechCategory::Cms,
        aliases: &["shopify"],
    },
    CpeMapping {
        tech_name: "ghost",
        vendor: "ghost",
        product: "ghost",
        category: TechCategory::Cms,
        aliases: &["ghost"],
    },
    CpeMapping {
        tech_name: "strapi",
        vendor: "strapi",
        product: "strapi",
        category: TechCategory::Cms,
        aliases: &["strapi"],
    },
    CpeMapping {
        tech_name: "directus",
        vendor: "directus",
        product: "directus",
        category: TechCategory::Cms,
        aliases: &["directus"],
    },
    CpeMapping {
        tech_name: "typo3",
        vendor: "typo3",
        product: "typo3",
        category: TechCategory::Cms,
        aliases: &["typo3"],
    },
    CpeMapping {
        tech_name: "prestashop",
        vendor: "prestashop",
        product: "prestashop",
        category: TechCategory::Cms,
        aliases: &["prestashop"],
    },

    // ============================================
    // JAVASCRIPT LIBRARIES
    // ============================================
    CpeMapping {
        tech_name: "jquery",
        vendor: "jquery",
        product: "jquery",
        category: TechCategory::JsLibrary,
        aliases: &["jquery"],
    },
    CpeMapping {
        tech_name: "react",
        vendor: "facebook",
        product: "react",
        category: TechCategory::JsLibrary,
        aliases: &["react", "reactjs"],
    },
    CpeMapping {
        tech_name: "vue",
        vendor: "vuejs",
        product: "vue.js",
        category: TechCategory::JsLibrary,
        aliases: &["vue", "vuejs", "vue.js"],
    },
    CpeMapping {
        tech_name: "angular",
        vendor: "google",
        product: "angular",
        category: TechCategory::JsLibrary,
        aliases: &["angular", "angularjs"],
    },
    CpeMapping {
        tech_name: "lodash",
        vendor: "lodash",
        product: "lodash",
        category: TechCategory::JsLibrary,
        aliases: &["lodash", "_"],
    },
    CpeMapping {
        tech_name: "moment",
        vendor: "momentjs",
        product: "moment",
        category: TechCategory::JsLibrary,
        aliases: &["moment", "momentjs", "moment.js"],
    },
    CpeMapping {
        tech_name: "axios",
        vendor: "axios",
        product: "axios",
        category: TechCategory::JsLibrary,
        aliases: &["axios"],
    },
    CpeMapping {
        tech_name: "bootstrap",
        vendor: "getbootstrap",
        product: "bootstrap",
        category: TechCategory::JsLibrary,
        aliases: &["bootstrap"],
    },

    // ============================================
    // DATABASES
    // ============================================
    CpeMapping {
        tech_name: "mysql",
        vendor: "oracle",
        product: "mysql",
        category: TechCategory::Database,
        aliases: &["mysql"],
    },
    CpeMapping {
        tech_name: "mariadb",
        vendor: "mariadb",
        product: "mariadb",
        category: TechCategory::Database,
        aliases: &["mariadb"],
    },
    CpeMapping {
        tech_name: "postgresql",
        vendor: "postgresql",
        product: "postgresql",
        category: TechCategory::Database,
        aliases: &["postgresql", "postgres", "pgsql"],
    },
    CpeMapping {
        tech_name: "mongodb",
        vendor: "mongodb",
        product: "mongodb",
        category: TechCategory::Database,
        aliases: &["mongodb", "mongo"],
    },
    CpeMapping {
        tech_name: "redis",
        vendor: "redis",
        product: "redis",
        category: TechCategory::Database,
        aliases: &["redis"],
    },
    CpeMapping {
        tech_name: "elasticsearch",
        vendor: "elastic",
        product: "elasticsearch",
        category: TechCategory::Database,
        aliases: &["elasticsearch", "elastic"],
    },
    CpeMapping {
        tech_name: "mssql",
        vendor: "microsoft",
        product: "sql_server",
        category: TechCategory::Database,
        aliases: &["mssql", "sql server", "sqlserver"],
    },
    CpeMapping {
        tech_name: "oracle_db",
        vendor: "oracle",
        product: "database",
        category: TechCategory::Database,
        aliases: &["oracle", "oracle db", "oracle database"],
    },
    CpeMapping {
        tech_name: "sqlite",
        vendor: "sqlite",
        product: "sqlite",
        category: TechCategory::Database,
        aliases: &["sqlite", "sqlite3"],
    },
    CpeMapping {
        tech_name: "couchdb",
        vendor: "apache",
        product: "couchdb",
        category: TechCategory::Database,
        aliases: &["couchdb"],
    },

    // ============================================
    // OPERATING SYSTEMS
    // ============================================
    CpeMapping {
        tech_name: "ubuntu",
        vendor: "canonical",
        product: "ubuntu_linux",
        category: TechCategory::OperatingSystem,
        aliases: &["ubuntu"],
    },
    CpeMapping {
        tech_name: "debian",
        vendor: "debian",
        product: "debian_linux",
        category: TechCategory::OperatingSystem,
        aliases: &["debian"],
    },
    CpeMapping {
        tech_name: "centos",
        vendor: "centos",
        product: "centos",
        category: TechCategory::OperatingSystem,
        aliases: &["centos"],
    },
    CpeMapping {
        tech_name: "rhel",
        vendor: "redhat",
        product: "enterprise_linux",
        category: TechCategory::OperatingSystem,
        aliases: &["rhel", "red hat", "redhat"],
    },
    CpeMapping {
        tech_name: "windows_server",
        vendor: "microsoft",
        product: "windows_server",
        category: TechCategory::OperatingSystem,
        aliases: &["windows server", "win server"],
    },

    // ============================================
    // OTHER / INFRASTRUCTURE
    // ============================================
    CpeMapping {
        tech_name: "openssh",
        vendor: "openbsd",
        product: "openssh",
        category: TechCategory::Other,
        aliases: &["openssh", "ssh"],
    },
    CpeMapping {
        tech_name: "openssl",
        vendor: "openssl",
        product: "openssl",
        category: TechCategory::Other,
        aliases: &["openssl"],
    },
    CpeMapping {
        tech_name: "docker",
        vendor: "docker",
        product: "docker",
        category: TechCategory::Other,
        aliases: &["docker"],
    },
    CpeMapping {
        tech_name: "kubernetes",
        vendor: "kubernetes",
        product: "kubernetes",
        category: TechCategory::Other,
        aliases: &["kubernetes", "k8s"],
    },
    CpeMapping {
        tech_name: "grafana",
        vendor: "grafana",
        product: "grafana",
        category: TechCategory::Other,
        aliases: &["grafana"],
    },
    CpeMapping {
        tech_name: "prometheus",
        vendor: "prometheus",
        product: "prometheus",
        category: TechCategory::Other,
        aliases: &["prometheus"],
    },
    CpeMapping {
        tech_name: "jenkins",
        vendor: "jenkins",
        product: "jenkins",
        category: TechCategory::Other,
        aliases: &["jenkins"],
    },
    CpeMapping {
        tech_name: "gitlab",
        vendor: "gitlab",
        product: "gitlab",
        category: TechCategory::Other,
        aliases: &["gitlab"],
    },
    CpeMapping {
        tech_name: "rabbitmq",
        vendor: "vmware",
        product: "rabbitmq",
        category: TechCategory::Other,
        aliases: &["rabbitmq"],
    },
    CpeMapping {
        tech_name: "kafka",
        vendor: "apache",
        product: "kafka",
        category: TechCategory::Other,
        aliases: &["kafka", "apache kafka"],
    },
];

/// Find CPE mapping by technology name (case-insensitive)
pub fn find_cpe(tech_name: &str) -> Option<&'static CpeMapping> {
    let name_lower = tech_name.to_lowercase();

    CPE_DICTIONARY.iter().find(|mapping| {
        mapping.tech_name == name_lower
            || mapping.aliases.iter().any(|alias| alias.to_lowercase() == name_lower)
    })
}

/// Find CPE mapping by vendor and product
pub fn find_cpe_by_vendor_product(vendor: &str, product: &str) -> Option<&'static CpeMapping> {
    let vendor_lower = vendor.to_lowercase();
    let product_lower = product.to_lowercase();

    CPE_DICTIONARY.iter().find(|mapping| {
        mapping.vendor.to_lowercase() == vendor_lower
            && mapping.product.to_lowercase() == product_lower
    })
}

/// Get all CPE mappings for a category
pub fn get_by_category(category: TechCategory) -> Vec<&'static CpeMapping> {
    CPE_DICTIONARY.iter()
        .filter(|mapping| mapping.category == category)
        .collect()
}

/// Generate CPE string from tech name and version
pub fn generate_cpe(tech_name: &str, version: Option<&str>) -> Option<String> {
    find_cpe(tech_name).map(|mapping| mapping.to_cpe(version))
}

/// Get all CPE mappings
pub fn get_all_cpe_mappings() -> &'static [CpeMapping] {
    CPE_DICTIONARY
}

/// Parse version from CPE string
pub fn parse_cpe_version(cpe: &str) -> Option<String> {
    // cpe:2.3:a:vendor:product:version:...
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 6 && parts[5] != "*" && parts[5] != "-" {
        Some(parts[5].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_cpe_nginx() {
        let mapping = find_cpe("nginx").unwrap();
        assert_eq!(mapping.vendor, "f5");
        assert_eq!(mapping.product, "nginx");
    }

    #[test]
    fn test_find_cpe_case_insensitive() {
        assert!(find_cpe("NGINX").is_some());
        assert!(find_cpe("Nginx").is_some());
        assert!(find_cpe("nginx").is_some());
    }

    #[test]
    fn test_find_cpe_by_alias() {
        let mapping = find_cpe("httpd").unwrap();
        assert_eq!(mapping.tech_name, "apache");
    }

    #[test]
    fn test_generate_cpe_with_version() {
        let cpe = generate_cpe("nginx", Some("1.18.0")).unwrap();
        assert_eq!(cpe, "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_generate_cpe_without_version() {
        let cpe = generate_cpe("nginx", None).unwrap();
        assert_eq!(cpe, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_get_by_category() {
        let servers = get_by_category(TechCategory::WebServer);
        assert!(servers.len() >= 5);
        assert!(servers.iter().any(|m| m.tech_name == "nginx"));
    }

    #[test]
    fn test_parse_cpe_version() {
        let version = parse_cpe_version("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
        assert_eq!(version, Some("1.18.0".to_string()));
    }
}
