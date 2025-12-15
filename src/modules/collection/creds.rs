pub struct DefaultCredential {
    pub app: &'static str,
    pub user: &'static str,
    pub pass: &'static str,
}

pub struct DefaultCreds;

impl DefaultCreds {
    pub fn find_for_app(app_name: &str) -> Vec<&'static DefaultCredential> {
        let app_lower = app_name.to_lowercase();
        DEFAULTS
            .iter()
            .filter(|c| {
                c.app.to_lowercase().contains(&app_lower)
                    || app_lower.contains(&c.app.to_lowercase())
            })
            .collect()
    }
}

pub const DEFAULTS: &[DefaultCredential] = &[
    DefaultCredential {
        app: "Tomcat",
        user: "tomcat",
        pass: "tomcat",
    },
    DefaultCredential {
        app: "Tomcat",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "Tomcat",
        user: "admin",
        pass: "",
    },
    DefaultCredential {
        app: "Jenkins",
        user: "admin",
        pass: "password",
    },
    DefaultCredential {
        app: "Jenkins",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "WordPress",
        user: "admin",
        pass: "password",
    },
    DefaultCredential {
        app: "WordPress",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "MySQL",
        user: "root",
        pass: "",
    },
    DefaultCredential {
        app: "MySQL",
        user: "root",
        pass: "root",
    },
    DefaultCredential {
        app: "PostgreSQL",
        user: "postgres",
        pass: "postgres",
    },
    DefaultCredential {
        app: "PostgreSQL",
        user: "postgres",
        pass: "",
    },
    DefaultCredential {
        app: "Mongo",
        user: "admin",
        pass: "password",
    },
    DefaultCredential {
        app: "Redis",
        user: "default",
        pass: "",
    },
    DefaultCredential {
        app: "RabbitMQ",
        user: "guest",
        pass: "guest",
    },
    DefaultCredential {
        app: "Elasticsearch",
        user: "elastic",
        pass: "changeme",
    },
    DefaultCredential {
        app: "WebLogic",
        user: "weblogic",
        pass: "weblogic",
    },
    DefaultCredential {
        app: "WebLogic",
        user: "weblogic",
        pass: "weblogic1",
    },
    DefaultCredential {
        app: "JBoss",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "GlassFish",
        user: "admin",
        pass: "adminadmin",
    },
    DefaultCredential {
        app: "WebSphere",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "Axis2",
        user: "admin",
        pass: "axis2",
    },
    DefaultCredential {
        app: "Grafana",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "Kibana",
        user: "kibana",
        pass: "kibana",
    },
    DefaultCredential {
        app: "Zabbix",
        user: "Admin",
        pass: "zabbix",
    },
    DefaultCredential {
        app: "Nagios",
        user: "nagiosadmin",
        pass: "nagios",
    },
    DefaultCredential {
        app: "Splunk",
        user: "admin",
        pass: "changeme",
    },
    DefaultCredential {
        app: "Pfsense",
        user: "admin",
        pass: "pfsense",
    },
    DefaultCredential {
        app: "OpenWRT",
        user: "root",
        pass: "",
    },
    DefaultCredential {
        app: "DD-WRT",
        user: "root",
        pass: "admin",
    },
    DefaultCredential {
        app: "Mikrotik",
        user: "admin",
        pass: "",
    },
    DefaultCredential {
        app: "Ubiquiti",
        user: "ubnt",
        pass: "ubnt",
    },
    DefaultCredential {
        app: "Cisco",
        user: "cisco",
        pass: "cisco",
    },
    DefaultCredential {
        app: "Cisco",
        user: "admin",
        pass: "admin",
    },
    DefaultCredential {
        app: "Fortigate",
        user: "admin",
        pass: "",
    },
    DefaultCredential {
        app: "SonicWall",
        user: "admin",
        pass: "password",
    },
    DefaultCredential {
        app: "VNC",
        user: "",
        pass: "password",
    },
    DefaultCredential {
        app: "TeamViewer",
        user: "",
        pass: "1234",
    },
    DefaultCredential {
        app: "RDP",
        user: "Administrator",
        pass: "",
    },
    DefaultCredential {
        app: "SSH",
        user: "root",
        pass: "toor",
    },
    DefaultCredential {
        app: "SSH",
        user: "user",
        pass: "user",
    },
    DefaultCredential {
        app: "Telnet",
        user: "root",
        pass: "root",
    },
    DefaultCredential {
        app: "FTP",
        user: "anonymous",
        pass: "anonymous",
    },
    DefaultCredential {
        app: "SMB",
        user: "Guest",
        pass: "",
    },
    DefaultCredential {
        app: "SNMP",
        user: "public",
        pass: "",
    }, // Community string
    DefaultCredential {
        app: "SNMP",
        user: "private",
        pass: "",
    },
    DefaultCredential {
        app: "IPMI",
        user: "ADMIN",
        pass: "ADMIN",
    },
    DefaultCredential {
        app: "iLO",
        user: "Administrator",
        pass: "password",
    },
    DefaultCredential {
        app: "DRAC",
        user: "root",
        pass: "calvin",
    },
    DefaultCredential {
        app: "GitLab",
        user: "root",
        pass: "5liveL!fe",
    },
    DefaultCredential {
        app: "Gitea",
        user: "administrator",
        pass: "root",
    },
];
