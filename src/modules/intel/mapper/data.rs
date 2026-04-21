use std::collections::HashMap;

use super::{Confidence, CvePattern, FingerprintMapping, PortMapping};

pub(crate) fn build_port_mappings() -> HashMap<u16, Vec<PortMapping>> {
  let mut port_mappings = HashMap::new();

  // SSH (22) - Remote Services
  port_mappings.insert(
    22,
    vec![
      PortMapping {
        technique_id: "T1021.004",
        name: "Remote Services: SSH",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "SSH enables remote command execution and lateral movement",
      },
      PortMapping {
        technique_id: "T1110.001",
        name: "Brute Force: Password Guessing",
        tactic: "Credential Access",
        confidence: Confidence::Medium,
        reason: "SSH is commonly targeted for password attacks",
      },
    ],
  );

  // Telnet (23) - Remote Services
  port_mappings.insert(
    23,
    vec![
      PortMapping {
        technique_id: "T1021",
        name: "Remote Services",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "Telnet provides unencrypted remote access",
      },
      PortMapping {
        technique_id: "T1557",
        name: "Adversary-in-the-Middle",
        tactic: "Credential Access",
        confidence: Confidence::High,
        reason: "Telnet transmits credentials in cleartext",
      },
    ],
  );

  // FTP (21) - Data Transfer
  port_mappings.insert(
    21,
    vec![
      PortMapping {
        technique_id: "T1071.002",
        name: "Application Layer Protocol: File Transfer Protocols",
        tactic: "Command and Control",
        confidence: Confidence::Medium,
        reason: "FTP can be used for C2 and data exfiltration",
      },
      PortMapping {
        technique_id: "T1048.003",
        name: "Exfiltration Over Alternative Protocol: Unencrypted",
        tactic: "Exfiltration",
        confidence: Confidence::Medium,
        reason: "FTP enables data exfiltration over cleartext protocol",
      },
    ],
  );

  // SMTP (25, 587, 465) - Email
  for port in [25, 587, 465] {
    port_mappings.insert(
      port,
      vec![
        PortMapping {
          technique_id: "T1071.003",
          name: "Application Layer Protocol: Mail Protocols",
          tactic: "Command and Control",
          confidence: Confidence::Medium,
          reason: "SMTP can be abused for C2 communication",
        },
        PortMapping {
          technique_id: "T1566.001",
          name: "Phishing: Spearphishing Attachment",
          tactic: "Initial Access",
          confidence: Confidence::Low,
          reason: "Mail server may be used for phishing campaigns",
        },
      ],
    );
  }

  // DNS (53) - DNS
  port_mappings.insert(
    53,
    vec![
      PortMapping {
        technique_id: "T1071.004",
        name: "Application Layer Protocol: DNS",
        tactic: "Command and Control",
        confidence: Confidence::Medium,
        reason: "DNS is commonly used for C2 tunneling",
      },
      PortMapping {
        technique_id: "T1568.002",
        name: "Dynamic Resolution: Domain Generation Algorithms",
        tactic: "Command and Control",
        confidence: Confidence::Low,
        reason: "DNS server may resolve DGA domains",
      },
    ],
  );

  // HTTP (80) - Web Services
  port_mappings.insert(
    80,
    vec![
      PortMapping {
        technique_id: "T1071.001",
        name: "Application Layer Protocol: Web Protocols",
        tactic: "Command and Control",
        confidence: Confidence::Medium,
        reason: "HTTP is used for web-based C2",
      },
      PortMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::Medium,
        reason: "Web applications are common attack vectors",
      },
    ],
  );

  // HTTPS (443) - Web Services
  port_mappings.insert(
    443,
    vec![
      PortMapping {
        technique_id: "T1071.001",
        name: "Application Layer Protocol: Web Protocols",
        tactic: "Command and Control",
        confidence: Confidence::Medium,
        reason: "HTTPS provides encrypted C2 channel",
      },
      PortMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::Medium,
        reason: "HTTPS web applications are common attack vectors",
      },
      PortMapping {
        technique_id: "T1573.002",
        name: "Encrypted Channel: Asymmetric Cryptography",
        tactic: "Command and Control",
        confidence: Confidence::Low,
        reason: "TLS provides encrypted communication channel",
      },
    ],
  );

  // POP3 (110, 995)
  for port in [110, 995] {
    port_mappings.insert(
      port,
      vec![PortMapping {
        technique_id: "T1114.002",
        name: "Email Collection: Remote Email Collection",
        tactic: "Collection",
        confidence: Confidence::Medium,
        reason: "POP3 enables remote email access and collection",
      }],
    );
  }

  // IMAP (143, 993)
  for port in [143, 993] {
    port_mappings.insert(
      port,
      vec![PortMapping {
        technique_id: "T1114.002",
        name: "Email Collection: Remote Email Collection",
        tactic: "Collection",
        confidence: Confidence::Medium,
        reason: "IMAP enables remote email access and collection",
      }],
    );
  }

  // NetBIOS/SMB (135, 137, 138, 139, 445)
  for port in [135, 137, 138, 139] {
    port_mappings.insert(
      port,
      vec![PortMapping {
        technique_id: "T1021.002",
        name: "Remote Services: SMB/Windows Admin Shares",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "NetBIOS enables Windows lateral movement",
      }],
    );
  }

  // SMB (445) - Windows File Sharing
  port_mappings.insert(
    445,
    vec![
      PortMapping {
        technique_id: "T1021.002",
        name: "Remote Services: SMB/Windows Admin Shares",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "SMB enables lateral movement via admin shares",
      },
      PortMapping {
        technique_id: "T1570",
        name: "Lateral Tool Transfer",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "SMB enables file transfers between systems",
      },
      PortMapping {
        technique_id: "T1187",
        name: "Forced Authentication",
        tactic: "Credential Access",
        confidence: Confidence::Medium,
        reason: "SMB can be used for NTLM relay attacks",
      },
    ],
  );

  // Microsoft SQL Server (1433)
  port_mappings.insert(
    1433,
    vec![
      PortMapping {
        technique_id: "T1059.001",
        name: "Command and Scripting Interpreter: PowerShell",
        tactic: "Execution",
        confidence: Confidence::Medium,
        reason: "SQL Server can execute OS commands via xp_cmdshell",
      },
      PortMapping {
        technique_id: "T1505.001",
        name: "Server Software Component: SQL Stored Procedures",
        tactic: "Persistence",
        confidence: Confidence::High,
        reason: "SQL stored procedures enable persistent access",
      },
    ],
  );

  // MySQL (3306)
  port_mappings.insert(
    3306,
    vec![
      PortMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::Medium,
        reason: "MySQL may be vulnerable to SQL injection",
      },
      PortMapping {
        technique_id: "T1505.001",
        name: "Server Software Component: SQL Stored Procedures",
        tactic: "Persistence",
        confidence: Confidence::Medium,
        reason: "MySQL stored procedures enable persistent access",
      },
    ],
  );

  // PostgreSQL (5432)
  port_mappings.insert(
    5432,
    vec![PortMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "PostgreSQL may be vulnerable to SQL injection",
    }],
  );

  // Oracle (1521)
  port_mappings.insert(
    1521,
    vec![PortMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "Oracle DB may be vulnerable to SQL injection",
    }],
  );

  // RDP (3389) - Remote Desktop
  port_mappings.insert(
    3389,
    vec![
      PortMapping {
        technique_id: "T1021.001",
        name: "Remote Services: Remote Desktop Protocol",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "RDP enables remote desktop access",
      },
      PortMapping {
        technique_id: "T1110.001",
        name: "Brute Force: Password Guessing",
        tactic: "Credential Access",
        confidence: Confidence::Medium,
        reason: "RDP is commonly targeted for credential attacks",
      },
      PortMapping {
        technique_id: "T1563.002",
        name: "Remote Service Session Hijacking: RDP Hijacking",
        tactic: "Lateral Movement",
        confidence: Confidence::Medium,
        reason: "RDP sessions can be hijacked",
      },
    ],
  );

  // VNC (5900-5910)
  for port in 5900..=5910 {
    port_mappings.insert(
      port,
      vec![PortMapping {
        technique_id: "T1021.005",
        name: "Remote Services: VNC",
        tactic: "Lateral Movement",
        confidence: Confidence::High,
        reason: "VNC enables remote desktop access",
      }],
    );
  }

  // WinRM (5985, 5986)
  for port in [5985, 5986] {
    port_mappings.insert(
      port,
      vec![
        PortMapping {
          technique_id: "T1021.006",
          name: "Remote Services: Windows Remote Management",
          tactic: "Lateral Movement",
          confidence: Confidence::High,
          reason: "WinRM enables remote PowerShell execution",
        },
        PortMapping {
          technique_id: "T1059.001",
          name: "Command and Scripting Interpreter: PowerShell",
          tactic: "Execution",
          confidence: Confidence::High,
          reason: "WinRM runs PowerShell commands remotely",
        },
      ],
    );
  }

  // LDAP (389, 636)
  for port in [389, 636] {
    port_mappings.insert(
      port,
      vec![
        PortMapping {
          technique_id: "T1087.002",
          name: "Account Discovery: Domain Account",
          tactic: "Discovery",
          confidence: Confidence::High,
          reason: "LDAP enables Active Directory enumeration",
        },
        PortMapping {
          technique_id: "T1069.002",
          name: "Permission Groups Discovery: Domain Groups",
          tactic: "Discovery",
          confidence: Confidence::High,
          reason: "LDAP reveals domain group membership",
        },
      ],
    );
  }

  // Kerberos (88)
  port_mappings.insert(
    88,
    vec![
      PortMapping {
        technique_id: "T1558.003",
        name: "Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic: "Credential Access",
        confidence: Confidence::High,
        reason: "Kerberos service enables Kerberoasting attacks",
      },
      PortMapping {
        technique_id: "T1558.004",
        name: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        tactic: "Credential Access",
        confidence: Confidence::Medium,
        reason: "Kerberos may allow AS-REP roasting",
      },
    ],
  );

  // SNMP (161, 162)
  for port in [161, 162] {
    port_mappings.insert(
      port,
      vec![
        PortMapping {
          technique_id: "T1602.001",
          name: "Data from Configuration Repository: SNMP",
          tactic: "Collection",
          confidence: Confidence::High,
          reason: "SNMP may expose configuration data",
        },
        PortMapping {
          technique_id: "T1018",
          name: "Remote System Discovery",
          tactic: "Discovery",
          confidence: Confidence::Medium,
          reason: "SNMP can reveal network topology",
        },
      ],
    );
  }

  // NFS (2049)
  port_mappings.insert(
    2049,
    vec![PortMapping {
      technique_id: "T1039",
      name: "Data from Network Shared Drive",
      tactic: "Collection",
      confidence: Confidence::High,
      reason: "NFS shares may contain sensitive data",
    }],
  );

  // Docker (2375, 2376)
  for port in [2375, 2376] {
    port_mappings.insert(
      port,
      vec![
        PortMapping {
          technique_id: "T1610",
          name: "Deploy Container",
          tactic: "Defense Evasion",
          confidence: Confidence::High,
          reason: "Docker API enables container deployment",
        },
        PortMapping {
          technique_id: "T1613",
          name: "Container and Resource Discovery",
          tactic: "Discovery",
          confidence: Confidence::High,
          reason: "Docker API exposes container information",
        },
      ],
    );
  }

  // Kubernetes (6443, 8443, 10250)
  for port in [6443, 8443, 10250] {
    port_mappings.insert(
      port,
      vec![
        PortMapping {
          technique_id: "T1609",
          name: "Container Administration Command",
          tactic: "Execution",
          confidence: Confidence::High,
          reason: "Kubernetes API enables container control",
        },
        PortMapping {
          technique_id: "T1610",
          name: "Deploy Container",
          tactic: "Defense Evasion",
          confidence: Confidence::High,
          reason: "Kubernetes enables malicious container deployment",
        },
      ],
    );
  }

  // Redis (6379)
  port_mappings.insert(
    6379,
    vec![
      PortMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::High,
        reason: "Redis without auth enables RCE",
      },
      PortMapping {
        technique_id: "T1136.001",
        name: "Create Account: Local Account",
        tactic: "Persistence",
        confidence: Confidence::Medium,
        reason: "Redis can be used to write SSH keys",
      },
    ],
  );

  // MongoDB (27017)
  port_mappings.insert(
    27017,
    vec![PortMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::High,
      reason: "MongoDB without auth exposes data",
    }],
  );

  // Elasticsearch (9200, 9300)
  for port in [9200, 9300] {
    port_mappings.insert(
      port,
      vec![PortMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::High,
        reason: "Elasticsearch may expose indexed data",
      }],
    );
  }

  // Memcached (11211)
  port_mappings.insert(
    11211,
    vec![PortMapping {
      technique_id: "T1498.001",
      name: "Network Denial of Service: Direct Network Flood",
      tactic: "Impact",
      confidence: Confidence::Medium,
      reason: "Memcached can be used for DDoS amplification",
    }],
  );

  // Rsync (873)
  port_mappings.insert(
    873,
    vec![PortMapping {
      technique_id: "T1048",
      name: "Exfiltration Over Alternative Protocol",
      tactic: "Exfiltration",
      confidence: Confidence::Medium,
      reason: "Rsync enables data exfiltration",
    }],
  );

  // Git (9418)
  port_mappings.insert(
    9418,
    vec![PortMapping {
      technique_id: "T1213.003",
      name: "Data from Information Repositories: Code Repositories",
      tactic: "Collection",
      confidence: Confidence::High,
      reason: "Git repositories may contain secrets",
    }],
  );

  // Jenkins (8080, 8443)
  // Note: 8080 is generic HTTP alternative, but commonly Jenkins
  // We'll add Jenkins-specific handling in fingerprint mappings

  // Proxy ports (3128, 8080, 8888)
  for port in [3128, 8080, 8888] {
    port_mappings
      .entry(port)
      .or_insert_with(Vec::new)
      .push(PortMapping {
        technique_id: "T1090",
        name: "Proxy",
        tactic: "Command and Control",
        confidence: Confidence::Low,
        reason: "Port commonly used for proxy services",
      });
  }

  port_mappings
}

pub(crate) fn build_cve_patterns() -> Vec<CvePattern> {
  let cve_patterns = vec![
    // Remote Code Execution
    CvePattern {
      keywords: vec![
        "remote code execution",
        "rce",
        "arbitrary code",
        "code execution",
      ],
      technique_id: "T1203",
      name: "Exploitation for Client Execution",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "CVE enables remote code execution",
    },
    // SQL Injection
    CvePattern {
      keywords: vec!["sql injection", "sqli", "sql query"],
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::High,
      reason: "SQL injection vulnerability",
    },
    // XSS
    CvePattern {
      keywords: vec!["cross-site scripting", "xss", "script injection"],
      technique_id: "T1189",
      name: "Drive-by Compromise",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "XSS can lead to drive-by compromise",
    },
    // Command Injection
    CvePattern {
      keywords: vec!["command injection", "os command", "shell injection"],
      technique_id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "Command injection enables arbitrary command execution",
    },
    // Path Traversal
    CvePattern {
      keywords: vec![
        "path traversal",
        "directory traversal",
        "lfi",
        "local file inclusion",
      ],
      technique_id: "T1083",
      name: "File and Directory Discovery",
      tactic: "Discovery",
      confidence: Confidence::Medium,
      reason: "Path traversal enables file system access",
    },
    // Authentication Bypass
    CvePattern {
      keywords: vec![
        "authentication bypass",
        "auth bypass",
        "unauthorized access",
      ],
      technique_id: "T1078",
      name: "Valid Accounts",
      tactic: "Defense Evasion",
      confidence: Confidence::High,
      reason: "Authentication bypass enables unauthorized access",
    },
    // Privilege Escalation
    CvePattern {
      keywords: vec!["privilege escalation", "privesc", "elevation of privilege"],
      technique_id: "T1068",
      name: "Exploitation for Privilege Escalation",
      tactic: "Privilege Escalation",
      confidence: Confidence::High,
      reason: "CVE enables privilege escalation",
    },
    // Information Disclosure
    CvePattern {
      keywords: vec![
        "information disclosure",
        "data leak",
        "sensitive data exposure",
      ],
      technique_id: "T1005",
      name: "Data from Local System",
      tactic: "Collection",
      confidence: Confidence::Medium,
      reason: "Information disclosure exposes sensitive data",
    },
    // Denial of Service
    CvePattern {
      keywords: vec!["denial of service", "dos", "crash", "resource exhaustion"],
      technique_id: "T1499",
      name: "Endpoint Denial of Service",
      tactic: "Impact",
      confidence: Confidence::Medium,
      reason: "CVE can cause denial of service",
    },
    // Deserialization
    CvePattern {
      keywords: vec!["deserialization", "object injection", "unserialize"],
      technique_id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "Deserialization can lead to code execution",
    },
    // SSRF
    CvePattern {
      keywords: vec!["ssrf", "server-side request forgery", "internal network"],
      technique_id: "T1090.002",
      name: "Proxy: External Proxy",
      tactic: "Command and Control",
      confidence: Confidence::Medium,
      reason: "SSRF enables internal network access",
    },
    // XXE
    CvePattern {
      keywords: vec!["xxe", "xml external entity", "xml injection"],
      technique_id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: Confidence::Medium,
      reason: "XXE can lead to data exfiltration or SSRF",
    },
    // Buffer Overflow
    CvePattern {
      keywords: vec![
        "buffer overflow",
        "heap overflow",
        "stack overflow",
        "memory corruption",
      ],
      technique_id: "T1203",
      name: "Exploitation for Client Execution",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "Memory corruption vulnerability",
    },
    // Use After Free
    CvePattern {
      keywords: vec!["use after free", "uaf", "double free"],
      technique_id: "T1203",
      name: "Exploitation for Client Execution",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "Memory corruption vulnerability",
    },
    // CSRF
    CvePattern {
      keywords: vec!["csrf", "cross-site request forgery", "request forgery"],
      technique_id: "T1185",
      name: "Browser Session Hijacking",
      tactic: "Collection",
      confidence: Confidence::Medium,
      reason: "CSRF can hijack user sessions",
    },
  ];
  cve_patterns
}

pub(crate) fn build_fingerprint_mappings() -> HashMap<String, Vec<FingerprintMapping>> {
  let mut fingerprint_mappings = HashMap::new();
  // WordPress
  fingerprint_mappings.insert(
    "wordpress".to_string(),
    vec![
      FingerprintMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::Medium,
        reason: "WordPress is a common target for exploitation",
      },
      FingerprintMapping {
        technique_id: "T1583.008",
        name: "Acquire Infrastructure: Malvertising",
        tactic: "Resource Development",
        confidence: Confidence::Low,
        reason: "WordPress sites are often compromised for malvertising",
      },
    ],
  );

  // Drupal
  fingerprint_mappings.insert(
    "drupal".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "Drupal has known vulnerabilities (Drupalgeddon)",
    }],
  );

  // Joomla
  fingerprint_mappings.insert(
    "joomla".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "Joomla has known vulnerabilities",
    }],
  );

  // Apache HTTP Server
  fingerprint_mappings.insert(
    "apache".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Low,
      reason: "Apache may have known vulnerabilities",
    }],
  );

  // nginx
  fingerprint_mappings.insert(
    "nginx".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Low,
      reason: "nginx may have known vulnerabilities",
    }],
  );

  // IIS
  fingerprint_mappings.insert(
    "iis".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "IIS may have known vulnerabilities",
    }],
  );

  // Tomcat
  fingerprint_mappings.insert(
    "tomcat".to_string(),
    vec![
      FingerprintMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::Medium,
        reason: "Tomcat manager interface is often targeted",
      },
      FingerprintMapping {
        technique_id: "T1505.003",
        name: "Server Software Component: Web Shell",
        tactic: "Persistence",
        confidence: Confidence::Medium,
        reason: "Tomcat can be used to deploy malicious WAR files",
      },
    ],
  );

  // Jenkins
  fingerprint_mappings.insert(
    "jenkins".to_string(),
    vec![
      FingerprintMapping {
        technique_id: "T1059.004",
        name: "Command and Scripting Interpreter: Unix Shell",
        tactic: "Execution",
        confidence: Confidence::High,
        reason: "Jenkins Script Console enables code execution",
      },
      FingerprintMapping {
        technique_id: "T1552.001",
        name: "Unsecured Credentials: Credentials In Files",
        tactic: "Credential Access",
        confidence: Confidence::Medium,
        reason: "Jenkins stores credentials that may be exposed",
      },
    ],
  );

  // GitLab
  fingerprint_mappings.insert(
    "gitlab".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1213.003",
      name: "Data from Information Repositories: Code Repositories",
      tactic: "Collection",
      confidence: Confidence::High,
      reason: "GitLab contains source code and secrets",
    }],
  );

  // Confluence
  fingerprint_mappings.insert(
    "confluence".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1213.001",
      name: "Data from Information Repositories: Confluence",
      tactic: "Collection",
      confidence: Confidence::High,
      reason: "Confluence contains organizational knowledge",
    }],
  );

  // Jira
  fingerprint_mappings.insert(
    "jira".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1213",
      name: "Data from Information Repositories",
      tactic: "Collection",
      confidence: Confidence::Medium,
      reason: "Jira contains project and security information",
    }],
  );

  // Exchange
  fingerprint_mappings.insert(
    "exchange".to_string(),
    vec![
      FingerprintMapping {
        technique_id: "T1114",
        name: "Email Collection",
        tactic: "Collection",
        confidence: Confidence::High,
        reason: "Exchange is primary target for email collection",
      },
      FingerprintMapping {
        technique_id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        confidence: Confidence::High,
        reason: "Exchange has critical vulnerabilities (ProxyLogon/ProxyShell)",
      },
    ],
  );

  // SharePoint
  fingerprint_mappings.insert(
    "sharepoint".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1213.002",
      name: "Data from Information Repositories: Sharepoint",
      tactic: "Collection",
      confidence: Confidence::High,
      reason: "SharePoint contains sensitive documents",
    }],
  );

  // AWS
  fingerprint_mappings.insert(
    "aws".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1580",
      name: "Cloud Infrastructure Discovery",
      tactic: "Discovery",
      confidence: Confidence::Medium,
      reason: "AWS infrastructure may be enumerated",
    }],
  );

  // Azure
  fingerprint_mappings.insert(
    "azure".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1580",
      name: "Cloud Infrastructure Discovery",
      tactic: "Discovery",
      confidence: Confidence::Medium,
      reason: "Azure infrastructure may be enumerated",
    }],
  );

  // Kubernetes
  fingerprint_mappings.insert(
    "kubernetes".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1609",
      name: "Container Administration Command",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "Kubernetes API enables container control",
    }],
  );

  // Docker
  fingerprint_mappings.insert(
    "docker".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1610",
      name: "Deploy Container",
      tactic: "Defense Evasion",
      confidence: Confidence::High,
      reason: "Docker enables container deployment",
    }],
  );

  // Elasticsearch
  fingerprint_mappings.insert(
    "elasticsearch".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::High,
      reason: "Elasticsearch may expose indexed data",
    }],
  );

  // Kibana
  fingerprint_mappings.insert(
    "kibana".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "Kibana may expose log data",
    }],
  );

  // Grafana
  fingerprint_mappings.insert(
    "grafana".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "Grafana may expose metrics and dashboards",
    }],
  );

  // phpMyAdmin
  fingerprint_mappings.insert(
    "phpmyadmin".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::High,
      reason: "phpMyAdmin provides database access",
    }],
  );

  // Webmin
  fingerprint_mappings.insert(
    "webmin".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: Confidence::High,
      reason: "Webmin enables system administration",
    }],
  );

  // cPanel
  fingerprint_mappings.insert(
    "cpanel".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: Confidence::Medium,
      reason: "cPanel provides hosting control",
    }],
  );

  // Plesk
  fingerprint_mappings.insert(
    "plesk".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution",
      confidence: Confidence::Medium,
      reason: "Plesk provides hosting control",
    }],
  );

  // PHP
  fingerprint_mappings.insert(
    "php".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Low,
      reason: "PHP applications may have vulnerabilities",
    }],
  );

  // ASP.NET
  fingerprint_mappings.insert(
    "aspnet".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Low,
      reason: "ASP.NET applications may have vulnerabilities",
    }],
  );

  // Spring
  fingerprint_mappings.insert(
    "spring".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Medium,
      reason: "Spring Framework has known vulnerabilities (Spring4Shell)",
    }],
  );

  // Struts
  fingerprint_mappings.insert(
    "struts".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::High,
      reason: "Apache Struts has critical RCE vulnerabilities",
    }],
  );

  // Log4j
  fingerprint_mappings.insert(
    "log4j".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::High,
      reason: "Log4j has critical RCE vulnerability (Log4Shell)",
    }],
  );

  // OpenSSL
  fingerprint_mappings.insert(
    "openssl".to_string(),
    vec![FingerprintMapping {
      technique_id: "T1190",
      name: "Exploit Public-Facing Application",
      tactic: "Initial Access",
      confidence: Confidence::Low,
      reason: "OpenSSL may have vulnerabilities (Heartbleed)",
    }],
  );
  fingerprint_mappings
}
