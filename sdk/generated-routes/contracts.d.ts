  "access": {
    "system": {
      "file": TInvocation;
      "network": TInvocation;
      "process": TInvocation;
      "registry": TInvocation;
      "service": TInvocation;
    };
  };
  "agent": {
    "c2": {
      "connect": TInvocation;
      "server": TInvocation;
    };
  };
  "assess": {
    "target": {
      "run": TInvocation;
      "show": TInvocation;
    };
  };
  "attack": {
    "target": {
      "apt": TInvocation;
      "plan": TInvocation;
      "playbooks": TInvocation;
      "run": TInvocation;
    };
  };
  "auth": {
    "test": {
      "http": TInvocation;
    };
  };
  "bench": {
    "load": {
      "run": TInvocation;
      "stress": TInvocation;
    };
  };
  "binary": {
    "analysis": {
      "checksec": TInvocation;
      "find": TInvocation;
      "got": TInvocation;
      "info": TInvocation;
      "pattern": TInvocation;
      "plt": TInvocation;
      "rop": TInvocation;
      "sections": TInvocation;
      "symbols": TInvocation;
    };
  };
  "cloud": {
    "asset": {
      "services": TInvocation;
      "takeover": TInvocation;
      "takeover-scan": TInvocation;
    };
    "storage": {
      "enumerate": TInvocation;
      "scan": TInvocation;
    };
  };
  "code": {
    "dependencies": {
      "scan": TInvocation;
    };
    "secrets": {
      "providers": TInvocation;
      "scan": TInvocation;
      "validate": TInvocation;
    };
  };
  "collect": {
    "browser": {
      "all": TInvocation;
      "chrome": TInvocation;
      "firefox": TInvocation;
    };
  };
  "collection": {
    "screenshot": {
      "batch": TInvocation;
      "capture": TInvocation;
      "http": TInvocation;
    };
  };
  "config": {
    "database": {
      "clear-password": TInvocation;
      "set-password": TInvocation;
      "show": TInvocation;
    };
    "init": {
      "create": TInvocation;
    };
  };
  "crypto": {
    "analyze": {
      "auto": TInvocation;
      "entropy": TInvocation;
      "frequency": TInvocation;
      "hash": TInvocation;
    };
    "cipher": {
      "crack": TInvocation;
      "decrypt": TInvocation;
      "encrypt": TInvocation;
      "list": TInvocation;
    };
    "codec": {
      "decode": TInvocation;
      "detect": TInvocation;
      "encode": TInvocation;
      "list": TInvocation;
    };
    "cyclic": {
      "find": TInvocation;
      "generate": TInvocation;
      "offset": TInvocation;
    };
    "hash": {
      "verify": TInvocation;
    };
    "recipe": {
      "bake": TInvocation;
      "run": TInvocation;
    };
    "vault": {
      "decrypt": TInvocation;
      "encrypt": TInvocation;
      "info": TInvocation;
    };
  };
  "database": {
    "engine": {
      "checkpoint": TInvocation;
      "info": TInvocation;
      "open": TInvocation;
      "stats": TInvocation;
    };
    "query": {
      "dns": TInvocation;
      "hosts": TInvocation;
      "http": TInvocation;
      "ports": TInvocation;
      "subdomains": TInvocation;
      "summary": TInvocation;
      "tls": TInvocation;
      "whois": TInvocation;
    };
    "vector": {
      "index": TInvocation;
      "info": TInvocation;
      "search": TInvocation;
    };
  };
  "dns": {
    "record": {
      "all": TInvocation;
      "bruteforce": TInvocation;
      "describe": TInvocation;
      "email": TInvocation;
      "get": TInvocation;
      "list": TInvocation;
      "lookup": TInvocation;
      "propagation": TInvocation;
      "resolve": TInvocation;
      "reverse": TInvocation;
    };
    "server": {
      "block": TInvocation;
      "hijack": TInvocation;
      "start": TInvocation;
    };
  };
  "docs": {
    "kb": {
      "index": TInvocation;
      "search": TInvocation;
    };
  };
  "evasion": {
    "amsi": {
      "csharp": TInvocation;
      "obfuscated": TInvocation;
      "powershell": TInvocation;
      "providers": TInvocation;
    };
    "antidebug": {
      "check": TInvocation;
      "paranoid": TInvocation;
      "quick": TInvocation;
    };
    "apihash": {
      "hash": TInvocation;
      "list": TInvocation;
      "syscalls": TInvocation;
    };
    "build": {
      "deobfuscate": TInvocation;
      "info": TInvocation;
      "obfuscate": TInvocation;
      "rehash": TInvocation;
    };
    "config": {
      "aggressive": TInvocation;
      "default": TInvocation;
      "show": TInvocation;
      "stealth": TInvocation;
    };
    "controlflow": {
      "demo": TInvocation;
      "predicates": TInvocation;
      "substitute": TInvocation;
    };
    "inject": {
      "encode": TInvocation;
      "list": TInvocation;
      "shellcode": TInvocation;
    };
    "memory": {
      "demo": TInvocation;
      "encrypt": TInvocation;
      "heap": TInvocation;
      "rotate": TInvocation;
      "sleep": TInvocation;
      "vault": TInvocation;
    };
    "network": {
      "jitter": TInvocation;
      "shape": TInvocation;
      "timer": TInvocation;
    };
    "obfuscate": {
      "base64": TInvocation;
      "deobfuscate": TInvocation;
      "rot": TInvocation;
      "xor": TInvocation;
    };
    "sandbox": {
      "check": TInvocation;
      "delay": TInvocation;
      "score": TInvocation;
    };
    "strings": {
      "demo": TInvocation;
      "encrypt": TInvocation;
      "sensitive": TInvocation;
    };
    "tracks": {
      "clear": TInvocation;
      "command": TInvocation;
      "scan": TInvocation;
      "sessions": TInvocation;
    };
  };
  "exploit": {
    "browser": {
      "exec": TInvocation;
      "list": TInvocation;
      "serve": TInvocation;
    };
    "payload": {
      "apt": TInvocation;
      "dns-shell": TInvocation;
      "encrypted-shell": TInvocation;
      "http-shell": TInvocation;
      "icmp-shell": TInvocation;
      "lateral": TInvocation;
      "listener": TInvocation;
      "multi-shell": TInvocation;
      "persist": TInvocation;
      "plan": TInvocation;
      "playbooks": TInvocation;
      "privesc": TInvocation;
      "recommend": TInvocation;
      "replicate": TInvocation;
      "run": TInvocation;
      "sessions": TInvocation;
      "shell": TInvocation;
      "start": TInvocation;
      "suggest": TInvocation;
      "websocket-shell": TInvocation;
    };
    "phish": {
      "clone": TInvocation;
      "email": TInvocation;
      "serve": TInvocation;
      "templates": TInvocation;
    };
  };
  "file": {
    "ops": {
      "hash": TInvocation;
      "info": TInvocation;
      "unzip": TInvocation;
      "zip": TInvocation;
    };
  };
  "hex": {
    "file": {
      "compare": TInvocation;
      "info": TInvocation;
      "inspect": TInvocation;
      "read": TInvocation;
      "replace": TInvocation;
      "search": TInvocation;
      "view": TInvocation;
      "write": TInvocation;
    };
  };
  "http": {
    "server": {
      "payloads": TInvocation;
      "serve": TInvocation;
    };
  };
  "intelligence": {
    "graph": {
      "centrality": TInvocation;
      "cert": TInvocation;
      "communities": TInvocation;
      "components": TInvocation;
      "credential": TInvocation;
      "cycles": TInvocation;
      "domain": TInvocation;
      "export": TInvocation;
      "host": TInvocation;
      "import": TInvocation;
      "insights": TInvocation;
      "network": TInvocation;
      "pagerank": TInvocation;
      "paths": TInvocation;
      "query": TInvocation;
      "report": TInvocation;
      "rql": TInvocation;
      "service": TInvocation;
      "stats": TInvocation;
      "summary": TInvocation;
      "tech": TInvocation;
      "user": TInvocation;
      "viz": TInvocation;
      "vuln": TInvocation;
    };
    "ioc": {
      "demo": TInvocation;
      "export": TInvocation;
      "extract": TInvocation;
      "import": TInvocation;
      "search": TInvocation;
      "types": TInvocation;
    };
    "mitre": {
      "cache": TInvocation;
      "correlate": TInvocation;
      "coverage": TInvocation;
      "detection": TInvocation;
      "export": TInvocation;
      "gaps": TInvocation;
      "group": TInvocation;
      "map": TInvocation;
      "matrix": TInvocation;
      "mitigations": TInvocation;
      "navigator": TInvocation;
      "ports": TInvocation;
      "search": TInvocation;
      "software": TInvocation;
      "stats": TInvocation;
      "tactic": TInvocation;
      "technique": TInvocation;
    };
    "taxii": {
      "collections": TInvocation;
      "sync": TInvocation;
    };
    "vuln": {
      "correlate": TInvocation;
      "cpe": TInvocation;
      "cve": TInvocation;
      "exploit": TInvocation;
      "kev": TInvocation;
      "report": TInvocation;
      "scan": TInvocation;
      "search": TInvocation;
    };
  };
  "loot": {
    "entry": {
      "add": TInvocation;
      "delete": TInvocation;
      "export": TInvocation;
      "list": TInvocation;
      "show": TInvocation;
      "stats": TInvocation;
    };
    "graph": {
      "insights": TInvocation;
      "paths": TInvocation;
      "rebuild": TInvocation;
      "show": TInvocation;
      "stats": TInvocation;
    };
  };
  "mcp": {
    "server": {
      "start": TInvocation;
    };
  };
  "memory": {
    "process": {
      "aob": TInvocation;
      "dump": TInvocation;
      "list": TInvocation;
      "maps": TInvocation;
      "read": TInvocation;
      "scan": TInvocation;
      "string": TInvocation;
      "write": TInvocation;
    };
  };
  "mitm": {
    "intercept": {
      "dns": TInvocation;
      "export-ca": TInvocation;
      "generate-ca": TInvocation;
      "proxy": TInvocation;
      "shell": TInvocation;
      "start": TInvocation;
    };
  };
  "network": {
    "health": {
      "check": TInvocation;
      "diff": TInvocation;
      "watch": TInvocation;
    };
    "host": {
      "discover": TInvocation;
      "fingerprint": TInvocation;
      "intel": TInvocation;
      "list": TInvocation;
      "ping": TInvocation;
    };
    "nc": {
      "broker": TInvocation;
      "connect": TInvocation;
      "listen": TInvocation;
      "relay": TInvocation;
      "scan": TInvocation;
    };
    "ports": {
      "mass-scan": TInvocation;
      "range": TInvocation;
      "scan": TInvocation;
      "stealth": TInvocation;
      "subnet": TInvocation;
      "syn-scan": TInvocation;
      "udp-scan": TInvocation;
    };
    "trace": {
      "mtr": TInvocation;
      "run": TInvocation;
    };
  };
  "password": {
    "hash": {
      "benchmark": TInvocation;
      "crack": TInvocation;
      "generate": TInvocation;
      "identify": TInvocation;
      "mask": TInvocation;
      "rules": TInvocation;
      "verify": TInvocation;
    };
  };
  "playbook": {
    "methodology": {
      "catalog": TInvocation;
      "chain": TInvocation;
      "chains": TInvocation;
      "history": TInvocation;
      "list": TInvocation;
      "phases": TInvocation;
      "run": TInvocation;
      "show": TInvocation;
    };
  };
  "proxy": {
    "data": {
      "list": TInvocation;
      "requests": TInvocation;
      "responses": TInvocation;
      "show": TInvocation;
      "stats": TInvocation;
    };
    "http": {
      "start": TInvocation;
    };
    "socks5": {
      "start": TInvocation;
    };
    "transparent": {
      "iptables": TInvocation;
      "nftables": TInvocation;
      "start": TInvocation;
    };
  };
  "recon": {
    "domain": {
      "asn": TInvocation;
      "breach": TInvocation;
      "describe": TInvocation;
      "dnsdumpster": TInvocation;
      "dorks": TInvocation;
      "email": TInvocation;
      "full": TInvocation;
      "get": TInvocation;
      "graph": TInvocation;
      "harvest": TInvocation;
      "list": TInvocation;
      "massdns": TInvocation;
      "osint": TInvocation;
      "rdap": TInvocation;
      "secrets": TInvocation;
      "show": TInvocation;
      "social": TInvocation;
      "subdomains": TInvocation;
      "urls": TInvocation;
      "vuln": TInvocation;
      "whois": TInvocation;
    };
    "identity": {
      "breach": TInvocation;
      "email": TInvocation;
      "username": TInvocation;
    };
  };
  "report": {
    "pentest": {
      "generate": TInvocation;
      "preview": TInvocation;
      "stats": TInvocation;
    };
  };
  "search": {
    "data": {
      "list": TInvocation;
      "query": TInvocation;
      "stats": TInvocation;
    };
  };
  "service": {
    "manage": {
      "install": TInvocation;
      "list": TInvocation;
      "restart": TInvocation;
      "start": TInvocation;
      "status": TInvocation;
      "stop": TInvocation;
      "uninstall": TInvocation;
    };
  };
  "system": {
    "host": {
      "inspect": TInvocation;
      "summary": TInvocation;
    };
  };
  "tls": {
    "intel": {
      "fingerprint": TInvocation;
      "infrastructure": TInvocation;
      "scan": TInvocation;
    };
    "security": {
      "audit": TInvocation;
      "ciphers": TInvocation;
      "describe": TInvocation;
      "get": TInvocation;
      "list": TInvocation;
      "mozilla": TInvocation;
      "resume": TInvocation;
      "vuln": TInvocation;
    };
  };
  "web": {
    "asset": {
      "cert": TInvocation;
      "cms": TInvocation;
      "cms-scan": TInvocation;
      "crawl": TInvocation;
      "describe": TInvocation;
      "drupal-scan": TInvocation;
      "fingerprint": TInvocation;
      "forms": TInvocation;
      "fuzz": TInvocation;
      "get": TInvocation;
      "grade": TInvocation;
      "har-export": TInvocation;
      "har-replay": TInvocation;
      "har-to-curl": TInvocation;
      "har-view": TInvocation;
      "headers": TInvocation;
      "http2": TInvocation;
      "images": TInvocation;
      "joomla-scan": TInvocation;
      "linkfinder": TInvocation;
      "links": TInvocation;
      "list": TInvocation;
      "meta": TInvocation;
      "scan": TInvocation;
      "scrape": TInvocation;
      "security": TInvocation;
      "tables": TInvocation;
      "vuln-scan": TInvocation;
      "wpscan": TInvocation;
    };
    "fuzz": {
      "run": TInvocation;
    };
    "git": {
      "dump": TInvocation;
      "scan": TInvocation;
    };
    "nosqli": {
      "payloads": TInvocation;
      "test": TInvocation;
    };
    "sqli": {
      "payloads": TInvocation;
      "tampers": TInvocation;
      "test": TInvocation;
    };
  };
  "wordlist": {
    "collection": {
      "get": TInvocation;
      "info": TInvocation;
      "init": TInvocation;
      "install": TInvocation;
      "list": TInvocation;
      "remove": TInvocation;
      "search": TInvocation;
      "sources": TInvocation;
      "status": TInvocation;
      "update": TInvocation;
    };
    "file": {
      "filter": TInvocation;
      "info": TInvocation;
    };
  };
}
export interface GeneratedRouteContract {
  schema_version: number;
  manifest_version: string;
  route_count: number;
  routes: GeneratedCanonicalRoutePath[];
}
