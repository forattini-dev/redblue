/// CLI Parser - FINAL RULE
///
/// Pattern: rb [domain] [restful verb] [resource] [optional subresource] [flags]
///
/// RESTful verbs: list, get, describe, delete, update, create, watch, patch, scan, lookup
///
/// Examples:
///   rb network scan ports 192.168.1.1       # domain=network, verb=scan, resource=ports, target=IP
///   rb dns lookup record example.com        # domain=dns, verb=lookup, resource=record, target=domain
///   rb exploit shell payload 10.10.10.10    # domain=exploit, verb=shell, resource=payload, target=IP
///   rb web get asset https://example.com    # domain=web, verb=get, resource=asset, target=URL
use super::CliContext;

/// RESTful verbs plus common security actions
const RESTFUL_VERBS: &[&str] = &[
    "list",
    "get",
    "describe",
    "delete",
    "update",
    "create",
    "watch",
    "patch",
    // Security-specific verbs that act like RESTful verbs
    "scan",
    "lookup",
    "shell",
    "privesc",
    "listener",
    "lateral",
    "persist",
    "headers",
    "security",
    "cert",
    "fuzz",
    "crawl",
    "whois",
    "subdomains",
    "trace",
    "resolve",
    "bruteforce",
    "reverse",
    // Netcat verbs
    "listen",
    "connect",
    "relay",
    "broker",
];

pub fn parse_args(args: &[String]) -> Result<CliContext, String> {
    if args.is_empty() {
        return Err("No command provided".to_string());
    }

    let mut ctx = CliContext::new();
    ctx.raw = args.to_vec();

    // Load YAML config from current directory if it exists
    ctx.config = crate::config::yaml::YamlConfig::load_from_cwd();

    let mut i = 0;
    let mut positionals: Vec<String> = Vec::new();

    // Parse flags
    while i < args.len() {
        let arg = &args[i];

        if arg == "--" {
            positionals.extend_from_slice(&args[i + 1..]);
            break;
        }

        if arg.starts_with("--") {
            let flag_name = arg.trim_start_matches("--");

            if let Some(eq_pos) = flag_name.find('=') {
                let (key, value) = flag_name.split_at(eq_pos);
                ctx.flags.insert(key.to_string(), value[1..].to_string());
            } else if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                i += 1;
                ctx.flags.insert(flag_name.to_string(), args[i].clone());
            } else {
                ctx.flags.insert(flag_name.to_string(), "true".to_string());
            }
        } else if arg.starts_with('-') && arg.len() >= 2 {
            let flag_char = &arg[1..2];

            if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                i += 1;
                ctx.flags.insert(flag_char.to_string(), args[i].clone());
            } else {
                ctx.flags.insert(flag_char.to_string(), "true".to_string());
            }
        } else {
            positionals.push(arg.clone());
        }

        i += 1;
    }

    // Parse positional arguments following FINAL pattern:
    // rb [domain] [verb] [resource] [subresource/target] [args...]
    if !positionals.is_empty() {
        ctx.domain = Some(positionals[0].clone());
    }

    if positionals.len() > 1 {
        let second = &positionals[1];

        // If second arg is a verb, use FINAL pattern
        if RESTFUL_VERBS.contains(&second.as_str()) {
            ctx.verb = Some(positionals[1].clone());

            if positionals.len() > 2 {
                ctx.resource = Some(positionals[2].clone());
            }

            if positionals.len() > 3 {
                ctx.target = Some(positionals[3].clone());
            }

            if positionals.len() > 4 {
                ctx.args = positionals[4..].to_vec();
            }
        } else {
            // Fallback: treat as old pattern for backward compat
            // domain resource verb target
            ctx.resource = Some(positionals[1].clone());

            if positionals.len() > 2 {
                ctx.verb = Some(positionals[2].clone());
            }

            if positionals.len() > 3 {
                ctx.target = Some(positionals[3].clone());
            }

            if positionals.len() > 4 {
                ctx.args = positionals[4..].to_vec();
            }
        }
    }

    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NEW FINAL pattern tests: rb [domain] [verb] [resource] [target]
    #[test]
    fn test_new_pattern_network_scan() {
        // rb network scan ports 192.168.1.1
        let args = vec![
            "network".to_string(),
            "scan".to_string(),
            "ports".to_string(),
            "192.168.1.1".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("network".to_string()));
        assert_eq!(ctx.verb, Some("scan".to_string()));
        assert_eq!(ctx.resource, Some("ports".to_string()));
        assert_eq!(ctx.target, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_new_pattern_exploit_shell() {
        // rb exploit shell payload 10.10.10.10
        let args = vec![
            "exploit".to_string(),
            "shell".to_string(),
            "payload".to_string(),
            "10.10.10.10".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("exploit".to_string()));
        assert_eq!(ctx.verb, Some("shell".to_string()));
        assert_eq!(ctx.resource, Some("payload".to_string()));
        assert_eq!(ctx.target, Some("10.10.10.10".to_string()));
    }

    #[test]
    fn test_new_pattern_dns_lookup() {
        // rb dns lookup record example.com
        let args = vec![
            "dns".to_string(),
            "lookup".to_string(),
            "record".to_string(),
            "example.com".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("dns".to_string()));
        assert_eq!(ctx.verb, Some("lookup".to_string()));
        assert_eq!(ctx.resource, Some("record".to_string()));
        assert_eq!(ctx.target, Some("example.com".to_string()));
    }

    #[test]
    fn test_new_pattern_web_get() {
        // rb web get asset https://example.com
        let args = vec![
            "web".to_string(),
            "get".to_string(),
            "asset".to_string(),
            "https://example.com".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("web".to_string()));
        assert_eq!(ctx.verb, Some("get".to_string()));
        assert_eq!(ctx.resource, Some("asset".to_string()));
        assert_eq!(ctx.target, Some("https://example.com".to_string()));
    }

    // OLD pattern fallback tests: rb [domain] [resource] [verb] [target]
    #[test]
    fn test_old_pattern_network_ports_scan() {
        // rb network ports scan 192.168.1.1
        let args = vec![
            "network".to_string(),
            "ports".to_string(),
            "scan".to_string(),
            "192.168.1.1".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("network".to_string()));
        assert_eq!(ctx.resource, Some("ports".to_string()));
        assert_eq!(ctx.verb, Some("scan".to_string()));
        assert_eq!(ctx.target, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_old_pattern_exploit_payload_shell() {
        // rb exploit payload shell 10.10.10.10
        let args = vec![
            "exploit".to_string(),
            "payload".to_string(),
            "shell".to_string(),
            "10.10.10.10".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("exploit".to_string()));
        assert_eq!(ctx.resource, Some("payload".to_string()));
        assert_eq!(ctx.verb, Some("shell".to_string()));
        assert_eq!(ctx.target, Some("10.10.10.10".to_string()));
    }

    #[test]
    fn test_with_flags() {
        // rb network scan ports 192.168.1.1 --threads 200
        let args = vec![
            "network".to_string(),
            "scan".to_string(),
            "ports".to_string(),
            "192.168.1.1".to_string(),
            "--threads".to_string(),
            "200".to_string(),
        ];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("network".to_string()));
        assert_eq!(ctx.verb, Some("scan".to_string()));
        assert_eq!(ctx.resource, Some("ports".to_string()));
        assert_eq!(ctx.target, Some("192.168.1.1".to_string()));
        assert_eq!(ctx.get_flag("threads"), Some(&"200".to_string()));
    }

    // Global/utility commands
    #[test]
    fn test_global_version() {
        let args = vec!["version".to_string()];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("version".to_string()));
        assert_eq!(ctx.resource, None);
        assert_eq!(ctx.verb, None);
    }

    #[test]
    fn test_global_help() {
        let args = vec!["help".to_string()];
        let ctx = parse_args(&args).unwrap();

        assert_eq!(ctx.domain, Some("help".to_string()));
        assert_eq!(ctx.resource, None);
        assert_eq!(ctx.verb, None);
    }
}
