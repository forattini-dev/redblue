# redblue Documentation

## TL;DR
Central index that points to every deep-dive doc so contributors can jump straight to the domain or guide they need.

This directory contains in-depth technical documentation for redblue features and modules.

## 📚 Documentation Index

### Command Line Interface
- **[cli-semantics.md](./cli-semantics.md)** - Command structure, syntax, and design patterns

### Network & Exploitation
- **[netcat-ultimate.md](./netcat-ultimate.md)** - Netcat-style reverse shells and listener implementation
- **[self-replication.md](./self-replication.md)** - Binary deployment to victim systems (Linux/Windows/MacOS)

### Domain-Specific Documentation
- **[domains/](./domains/)** - Domain-specific guides (network, dns, web, recon, tls, exploit, etc.)

### Examples & Scripts
- **[examples/](./examples/)** - Example workflows and use cases

## 🚀 Quick Links

### For Users
- [Main README](../README.md) - Project overview and quick start
- [CLI Semantics](./cli-semantics.md) - Understanding the kubectl-style CLI
- [Netcat Guide](./netcat-ultimate.md) - Reverse shells and listeners

### For Security Researchers
- [Self-Replication](./self-replication.md) - Binary deployment techniques
- [Netcat Implementation](./netcat-ultimate.md) - Advanced shell payloads

### For Developers
- [CLI Semantics](./cli-semantics.md) - Adding new commands
- [Project Structure](../CLAUDE.md) - Module organization

## 📖 Documentation by Feature

### Network Scanning
- Port scanning: See [Main README - Network Scanning](../README.md#network-scanning--discovery)
- Service detection: See [Main README - Service Detection](../README.md#network-scanning--discovery)

### DNS & Domain
- DNS lookups: See [Main README - DNS Operations](../README.md#dns-operations)
- WHOIS queries: See [Main README - OSINT](../README.md#osint--intelligence-gathering)
- Subdomain enumeration: See [Main README - Subdomain Discovery](../README.md#subdomain-discovery)

### Web Security
- HTTP client: See [Main README - Web Testing](../README.md#web-security-testing)
- Header analysis: See [Main README - Security Headers](../README.md#web-security-testing)
- TLS inspection: See [Main README - TLS Auditing](../README.md#tls--certificate-inspection)

### Exploitation (AUTHORIZED USE ONLY)
- **Reverse Shells**: [netcat-ultimate.md](./netcat-ultimate.md)
- **Self-Replication**: [self-replication.md](./self-replication.md)
- Privilege escalation: See [Main README - Exploitation](../README.md#-exploitation--data-management)
- Lateral movement: See [Main README - Exploitation](../README.md#-exploitation--data-management)

## 🔍 Finding Documentation

### By Topic

| Topic | Documentation |
|-------|---------------|
| Command structure | [cli-semantics.md](./cli-semantics.md) |
| Reverse shells | [netcat-ultimate.md](./netcat-ultimate.md) |
| Binary deployment | [self-replication.md](./self-replication.md) |
| Port scanning | [Main README](../README.md#network-scanning--discovery) |
| DNS lookups | [Main README](../README.md#dns-operations) |
| Web testing | [Main README](../README.md#web-security-testing) |
| TLS auditing | [Main README](../README.md#tls--certificate-inspection) |
| WHOIS lookups | [Main README](../README.md#osint--intelligence-gathering) |

### By Command

| Command | Documentation |
|---------|---------------|
| `rb network ports scan` | [Main README](../README.md#network-scanning--discovery) |
| `rb dns record lookup` | [Main README](../README.md#dns-operations) |
| `rb web asset *` | [Main README](../README.md#web-security-testing) |
| `rb tls security *` | [Main README](../README.md#tls--certificate-inspection) |
| `rb recon domain whois` | [Main README](../README.md#osint--intelligence-gathering) |
| `rb exploit payload shell` | [netcat-ultimate.md](./netcat-ultimate.md) |
| `rb exploit payload listener` | [netcat-ultimate.md](./netcat-ultimate.md) |
| `rb exploit payload replicate` | [self-replication.md](./self-replication.md) |

## 🎯 Documentation Goals

1. **Comprehensive** - Cover all features and use cases
2. **Practical** - Real-world examples and workflows
3. **Ethical** - Clear legal and ethical guidelines
4. **Technical** - Implementation details for developers
5. **Accessible** - Easy to navigate and understand

## 🤝 Contributing to Documentation

When adding new features to redblue:

1. **Update Main README** - Add feature to appropriate section
2. **Create Detailed Docs** - For complex features, create dedicated .md file in `docs/`
3. **Update This Index** - Link new documentation here
4. **Add Examples** - Include practical usage examples
5. **Cross-Reference** - Link related documentation

### Documentation Standards

- ✅ Use clear, concise language
- ✅ Include code examples with expected output
- ✅ Add legal/ethical warnings where appropriate
- ✅ Cross-reference related documentation
- ✅ Keep examples up-to-date with latest CLI syntax

## 📜 Legal & Ethical Notice

**All exploitation features require explicit written authorization.**

redblue is a security tool for:
- ✅ Authorized penetration testing
- ✅ CTF competitions
- ✅ Bug bounty programs (with scope approval)
- ✅ Your own security audits
- ✅ Education and research

Never use on systems you don't own or without proper authorization.

See individual feature documentation for specific legal considerations.

## 📞 Getting Help

- **General usage**: Start with [Main README](../README.md)
- **CLI help**: Run `rb help` or `rb <domain> help`
- **Feature-specific**: See feature documentation above
- **Issues**: [GitHub Issues](https://github.com/forattini-dev/redblue/issues)
- **Discussions**: [GitHub Discussions](https://github.com/forattini-dev/redblue/discussions)

---

**Documentation Last Updated**: 2025-11-03

**redblue version**: Check with `rb --version`
