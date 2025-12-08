# Change: Tool Parity Audit & Gap Analysis

## Why

We have implemented a significant portion of the core functionality for `redblue`. To ensure we meet the goal of being a "single-binary replacement" for common security tools, we must systematically compare our current implementation against the specific reference tools stored in `references/`.

This audit will identify specific gaps, missing flags, or capabilities that established tools have but `redblue` currently lacks.

## What Changes

This is an **Analysis & Documentation** phase. We will not be writing code features in this phase, but rather generating a prioritized backlog of features to be implemented in subsequent phases.

We will examine each tool in `references/`, identify its core unique selling points (USPs), and check if `redblue` covers them.

## Impact

- **Output:** A set of new Feature Requests / Tasks added to the backlog.
- **Docs:** Updated comparison matrices in documentation.
- **Confidence:** Verification that our "from scratch" implementations hold up against industry standards.

### Scope of Audit

**Reconnaissance & Discovery**
- `amass` (Advanced enum, graphing)
- `assetfinder` (Speed, sources)
- `subfinder` (Passive sources)
- `theHarvester` (OSINT sources)
- `maigret` / `sherlock` (Username enumeration)

**Network Scanning**
- `nmap` (Scripting engine, OS fingerprinting, timing)
- `masscan` (Raw socket speed)

**Web Security**
- `ffuf` / `gobuster` / `feroxbuster` (Fuzzing speed, filters, recursive)
- `nikto` (Vuln templates, fingerprinting)
- `wpscan` / `droopescan` (CMS specific checks)
- `WhatWeb` (Tech stack fingerprinting)
- `aquatone` / `EyeWitness` (Visual recon)

**Secrets & Code**
- `gitleaks` / `trufflehog` (Entropy, regex rules, git history)

**TLS/SSL**
- `sslscan` / `sslyze` / `testssl.sh` (Ciphers, heartbleed, compliance)

**Proxy/MITM**
- `mitmproxy` (Interception, replay, scripting)
