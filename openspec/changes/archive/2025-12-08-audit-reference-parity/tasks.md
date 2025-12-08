# Audit Tasks

## 1. Reconnaissance & Discovery Audit
- [ ] 1.1 Analyze `amass` vs `rb recon domain subdomains` (Check: Graphing, ASN viz, data sources)
- [ ] 1.2 Analyze `subfinder` vs `rb recon domain subdomains --passive` (Check: Source count, speed)
- [ ] 1.3 Analyze `theHarvester` vs `rb recon domain harvest` (Check: Data sources coverage)
- [ ] 1.4 Analyze `maigret`/`sherlock` vs `rb recon username` (Check: Platform count, false positive detection)

## 2. Network Scanning Audit
- [ ] 2.1 Analyze `nmap` vs `rb network ports scan` (Check: Scripting Engine capabilities, UDP logic, OS Fingerprinting depth)
- [ ] 2.2 Analyze `masscan` vs `rb network ports scan` (Check: Raw packet rate, stateless scanning)

## 3. Web Security Audit
- [ ] 3.1 Analyze `ffuf` vs `rb web fuzz` (Check: Filters, recursion, calibration, POST fuzzing)
- [ ] 3.2 Analyze `wpscan`/`droopescan` vs `rb recon domain vuln` (Check: Specific CMS version detection, plugin enumeration)
- [ ] 3.3 Analyze `WhatWeb` vs `rb recon domain vuln` (Check: Fingerprint database size)
- [ ] 3.4 Analyze `EyeWitness`/`aquatone` vs `rb collection screenshot` (Check: Report format, headless options)

## 4. Secrets & Code Audit
- [ ] 4.1 Analyze `gitleaks`/`trufflehog` vs `rb recon domain secrets` (Check: Regex ruleset size, entropy math, commit scanning)

## 5. TLS/SSL Audit
- [ ] 5.1 Analyze `testssl.sh` vs `rb tls audit` (Check: Cipher enumeration completeness, specific vuln checks like ROBOT/Heartbleed)

## 6. Proxy/MITM Audit
- [ ] 6.1 Analyze `mitmproxy` vs `rb proxy` (Check: Interception capabilities, cert generation)
