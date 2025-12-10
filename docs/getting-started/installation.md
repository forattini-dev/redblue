# Installation

## Quick Install

The fastest way to install redblue:

<!-- tabs:start -->

#### **Linux/macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash
```

#### **Windows (PowerShell)**

```powershell
Invoke-WebRequest -Uri "https://github.com/forattini-dev/redblue/releases/latest/download/rb-windows-x86_64.exe" -OutFile "rb.exe"
```

<!-- tabs:end -->

## Manual Download

Download the binary directly from GitHub Releases:

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | x86_64 | [rb-linux-x86_64](https://github.com/forattini-dev/redblue/releases/latest/download/rb-linux-x86_64) |
| Linux | ARM64 | [rb-linux-aarch64](https://github.com/forattini-dev/redblue/releases/latest/download/rb-linux-aarch64) |
| macOS | Intel | [rb-macos-x86_64](https://github.com/forattini-dev/redblue/releases/latest/download/rb-macos-x86_64) |
| macOS | Apple Silicon | [rb-macos-aarch64](https://github.com/forattini-dev/redblue/releases/latest/download/rb-macos-aarch64) |
| Windows | x86_64 | [rb-windows-x86_64.exe](https://github.com/forattini-dev/redblue/releases/latest/download/rb-windows-x86_64.exe) |

After downloading:

```bash
chmod +x rb-linux-x86_64
sudo mv rb-linux-x86_64 /usr/local/bin/rb
```

## Build from Source

### Requirements

- Rust 1.70+
- Git

### Steps

```bash
# Clone repository
git clone https://github.com/forattini-dev/redblue
cd redblue

# Build release
cargo build --release

# Binary location
./target/release/redblue

# Install to PATH
sudo cp target/release/redblue /usr/local/bin/rb
```

## Verification

After installation, verify it works:

```bash
# Check version
rb --version

# Show help
rb help

# Quick test
rb dns lookup record google.com
```

## Next Channel

For bleeding-edge features:

```bash
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --channel next
```

> **Note:** Next releases may contain unstable features.

## Uninstallation

```bash
# Interactive uninstall
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/uninstall.sh | bash

# Force uninstall
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/uninstall.sh | bash -s -- --force
```
