# Track Covering

> Clear forensic artifacts and operational traces.

## Overview

The `tracks` resource provides techniques to cover your tracks:
- Shell history clearing (bash, zsh, fish, etc.)
- redblue session file cleanup
- Secure file wiping

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan for history files without clearing |
| `clear` | Clear all shell history files |
| `sessions` | Clear redblue session files |
| `command` | Show shell command to clear current session |

## Usage

### Scan for History Files

```bash
rb evasion tracks scan
```

Output:
```
▸ Track Scanner

ℹ History Files Found:
    1 Bash history files:
        /home/user/.bash_history (12345 bytes)
    1 Fish history files:
        /home/user/.local/share/fish/fish_history (54321 bytes)

ℹ Summary:
    Total history files:  2
    Total history bytes:  66666 bytes
    Session files (.rb):  5

ℹ To clear:
    rb evasion tracks clear           # Quick clear
    rb evasion tracks clear --secure  # Secure wipe
```

### Clear History Files

```bash
# Quick clear (truncate files)
rb evasion tracks clear

# Secure wipe (overwrite with zeros, then random, then truncate)
rb evasion tracks clear --secure

# Clear only bash history
rb evasion tracks clear --shell bash

# Clear only zsh history
rb evasion tracks clear --shell zsh
```

### Clear Session Files

```bash
rb evasion tracks sessions
```

This clears:
- All `.rb-session` files in the current directory
- Session files in `~/.redblue/`

### Get Clear Command

```bash
rb evasion tracks command
```

Output:
```
▸ Session Clear Command

  Detected shell bash
  Target shell bash

ℹ Run this command to clear current session history:

    history -c && history -w

ℹ All shells:
    bash:  history -c && history -w
    zsh:   fc -p && history -p
    fish:  history clear
    sh:    unset HISTFILE
```

## Shell Commands

| Shell | Clear Command |
|-------|---------------|
| bash | `history -c && history -w` |
| zsh | `fc -p && history -p` |
| fish | `history clear` |
| sh | `unset HISTFILE` |

## Quick Clear vs Secure Wipe

| Mode | Method | Speed | Security |
|------|--------|-------|----------|
| Quick | Truncate only | Fast | Basic |
| Secure | Zero → Random → Truncate | Slower | High |

**Quick clear** just truncates files to zero length. The data might be recoverable with forensic tools.

**Secure wipe** overwrites the file with zeros, then random data, then truncates. Much harder to recover.

## History File Locations

### Bash
- `~/.bash_history`
- `~/.history`
- `/root/.bash_history`

### Zsh
- `~/.zsh_history`
- `~/.zhistory`
- `~/.local/share/zsh/history`

### Fish
- `~/.local/share/fish/fish_history`
- `~/.config/fish/fish_history`

### Other Shells
- `~/.sh_history` (sh)
- `~/.ksh_history` (ksh)
- `~/.tcsh_history` (tcsh)
- `~/.csh_history` (csh)

## Programmatic Usage

```rust
use redblue::modules::evasion::tracks;

// Detect history files
let files = tracks::HistoryFiles::detect();
println!("Found {} history files", files.count());

// Clear all history (quick mode)
let results = tracks::clear_all_history(false);

// Clear all history (secure mode)
let results = tracks::clear_all_history(true);

// Clear specific shell
let results = tracks::clear_shell_history("bash", true);

// Clear a single file
let result = tracks::clear_file(&path);

// Secure wipe a file
let result = tracks::secure_clear_file(&path);

// Get command for current shell
let shell = tracks::detect_shell();
let cmd = tracks::get_clear_session_command(&shell);
println!("Run: {}", cmd);

// Gather statistics
let stats = tracks::ClearStats::gather();
println!("History files: {}", stats.history_files);
println!("History bytes: {}", stats.history_bytes);
```

## Warning

Track covering is for **authorized penetration testing only**:

- Always have explicit written authorization
- Document all actions taken
- Only clear tracks on systems you're authorized to test
- Be aware of legal implications in your jurisdiction

## Related

- [memory](/domains/evasion/04-memory.md) - SecureVault for protected variables
- [strings](/domains/evasion/08-strings.md) - String encryption
