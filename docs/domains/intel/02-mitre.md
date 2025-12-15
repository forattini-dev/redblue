# intel mitre

> MITRE ATT&CK framework queries

## Commands

```
rb intel mitre <verb> [args] [flags]
```

| Verb | Description |
|------|-------------|
| `technique` | Lookup technique by ID |
| `tactic` | List techniques for a tactic |
| `procedure` | Get procedure examples |
| `group` | Lookup threat group |
| `software` | Lookup malware/tool |
| `search` | Free-text search |

## Usage Examples

### Technique Lookup

```bash
# Get technique details
rb intel mitre technique T1059

# Get sub-technique
rb intel mitre technique T1059.001
```

### Tactic Overview

```bash
# List techniques for a tactic
rb intel mitre tactic execution

# Available tactics:
# reconnaissance, resource-development, initial-access,
# execution, persistence, privilege-escalation,
# defense-evasion, credential-access, discovery,
# lateral-movement, collection, command-and-control,
# exfiltration, impact
```

### Threat Groups

```bash
# Lookup threat group
rb intel mitre group APT29

# List all groups
rb intel mitre group --list
```

### Software/Malware

```bash
# Lookup malware
rb intel mitre software Cobalt Strike

# Lookup tool
rb intel mitre software Mimikatz
```

### Search

```bash
# Free-text search
rb intel mitre search "powershell"

# Search with filters
rb intel mitre search "credential" --tactic credential-access
```

## Output

Each technique includes:

- **ID**: ATT&CK identifier (e.g., T1059)
- **Name**: Technique name
- **Tactic**: Associated tactic(s)
- **Description**: What the technique does
- **Detection**: How to detect it
- **Mitigations**: How to prevent it
- **Procedures**: Real-world examples

## Use Cases

### Threat Hunting

Map observed behaviors to ATT&CK techniques:

```bash
# Observed: PowerShell execution
rb intel mitre technique T1059.001

# Observed: Scheduled task
rb intel mitre technique T1053.005
```

### Red Team Planning

Find techniques for a specific tactic:

```bash
# Initial access options
rb intel mitre tactic initial-access

# Persistence options
rb intel mitre tactic persistence
```

### Detection Engineering

Get detection guidance:

```bash
rb intel mitre technique T1055 --detection
```
