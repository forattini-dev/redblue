# file

File operations domain for compression, decompression, and hash verification.

## Overview

The `file` domain provides native implementations for common file operations:
- **Compression/Decompression**: gzip, tar, zip, tar.gz
- **Hash Calculation/Verification**: md5, sha1, sha256, sha384, blake2b, crc32
- **File Information**: magic bytes detection, entropy analysis

All implementations are from scratch with zero external dependencies.

## Commands

### zip

Compress a file (currently shows implementation status).

```bash
# Compress with gzip (not yet implemented)
rb file ops zip gzip data.txt
rb file ops zip gzip data.txt -o data.txt.gz
```

**Note**: Currently only decompression is implemented.

### unzip

Decompress files with auto-format detection.

```bash
# Auto-detect format from magic bytes
rb file ops unzip data.txt.gz
rb file ops unzip archive.tar
rb file ops unzip archive.zip

# List archive contents without extracting
rb file ops unzip archive.tar --list
rb file ops unzip archive.zip -l

# Extract to specific directory
rb file ops unzip archive.tar -o ./output
rb file ops unzip archive.tar.gz -o ./extracted

# Force specific format
rb file ops unzip mystery.bin --format gzip
```

**Supported formats**:
| Format | Magic Bytes | Extensions |
|--------|-------------|------------|
| gzip | `1f 8b` | .gz, .gzip |
| tar | `ustar` @ 257 | .tar |
| zip | `50 4b` (PK) | .zip |
| tar.gz | gzip + tar | .tar.gz, .tgz |

### hash

Calculate or verify file hashes.

```bash
# Calculate hash (output compatible with sha256sum, md5sum, etc.)
rb file ops hash sha256 file.bin
rb file ops hash md5 file.bin
rb file ops hash sha1 file.bin
rb file ops hash blake2b file.bin
rb file ops hash crc32 file.bin

# Verify hash against known value
rb file ops hash sha256 file.bin --verify abc123def456...

# Verify from checksum file (sha256sum format)
rb file ops hash sha256 file.bin --verify checksums.txt

# JSON output
rb file ops hash sha256 file.bin -o json
```

**Supported algorithms**:
| Algorithm | Output Size | Speed |
|-----------|-------------|-------|
| md5 | 128 bits | Fast |
| sha1 | 160 bits | Fast |
| sha256 | 256 bits | Medium |
| sha384 | 384 bits | Medium |
| blake2b | 512 bits | Fast |
| crc32 | 32 bits | Fastest |

### info

Show detailed file information.

```bash
rb file ops info mystery.bin
```

**Output includes**:
- File size
- Detected file type (from magic bytes)
- First 16 bytes in hex and ASCII
- Compression format (if applicable)
- Shannon entropy (bits/byte)
  - High (>7.5): likely compressed/encrypted
  - Low (<4.0): likely text/structured

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--output` | `-o` | Output file/directory path |
| `--verify` | `-v` | Hash to verify against |
| `--list` | `-l` | List archive contents only |
| `--format` | `-f` | Force specific format |

## Examples

### Workflow: Download and Verify

```bash
# Download file
rb web asset get https://example.com/release.tar.gz -o release.tar.gz

# Verify integrity
rb file ops hash sha256 release.tar.gz --verify expected_hash_here

# Extract
rb file ops unzip release.tar.gz -o ./release
```

### Workflow: Inspect Unknown File

```bash
# Get file info
rb file ops info suspicious.bin

# Calculate multiple hashes
rb file ops hash md5 suspicious.bin
rb file ops hash sha256 suspicious.bin
rb file ops hash blake2b suspicious.bin

# Check VirusTotal (if intel module available)
rb intel ioc hash $(rb file ops hash sha256 suspicious.bin | cut -d' ' -f1)
```

### Archive Inspection

```bash
# List tar contents
rb file ops unzip backup.tar.gz --list

# Extract specific archive
rb file ops unzip data.zip -o ./extracted
```

## Implementation Details

### Format Detection

1. **Magic bytes** (highest priority):
   - gzip: `1f 8b`
   - ZIP: `50 4b 03 04`
   - TAR: `ustar` at offset 257

2. **File extension** (fallback):
   - `.gz`, `.gzip` → gzip
   - `.tar` → tar
   - `.zip` → zip
   - `.tar.gz`, `.tgz` → tar.gz

### Hash Verification Formats

Supports standard checksum file formats:

```
# sha256sum format
abc123def456...  filename.txt

# BSD format
abc123def456... *filename.txt

# Single hash (no filename)
abc123def456...
```

## Related Commands

- `rb crypto vault` - File encryption with AES-256-GCM
- `rb crypto codec` - Base64/Hex encoding
- `rb binary` - Binary analysis (ELF/PE)
- `rb hex` - Hex editor
