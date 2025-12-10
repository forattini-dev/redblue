# Certificate Management

> Generate and manage CA certificates for TLS interception.

## Overview

TLS interception requires a Certificate Authority (CA) to sign dynamically generated certificates. The target must trust this CA for interception to work without browser warnings.

## Certificate Generation

### Generate New CA

```bash
# Generate CA with default settings
rb mitm intercept generate-ca

# Specify output directory
rb mitm intercept generate-ca --output ./certs

# Generated files:
# ./certs/mitm-ca.pem      - CA certificate
# ./certs/mitm-ca-key.pem  - CA private key
```

### CA Properties

| Property | Value |
|----------|-------|
| Subject | `CN=redblue MITM CA, O=redblue Security, C=XX` |
| Key Algorithm | ECDSA P-256 (default) |
| Validity | 10 years (3650 days) |
| Key Usage | Certificate Sign, CRL Sign |
| Basic Constraints | CA:TRUE |

### Output

```
──────────────────────────────────────
  Generate MITM CA Certificate
──────────────────────────────────────

⠋ Generating CA certificate...
✓ Done

✓ CA certificate generated!

  Certificate : ./certs/mitm-ca.pem
  Private Key : ./certs/mitm-ca-key.pem
  Subject     : CN=redblue MITM CA, O=redblue Security, C=XX
  Fingerprint : SHA256:AB:CD:EF:12:34:56:78:90:...

ℹ Install mitm-ca.pem in target's trust store to avoid warnings
```

## Certificate Export

### Export for Installation

```bash
# Export as PEM (default)
rb mitm intercept export-ca --ca-cert ./certs/mitm-ca.pem

# Export as DER (for Windows)
rb mitm intercept export-ca --ca-cert ./certs/mitm-ca.pem --format der

# Specify output file
rb mitm intercept export-ca --ca-cert ./certs/mitm-ca.pem \
  --format der --output ./mitm-ca.der
```

### Export Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| PEM | `.pem`, `.crt` | Linux, macOS, Firefox |
| DER | `.der`, `.cer` | Windows, Java |

## Installing CA Certificate

### Windows

**Method 1: Double-click**
1. Double-click the `.der` file
2. Click "Install Certificate"
3. Select "Local Machine" → Next
4. Select "Place all certificates in the following store"
5. Click "Browse" → Select "Trusted Root Certification Authorities"
6. Click "Finish"

**Method 2: MMC**
1. Run `mmc.exe` as Administrator
2. File → Add/Remove Snap-in → Certificates → Add
3. Select "Computer account" → Next → Finish
4. Expand Certificates → Trusted Root Certification Authorities
5. Right-click Certificates → All Tasks → Import
6. Follow wizard to import the certificate

**Method 3: PowerShell (Admin)**
```powershell
Import-Certificate -FilePath ".\mitm-ca.der" `
  -CertStoreLocation Cert:\LocalMachine\Root
```

### macOS

**Method 1: Keychain Access**
1. Open Keychain Access
2. Select "System" keychain
3. File → Import Items → Select certificate
4. Double-click imported certificate
5. Expand "Trust" → Set "When using this certificate" to "Always Trust"
6. Close window (will prompt for password)

**Method 2: Command Line**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain mitm-ca.pem
```

### Linux

**Debian/Ubuntu**
```bash
# Copy certificate
sudo cp mitm-ca.pem /usr/local/share/ca-certificates/mitm-ca.crt

# Update CA store
sudo update-ca-certificates
```

**RHEL/CentOS/Fedora**
```bash
# Copy certificate
sudo cp mitm-ca.pem /etc/pki/ca-trust/source/anchors/

# Update CA store
sudo update-ca-trust
```

**Arch Linux**
```bash
# Copy certificate
sudo cp mitm-ca.pem /etc/ca-certificates/trust-source/anchors/

# Update CA store
sudo trust extract-compat
```

### Firefox (All Platforms)

Firefox uses its own certificate store:

1. Open Firefox → Settings
2. Privacy & Security → Certificates → View Certificates
3. Authorities tab → Import
4. Select certificate file
5. Check "Trust this CA to identify websites"
6. Click OK

### Chrome/Chromium

Chrome uses the system certificate store:
- **Windows**: Install in Windows (see above)
- **macOS**: Install in Keychain (see above)
- **Linux**: Install in system store (see above)

### Android

1. Copy certificate to device (email, USB, cloud)
2. Settings → Security → Encryption & Credentials
3. Install from storage → Select certificate
4. Name the certificate and confirm

**Note**: Android 7+ requires app modification for user-installed CAs to work.

### iOS

1. Email the certificate or host on web server
2. Open certificate → Install Profile
3. Settings → General → VPN & Device Management → Install
4. Settings → General → About → Certificate Trust Settings
5. Enable full trust for the certificate

## Using Custom CA

### With Proxy

```bash
# Use existing CA
rb mitm intercept proxy --proxy-port 8080 \
  --ca-cert ./certs/mitm-ca.pem \
  --ca-key ./certs/mitm-ca-key.pem

# With full MITM stack
rb mitm intercept start --target "*.target.com" --proxy-ip 10.0.0.5 \
  --ca-cert ./certs/mitm-ca.pem \
  --ca-key ./certs/mitm-ca-key.pem
```

### Auto-Generated CA

If no CA is provided, a temporary one is generated:

```bash
# Temporary CA (valid for current session)
rb mitm intercept proxy --proxy-port 8080

# Output:
# ℹ No CA provided, generating temporary CA...
# CA Subject: CN=redblue MITM CA, O=redblue Security, C=XX
```

## Certificate Architecture

### CA Certificate Structure

```
Certificate:
    Version: 3 (0x2)
    Serial Number: [random 64-bit]
    Signature Algorithm: ecdsa-with-SHA256
    Issuer: CN=redblue MITM CA, O=redblue Security, C=XX
    Validity:
        Not Before: [current date]
        Not After:  [current date + 10 years]
    Subject: CN=redblue MITM CA, O=redblue Security, C=XX
    Subject Public Key Info:
        Public Key Algorithm: id-ecPublicKey
        EC Public-Key: (256 bit)
        ASN1 OID: prime256v1 (P-256)
    X509v3 Extensions:
        X509v3 Basic Constraints: critical
            CA:TRUE
        X509v3 Key Usage: critical
            Certificate Sign, CRL Sign
        X509v3 Subject Key Identifier:
            [SHA1 of public key]
```

### Generated Server Certificate

For each hostname (e.g., `api.example.com`):

```
Certificate:
    Version: 3 (0x2)
    Serial Number: [random 64-bit]
    Signature Algorithm: ecdsa-with-SHA256
    Issuer: CN=redblue MITM CA, O=redblue Security, C=XX
    Validity:
        Not Before: [current date]
        Not After:  [current date + 1 year]
    Subject: CN=api.example.com
    Subject Public Key Info:
        Public Key Algorithm: id-ecPublicKey
        EC Public-Key: (256 bit)
    X509v3 Extensions:
        X509v3 Basic Constraints:
            CA:FALSE
        X509v3 Key Usage:
            Digital Signature, Key Encipherment
        X509v3 Extended Key Usage:
            TLS Web Server Authentication
        X509v3 Subject Alternative Name:
            DNS:api.example.com
```

## Key Algorithms

### Supported Algorithms

| Algorithm | Key Size | Notes |
|-----------|----------|-------|
| ECDSA P-256 | 256-bit | Default, fast, small keys |
| ECDSA P-384 | 384-bit | Higher security |
| RSA | 2048-bit | Wider compatibility |
| RSA | 4096-bit | Maximum security |

### Performance Comparison

| Algorithm | Key Gen | Sign | Verify | Certificate Size |
|-----------|---------|------|--------|------------------|
| ECDSA P-256 | ~1ms | ~0.5ms | ~1ms | ~400 bytes |
| ECDSA P-384 | ~2ms | ~1ms | ~2ms | ~500 bytes |
| RSA 2048 | ~100ms | ~5ms | ~0.2ms | ~1200 bytes |
| RSA 4096 | ~1000ms | ~20ms | ~0.5ms | ~2400 bytes |

## Certificate Caching

Server certificates are cached in memory:

```rust
CertCache {
    ca: CertificateAuthority,
    cache: HashMap<String, (cert_pem, key_pem)>
}

// Example cache entries:
// "api.example.com" → (cert, key)
// "www.example.com" → (cert, key)
// "cdn.example.com" → (cert, key)
```

### Cache Benefits

- Avoid regenerating certificates for repeated connections
- Faster TLS handshakes for known hosts
- Reduced CPU usage

### Cache Limitations

- Memory-only (cleared on restart)
- No disk persistence
- No expiration (certificates valid for 1 year)

## Security Considerations

### Protecting the CA Key

The CA private key is **extremely sensitive**:

```bash
# Restrict permissions
chmod 600 mitm-ca-key.pem

# Never commit to version control
echo "*.pem" >> .gitignore

# Store securely
# - Encrypted disk
# - Hardware security module
# - Secure key management
```

### CA Exposure Risks

If your CA key is compromised:

1. **All traffic can be intercepted**: Attacker can sign certificates for any domain
2. **No detection**: Targets trust the CA, no warnings
3. **Revocation difficult**: User-installed CAs hard to revoke

### Mitigation

1. **Generate per-engagement**: New CA for each test
2. **Short validity**: Use shorter validity periods
3. **Secure storage**: Encrypt CA key at rest
4. **Clean up**: Remove CA from targets after testing
5. **Document**: Track where CA is installed

## Viewing Certificate Details

### With OpenSSL

```bash
# View CA certificate
openssl x509 -in mitm-ca.pem -text -noout

# View certificate fingerprint
openssl x509 -in mitm-ca.pem -fingerprint -sha256 -noout

# Verify certificate chain
openssl verify -CAfile mitm-ca.pem server-cert.pem
```

### With redblue

```bash
# Export shows certificate details
rb mitm intercept export-ca --ca-cert mitm-ca.pem

# Output includes:
# Source: ./mitm-ca.pem
# Subject: CN=redblue MITM CA, O=redblue Security, C=XX
# Fingerprint: SHA256:AB:CD:EF:...
```

## Troubleshooting

### Certificate Not Trusted

**Problem**: Browser shows certificate warning

**Solutions**:
1. Verify CA is installed in correct store
2. Restart browser after installation
3. Check certificate chain is complete
4. Verify CA hasn't expired

### Permission Denied Writing Certificate

**Problem**: Can't save generated certificate

**Solution**:
```bash
# Create directory with proper permissions
mkdir -p ./certs
chmod 700 ./certs

# Generate certificate
rb mitm intercept generate-ca --output ./certs
```

### CA Key Mismatch

**Problem**: Error loading CA cert and key

**Solutions**:
1. Ensure cert and key are from same generation
2. Check file paths are correct
3. Verify PEM format is valid

```bash
# Verify key matches certificate
openssl x509 -in mitm-ca.pem -pubkey -noout > pub1.pem
openssl ec -in mitm-ca-key.pem -pubout > pub2.pem
diff pub1.pem pub2.pem
```

## Examples

### Complete CA Workflow

```bash
# 1. Generate CA
rb mitm intercept generate-ca --output ./certs

# 2. Export for Windows target
rb mitm intercept export-ca --ca-cert ./certs/mitm-ca.pem \
  --format der --output ./certs/mitm-ca.der

# 3. Install on target (Windows)
# Double-click mitm-ca.der → Install → Trusted Root CAs

# 4. Start proxy with CA
rb mitm intercept proxy --proxy-port 8080 \
  --ca-cert ./certs/mitm-ca.pem \
  --ca-key ./certs/mitm-ca-key.pem

# 5. Configure target browser proxy
# HTTP Proxy: 10.0.0.5:8080
# HTTPS Proxy: 10.0.0.5:8080

# 6. Test - no certificate warnings!
```

### Testing CA Installation

```bash
# Generate test certificate for localhost
# (using openssl for verification)
openssl req -x509 -new -key ./certs/mitm-ca-key.pem \
  -out test.pem -days 1 -subj "/CN=localhost"

# Verify trust (should say "OK")
openssl verify -CAfile ./certs/mitm-ca.pem test.pem
```

## Next Steps

- [Attack Scenarios](/domains/mitm/05-scenarios.md) - Real-world examples
- [Configuration](/domains/mitm/06-configuration.md) - All options reference
