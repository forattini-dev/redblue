# Proposal: Add Proxy, MITM, DNS & Certificate Modules

**Status:** In Progress (Phase 5 Complete)
**Author:** Claude
**Created:** 2024-12-07
**Updated:** 2024-12-07
**Progress:** Phase 1 ✅ | Phase 2 ✅ | Phase 3 ✅ | Phase 4 ⏳ | Phase 5 ✅ | Phase 6 🔄
**References:** shadowsocks-rust, mitmproxy_rs, OpenWrt-nikki

## Summary

Add comprehensive proxy, DNS, and certificate capabilities to redblue for full MITM interception:
- **Proxy Module**: SOCKS5, HTTP CONNECT, Transparent proxy
- **Certificate Module**: X.509 parsing, CA creation, on-the-fly cert generation
- **DNS Server Module**: DNS resolver, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), DNS hijacking

This enables complete traffic interception by controlling DNS resolution and TLS termination.

## Motivation

Pentest workflows require full traffic control:
- **DNS Control**: Redirect target traffic to our proxy
- **TLS Interception**: Decrypt HTTPS with generated certificates
- **Traffic Analysis**: Inspect and modify requests/responses
- **Credential Capture**: Intercept authentication flows
- **Protocol Analysis**: Debug encrypted connections

### The MITM Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Complete MITM Flow                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   1. Target configures DNS to use our server (or we hijack via ARP)     │
│                                                                          │
│   Target App                                                             │
│       │                                                                  │
│       ▼                                                                  │
│   ┌─────────────────┐                                                   │
│   │  DNS Server     │◄── Query: example.com A?                          │
│   │  (redblue)      │                                                   │
│   │  Port 53/853    │──► Response: 10.0.0.1 (our proxy IP)             │
│   │  DoT/DoH        │                                                   │
│   └─────────────────┘                                                   │
│           │                                                              │
│           ▼ Target connects to 10.0.0.1:443                             │
│   ┌─────────────────┐                                                   │
│   │  MITM Proxy     │◄── TLS ClientHello (SNI: example.com)            │
│   │  (redblue)      │                                                   │
│   │  - Cert Gen     │──► Generate fake cert for example.com            │
│   │  - TLS Term     │◄── Complete TLS handshake with fake cert         │
│   └─────────────────┘                                                   │
│           │                                                              │
│           ▼ Proxy connects to real server                               │
│   ┌─────────────────┐                                                   │
│   │  Real Server    │◄── TLS handshake with real cert                  │
│   │  (example.com)  │                                                   │
│   │  93.184.216.34  │◄══► Relay traffic (inspect/modify)               │
│   └─────────────────┘                                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Design Goals

1. **Zero external dependencies** - All protocols from scratch
2. **Full DNS control** - Server, DoT, DoH, hijacking rules
3. **Certificate authority** - Generate CA and sign certs on-the-fly
4. **Multiple proxy modes** - SOCKS5, HTTP CONNECT, Transparent
5. **Stream abstraction** - Clean API for connection handling
6. **TLS termination** - Full MITM for HTTPS
7. **Flow statistics** - Track all traffic
8. **Process tracking** - Know which process initiated connection

## Architecture

### Complete Module Structure

```
src/modules/
├── proxy/                      # ✅ IMPLEMENTED (Phase 1)
│   ├── mod.rs                  # Core types, ConnectionId, FlowStats
│   ├── socks5.rs               # SOCKS5 protocol (RFC 1928)
│   ├── http.rs                 # HTTP CONNECT proxy
│   ├── stream.rs               # Stream abstraction
│   ├── acl.rs                  # Access control lists
│   ├── relay/
│   │   ├── tcp.rs              # TCP bidirectional relay
│   │   └── udp.rs              # UDP association relay
│   └── tracking/
│       ├── connection.rs       # Connection state
│       └── process.rs          # Process info (Linux)
│
├── crypto/certs/               # 🆕 NEW - Certificate Module
│   ├── mod.rs                  # Module exports
│   ├── x509.rs                 # X.509 parsing (RFC 5280)
│   ├── asn1.rs                 # ASN.1 DER encoding/decoding
│   ├── oid.rs                  # Object Identifiers
│   ├── pem.rs                  # PEM format handling
│   ├── ca.rs                   # Certificate Authority
│   ├── generator.rs            # On-the-fly cert generation
│   └── store.rs                # Certificate cache/store
│
├── dns/server/                 # 🆕 NEW - DNS Server Module
│   ├── mod.rs                  # Module exports
│   ├── server.rs               # DNS server (UDP/TCP port 53)
│   ├── dot.rs                  # DNS-over-TLS (RFC 7858, port 853)
│   ├── doh.rs                  # DNS-over-HTTPS (RFC 8484)
│   ├── resolver.rs             # Upstream DNS resolution
│   ├── cache.rs                # DNS response caching
│   ├── rules.rs                # Hijacking/redirect rules
│   └── zone.rs                 # Zone file support
│
└── mitm/                       # 🆕 NEW - MITM Orchestration
    ├── mod.rs                  # Module exports
    ├── interceptor.rs          # TLS interception logic
    ├── inspector.rs            # Traffic inspection hooks
    └── recorder.rs             # Traffic recording (HAR)
```

---

## Module 1: Crypto & Certificate Module (`crypto/`)

### Purpose

Complete cryptographic toolkit for key management, certificate operations, and format conversions - all from scratch without external dependencies.

### Module Structure

```
src/modules/crypto/
├── mod.rs                  # Module exports
├── keys/                   # Key management
│   ├── mod.rs
│   ├── rsa.rs              # RSA key generation/operations
│   ├── ecdsa.rs            # ECDSA (P-256, P-384, secp256k1)
│   ├── ed25519.rs          # Ed25519 keys
│   ├── x25519.rs           # X25519 (key exchange) - exists
│   └── formats.rs          # Key format conversions
├── certs/                  # Certificate management
│   ├── mod.rs
│   ├── x509.rs             # X.509 parsing/generation (RFC 5280)
│   ├── csr.rs              # Certificate Signing Requests (RFC 2986)
│   ├── ca.rs               # Certificate Authority
│   ├── chain.rs            # Certificate chain validation
│   ├── extensions.rs       # X.509 v3 extensions
│   └── store.rs            # Certificate cache/store
├── encoding/               # Encoding formats
│   ├── mod.rs
│   ├── asn1.rs             # ASN.1 DER/BER encoding
│   ├── pem.rs              # PEM format
│   ├── pkcs8.rs            # PKCS#8 private keys
│   ├── pkcs12.rs           # PKCS#12 (.p12/.pfx) bundles
│   └── jwk.rs              # JSON Web Keys (RFC 7517)
└── utils/                  # Utilities
    ├── mod.rs
    ├── verify.rs           # Key/cert verification
    ├── compare.rs          # Key pair matching
    └── fingerprint.rs      # Certificate fingerprints
```

### Core Types

```rust
//=============================================================================
// KEY TYPES
//=============================================================================

/// Supported key algorithms
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaSecp256k1,
    Ed25519,
    X25519,
}

/// Private key (algorithm-agnostic)
pub struct PrivateKey {
    algorithm: KeyAlgorithm,
    key_data: Vec<u8>,
}

impl PrivateKey {
    /// Generate new key pair
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, KeyError>;

    /// Extract public key
    pub fn public_key(&self) -> PublicKey;

    /// Check if this private key matches a public key
    pub fn matches(&self, public: &PublicKey) -> bool;

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// Export to various formats
    pub fn to_pem(&self) -> String;
    pub fn to_der(&self) -> Vec<u8>;
    pub fn to_pkcs8(&self) -> Vec<u8>;
    pub fn to_pkcs8_encrypted(&self, password: &str) -> Vec<u8>;
    pub fn to_jwk(&self) -> String;

    /// Import from various formats
    pub fn from_pem(pem: &str) -> Result<Self, KeyError>;
    pub fn from_der(der: &[u8]) -> Result<Self, KeyError>;
    pub fn from_pkcs8(data: &[u8]) -> Result<Self, KeyError>;
    pub fn from_pkcs8_encrypted(data: &[u8], password: &str) -> Result<Self, KeyError>;
    pub fn from_jwk(jwk: &str) -> Result<Self, KeyError>;
}

/// Public key
pub struct PublicKey {
    algorithm: KeyAlgorithm,
    key_data: Vec<u8>,
}

impl PublicKey {
    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool;

    /// Export to various formats
    pub fn to_pem(&self) -> String;
    pub fn to_der(&self) -> Vec<u8>;
    pub fn to_ssh(&self) -> String;  // OpenSSH format
    pub fn to_jwk(&self) -> String;

    /// Calculate fingerprints
    pub fn fingerprint_sha256(&self) -> String;
    pub fn fingerprint_md5(&self) -> String;

    /// Import from various formats
    pub fn from_pem(pem: &str) -> Result<Self, KeyError>;
    pub fn from_der(der: &[u8]) -> Result<Self, KeyError>;
    pub fn from_ssh(ssh: &str) -> Result<Self, KeyError>;
    pub fn from_jwk(jwk: &str) -> Result<Self, KeyError>;
}

//=============================================================================
// CERTIFICATE TYPES
//=============================================================================

/// X.509 Certificate (RFC 5280)
pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
}

impl Certificate {
    /// Parse from various formats
    pub fn from_pem(pem: &str) -> Result<Self, CertError>;
    pub fn from_der(der: &[u8]) -> Result<Self, CertError>;

    /// Export to various formats
    pub fn to_pem(&self) -> String;
    pub fn to_der(&self) -> Vec<u8>;

    /// Get certificate information
    pub fn subject(&self) -> &Name;
    pub fn issuer(&self) -> &Name;
    pub fn serial_number(&self) -> &[u8];
    pub fn not_before(&self) -> DateTime;
    pub fn not_after(&self) -> DateTime;
    pub fn public_key(&self) -> PublicKey;
    pub fn extensions(&self) -> &[Extension];

    /// Get Subject Alternative Names (SANs)
    pub fn san_dns_names(&self) -> Vec<&str>;
    pub fn san_ip_addresses(&self) -> Vec<IpAddr>;
    pub fn san_emails(&self) -> Vec<&str>;

    /// Calculate fingerprints
    pub fn fingerprint_sha256(&self) -> String;
    pub fn fingerprint_sha1(&self) -> String;
    pub fn fingerprint_md5(&self) -> String;

    /// Verification
    pub fn verify_signature(&self, issuer_cert: &Certificate) -> bool;
    pub fn is_self_signed(&self) -> bool;
    pub fn is_ca(&self) -> bool;
    pub fn is_valid_now(&self) -> bool;
    pub fn is_valid_for_hostname(&self, hostname: &str) -> bool;

    /// Check if certificate matches private key
    pub fn matches_private_key(&self, key: &PrivateKey) -> bool;
}

/// Certificate Signing Request (RFC 2986)
pub struct CertificateRequest {
    pub subject: Name,
    pub public_key: PublicKey,
    pub extensions: Vec<Extension>,
}

impl CertificateRequest {
    /// Create new CSR
    pub fn new(subject: &str, private_key: &PrivateKey) -> Result<Self, CertError>;

    /// Add extensions
    pub fn add_san_dns(&mut self, dns: &str);
    pub fn add_san_ip(&mut self, ip: IpAddr);
    pub fn add_san_email(&mut self, email: &str);

    /// Export
    pub fn to_pem(&self, signing_key: &PrivateKey) -> String;
    pub fn to_der(&self, signing_key: &PrivateKey) -> Vec<u8>;

    /// Import
    pub fn from_pem(pem: &str) -> Result<Self, CertError>;
    pub fn from_der(der: &[u8]) -> Result<Self, CertError>;
}

/// Certificate Authority
pub struct CertificateAuthority {
    pub cert: Certificate,
    pub private_key: PrivateKey,
    serial_counter: AtomicU64,
}

impl CertificateAuthority {
    /// Create new self-signed CA
    pub fn new(
        subject: &str,
        key_algorithm: KeyAlgorithm,
        validity_days: u32,
    ) -> Result<Self, CertError>;

    /// Load existing CA
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self, CertError>;

    /// Sign a CSR
    pub fn sign_csr(
        &self,
        csr: &CertificateRequest,
        validity_days: u32,
    ) -> Result<Certificate, CertError>;

    /// Generate certificate for hostname (MITM)
    pub fn generate_cert(&self, hostname: &str) -> Result<Certificate, CertError>;

    /// Generate certificate with SANs
    pub fn generate_cert_with_sans(
        &self,
        common_name: &str,
        dns_names: &[&str],
        ip_addresses: &[IpAddr],
    ) -> Result<Certificate, CertError>;

    /// Export CA certificate
    pub fn export_ca_pem(&self) -> String;
    pub fn export_ca_der(&self) -> Vec<u8>;
}

//=============================================================================
// FORMAT CONVERSIONS
//=============================================================================

/// PKCS#12 bundle (.p12/.pfx)
pub struct Pkcs12Bundle {
    pub certificate: Certificate,
    pub private_key: PrivateKey,
    pub ca_chain: Vec<Certificate>,
}

impl Pkcs12Bundle {
    /// Create new bundle
    pub fn new(
        cert: Certificate,
        key: PrivateKey,
        ca_chain: Vec<Certificate>,
    ) -> Self;

    /// Export to .p12/.pfx
    pub fn to_pkcs12(&self, password: &str) -> Vec<u8>;

    /// Import from .p12/.pfx
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<Self, CertError>;
}

/// Certificate chain
pub struct CertificateChain {
    pub certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Build chain from leaf to root
    pub fn build(leaf: Certificate, intermediates: &[Certificate]) -> Result<Self, CertError>;

    /// Verify chain integrity
    pub fn verify(&self) -> Result<(), CertError>;

    /// Export as PEM bundle
    pub fn to_pem(&self) -> String;

    /// Import from PEM bundle
    pub fn from_pem(pem: &str) -> Result<Self, CertError>;
}
```

### ASN.1 DER Encoding

```rust
// src/modules/crypto/encoding/asn1.rs

pub enum Asn1Value {
    Boolean(bool),
    Integer(Vec<u8>),            // Big-endian bytes
    BitString(Vec<u8>, u8),      // data, unused bits
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u32>),
    Utf8String(String),
    PrintableString(String),
    Ia5String(String),
    UtcTime(DateTime),
    GeneralizedTime(DateTime),
    Sequence(Vec<Asn1Value>),
    Set(Vec<Asn1Value>),
    ContextSpecific(u8, Box<Asn1Value>),
    Raw(u8, Vec<u8>),            // Tag + raw data
}

impl Asn1Value {
    pub fn encode_der(&self) -> Vec<u8>;
    pub fn decode_der(data: &[u8]) -> Result<(Self, usize), Asn1Error>;

    // Helper constructors
    pub fn integer_from_u64(n: u64) -> Self;
    pub fn integer_from_bytes(bytes: &[u8]) -> Self;
    pub fn oid(components: &[u32]) -> Self;
    pub fn sequence(items: Vec<Asn1Value>) -> Self;
}
```

### CLI Commands - Complete Reference

```bash
#=============================================================================
# KEY MANAGEMENT
#=============================================================================

# Generate new key pairs
rb crypto key generate --algorithm rsa2048 -o private.pem
rb crypto key generate --algorithm rsa4096 -o private.pem
rb crypto key generate --algorithm ecdsa-p256 -o private.pem
rb crypto key generate --algorithm ecdsa-p384 -o private.pem
rb crypto key generate --algorithm ed25519 -o private.pem
rb crypto key generate --algorithm x25519 -o private.pem

# Extract public key from private key
rb crypto key public --in private.pem -o public.pem
rb crypto key public --in private.pem --format ssh -o id_ed25519.pub
rb crypto key public --in private.pem --format jwk -o public.jwk

# Inspect key details
rb crypto key inspect private.pem
rb crypto key inspect public.pem
# Output:
# Algorithm: RSA 2048-bit
# Public Key Fingerprint (SHA256): SHA256:xxxxxxxxxxx
# Public Key Fingerprint (MD5): MD5:xx:xx:xx:xx:xx

# Convert key formats
rb crypto key convert --in private.pem --format pkcs8 -o private.p8
rb crypto key convert --in private.pem --format der -o private.der
rb crypto key convert --in private.pem --format jwk -o private.jwk
rb crypto key convert --in private.der --format pem -o private.pem

# Encrypt/decrypt private key
rb crypto key encrypt --in private.pem --password "secret" -o private.enc.pem
rb crypto key decrypt --in private.enc.pem --password "secret" -o private.pem

# Compare keys (check if they match)
rb crypto key compare --private private.pem --public public.pem
# Output: ✓ Keys match (same key pair)
# Output: ✗ Keys do NOT match

rb crypto key compare --private private.pem --cert server.crt
# Output: ✓ Private key matches certificate

#=============================================================================
# CERTIFICATE MANAGEMENT
#=============================================================================

# Inspect certificate
rb crypto cert inspect server.crt
rb crypto cert inspect server.crt --format json
# Output:
# Subject: CN=example.com, O=Example Inc
# Issuer: CN=Example CA
# Serial: 01:23:45:67:89:AB
# Valid From: 2024-01-01 00:00:00 UTC
# Valid Until: 2025-01-01 00:00:00 UTC
# Algorithm: RSA 2048-bit with SHA-256
# Fingerprint (SHA256): SHA256:xxxxxxxxxxx
# SANs: DNS:example.com, DNS:*.example.com, IP:192.168.1.1
# Extensions:
#   - Basic Constraints: CA:FALSE
#   - Key Usage: Digital Signature, Key Encipherment
#   - Extended Key Usage: TLS Web Server Authentication

# Verify certificate
rb crypto cert verify server.crt --ca ca.crt
rb crypto cert verify server.crt --chain chain.pem
rb crypto cert verify server.crt --hostname example.com

# Check certificate/key match
rb crypto cert match --cert server.crt --key private.pem
# Output: ✓ Certificate and private key match

# Get certificate fingerprints
rb crypto cert fingerprint server.crt
rb crypto cert fingerprint server.crt --algorithm sha1
rb crypto cert fingerprint server.crt --algorithm md5

# Get certificate dates
rb crypto cert dates server.crt
# Output:
# Not Before: 2024-01-01 00:00:00 UTC
# Not After:  2025-01-01 00:00:00 UTC
# Expires in: 180 days
# Status: ✓ Valid

# Get SANs
rb crypto cert sans server.crt
# Output:
# DNS: example.com
# DNS: *.example.com
# IP: 192.168.1.1
# Email: admin@example.com

#=============================================================================
# CERTIFICATE SIGNING REQUESTS (CSR)
#=============================================================================

# Generate CSR
rb crypto csr generate --key private.pem --subject "CN=example.com,O=Example Inc" -o request.csr
rb crypto csr generate --key private.pem --subject "CN=example.com" \
    --san-dns "*.example.com" --san-dns "api.example.com" \
    --san-ip "192.168.1.1" -o request.csr

# Inspect CSR
rb crypto csr inspect request.csr

# Verify CSR signature
rb crypto csr verify request.csr

#=============================================================================
# CERTIFICATE AUTHORITY (CA)
#=============================================================================

# Generate new CA
rb crypto ca generate --subject "CN=My Root CA,O=My Company" --days 3650 \
    --key-algorithm rsa4096 -o ca.pem --key-out ca-key.pem

# Generate intermediate CA
rb crypto ca generate --subject "CN=My Intermediate CA" --days 1825 \
    --issuer-cert ca.pem --issuer-key ca-key.pem \
    -o intermediate.pem --key-out intermediate-key.pem

# Sign CSR with CA
rb crypto ca sign --ca ca.pem --ca-key ca-key.pem --csr request.csr \
    --days 365 -o server.crt

# Generate certificate directly (without CSR)
rb crypto ca issue --ca ca.pem --ca-key ca-key.pem \
    --subject "CN=example.com" --days 365 \
    --san-dns "example.com" --san-dns "*.example.com" \
    -o server.crt --key-out server-key.pem

# Export CA for browser/system installation
rb crypto ca export --in ca.pem --format der -o ca.crt
rb crypto ca export --in ca.pem --format pem -o ca.pem

#=============================================================================
# FORMAT CONVERSIONS
#=============================================================================

# PEM <-> DER conversion
rb crypto convert --in cert.pem --format der -o cert.der
rb crypto convert --in cert.der --format pem -o cert.pem

# Create PKCS#12 bundle (.p12/.pfx)
rb crypto bundle create --cert server.crt --key server-key.pem \
    --ca ca.crt --password "secret" -o bundle.p12

# Extract from PKCS#12 bundle
rb crypto bundle extract --in bundle.p12 --password "secret" \
    --cert-out server.crt --key-out server-key.pem --ca-out ca.crt

# Create certificate chain/bundle
rb crypto chain create --cert server.crt --intermediate intermediate.crt \
    --ca ca.crt -o fullchain.pem

# Split certificate chain
rb crypto chain split --in fullchain.pem --output-dir ./certs/

# Combine PEM files
rb crypto combine --in cert.pem --in key.pem -o combined.pem

#=============================================================================
# VERIFICATION & COMPARISON
#=============================================================================

# Verify certificate chain
rb crypto verify chain --cert server.crt --chain chain.pem --ca ca.crt

# Check if cert is valid for hostname
rb crypto verify hostname --cert server.crt --hostname example.com

# Check certificate expiration
rb crypto verify expiry --cert server.crt --warn-days 30

# Compare certificate and key
rb crypto compare --cert server.crt --key server-key.pem

# Compare two certificates
rb crypto compare --cert1 server1.crt --cert2 server2.crt

#=============================================================================
# MITM-SPECIFIC COMMANDS
#=============================================================================

# Generate MITM CA (optimized for interception)
rb crypto mitm-ca generate --subject "redblue MITM CA" -o mitm-ca.pem

# Generate certificate for interception (on-the-fly)
rb crypto mitm-cert --ca mitm-ca.pem --hostname example.com

# Install CA in system trust store (requires root)
rb crypto ca install --cert mitm-ca.pem --system
rb crypto ca install --cert mitm-ca.pem --firefox
rb crypto ca install --cert mitm-ca.pem --chrome

# Remove CA from system trust store
rb crypto ca uninstall --cert mitm-ca.pem --system
```

### Key/Certificate Comparison Logic

```rust
// src/modules/crypto/utils/compare.rs

/// Compare private key with public key
pub fn keys_match(private: &PrivateKey, public: &PublicKey) -> bool {
    // Extract public key from private and compare
    let derived_public = private.public_key();
    derived_public.key_data == public.key_data
}

/// Compare private key with certificate
pub fn key_matches_cert(private: &PrivateKey, cert: &Certificate) -> bool {
    let cert_public = cert.public_key();
    keys_match(private, &cert_public)
}

/// Compare two certificates
pub struct CertComparison {
    pub same_subject: bool,
    pub same_issuer: bool,
    pub same_serial: bool,
    pub same_public_key: bool,
    pub same_validity: bool,
    pub same_fingerprint: bool,
}

pub fn compare_certs(cert1: &Certificate, cert2: &Certificate) -> CertComparison {
    CertComparison {
        same_subject: cert1.subject() == cert2.subject(),
        same_issuer: cert1.issuer() == cert2.issuer(),
        same_serial: cert1.serial_number() == cert2.serial_number(),
        same_public_key: cert1.public_key().key_data == cert2.public_key().key_data,
        same_validity: cert1.not_before() == cert2.not_before()
            && cert1.not_after() == cert2.not_after(),
        same_fingerprint: cert1.fingerprint_sha256() == cert2.fingerprint_sha256(),
    }
}
```

### Supported Formats Matrix

| Format | Extension | Keys | Certs | Description |
|--------|-----------|------|-------|-------------|
| PEM | .pem, .crt, .key | ✓ | ✓ | Base64 with headers |
| DER | .der, .cer | ✓ | ✓ | Binary ASN.1 |
| PKCS#8 | .p8, .key | ✓ | - | Private key container |
| PKCS#12 | .p12, .pfx | ✓ | ✓ | Bundle with password |
| JWK | .jwk, .json | ✓ | - | JSON Web Key |
| OpenSSH | .pub | Pub | - | SSH public key |

---

## Module 2: DNS Server Module (`dns/server/`)

### Purpose

Act as a DNS resolver with hijacking capabilities, supporting modern secure DNS protocols.

### Core Types

```rust
// DNS Server Configuration
pub struct DnsServerConfig {
    /// Listen addresses for plain DNS (UDP/TCP port 53)
    pub listen_addrs: Vec<SocketAddr>,
    /// Enable DNS-over-TLS (port 853)
    pub dot_enabled: bool,
    pub dot_cert: Option<Certificate>,
    pub dot_key: Option<PrivateKey>,
    /// Enable DNS-over-HTTPS
    pub doh_enabled: bool,
    pub doh_path: String,  // e.g., "/dns-query"
    /// Upstream resolvers
    pub upstreams: Vec<UpstreamResolver>,
    /// Cache configuration
    pub cache_size: usize,
    pub cache_ttl: Duration,
    /// Hijacking rules
    pub rules: Vec<DnsRule>,
}

// Upstream resolver types
pub enum UpstreamResolver {
    /// Plain DNS (UDP/TCP)
    Plain(SocketAddr),
    /// DNS-over-TLS
    Tls { addr: SocketAddr, hostname: String },
    /// DNS-over-HTTPS
    Https { url: String },
}

// DNS hijacking rules
pub enum DnsRule {
    /// Override A/AAAA record
    Override {
        pattern: String,        // "*.example.com" or "example.com"
        record_type: RecordType,
        value: IpAddr,
    },
    /// Block domain (return NXDOMAIN)
    Block {
        pattern: String,
    },
    /// Redirect to different domain
    Redirect {
        pattern: String,
        target: String,
    },
    /// Forward to specific upstream
    Forward {
        pattern: String,
        upstream: UpstreamResolver,
    },
}
```

### DNS-over-TLS (DoT) Implementation

```rust
// src/modules/dns/server/dot.rs

pub struct DotServer {
    listener: TcpListener,
    tls_config: TlsServerConfig,
    resolver: Arc<DnsResolver>,
}

impl DotServer {
    /// Start DoT server on port 853
    pub fn bind(addr: SocketAddr, cert: Certificate, key: PrivateKey) -> Result<Self>;

    /// Run server loop
    pub fn run(&self) -> Result<()> {
        for stream in self.listener.incoming() {
            let tls_stream = self.tls_config.accept(stream)?;
            // DNS over TCP format: 2-byte length prefix + DNS message
            self.handle_dns_tcp(tls_stream)?;
        }
    }
}
```

### DNS-over-HTTPS (DoH) Implementation

```rust
// src/modules/dns/server/doh.rs

pub struct DohServer {
    http_server: HttpServer,
    resolver: Arc<DnsResolver>,
}

impl DohServer {
    /// Handle DoH request (RFC 8484)
    pub fn handle_request(&self, req: &HttpRequest) -> HttpResponse {
        // GET: dns parameter is base64url-encoded DNS query
        // POST: body is raw DNS message, Content-Type: application/dns-message

        let dns_query = match req.method {
            Method::Get => {
                let dns_param = req.query_param("dns")?;
                base64url_decode(dns_param)?
            }
            Method::Post => {
                req.body.clone()
            }
        };

        let response = self.resolver.resolve(&dns_query)?;

        HttpResponse::ok()
            .content_type("application/dns-message")
            .body(response)
    }
}
```

### DNS Hijacking Flow

```rust
// src/modules/dns/server/rules.rs

impl DnsResolver {
    pub fn resolve(&self, query: &DnsQuery) -> DnsResponse {
        let domain = &query.questions[0].name;

        // Check hijacking rules first
        for rule in &self.rules {
            match rule {
                DnsRule::Override { pattern, record_type, value } => {
                    if matches_pattern(domain, pattern) && query.qtype == *record_type {
                        return self.create_response(query, *value);
                    }
                }
                DnsRule::Block { pattern } => {
                    if matches_pattern(domain, pattern) {
                        return self.create_nxdomain(query);
                    }
                }
                DnsRule::Redirect { pattern, target } => {
                    if matches_pattern(domain, pattern) {
                        // Resolve target instead
                        return self.resolve_upstream(target);
                    }
                }
                _ => {}
            }
        }

        // No rule matched, forward to upstream
        self.resolve_upstream(domain)
    }
}
```

### CLI Commands

```bash
# Start DNS server
rb dns server start --port 53
rb dns server start --port 53 --upstream 8.8.8.8 --upstream 1.1.1.1

# Start with DoT
rb dns server start --dot --cert server.pem --key server-key.pem

# Start with DoH
rb dns server start --doh --doh-path /dns-query --cert server.pem

# Add hijacking rules
rb dns server start --hijack "*.target.com=10.0.0.1"
rb dns server start --block "*.ads.com"
rb dns server start --config dns-rules.yaml

# Test DNS resolution
rb dns server test example.com
rb dns server test example.com --type AAAA
```

### Configuration File

```yaml
# dns-server.yaml
server:
  listen:
    - "0.0.0.0:53"      # Plain DNS
    - "0.0.0.0:853"     # DoT

  dot:
    enabled: true
    cert: /path/to/cert.pem
    key: /path/to/key.pem

  doh:
    enabled: true
    path: /dns-query

  upstreams:
    - type: plain
      addr: 8.8.8.8:53
    - type: tls
      addr: 1.1.1.1:853
      hostname: cloudflare-dns.com
    - type: https
      url: https://dns.google/dns-query

  cache:
    size: 10000
    ttl: 300

rules:
  # Redirect all target.com traffic to our proxy
  - pattern: "*.target.com"
    action: override
    type: A
    value: 10.0.0.1

  # Block ads
  - pattern: "*.doubleclick.net"
    action: block

  # Custom upstream for internal domains
  - pattern: "*.internal.corp"
    action: forward
    upstream: 192.168.1.1:53
```

---

## Module 3: MITM Orchestration (`mitm/`)

### Purpose

Coordinate DNS, proxy, and certificates for seamless MITM interception.

### Core Types

```rust
// MITM Controller
pub struct MitmController {
    /// DNS server for hijacking
    dns_server: DnsServer,
    /// Proxy server for interception
    proxy_server: ProxyServer,
    /// Certificate authority
    ca: CertificateAuthority,
    /// Generated certificate cache
    cert_cache: HashMap<String, Certificate>,
    /// Traffic recorder
    recorder: Option<HarRecorder>,
}

impl MitmController {
    /// Start full MITM stack
    pub fn start(&self, config: MitmConfig) -> Result<()> {
        // 1. Start DNS server with hijacking rules
        self.dns_server.start()?;

        // 2. Start MITM proxy
        self.proxy_server.start()?;

        // 3. Ready for interception
        Ok(())
    }

    /// Handle new TLS connection
    pub fn intercept_tls(&self, client: TcpStream, sni: &str) -> Result<()> {
        // 1. Get or generate certificate for SNI
        let cert = self.get_or_generate_cert(sni)?;

        // 2. TLS handshake with client using fake cert
        let client_tls = tls_accept(client, &cert, &self.ca.private_key)?;

        // 3. Connect to real server
        let server = TcpStream::connect(sni)?;
        let server_tls = tls_connect(server, sni)?;

        // 4. Relay with inspection
        self.relay_with_inspection(client_tls, server_tls)?;

        Ok(())
    }
}
```

### CLI Commands

```bash
# Full MITM stack
rb mitm start --dns-port 53 --proxy-port 8080 --ca ca.pem

# MITM with auto-generated CA
rb mitm start --generate-ca --proxy-port 8080

# MITM specific targets
rb mitm start --target "*.target.com" --proxy-port 8080

# Export intercepted traffic
rb mitm start --record traffic.har

# Interactive mode with TUI
rb mitm start --tui
```

---

## Implementation Phases

### Phase 1: Proxy Infrastructure ✅ COMPLETED
- [x] SOCKS5 protocol (RFC 1928)
- [x] HTTP CONNECT proxy
- [x] TCP/UDP relay
- [x] Stream abstraction
- [x] ACL support
- [x] Connection tracking
- [x] Flow statistics
- [x] CLI: `rb proxy socks5 start`
- [x] CLI: `rb proxy http start`

### Phase 2: Certificate Module ✅ COMPLETED
- [x] ASN.1 DER encoder/decoder (`src/crypto/encoding/asn1.rs`)
- [x] X.509 certificate parsing (`src/crypto/certs/x509.rs`)
- [x] X.509 certificate generation (via CA)
- [x] PEM format handling (`src/crypto/encoding/pem.rs`)
- [x] Base64 encoding (`src/crypto/encoding/base64.rs`)
- [x] OID handling (`src/crypto/encoding/oid.rs`)
- [x] Certificate Authority implementation (`src/crypto/certs/ca.rs`)
- [x] Certificate Signing Requests (`src/crypto/certs/csr.rs`)
- [x] Certificate chain validation (`src/crypto/certs/chain.rs`)
- [x] On-the-fly cert generation (in MITM proxy)
- [x] Certificate caching (in MITM proxy)
- [x] CLI: `rb proxy mitm generate-ca`
- [x] CLI: `rb proxy mitm start`
- [x] CLI: `rb proxy mitm export-ca`

### Phase 3: DNS Server Module ✅ COMPLETED
- [x] DNS server (UDP port 53)
- [x] DNS server (TCP port 53)
- [ ] DNS-over-TLS (DoT, port 853) - Nice to have
- [ ] DNS-over-HTTPS (DoH) - Nice to have
- [x] DNS caching
- [x] Hijacking rules engine
- [x] Upstream resolver support
- [x] CLI: `rb dns server start`

### Phase 4: TLS Improvements
- [ ] TLS 1.3 server mode
- [ ] TLS 1.3 client mode
- [ ] SNI extraction
- [ ] Certificate chain handling
- [ ] Session resumption

### Phase 5: MITM Integration ✅ COMPLETED
- [x] MITM controller (basic - `src/modules/proxy/mitm.rs`)
- [x] MITM orchestrator (`src/cli/commands/mitm.rs`)
- [x] DNS + Proxy integration (`rb mitm attack start`)
- [x] CLI integration (`rb proxy mitm`, `rb mitm attack`)
- [x] CA certificate generation and management
- [ ] Traffic inspection hooks - Nice to have
- [ ] HAR recording - Nice to have
- [ ] TUI monitoring - Nice to have

### Phase 6: CLI & Documentation (Partial)
- [ ] `rb crypto` commands (key management, cert inspection) - Nice to have
- [x] `rb dns server` commands - DONE
- [x] `rb proxy mitm` commands - DONE
- [x] `rb mitm attack` commands - DONE
- [ ] Documentation - TODO
- [ ] Examples - TODO

---

## Dependencies

**All from scratch (std only):**
- X.509/ASN.1 (RFC 5280)
- DNS protocol (RFC 1035) - exists
- DNS-over-TLS (RFC 7858)
- DNS-over-HTTPS (RFC 8484)
- TLS 1.3 (RFC 8446) - partial
- SOCKS5 (RFC 1928) - done
- HTTP/1.1 (RFC 2616) - exists

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| ASN.1 complexity | High | Start with minimal subset for X.509 |
| TLS stack incomplete | High | Prioritize TLS 1.3 server mode |
| DNS performance | Medium | Implement caching early |
| Certificate trust | Low | Document CA installation |
| Platform differences | Medium | Start with Linux |

---

## Success Criteria

1. `rb crypto ca generate` creates valid CA certificate
2. `rb dns server start` resolves DNS queries
3. `rb dns server start --dot` works with secure DNS clients
4. `rb mitm start` intercepts HTTPS traffic end-to-end
5. Traffic visible in HAR export
6. No external binaries called
7. All protocols implemented from scratch

---

## References

### RFCs
- [RFC 5280 - X.509 PKI](https://tools.ietf.org/html/rfc5280)
- [RFC 1035 - DNS](https://tools.ietf.org/html/rfc1035)
- [RFC 7858 - DNS-over-TLS](https://tools.ietf.org/html/rfc7858)
- [RFC 8484 - DNS-over-HTTPS](https://tools.ietf.org/html/rfc8484)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 1928 - SOCKS5](https://tools.ietf.org/html/rfc1928)

### Reference Implementations
- [shadowsocks-rust](./references/shadowsocks-rust) - Proxy patterns
- [mitmproxy_rs](./references/mitmproxy_rs) - Interception patterns
- [OpenWrt-nikki](./references/OpenWrt-nikki) - DNS hijacking patterns
