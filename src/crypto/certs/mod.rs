//! X.509 Certificate Management
//!
//! This module provides:
//! - X.509 certificate parsing and generation (RFC 5280)
//! - Certificate Signing Requests (CSR) (RFC 2986)
//! - Certificate Authority operations
//! - Certificate chain validation
//!
//! Note: CA operations and CSR building require OpenSSL (boring) which is not
//! available on Windows. Those modules are conditionally compiled.

#[cfg(not(target_os = "windows"))]
pub mod ca;
pub mod chain;
pub mod csr;
pub mod x509;

#[cfg(not(target_os = "windows"))]
pub use ca::CertificateAuthority;
pub use chain::CertificateChain;
pub use csr::CertificateRequest;
pub use x509::{Certificate, Extension, Name, TbsCertificate, Validity};
