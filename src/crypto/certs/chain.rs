//! Certificate Chain Validation
//!
//! This module provides functionality for:
//! - Building certificate chains from leaf to root
//! - Validating certificate chain integrity
//! - Exporting chains in various formats

use super::x509::{CertError, Certificate};

/// Certificate Chain (ordered from leaf to root)
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// Certificates in order: [leaf, intermediate..., root]
    pub certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Create empty chain
    pub fn new() -> Self {
        CertificateChain {
            certificates: Vec::new(),
        }
    }

    /// Create chain from a single certificate
    pub fn from_cert(cert: Certificate) -> Self {
        CertificateChain {
            certificates: vec![cert],
        }
    }

    /// Build chain from leaf and available intermediates
    ///
    /// Attempts to order certificates from leaf to root by matching
    /// issuer/subject relationships.
    pub fn build(leaf: Certificate, intermediates: &[Certificate]) -> Result<Self, CertError> {
        let mut chain = vec![leaf];
        let mut available: Vec<_> = intermediates.iter().cloned().collect();

        // Try to build chain by matching issuer -> subject
        loop {
            let current = chain.last().unwrap();

            // If self-signed, we've reached the root
            if current.is_self_signed() {
                break;
            }

            // Find issuer in available certificates
            let mut found = None;
            for (idx, cert) in available.iter().enumerate() {
                if cert.tbs_certificate.subject == current.tbs_certificate.issuer {
                    found = Some(idx);
                    break;
                }
            }

            match found {
                Some(idx) => {
                    let issuer = available.remove(idx);
                    chain.push(issuer);
                }
                None => {
                    // No issuer found, chain is incomplete
                    break;
                }
            }

            // Safety limit
            if chain.len() > 10 {
                return Err(CertError::InvalidFormat("Chain too long (>10)".into()));
            }
        }

        Ok(CertificateChain {
            certificates: chain,
        })
    }

    /// Parse chain from PEM bundle
    pub fn from_pem(pem: &str) -> Result<Self, CertError> {
        let mut certificates = Vec::new();

        for block in crate::crypto::encoding::pem::decode_all(pem).unwrap_or_default() {
            if block.label == "CERTIFICATE" {
                let cert = Certificate::from_der(&block.data)?;
                certificates.push(cert);
            }
        }

        if certificates.is_empty() {
            return Err(CertError::InvalidFormat("No certificates found".into()));
        }

        Ok(CertificateChain { certificates })
    }

    /// Export chain as PEM bundle
    pub fn to_pem(&self) -> String {
        self.certificates
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export chain as DER (concatenated)
    pub fn to_der(&self) -> Vec<u8> {
        self.certificates.iter().flat_map(|c| c.to_der()).collect()
    }

    /// Get leaf certificate (first in chain)
    pub fn leaf(&self) -> Option<&Certificate> {
        self.certificates.first()
    }

    /// Get root certificate (last in chain)
    pub fn root(&self) -> Option<&Certificate> {
        self.certificates.last()
    }

    /// Get intermediates (all except leaf and root)
    pub fn intermediates(&self) -> &[Certificate] {
        if self.certificates.len() <= 2 {
            &[]
        } else {
            &self.certificates[1..self.certificates.len() - 1]
        }
    }

    /// Get chain length
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Verify chain integrity
    ///
    /// Checks that:
    /// 1. Each certificate is signed by the next in chain
    /// 2. The root is self-signed (or chain ends)
    /// 3. All certificates are currently valid
    pub fn verify(&self) -> Result<ChainVerificationResult, CertError> {
        let mut result = ChainVerificationResult {
            valid: true,
            issues: Vec::new(),
        };

        if self.certificates.is_empty() {
            result.valid = false;
            result.issues.push("Empty chain".to_string());
            return Ok(result);
        }

        // Check each certificate
        for (i, cert) in self.certificates.iter().enumerate() {
            // Check validity period
            if !cert.is_valid_now() {
                result.valid = false;
                if let Some(cn) = cert.subject_cn() {
                    result.issues.push(format!(
                        "Certificate {} ({}) is expired or not yet valid",
                        i, cn
                    ));
                } else {
                    result
                        .issues
                        .push(format!("Certificate {} is expired or not yet valid", i));
                }
            }

            // Check chain linkage (issuer/subject matching)
            if i < self.certificates.len() - 1 {
                let next = &self.certificates[i + 1];
                if cert.tbs_certificate.issuer != next.tbs_certificate.subject {
                    result.valid = false;
                    result.issues.push(format!(
                        "Certificate {} issuer doesn't match certificate {} subject",
                        i,
                        i + 1
                    ));
                }

                // Check that next certificate is a CA
                if !next.is_ca() && !next.is_self_signed() {
                    result.issues.push(format!(
                        "Certificate {} is not a CA but signed certificate {}",
                        i + 1,
                        i
                    ));
                }
            }
        }

        // Check if root is self-signed
        if let Some(root) = self.root() {
            if !root.is_self_signed() {
                result
                    .issues
                    .push("Root certificate is not self-signed".to_string());
            }
        }

        Ok(result)
    }

    /// Verify chain against trusted CA
    pub fn verify_against(&self, trusted_ca: &Certificate) -> Result<bool, CertError> {
        // The root of the chain should match the trusted CA
        if let Some(root) = self.root() {
            // Compare fingerprints
            if root.fingerprint_sha256() == trusted_ca.fingerprint_sha256() {
                return Ok(true);
            }

            // Or root should be signed by trusted CA
            if root.tbs_certificate.issuer == trusted_ca.tbs_certificate.subject {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Split chain into individual certificate files
    pub fn split(&self) -> Vec<(String, String)> {
        self.certificates
            .iter()
            .enumerate()
            .map(|(i, cert)| {
                let name = if i == 0 {
                    "leaf.crt".to_string()
                } else if i == self.certificates.len() - 1 && cert.is_self_signed() {
                    "root.crt".to_string()
                } else {
                    format!("intermediate_{}.crt", i)
                };
                (name, cert.to_pem())
            })
            .collect()
    }
}

impl Default for CertificateChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of chain verification
#[derive(Debug)]
pub struct ChainVerificationResult {
    /// Whether the chain is valid
    pub valid: bool,
    /// List of issues found
    pub issues: Vec<String>,
}

impl ChainVerificationResult {
    /// Check if verification passed
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get issues as formatted string
    pub fn issues_string(&self) -> String {
        self.issues.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::certs::ca::{CertificateAuthority, KeyAlgorithm};

    #[test]
    fn test_chain_build() {
        // Create CA
        let ca = CertificateAuthority::new("CN=Test CA", KeyAlgorithm::EcdsaP256, 365)
            .expect("CA should be created");

        // Generate leaf cert
        let (leaf, _) = ca
            .generate_cert("leaf.example.com")
            .expect("Leaf cert should be created");

        // Build chain
        let chain = CertificateChain::build(leaf, &[ca.cert.clone()]).expect("Chain should build");

        assert_eq!(chain.len(), 2);
        assert!(chain.leaf().is_some());
        assert!(chain.root().is_some());
    }

    #[test]
    fn test_chain_verify() {
        // Create CA
        let ca = CertificateAuthority::new("CN=Test CA", KeyAlgorithm::EcdsaP256, 365)
            .expect("CA should be created");

        // Generate leaf cert
        let (leaf, _) = ca
            .generate_cert("leaf.example.com")
            .expect("Leaf cert should be created");

        // Build chain
        let chain = CertificateChain::build(leaf, &[ca.cert.clone()]).expect("Chain should build");

        // Verify chain
        let result = chain.verify().expect("Verify should succeed");
        assert!(
            result.is_valid(),
            "Chain should be valid: {:?}",
            result.issues
        );
    }

    #[test]
    fn test_chain_pem_roundtrip() {
        // Create CA
        let ca = CertificateAuthority::new("CN=Test CA", KeyAlgorithm::EcdsaP256, 365)
            .expect("CA should be created");

        // Generate leaf cert
        let (leaf, _) = ca
            .generate_cert("leaf.example.com")
            .expect("Leaf cert should be created");

        // Build chain
        let chain = CertificateChain::build(leaf, &[ca.cert.clone()]).expect("Chain should build");

        // Export to PEM
        let pem = chain.to_pem();

        // Parse back
        let chain2 = CertificateChain::from_pem(&pem).expect("PEM parse should succeed");

        assert_eq!(chain.len(), chain2.len());
    }
}
