//! CTF Challenge Playbooks
//!
//! Playbooks for CTF challenges: web exploitation, crypto analysis.

use crate::playbooks::types::*;
use crate::scripts::FindingSeverity;

/// CTF Web Challenge Workflow
pub fn ctf_web_challenge() -> Playbook {
    Playbook::new("ctf-web-challenge", "CTF Web Challenge Workflow")
        .with_description("Systematic approach to solving web-based CTF challenges")
        .with_objective("Find the flag through web vulnerability exploitation")
        .for_target(TargetType::WebApp)
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Low)
        .with_duration("15-60 minutes")
        .with_tag("ctf")
        .with_tag("web")
        .with_tag("challenge")
        .add_precondition(PreCondition::new("CTF challenge URL accessible"))
        // Initial Recon
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Page Analysis")
                .with_description("Analyze page source and headers")
                .with_command("rb web asset get {{ target }}")
                .with_manual("View source, check comments, inspect headers")
                .with_success("Initial reconnaissance complete")
                .collects(EvidenceType::SystemInfo),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Directory Bruteforce")
                .with_description("Find hidden paths and files")
                .with_command("rb web fuzz {{ target }} --wordlist common")
                .with_success("Hidden paths discovered")
                .parallel(1)
                .collects(EvidenceType::SystemInfo),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "robots.txt Check")
                .with_description("Check for robots.txt hints")
                .with_command("rb web asset get {{ target }}/robots.txt")
                .with_success("robots.txt analyzed")
                .parallel(1),
        )
        // Vulnerability Testing
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Input Testing")
                .with_description("Test inputs for injection vulnerabilities")
                .with_manual("Test SQLi, XSS, SSTI, command injection")
                .with_success("Vulnerability identified")
                .depends(1)
                .collects(EvidenceType::Vulnerability),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Collection, "Flag Extraction")
                .with_description("Extract flag from vulnerability")
                .with_manual("Exploit identified vulnerability to get flag")
                .with_success("Flag captured!")
                .depends(4)
                .collects(EvidenceType::FileArtifact),
        )
        .add_evidence(
            ExpectedEvidence::new("CTF Flag")
                .at("Challenge output")
                .with_indicator("flag{...} or CTF{...} format")
                .severity(FindingSeverity::Info),
        )
}

/// CTF Crypto Challenge Workflow
pub fn ctf_crypto_challenge() -> Playbook {
    Playbook::new("ctf-crypto-challenge", "CTF Crypto Challenge Workflow")
        .with_description("Systematic approach to solving cryptography CTF challenges")
        .with_objective("Decrypt/decode the flag through cryptanalysis")
        .for_target(TargetType::Domain) // Generic target
        .for_os(TargetOS::Any)
        .with_risk(RiskLevel::Passive)
        .with_duration("15-120 minutes")
        .with_tag("ctf")
        .with_tag("crypto")
        .with_tag("challenge")
        .add_precondition(PreCondition::new("Ciphertext or encrypted data available"))
        // Identification Phase
        .add_step(
            PlaybookStep::new(1, PlaybookPhase::Recon, "Encoding Detection")
                .with_description("Identify encoding type")
                .with_command("rb crypto analyze auto {{ ciphertext }}")
                .with_success("Encoding identified")
                .collects(EvidenceType::SystemInfo),
        )
        .add_step(
            PlaybookStep::new(2, PlaybookPhase::Recon, "Cipher Identification")
                .with_description("Identify cipher type through analysis")
                .with_command("rb crypto analyze frequency {{ ciphertext }}")
                .with_success("Cipher type determined")
                .collects(EvidenceType::SystemInfo),
        )
        .add_step(
            PlaybookStep::new(3, PlaybookPhase::Recon, "Entropy Analysis")
                .with_description("Analyze randomness to identify encryption type")
                .with_command("rb crypto analyze entropy {{ ciphertext }}")
                .with_success("Encryption strength assessed")
                .collects(EvidenceType::SystemInfo),
        )
        // Decryption Phase
        .add_step(
            PlaybookStep::new(4, PlaybookPhase::Execution, "Classical Cipher Crack")
                .with_description("Attempt classical cipher decryption")
                .with_command("rb crypto cipher caesar {{ ciphertext }} --crack")
                .with_manual("Try ROT13, Vigenere, substitution ciphers")
                .with_success("Classical cipher broken")
                .depends(2)
                .collects(EvidenceType::CommandOutput),
        )
        .add_step(
            PlaybookStep::new(5, PlaybookPhase::Execution, "Decode Chain")
                .with_description("Apply detected encoding chain")
                .with_command("rb crypto recipe '{{ ciphertext }}' 'base64_decode | hex_decode'")
                .with_success("Decoding successful")
                .depends(1)
                .collects(EvidenceType::FileArtifact),
        )
        .add_evidence(
            ExpectedEvidence::new("Decrypted flag")
                .at("Decoded output")
                .with_indicator("Plaintext flag format")
                .severity(FindingSeverity::Info),
        )
}
