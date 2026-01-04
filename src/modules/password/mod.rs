pub mod bcrypt;
pub mod crack;
/// Password Cracking Module
///
/// Zero-dependency password hash cracking implementation inspired by
/// hashcat and John the Ripper. All cryptographic primitives use our
/// own implementations from src/crypto/.
///
/// Capabilities:
/// - 20+ hash format detection and cracking
/// - Dictionary attack with rule mutations
/// - Mask/brute-force attack with pattern generation
/// - Hybrid modes (dict+mask, mask+dict)
/// - Rule engine with 30+ mutation operations
/// - Session management for resume capability
///
/// Example usage:
/// ```ignore
/// use redblue::modules::password::{Cracker, HashFormat, AttackMode};
///
/// let cracker = Cracker::new()
///     .format(HashFormat::MD5)
///     .mode(AttackMode::Dictionary)
///     .wordlist("/path/to/wordlist.txt")
///     .rules(&["l", "u", "c", "$1", "^!"]);
///
/// for hash in hashes {
///     if let Some(password) = cracker.crack(&hash) {
///         println!("Cracked: {} -> {}", hash, password);
///     }
/// }
/// ```
pub mod formats;
pub mod rules;

pub use crack::{AttackMode, CrackResult, CrackSession, CrackStats, Cracker, MaskGenerator};
pub use formats::{detect_format, format_hash, parse_hash, verify_hash, HashFormat, HashInfo};
pub use rules::{apply_rules, Rule, RuleEngine};
