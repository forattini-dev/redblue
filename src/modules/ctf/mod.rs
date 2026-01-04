//! CTF Challenge Generation Module
//!
//! Generate CTF challenges from security scan findings, following the
//! juice-shop-ctf pattern. Supports multiple export formats.
//!
//! Features:
//! - Challenge generation from vulnerabilities
//! - HMAC-SHA1 flag generation
//! - Export to CTFd, FBCTF, RootTheBox
//! - Difficulty scoring based on severity

mod export;
mod flags;
mod generator;

pub use export::{CtfdExporter, ExportFormat, FbctfExporter, RtbExporter};
pub use flags::{FlagGenerator, FlagVerifier};
pub use generator::{Challenge, ChallengeCategory, ChallengeDifficulty, ChallengeGenerator};
