/// Wordlist Management System
///
/// Provides hybrid wordlist support:
/// - Embedded wordlists (~7KB compiled into binary)
/// - Cached wordlists in .redblue/wordlists/
/// - External wordlist file support
/// - Downloadable wordlists from remote sources
///
/// Credits:
/// - SecLists by Daniel Miessler (MIT License)
///   https://github.com/danielmiessler/SecLists
/// - Assetnote Wordlists (MIT License)
///   https://wordlists.assetnote.io/
/// - RockYou wordlist (public domain breach data)
pub mod downloader;
pub mod embedded;
pub mod loader;
pub mod manager;

pub use downloader::{get_wordlist_sources, Downloader, WordlistCategory, WordlistSource};
pub use embedded::{get_embedded, is_embedded, list_embedded};
pub use loader::Loader;
pub use manager::{WordlistInfo, WordlistManager};
