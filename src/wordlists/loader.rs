/// Wordlist Loader
///
/// Simple file loader for wordlists.
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct Loader;

impl Loader {
    /// Open a wordlist file for reading
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Box<dyn BufRead>> {
        let file = File::open(path)?;
        Ok(Box::new(BufReader::new(file)))
    }

    /// Load all lines from a wordlist file
    pub fn load_lines<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<String>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        reader.lines().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader() {
        // Test would require a test file
    }
}
