#[cfg(test)]
mod tests {
    use crate::modules::auth::iterator::CredentialIterator;

    #[test]
    fn test_iterator() {
        let users = vec!["admin".to_string(), "user".to_string()];
        let passwords = vec!["123".to_string(), "abc".to_string()];
        
        let iter = CredentialIterator::new(users, passwords);
        let pairs: Vec<_> = iter.collect();
        
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0], ("admin".to_string(), "123".to_string()));
    }
}
