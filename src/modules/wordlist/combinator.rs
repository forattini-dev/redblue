pub struct Combinator;

impl Combinator {
    pub fn combine(left: &[String], right: &[String]) -> Vec<String> {
        let mut results = Vec::with_capacity(left.len() * right.len());
        for l in left {
            for r in right {
                results.push(format!("{}{}", l, r));
            }
        }
        results
    }
    
    // Lazy iterator version would be better for memory, but requires storing references or cloning.
    // Given the constraints and typical usage (one list might be small), vector is a start.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine() {
        let left = vec!["a".to_string(), "b".to_string()];
        let right = vec!["1".to_string(), "2".to_string()];
        let combined = Combinator::combine(&left, &right);
        
        assert_eq!(combined.len(), 4);
        assert!(combined.contains(&"a1".to_string()));
        assert!(combined.contains(&"a2".to_string()));
        assert!(combined.contains(&"b1".to_string()));
        assert!(combined.contains(&"b2".to_string()));
    }
}
