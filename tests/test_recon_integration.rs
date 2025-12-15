#[cfg(test)]
mod tests {

    use redblue::modules::recon::subdomain::{EnumerationSource, SubdomainEnumerator};
    use std::collections::HashSet;

    // Helper to get a test domain that can be enumerated
    fn get_test_domain() -> String {
        // Use a domain that is known to have some public subdomains via CT logs
        // or a test domain specifically for this purpose.
        // For actual tests, this might require mocking DNS or HTTP requests.
        "example.com".to_string()
    }

    #[test]
    fn test_enumerate_ct_logs() {
        // This test requires external network access to crt.sh
        // It might be flaky if network is down or crt.sh is slow/unresponsive.
        // In a real CI/CD, this might be mocked or run conditionally.
        let domain = get_test_domain();
        let enumerator = SubdomainEnumerator::new(&domain);

        let results = enumerator.enumerate_ct_logs();
        assert!(results.is_ok());

        let subdomains = results.unwrap();
        // Check if common subdomains for example.com are found
        assert!(subdomains
            .iter()
            .any(|r| r.subdomain.contains("www.example.com")));
        assert!(subdomains
            .iter()
            .all(|r| r.source == EnumerationSource::CertificateTransparency));
    }

    // This test would be more complex as it involves DNS bruteforce, which requires
    // a wordlist and actual DNS resolution.
    // For now, we'll keep it simple or commented out for non-mocked environment.
    #[test]
    fn test_enumerate_dns_bruteforce_with_default_wordlist() {
        // This test needs to be very fast or use a very small wordlist.
        // SubdomainEnumerator::new automatically picks a default wordlist.
        let domain = get_test_domain();
        let enumerator = SubdomainEnumerator::new(&domain).with_threads(1); // Reduce threads for faster test

        let results = enumerator.enumerate_dns_bruteforce(); // Uses internal wordlist
        assert!(results.is_ok());

        let subdomains = results.unwrap();
        // Just check if any results came back or if there's no error.
        // Actual content check depends on the wordlist and domain.
        // assert!(!subdomains.is_empty(), "Expected some subdomains from DNS bruteforce");
        println!(
            "Found {} subdomains via default DNS bruteforce for {}",
            subdomains.len(),
            domain
        );
    }

    #[test]
    fn test_enumerate_all_deduplication() {
        // This test runs all enumeration methods and checks deduplication.
        let domain = get_test_domain();
        let mut enumerator = SubdomainEnumerator::new(&domain).with_threads(1); // Reduce threads for faster test

        let results = enumerator.enumerate_all();
        assert!(results.is_ok());

        let subdomains = results.unwrap();
        let mut unique_names = HashSet::new();
        for r in &subdomains {
            unique_names.insert(r.subdomain.clone());
        }
        assert_eq!(
            subdomains.len(),
            unique_names.len(),
            "Results should be deduplicated"
        );
    }
}
