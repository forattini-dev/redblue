// Import the redblue library
use redblue::modules::network::scanner::{AdvancedScanner, ScanType, TimingTemplate};
use redblue::protocols::raw::PortState;

/// Test timing template configurations
mod timing_templates {
    use super::*;

    #[test]
    fn test_paranoid_timing() {
        let tmpl = TimingTemplate::Paranoid;
        assert_eq!(
            tmpl.timeout_ms(),
            300000,
            "Paranoid should have 5 minute timeout"
        );
        assert_eq!(
            tmpl.delay_ms(),
            300000,
            "Paranoid should have 5 minute delay"
        );
        assert_eq!(tmpl.parallelism(), 1, "Paranoid should use 1 thread");
        assert_eq!(tmpl.retries(), 10, "Paranoid should have max retries");
    }

    #[test]
    fn test_sneaky_timing() {
        let tmpl = TimingTemplate::Sneaky;
        assert_eq!(
            tmpl.timeout_ms(),
            15000,
            "Sneaky should have 15 second timeout"
        );
        assert_eq!(tmpl.delay_ms(), 15000, "Sneaky should have 15 second delay");
        assert_eq!(tmpl.parallelism(), 1, "Sneaky should use 1 thread");
    }

    #[test]
    fn test_polite_timing() {
        let tmpl = TimingTemplate::Polite;
        assert_eq!(
            tmpl.timeout_ms(),
            2000,
            "Polite should have 2 second timeout"
        );
        assert_eq!(tmpl.delay_ms(), 400, "Polite should have 400ms delay");
        assert_eq!(tmpl.parallelism(), 10, "Polite should use 10 threads");
    }

    #[test]
    fn test_normal_timing() {
        let tmpl = TimingTemplate::Normal;
        assert_eq!(
            tmpl.timeout_ms(),
            1000,
            "Normal should have 1 second timeout"
        );
        assert_eq!(tmpl.delay_ms(), 0, "Normal should have no delay");
        assert_eq!(tmpl.parallelism(), 100, "Normal should use 100 threads");
    }

    #[test]
    fn test_aggressive_timing() {
        let tmpl = TimingTemplate::Aggressive;
        assert_eq!(
            tmpl.timeout_ms(),
            500,
            "Aggressive should have 500ms timeout"
        );
        assert_eq!(tmpl.delay_ms(), 0, "Aggressive should have no delay");
        assert_eq!(tmpl.parallelism(), 500, "Aggressive should use 500 threads");
    }

    #[test]
    fn test_insane_timing() {
        let tmpl = TimingTemplate::Insane;
        assert_eq!(tmpl.timeout_ms(), 250, "Insane should have 250ms timeout");
        assert_eq!(tmpl.delay_ms(), 0, "Insane should have no delay");
        assert_eq!(tmpl.parallelism(), 1000, "Insane should use 1000 threads");
    }

    #[test]
    fn test_timing_from_str() {
        assert_eq!(
            TimingTemplate::from_str("T0"),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(
            TimingTemplate::from_str("t0"),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(
            TimingTemplate::from_str("paranoid"),
            Some(TimingTemplate::Paranoid)
        );

        assert_eq!(TimingTemplate::from_str("T1"), Some(TimingTemplate::Sneaky));
        assert_eq!(
            TimingTemplate::from_str("sneaky"),
            Some(TimingTemplate::Sneaky)
        );

        assert_eq!(TimingTemplate::from_str("T2"), Some(TimingTemplate::Polite));
        assert_eq!(
            TimingTemplate::from_str("polite"),
            Some(TimingTemplate::Polite)
        );

        assert_eq!(TimingTemplate::from_str("T3"), Some(TimingTemplate::Normal));
        assert_eq!(
            TimingTemplate::from_str("normal"),
            Some(TimingTemplate::Normal)
        );

        assert_eq!(
            TimingTemplate::from_str("T4"),
            Some(TimingTemplate::Aggressive)
        );
        assert_eq!(
            TimingTemplate::from_str("aggressive"),
            Some(TimingTemplate::Aggressive)
        );

        assert_eq!(TimingTemplate::from_str("T5"), Some(TimingTemplate::Insane));
        assert_eq!(
            TimingTemplate::from_str("insane"),
            Some(TimingTemplate::Insane)
        );

        assert_eq!(TimingTemplate::from_str("invalid"), None);
        assert_eq!(TimingTemplate::from_str("T6"), None);
    }

    #[test]
    fn test_timing_descriptions() {
        assert!(TimingTemplate::Paranoid.description().contains("IDS"));
        assert!(TimingTemplate::Sneaky.description().contains("slow"));
        assert!(TimingTemplate::Polite.description().contains("Reduced"));
        assert!(TimingTemplate::Normal.description().contains("Default"));
        assert!(TimingTemplate::Aggressive.description().contains("Fast"));
        assert!(TimingTemplate::Insane.description().contains("Maximum"));
    }
}

/// Test port state classification
mod port_states {
    use super::*;

    #[test]
    fn test_port_state_display() {
        assert_eq!(format!("{}", PortState::Open), "open");
        assert_eq!(format!("{}", PortState::Closed), "closed");
        assert_eq!(format!("{}", PortState::Filtered), "filtered");
        assert_eq!(format!("{}", PortState::Unfiltered), "unfiltered");
        assert_eq!(format!("{}", PortState::OpenFiltered), "open|filtered");
        assert_eq!(format!("{}", PortState::ClosedFiltered), "closed|filtered");
    }

    #[test]
    fn test_port_state_equality() {
        assert_eq!(PortState::Open, PortState::Open);
        assert_ne!(PortState::Open, PortState::Closed);
        assert_ne!(PortState::Filtered, PortState::OpenFiltered);
    }
}

/// Test scan type enum
mod scan_types {
    use super::*;

    #[test]
    fn test_scan_type_display() {
        // Display format uses lowercase
        assert_eq!(format!("{}", ScanType::Syn), "syn");
        assert_eq!(format!("{}", ScanType::Udp), "udp");
        assert_eq!(format!("{}", ScanType::Fin), "fin");
        assert_eq!(format!("{}", ScanType::Null), "null");
        assert_eq!(format!("{}", ScanType::Xmas), "xmas");
        assert_eq!(format!("{}", ScanType::Ack), "ack");
    }

    #[test]
    fn test_scan_type_equality() {
        assert_eq!(ScanType::Syn, ScanType::Syn);
        assert_ne!(ScanType::Syn, ScanType::Fin);
        assert_ne!(ScanType::Null, ScanType::Xmas);
    }
}

/// Test advanced scanner builder
mod scanner_builder {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_scanner_with_timing() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let scanner = AdvancedScanner::new(target).with_timing(TimingTemplate::Aggressive);

        // Scanner should apply timing template settings
        // The internal state verification would need accessor methods
        // For now, we verify the builder pattern works without panic
    }

    #[test]
    fn test_scanner_with_scan_type() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();

        // Test each scan type can be set
        let _ = AdvancedScanner::new(target.clone()).with_scan_type(ScanType::Syn);
        let _ = AdvancedScanner::new(target.clone()).with_scan_type(ScanType::Udp);
        let _ = AdvancedScanner::new(target.clone()).with_scan_type(ScanType::Fin);
        let _ = AdvancedScanner::new(target.clone()).with_scan_type(ScanType::Null);
        let _ = AdvancedScanner::new(target.clone()).with_scan_type(ScanType::Xmas);
    }

    #[test]
    fn test_scanner_with_threads_and_timeout() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let scanner = AdvancedScanner::new(target)
            .with_threads(500)
            .with_timeout(2000);

        // Builder pattern should work without panic
    }

    #[test]
    fn test_scanner_full_configuration() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let scanner = AdvancedScanner::new(target)
            .with_scan_type(ScanType::Syn)
            .with_threads(200)
            .with_timeout(1000)
            .with_timing(TimingTemplate::Normal);

        // Full configuration should work without panic
    }
}

/// Test common UDP ports list
mod common_ports {
    use super::*;

    #[test]
    fn test_common_udp_ports_exist() {
        let ports = AdvancedScanner::get_common_udp_ports();

        // Should include essential UDP services
        assert!(ports.contains(&53), "Should include DNS (53)");
        assert!(ports.contains(&67), "Should include DHCP (67)");
        assert!(ports.contains(&68), "Should include DHCP client (68)");
        assert!(ports.contains(&69), "Should include TFTP (69)");
        assert!(ports.contains(&123), "Should include NTP (123)");
        assert!(ports.contains(&161), "Should include SNMP (161)");
        assert!(ports.contains(&500), "Should include IKE (500)");
        assert!(ports.contains(&514), "Should include Syslog (514)");
    }

    #[test]
    fn test_common_udp_ports_count() {
        let ports = AdvancedScanner::get_common_udp_ports();
        assert!(
            ports.len() >= 20,
            "Should have at least 20 common UDP ports"
        );
    }
}
