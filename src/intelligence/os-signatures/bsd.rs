/// BSD and Unix OS Signatures
///
/// TCP/IP fingerprints for FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and other Unix variants.
use super::types::*;

/// Add all BSD and Unix signatures to the database
pub fn signatures() -> Vec<OsSignature> {
    let mut sigs = Vec::with_capacity(80);

    // === FreeBSD ===
    sigs.extend(freebsd_signatures());

    // === OpenBSD ===
    sigs.extend(openbsd_signatures());

    // === NetBSD ===
    sigs.extend(netbsd_signatures());

    // === DragonFly BSD ===
    sigs.extend(dragonfly_signatures());

    // === Solaris / illumos ===
    sigs.extend(solaris_signatures());

    // === AIX / HP-UX ===
    sigs.extend(commercial_unix_signatures());

    sigs
}

fn freebsd_signatures() -> Vec<OsSignature> {
    vec![
        // FreeBSD 14.x
        SignatureBuilder::new(4000, "FreeBSD 14.x")
            .vendor("FreeBSD Project")
            .family("BSD")
            .generation("14")
            .cpe("cpe:/o:freebsd:freebsd:14")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),
        // FreeBSD 13.x
        SignatureBuilder::new(4001, "FreeBSD 13.x")
            .vendor("FreeBSD Project")
            .family("BSD")
            .generation("13")
            .cpe("cpe:/o:freebsd:freebsd:13")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),
        // FreeBSD 12.x
        SignatureBuilder::new(4002, "FreeBSD 12.x")
            .vendor("FreeBSD Project")
            .family("BSD")
            .generation("12")
            .cpe("cpe:/o:freebsd:freebsd:12")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // FreeBSD 11.x
        SignatureBuilder::new(4003, "FreeBSD 11.x")
            .vendor("FreeBSD Project")
            .family("BSD")
            .generation("11")
            .cpe("cpe:/o:freebsd:freebsd:11")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // FreeBSD 10.x
        SignatureBuilder::new(4004, "FreeBSD 10.x")
            .vendor("FreeBSD Project")
            .family("BSD")
            .generation("10")
            .cpe("cpe:/o:freebsd:freebsd:10")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.82)
            .build(),
        // FreeBSD 9.x
        SignatureBuilder::new(4005, "FreeBSD 9.x")
            .vendor("FreeBSD Project")
            .family("BSD")
            .generation("9")
            .cpe("cpe:/o:freebsd:freebsd:9")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(3)
            .options("MSWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.78)
            .build(),
        // pfSense (FreeBSD-based firewall)
        SignatureBuilder::new(4010, "pfSense")
            .vendor("Netgate")
            .family("BSD")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:netgate:pfsense")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // OPNsense (FreeBSD-based firewall)
        SignatureBuilder::new(4011, "OPNsense")
            .vendor("Deciso B.V.")
            .family("BSD")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:opnsense:opnsense")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // TrueNAS (FreeBSD-based NAS)
        SignatureBuilder::new(4020, "TrueNAS")
            .vendor("iXsystems")
            .family("BSD")
            .device(DeviceType::Storage)
            .cpe("cpe:/o:ixsystems:truenas")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),
        // FreeNAS (legacy TrueNAS)
        SignatureBuilder::new(4021, "FreeNAS")
            .vendor("iXsystems")
            .family("BSD")
            .device(DeviceType::Storage)
            .cpe("cpe:/o:ixsystems:freenas")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // PlayStation 5 (FreeBSD-based)
        SignatureBuilder::new(4030, "PlayStation 5")
            .vendor("Sony")
            .family("BSD")
            .device(DeviceType::GameConsole)
            .cpe("cpe:/o:sony:playstation_5_firmware")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),
        // PlayStation 4 (FreeBSD-based)
        SignatureBuilder::new(4031, "PlayStation 4")
            .vendor("Sony")
            .family("BSD")
            .device(DeviceType::GameConsole)
            .cpe("cpe:/o:sony:playstation_4_firmware")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // Nintendo Switch (FreeBSD-based)
        SignatureBuilder::new(4032, "Nintendo Switch")
            .vendor("Nintendo")
            .family("BSD")
            .device(DeviceType::GameConsole)
            .cpe("cpe:/o:nintendo:switch_firmware")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.82)
            .build(),
    ]
}

fn openbsd_signatures() -> Vec<OsSignature> {
    vec![
        // OpenBSD 7.x
        SignatureBuilder::new(4100, "OpenBSD 7.x")
            .vendor("OpenBSD Project")
            .family("BSD")
            .generation("7")
            .cpe("cpe:/o:openbsd:openbsd:7")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(6)
            .options("MNWST") // Different order from FreeBSD
            .df(true)
            .ip_id(IpIdPattern::Zero) // OpenBSD randomizes IP ID to 0
            .ecn(false)
            .confidence(0.95)
            .build(),
        // OpenBSD 7.4
        SignatureBuilder::new(4101, "OpenBSD 7.4")
            .vendor("OpenBSD Project")
            .family("BSD")
            .generation("7.4")
            .cpe("cpe:/o:openbsd:openbsd:7.4")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(6)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::Zero)
            .ecn(false)
            .confidence(0.93)
            .build(),
        // OpenBSD 7.3
        SignatureBuilder::new(4102, "OpenBSD 7.3")
            .vendor("OpenBSD Project")
            .family("BSD")
            .generation("7.3")
            .cpe("cpe:/o:openbsd:openbsd:7.3")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(6)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::Zero)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // OpenBSD 6.x
        SignatureBuilder::new(4103, "OpenBSD 6.x")
            .vendor("OpenBSD Project")
            .family("BSD")
            .generation("6")
            .cpe("cpe:/o:openbsd:openbsd:6")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(5)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::Zero)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // OpenBSD 5.x
        SignatureBuilder::new(4104, "OpenBSD 5.x")
            .vendor("OpenBSD Project")
            .family("BSD")
            .generation("5")
            .cpe("cpe:/o:openbsd:openbsd:5")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(4)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.82)
            .build(),
    ]
}

fn netbsd_signatures() -> Vec<OsSignature> {
    vec![
        // NetBSD 10.x
        SignatureBuilder::new(4200, "NetBSD 10.x")
            .vendor("NetBSD Foundation")
            .family("BSD")
            .generation("10")
            .cpe("cpe:/o:netbsd:netbsd:10")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),
        // NetBSD 9.x
        SignatureBuilder::new(4201, "NetBSD 9.x")
            .vendor("NetBSD Foundation")
            .family("BSD")
            .generation("9")
            .cpe("cpe:/o:netbsd:netbsd:9")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // NetBSD 8.x
        SignatureBuilder::new(4202, "NetBSD 8.x")
            .vendor("NetBSD Foundation")
            .family("BSD")
            .generation("8")
            .cpe("cpe:/o:netbsd:netbsd:8")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // NetBSD 7.x
        SignatureBuilder::new(4203, "NetBSD 7.x")
            .vendor("NetBSD Foundation")
            .family("BSD")
            .generation("7")
            .cpe("cpe:/o:netbsd:netbsd:7")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(3)
            .options("MSWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.80)
            .build(),
    ]
}

fn dragonfly_signatures() -> Vec<OsSignature> {
    vec![
        // DragonFly BSD 6.x
        SignatureBuilder::new(4300, "DragonFly BSD 6.x")
            .vendor("DragonFly BSD Project")
            .family("BSD")
            .generation("6")
            .cpe("cpe:/o:dragonflybsd:dragonflybsd:6")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),
        // DragonFly BSD 5.x
        SignatureBuilder::new(4301, "DragonFly BSD 5.x")
            .vendor("DragonFly BSD Project")
            .family("BSD")
            .generation("5")
            .cpe("cpe:/o:dragonflybsd:dragonflybsd:5")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // MidnightBSD 3.x
        SignatureBuilder::new(4310, "MidnightBSD 3.x")
            .vendor("MidnightBSD Project")
            .family("BSD")
            .generation("3")
            .cpe("cpe:/o:midnightbsd:midnightbsd:3")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.82)
            .build(),
        // GhostBSD
        SignatureBuilder::new(4320, "GhostBSD")
            .vendor("GhostBSD Project")
            .family("BSD")
            .cpe("cpe:/o:ghostbsd:ghostbsd")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.85)
            .build(),
        // HardenedBSD
        SignatureBuilder::new(4330, "HardenedBSD")
            .vendor("HardenedBSD Project")
            .family("BSD")
            .cpe("cpe:/o:hardenedbsd:hardenedbsd")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),
    ]
}

fn solaris_signatures() -> Vec<OsSignature> {
    vec![
        // Oracle Solaris 11.4
        SignatureBuilder::new(4400, "Oracle Solaris 11.4")
            .vendor("Oracle")
            .family("Solaris")
            .generation("11.4")
            .cpe("cpe:/o:oracle:solaris:11.4")
            .ttl_initial(255)
            .window_exact(49640)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Oracle Solaris 11.3
        SignatureBuilder::new(4401, "Oracle Solaris 11.3")
            .vendor("Oracle")
            .family("Solaris")
            .generation("11.3")
            .cpe("cpe:/o:oracle:solaris:11.3")
            .ttl_initial(255)
            .window_exact(49640)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // Oracle Solaris 10
        SignatureBuilder::new(4402, "Oracle Solaris 10")
            .vendor("Oracle")
            .family("Solaris")
            .generation("10")
            .cpe("cpe:/o:oracle:solaris:10")
            .ttl_initial(255)
            .window_exact(49232)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // illumos (OpenIndiana)
        SignatureBuilder::new(4410, "OpenIndiana")
            .vendor("illumos Project")
            .family("Solaris")
            .cpe("cpe:/o:openindiana:openindiana")
            .ttl_initial(255)
            .window_exact(49640)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // OmniOS
        SignatureBuilder::new(4411, "OmniOS")
            .vendor("OmniOS Community Edition")
            .family("Solaris")
            .cpe("cpe:/o:omnios:omnios")
            .ttl_initial(255)
            .window_exact(49640)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // SmartOS
        SignatureBuilder::new(4412, "SmartOS")
            .vendor("Joyent")
            .family("Solaris")
            .device(DeviceType::VirtualMachine)
            .cpe("cpe:/o:joyent:smartos")
            .ttl_initial(255)
            .window_exact(49640)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
    ]
}

fn commercial_unix_signatures() -> Vec<OsSignature> {
    vec![
        // IBM AIX 7.3
        SignatureBuilder::new(4500, "IBM AIX 7.3")
            .vendor("IBM")
            .family("AIX")
            .generation("7.3")
            .cpe("cpe:/o:ibm:aix:7.3")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // IBM AIX 7.2
        SignatureBuilder::new(4501, "IBM AIX 7.2")
            .vendor("IBM")
            .family("AIX")
            .generation("7.2")
            .cpe("cpe:/o:ibm:aix:7.2")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // IBM AIX 7.1
        SignatureBuilder::new(4502, "IBM AIX 7.1")
            .vendor("IBM")
            .family("AIX")
            .generation("7.1")
            .cpe("cpe:/o:ibm:aix:7.1")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // HP-UX 11.31
        SignatureBuilder::new(4510, "HP-UX 11.31")
            .vendor("Hewlett-Packard")
            .family("HP-UX")
            .generation("11.31")
            .cpe("cpe:/o:hp:hp-ux:11.31")
            .ttl_initial(64)
            .window_exact(32768)
            .mss_exact(1460)
            .ws(0)
            .options("MT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // HP-UX 11.23
        SignatureBuilder::new(4511, "HP-UX 11.23")
            .vendor("Hewlett-Packard")
            .family("HP-UX")
            .generation("11.23")
            .cpe("cpe:/o:hp:hp-ux:11.23")
            .ttl_initial(64)
            .window_exact(32768)
            .mss_exact(1460)
            .ws(0)
            .options("MT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // SCO UnixWare 7
        SignatureBuilder::new(4520, "SCO UnixWare 7")
            .vendor("SCO")
            .family("UnixWare")
            .generation("7")
            .cpe("cpe:/o:sco:unixware:7")
            .ttl_initial(64)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(0)
            .options("M")
            .df(false)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.75)
            .build(),
        // QNX Neutrino 7.x
        SignatureBuilder::new(4530, "QNX Neutrino 7.x")
            .vendor("BlackBerry QNX")
            .family("QNX")
            .generation("7")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:blackberry:qnx_neutrino:7")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // QNX Neutrino 6.x
        SignatureBuilder::new(4531, "QNX Neutrino 6.x")
            .vendor("BlackBerry QNX")
            .family("QNX")
            .generation("6")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:blackberry:qnx_neutrino:6")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(2)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.82)
            .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsd_signatures_count() {
        let sigs = signatures();
        assert!(
            sigs.len() >= 30,
            "Expected at least 30 BSD/Unix signatures, got {}",
            sigs.len()
        );
    }

    #[test]
    fn test_signature_ids_unique() {
        let sigs = signatures();
        let mut ids: Vec<u32> = sigs.iter().map(|s| s.id).collect();
        ids.sort();
        let unique_count = ids.len();
        ids.dedup();
        assert_eq!(unique_count, ids.len(), "Duplicate signature IDs found");
    }

    #[test]
    fn test_solaris_ttl_255() {
        let sigs = solaris_signatures();
        for sig in &sigs {
            match sig.ttl {
                TtlMatch::Initial(ttl) | TtlMatch::Exact(ttl) => {
                    assert_eq!(ttl, 255, "{} should have TTL 255", sig.name);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_openbsd_zero_ip_id() {
        let sigs = openbsd_signatures();
        // Modern OpenBSD uses zero IP ID for security
        let recent_openbsd: Vec<_> = sigs.iter().filter(|s| s.name.contains("7.")).collect();

        for sig in recent_openbsd {
            assert!(
                matches!(sig.ip_id, IpIdPattern::Zero),
                "{} should have Zero IP ID pattern",
                sig.name
            );
        }
    }
}
