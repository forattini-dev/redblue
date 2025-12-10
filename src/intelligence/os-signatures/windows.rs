/// Windows OS Signatures
///
/// TCP/IP fingerprints for Microsoft Windows versions.

use super::types::*;

/// Add all Windows signatures to the database
pub fn signatures() -> Vec<OsSignature> {
    let mut sigs = Vec::with_capacity(100);

    // === WINDOWS SERVER ===
    sigs.extend(server_signatures());

    // === WINDOWS DESKTOP ===
    sigs.extend(desktop_signatures());

    // === LEGACY WINDOWS ===
    sigs.extend(legacy_signatures());

    // === WINDOWS EMBEDDED / IoT ===
    sigs.extend(embedded_signatures());

    sigs
}

fn server_signatures() -> Vec<OsSignature> {
    vec![
        // Windows Server 2022
        SignatureBuilder::new(2000, "Windows Server 2022")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2022")
            .cpe("cpe:/o:microsoft:windows_server_2022")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.92)
            .build(),

        // Windows Server 2019
        SignatureBuilder::new(2001, "Windows Server 2019")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2019")
            .cpe("cpe:/o:microsoft:windows_server_2019")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.92)
            .build(),

        // Windows Server 2016
        SignatureBuilder::new(2002, "Windows Server 2016")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2016")
            .cpe("cpe:/o:microsoft:windows_server_2016")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.90)
            .build(),

        // Windows Server 2012 R2
        SignatureBuilder::new(2003, "Windows Server 2012 R2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2012 R2")
            .cpe("cpe:/o:microsoft:windows_server_2012:r2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Windows Server 2012
        SignatureBuilder::new(2004, "Windows Server 2012")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2012")
            .cpe("cpe:/o:microsoft:windows_server_2012")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Windows Server 2008 R2
        SignatureBuilder::new(2005, "Windows Server 2008 R2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2008 R2")
            .cpe("cpe:/o:microsoft:windows_server_2008:r2")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Windows Server 2008
        SignatureBuilder::new(2006, "Windows Server 2008")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2008")
            .cpe("cpe:/o:microsoft:windows_server_2008")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.82)
            .build(),

        // Windows Server 2003
        SignatureBuilder::new(2007, "Windows Server 2003")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2003")
            .cpe("cpe:/o:microsoft:windows_server_2003")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.80)
            .build(),

        // Windows Server Core 2022
        SignatureBuilder::new(2010, "Windows Server 2022 Core")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2022")
            .cpe("cpe:/o:microsoft:windows_server_2022")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.90)
            .build(),

        // Windows Server Hyper-V 2019
        SignatureBuilder::new(2020, "Windows Server 2019 Hyper-V")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2019")
            .device(DeviceType::VirtualMachine)
            .cpe("cpe:/o:microsoft:windows_server_2019")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.88)
            .build(),
    ]
}

fn desktop_signatures() -> Vec<OsSignature> {
    vec![
        // Windows 11 (23H2)
        SignatureBuilder::new(2100, "Windows 11 23H2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("11 23H2")
            .cpe("cpe:/o:microsoft:windows_11:23h2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.95)
            .build(),

        // Windows 11 (22H2)
        SignatureBuilder::new(2101, "Windows 11 22H2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("11 22H2")
            .cpe("cpe:/o:microsoft:windows_11:22h2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.95)
            .build(),

        // Windows 11 (21H2)
        SignatureBuilder::new(2102, "Windows 11 21H2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("11 21H2")
            .cpe("cpe:/o:microsoft:windows_11:21h2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.93)
            .build(),

        // Windows 10 (22H2)
        SignatureBuilder::new(2110, "Windows 10 22H2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 22H2")
            .cpe("cpe:/o:microsoft:windows_10:22h2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.95)
            .build(),

        // Windows 10 (21H2)
        SignatureBuilder::new(2111, "Windows 10 21H2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 21H2")
            .cpe("cpe:/o:microsoft:windows_10:21h2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.93)
            .build(),

        // Windows 10 (20H2)
        SignatureBuilder::new(2112, "Windows 10 20H2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 20H2")
            .cpe("cpe:/o:microsoft:windows_10:20h2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.90)
            .build(),

        // Windows 10 (1809/LTSC 2019)
        SignatureBuilder::new(2113, "Windows 10 LTSC 2019")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 LTSC 2019")
            .cpe("cpe:/o:microsoft:windows_10:1809")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Windows 10 (1607/LTSC 2016)
        SignatureBuilder::new(2114, "Windows 10 LTSC 2016")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 LTSC 2016")
            .cpe("cpe:/o:microsoft:windows_10:1607")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Windows 8.1
        SignatureBuilder::new(2120, "Windows 8.1")
            .vendor("Microsoft")
            .family("Windows")
            .generation("8.1")
            .cpe("cpe:/o:microsoft:windows_8.1")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Windows 8
        SignatureBuilder::new(2121, "Windows 8")
            .vendor("Microsoft")
            .family("Windows")
            .generation("8")
            .cpe("cpe:/o:microsoft:windows_8")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.82)
            .build(),

        // Windows 7 SP1
        SignatureBuilder::new(2130, "Windows 7 SP1")
            .vendor("Microsoft")
            .family("Windows")
            .generation("7 SP1")
            .cpe("cpe:/o:microsoft:windows_7:-:sp1")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Windows 7
        SignatureBuilder::new(2131, "Windows 7")
            .vendor("Microsoft")
            .family("Windows")
            .generation("7")
            .cpe("cpe:/o:microsoft:windows_7")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.82)
            .build(),
    ]
}

fn legacy_signatures() -> Vec<OsSignature> {
    vec![
        // Windows Vista SP2
        SignatureBuilder::new(2200, "Windows Vista SP2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Vista SP2")
            .cpe("cpe:/o:microsoft:windows_vista:-:sp2")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.80)
            .build(),

        // Windows Vista
        SignatureBuilder::new(2201, "Windows Vista")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Vista")
            .cpe("cpe:/o:microsoft:windows_vista")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.78)
            .build(),

        // Windows XP SP3
        SignatureBuilder::new(2210, "Windows XP SP3")
            .vendor("Microsoft")
            .family("Windows")
            .generation("XP SP3")
            .cpe("cpe:/o:microsoft:windows_xp:-:sp3")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.82)
            .build(),

        // Windows XP SP2
        SignatureBuilder::new(2211, "Windows XP SP2")
            .vendor("Microsoft")
            .family("Windows")
            .generation("XP SP2")
            .cpe("cpe:/o:microsoft:windows_xp:-:sp2")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.80)
            .build(),

        // Windows XP
        SignatureBuilder::new(2212, "Windows XP")
            .vendor("Microsoft")
            .family("Windows")
            .generation("XP")
            .cpe("cpe:/o:microsoft:windows_xp")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.78)
            .build(),

        // Windows 2000
        SignatureBuilder::new(2220, "Windows 2000")
            .vendor("Microsoft")
            .family("Windows")
            .generation("2000")
            .cpe("cpe:/o:microsoft:windows_2000")
            .ttl_initial(128)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.75)
            .build(),

        // Windows NT 4.0
        SignatureBuilder::new(2230, "Windows NT 4.0")
            .vendor("Microsoft")
            .family("Windows")
            .generation("NT 4.0")
            .cpe("cpe:/o:microsoft:windows_nt:4.0")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(0)
            .options("M")
            .df(false)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.70)
            .build(),

        // Windows 98
        SignatureBuilder::new(2240, "Windows 98")
            .vendor("Microsoft")
            .family("Windows")
            .generation("98")
            .cpe("cpe:/o:microsoft:windows_98")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(0)
            .options("M")
            .df(false)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.65)
            .build(),

        // Windows 95
        SignatureBuilder::new(2250, "Windows 95")
            .vendor("Microsoft")
            .family("Windows")
            .generation("95")
            .cpe("cpe:/o:microsoft:windows_95")
            .ttl_initial(32)
            .window_exact(8192)
            .mss_exact(536)
            .ws(0)
            .options("M")
            .df(false)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.60)
            .build(),
    ]
}

fn embedded_signatures() -> Vec<OsSignature> {
    vec![
        // Windows IoT Enterprise
        SignatureBuilder::new(2300, "Windows 10 IoT Enterprise")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 IoT")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:microsoft:windows_10_iot_enterprise")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Windows IoT Core
        SignatureBuilder::new(2301, "Windows 10 IoT Core")
            .vendor("Microsoft")
            .family("Windows")
            .generation("10 IoT Core")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:microsoft:windows_10_iot_core")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Windows Embedded POSReady 7
        SignatureBuilder::new(2310, "Windows Embedded POSReady 7")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Embedded POSReady 7")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:microsoft:windows_embedded_posready_7")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.82)
            .build(),

        // Windows Embedded Standard 7
        SignatureBuilder::new(2311, "Windows Embedded Standard 7")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Embedded Standard 7")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:microsoft:windows_embedded_standard_7")
            .ttl_initial(128)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(2)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.80)
            .build(),

        // Windows CE 6.0
        SignatureBuilder::new(2320, "Windows CE 6.0")
            .vendor("Microsoft")
            .family("Windows")
            .generation("CE 6.0")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:microsoft:windows_ce:6.0")
            .ttl_initial(128)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.75)
            .build(),

        // Windows Mobile 6.5
        SignatureBuilder::new(2330, "Windows Mobile 6.5")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Mobile 6.5")
            .device(DeviceType::Phone)
            .cpe("cpe:/o:microsoft:windows_mobile:6.5")
            .ttl_initial(128)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.70)
            .build(),

        // Windows Phone 8.1
        SignatureBuilder::new(2340, "Windows Phone 8.1")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Phone 8.1")
            .device(DeviceType::Phone)
            .cpe("cpe:/o:microsoft:windows_phone:8.1")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.78)
            .build(),

        // Xbox One
        SignatureBuilder::new(2350, "Xbox One")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Xbox One")
            .device(DeviceType::GameConsole)
            .cpe("cpe:/o:microsoft:xbox_one")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Xbox Series X/S
        SignatureBuilder::new(2351, "Xbox Series X/S")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Xbox Series")
            .device(DeviceType::GameConsole)
            .cpe("cpe:/o:microsoft:xbox_series")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Azure Stack HCI
        SignatureBuilder::new(2360, "Azure Stack HCI")
            .vendor("Microsoft")
            .family("Windows")
            .generation("Azure Stack HCI")
            .device(DeviceType::VirtualMachine)
            .cpe("cpe:/o:microsoft:azure_stack_hci")
            .ttl_initial(128)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MNWST")
            .df(true)
            .ip_id(IpIdPattern::GlobalIncrement)
            .ecn(false)
            .confidence(0.90)
            .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_signatures_count() {
        let sigs = signatures();
        assert!(sigs.len() >= 30, "Expected at least 30 Windows signatures, got {}", sigs.len());
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
    fn test_ttl_128_windows() {
        let sigs = signatures();
        // Most Windows should have TTL of 128
        let ttl_128_count = sigs.iter().filter(|s| {
            matches!(s.ttl, TtlMatch::Initial(128) | TtlMatch::Exact(128))
        }).count();

        assert!(ttl_128_count > sigs.len() * 90 / 100,
            "Most Windows signatures should have TTL 128");
    }
}
