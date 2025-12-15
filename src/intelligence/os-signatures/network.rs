/// Network Device OS Signatures
///
/// TCP/IP fingerprints for routers, switches, firewalls, load balancers,
/// and other network infrastructure devices.
use super::types::*;

/// Add all network device signatures to the database
pub fn signatures() -> Vec<OsSignature> {
    let mut sigs = Vec::with_capacity(100);

    // === CISCO ===
    sigs.extend(cisco_signatures());

    // === JUNIPER ===
    sigs.extend(juniper_signatures());

    // === FORTINET ===
    sigs.extend(fortinet_signatures());

    // === PALO ALTO ===
    sigs.extend(palo_alto_signatures());

    // === CHECK POINT ===
    sigs.extend(checkpoint_signatures());

    // === F5 ===
    sigs.extend(f5_signatures());

    // === ARISTA ===
    sigs.extend(arista_signatures());

    // === OTHER VENDORS ===
    sigs.extend(other_network_signatures());

    sigs
}

fn cisco_signatures() -> Vec<OsSignature> {
    vec![
        // Cisco IOS XE 17.x
        SignatureBuilder::new(5000, "Cisco IOS XE 17.x")
            .vendor("Cisco")
            .family("IOS")
            .generation("17")
            .device(DeviceType::Router)
            .cpe("cpe:/o:cisco:ios_xe:17")
            .ttl_initial(255)
            .window_exact(4128)
            .mss_exact(536)
            .ws(0)
            .options("M")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Cisco IOS XE 16.x
        SignatureBuilder::new(5001, "Cisco IOS XE 16.x")
            .vendor("Cisco")
            .family("IOS")
            .generation("16")
            .device(DeviceType::Router)
            .cpe("cpe:/o:cisco:ios_xe:16")
            .ttl_initial(255)
            .window_exact(4128)
            .mss_exact(536)
            .ws(0)
            .options("M")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // Cisco IOS 15.x
        SignatureBuilder::new(5002, "Cisco IOS 15.x")
            .vendor("Cisco")
            .family("IOS")
            .generation("15")
            .device(DeviceType::Router)
            .cpe("cpe:/o:cisco:ios:15")
            .ttl_initial(255)
            .window_exact(4128)
            .mss_exact(536)
            .ws(0)
            .options("M")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Cisco IOS 12.x
        SignatureBuilder::new(5003, "Cisco IOS 12.x")
            .vendor("Cisco")
            .family("IOS")
            .generation("12")
            .device(DeviceType::Router)
            .cpe("cpe:/o:cisco:ios:12")
            .ttl_initial(255)
            .window_exact(4128)
            .mss_exact(536)
            .ws(0)
            .options("M")
            .df(false)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.82)
            .build(),
        // Cisco NX-OS 10.x
        SignatureBuilder::new(5010, "Cisco NX-OS 10.x")
            .vendor("Cisco")
            .family("NX-OS")
            .generation("10")
            .device(DeviceType::Switch)
            .cpe("cpe:/o:cisco:nx-os:10")
            .ttl_initial(255)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Cisco NX-OS 9.x
        SignatureBuilder::new(5011, "Cisco NX-OS 9.x")
            .vendor("Cisco")
            .family("NX-OS")
            .generation("9")
            .device(DeviceType::Switch)
            .cpe("cpe:/o:cisco:nx-os:9")
            .ttl_initial(255)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // Cisco NX-OS 7.x
        SignatureBuilder::new(5012, "Cisco NX-OS 7.x")
            .vendor("Cisco")
            .family("NX-OS")
            .generation("7")
            .device(DeviceType::Switch)
            .cpe("cpe:/o:cisco:nx-os:7")
            .ttl_initial(255)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(3)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // Cisco ASA 9.x
        SignatureBuilder::new(5020, "Cisco ASA 9.x")
            .vendor("Cisco")
            .family("ASA")
            .generation("9")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:cisco:adaptive_security_appliance_software:9")
            .ttl_initial(255)
            .window_exact(8192)
            .mss_exact(1380)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Cisco ASA 8.x
        SignatureBuilder::new(5021, "Cisco ASA 8.x")
            .vendor("Cisco")
            .family("ASA")
            .generation("8")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:cisco:adaptive_security_appliance_software:8")
            .ttl_initial(255)
            .window_exact(8192)
            .mss_exact(1380)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Cisco Firepower (FTD)
        SignatureBuilder::new(5030, "Cisco Firepower Threat Defense")
            .vendor("Cisco")
            .family("FTD")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:cisco:firepower_threat_defense")
            .ttl_initial(64) // Linux-based
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // Cisco WLC (Wireless LAN Controller)
        SignatureBuilder::new(5040, "Cisco WLC")
            .vendor("Cisco")
            .family("AireOS")
            .device(DeviceType::WAP)
            .cpe("cpe:/o:cisco:wireless_lan_controller_software")
            .ttl_initial(255)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // Cisco Small Business
        SignatureBuilder::new(5050, "Cisco Small Business Router")
            .vendor("Cisco")
            .family("Small Business")
            .device(DeviceType::Router)
            .cpe("cpe:/o:cisco:small_business")
            .ttl_initial(64)
            .window_exact(5840)
            .mss_exact(1460)
            .ws(2)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.80)
            .build(),
        // Cisco Meraki
        SignatureBuilder::new(5060, "Cisco Meraki")
            .vendor("Cisco Meraki")
            .family("Meraki")
            .device(DeviceType::Router)
            .cpe("cpe:/o:cisco:meraki")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
    ]
}

fn juniper_signatures() -> Vec<OsSignature> {
    vec![
        // Juniper Junos 23.x
        SignatureBuilder::new(5100, "Juniper Junos 23.x")
            .vendor("Juniper")
            .family("Junos")
            .generation("23")
            .device(DeviceType::Router)
            .cpe("cpe:/o:juniper:junos:23")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Juniper Junos 22.x
        SignatureBuilder::new(5101, "Juniper Junos 22.x")
            .vendor("Juniper")
            .family("Junos")
            .generation("22")
            .device(DeviceType::Router)
            .cpe("cpe:/o:juniper:junos:22")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // Juniper Junos 21.x
        SignatureBuilder::new(5102, "Juniper Junos 21.x")
            .vendor("Juniper")
            .family("Junos")
            .generation("21")
            .device(DeviceType::Router)
            .cpe("cpe:/o:juniper:junos:21")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Juniper Junos 20.x
        SignatureBuilder::new(5103, "Juniper Junos 20.x")
            .vendor("Juniper")
            .family("Junos")
            .generation("20")
            .device(DeviceType::Router)
            .cpe("cpe:/o:juniper:junos:20")
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
        // Juniper ScreenOS (legacy)
        SignatureBuilder::new(5110, "Juniper ScreenOS")
            .vendor("Juniper")
            .family("ScreenOS")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:juniper:screenos")
            .ttl_initial(64)
            .window_exact(8192)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.80)
            .build(),
        // Juniper SRX Series
        SignatureBuilder::new(5120, "Juniper SRX Firewall")
            .vendor("Juniper")
            .family("Junos")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:juniper:junos")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
    ]
}

fn fortinet_signatures() -> Vec<OsSignature> {
    vec![
        // FortiOS 7.x
        SignatureBuilder::new(5200, "FortiGate FortiOS 7.x")
            .vendor("Fortinet")
            .family("FortiOS")
            .generation("7")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:fortinet:fortios:7")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // FortiOS 6.x
        SignatureBuilder::new(5201, "FortiGate FortiOS 6.x")
            .vendor("Fortinet")
            .family("FortiOS")
            .generation("6")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:fortinet:fortios:6")
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
        // FortiOS 5.x
        SignatureBuilder::new(5202, "FortiGate FortiOS 5.x")
            .vendor("Fortinet")
            .family("FortiOS")
            .generation("5")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:fortinet:fortios:5")
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
        // FortiSwitch
        SignatureBuilder::new(5210, "FortiSwitch")
            .vendor("Fortinet")
            .family("FortiSwitch")
            .device(DeviceType::Switch)
            .cpe("cpe:/o:fortinet:fortiswitch")
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
        // FortiAP
        SignatureBuilder::new(5220, "FortiAP")
            .vendor("Fortinet")
            .family("FortiAP")
            .device(DeviceType::WAP)
            .cpe("cpe:/h:fortinet:fortiap")
            .ttl_initial(64)
            .window_exact(29200)
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

fn palo_alto_signatures() -> Vec<OsSignature> {
    vec![
        // PAN-OS 11.x
        SignatureBuilder::new(5300, "Palo Alto PAN-OS 11.x")
            .vendor("Palo Alto Networks")
            .family("PAN-OS")
            .generation("11")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:paloaltonetworks:pan-os:11")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // PAN-OS 10.x
        SignatureBuilder::new(5301, "Palo Alto PAN-OS 10.x")
            .vendor("Palo Alto Networks")
            .family("PAN-OS")
            .generation("10")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:paloaltonetworks:pan-os:10")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // PAN-OS 9.x
        SignatureBuilder::new(5302, "Palo Alto PAN-OS 9.x")
            .vendor("Palo Alto Networks")
            .family("PAN-OS")
            .generation("9")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:paloaltonetworks:pan-os:9")
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
        // Prisma Access
        SignatureBuilder::new(5310, "Palo Alto Prisma Access")
            .vendor("Palo Alto Networks")
            .family("Prisma")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:paloaltonetworks:prisma_access")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.85)
            .build(),
    ]
}

fn checkpoint_signatures() -> Vec<OsSignature> {
    vec![
        // Check Point R81.x
        SignatureBuilder::new(5400, "Check Point R81.x")
            .vendor("Check Point")
            .family("Gaia")
            .generation("R81")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:checkpoint:gaia_os:r81")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Check Point R80.x
        SignatureBuilder::new(5401, "Check Point R80.x")
            .vendor("Check Point")
            .family("Gaia")
            .generation("R80")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:checkpoint:gaia_os:r80")
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
        // Check Point R77.x
        SignatureBuilder::new(5402, "Check Point R77.x")
            .vendor("Check Point")
            .family("Gaia")
            .generation("R77")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:checkpoint:gaia_os:r77")
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
    ]
}

fn f5_signatures() -> Vec<OsSignature> {
    vec![
        // F5 BIG-IP TMOS 17.x
        SignatureBuilder::new(5500, "F5 BIG-IP TMOS 17.x")
            .vendor("F5")
            .family("TMOS")
            .generation("17")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/o:f5:tmos:17")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // F5 BIG-IP TMOS 16.x
        SignatureBuilder::new(5501, "F5 BIG-IP TMOS 16.x")
            .vendor("F5")
            .family("TMOS")
            .generation("16")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/o:f5:tmos:16")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // F5 BIG-IP TMOS 15.x
        SignatureBuilder::new(5502, "F5 BIG-IP TMOS 15.x")
            .vendor("F5")
            .family("TMOS")
            .generation("15")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/o:f5:tmos:15")
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
        // F5 BIG-IP TMOS 14.x
        SignatureBuilder::new(5503, "F5 BIG-IP TMOS 14.x")
            .vendor("F5")
            .family("TMOS")
            .generation("14")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/o:f5:tmos:14")
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
        // F5 NGINX Plus
        SignatureBuilder::new(5510, "F5 NGINX Plus")
            .vendor("F5")
            .family("NGINX")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/a:f5:nginx_plus")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.85)
            .build(),
    ]
}

fn arista_signatures() -> Vec<OsSignature> {
    vec![
        // Arista EOS 4.x
        SignatureBuilder::new(5600, "Arista EOS 4.x")
            .vendor("Arista")
            .family("EOS")
            .generation("4")
            .device(DeviceType::Switch)
            .cpe("cpe:/o:arista:eos:4")
            .ttl_initial(64) // Linux-based
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),
        // Arista CloudEOS
        SignatureBuilder::new(5601, "Arista CloudEOS")
            .vendor("Arista")
            .family("EOS")
            .device(DeviceType::Router)
            .cpe("cpe:/o:arista:cloudeos")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),
    ]
}

fn other_network_signatures() -> Vec<OsSignature> {
    vec![
        // MikroTik RouterOS 7.x
        SignatureBuilder::new(5700, "MikroTik RouterOS 7.x")
            .vendor("MikroTik")
            .family("RouterOS")
            .generation("7")
            .device(DeviceType::Router)
            .cpe("cpe:/o:mikrotik:routeros:7")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // MikroTik RouterOS 6.x
        SignatureBuilder::new(5701, "MikroTik RouterOS 6.x")
            .vendor("MikroTik")
            .family("RouterOS")
            .generation("6")
            .device(DeviceType::Router)
            .cpe("cpe:/o:mikrotik:routeros:6")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Ubiquiti EdgeOS
        SignatureBuilder::new(5710, "Ubiquiti EdgeOS")
            .vendor("Ubiquiti")
            .family("EdgeOS")
            .device(DeviceType::Router)
            .cpe("cpe:/o:ubiquiti:edgeos")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Ubiquiti UniFi OS
        SignatureBuilder::new(5711, "Ubiquiti UniFi OS")
            .vendor("Ubiquiti")
            .family("UniFi")
            .device(DeviceType::Router)
            .cpe("cpe:/o:ubiquiti:unifi_os")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // SonicWall SonicOS
        SignatureBuilder::new(5720, "SonicWall SonicOS")
            .vendor("SonicWall")
            .family("SonicOS")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:sonicwall:sonicos")
            .ttl_initial(64)
            .window_exact(16384)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Sophos XG Firewall
        SignatureBuilder::new(5730, "Sophos XG Firewall")
            .vendor("Sophos")
            .family("SFOS")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:sophos:sfos")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // WatchGuard Fireware
        SignatureBuilder::new(5740, "WatchGuard Fireware")
            .vendor("WatchGuard")
            .family("Fireware")
            .device(DeviceType::Firewall)
            .cpe("cpe:/o:watchguard:fireware")
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
        // Citrix ADC (NetScaler)
        SignatureBuilder::new(5750, "Citrix ADC")
            .vendor("Citrix")
            .family("ADC")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/o:citrix:netscaler_adc")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.90)
            .build(),
        // A10 ACOS
        SignatureBuilder::new(5760, "A10 ACOS")
            .vendor("A10 Networks")
            .family("ACOS")
            .device(DeviceType::LoadBalancer)
            .cpe("cpe:/o:a10networks:acos")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // HPE Aruba OS
        SignatureBuilder::new(5770, "HPE Aruba OS")
            .vendor("HPE Aruba")
            .family("ArubaOS")
            .device(DeviceType::WAP)
            .cpe("cpe:/o:arubanetworks:arubaos")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),
        // Ruckus SmartZone
        SignatureBuilder::new(5780, "Ruckus SmartZone")
            .vendor("Ruckus")
            .family("SmartZone")
            .device(DeviceType::WAP)
            .cpe("cpe:/o:ruckuswireless:smartzone")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.85)
            .build(),
        // TP-Link Router
        SignatureBuilder::new(5790, "TP-Link Router")
            .vendor("TP-Link")
            .family("TP-Link")
            .device(DeviceType::Router)
            .cpe("cpe:/o:tp-link:tp-link")
            .ttl_initial(64)
            .window_exact(5840)
            .mss_exact(1460)
            .ws(2)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.78)
            .build(),
        // ASUS Router
        SignatureBuilder::new(5791, "ASUS Router")
            .vendor("ASUS")
            .family("ASUSWRT")
            .device(DeviceType::Router)
            .cpe("cpe:/o:asus:asuswrt")
            .ttl_initial(64)
            .window_exact(14600)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.80)
            .build(),
        // NETGEAR Router
        SignatureBuilder::new(5792, "NETGEAR Router")
            .vendor("NETGEAR")
            .family("NETGEAR")
            .device(DeviceType::Router)
            .cpe("cpe:/o:netgear:netgear")
            .ttl_initial(64)
            .window_exact(5840)
            .mss_exact(1460)
            .ws(2)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.75)
            .build(),
        // Synology DSM
        SignatureBuilder::new(5800, "Synology DSM")
            .vendor("Synology")
            .family("DSM")
            .device(DeviceType::Storage)
            .cpe("cpe:/o:synology:dsm")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),
        // QNAP QTS
        SignatureBuilder::new(5801, "QNAP QTS")
            .vendor("QNAP")
            .family("QTS")
            .device(DeviceType::Storage)
            .cpe("cpe:/o:qnap:qts")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),
        // VMware ESXi
        SignatureBuilder::new(5810, "VMware ESXi")
            .vendor("VMware")
            .family("ESXi")
            .device(DeviceType::VirtualMachine)
            .cpe("cpe:/o:vmware:esxi")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(8)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.92)
            .build(),
        // Proxmox VE
        SignatureBuilder::new(5820, "Proxmox VE")
            .vendor("Proxmox")
            .family("Proxmox VE")
            .device(DeviceType::VirtualMachine)
            .cpe("cpe:/o:proxmox:proxmox_ve")
            .ttl_initial(64)
            .window_exact(29200)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_signatures_count() {
        let sigs = signatures();
        assert!(
            sigs.len() >= 50,
            "Expected at least 50 network device signatures, got {}",
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
    fn test_cisco_ios_ttl_255() {
        let sigs = cisco_signatures();
        let ios_sigs: Vec<_> = sigs
            .iter()
            .filter(|s| s.os_family == "IOS" || s.os_family == "ASA")
            .collect();

        for sig in ios_sigs {
            match sig.ttl {
                TtlMatch::Initial(ttl) | TtlMatch::Exact(ttl) => {
                    assert_eq!(ttl, 255, "{} should have TTL 255", sig.name);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_device_types() {
        let sigs = signatures();

        let router_count = sigs
            .iter()
            .filter(|s| s.device_type == DeviceType::Router)
            .count();
        let firewall_count = sigs
            .iter()
            .filter(|s| s.device_type == DeviceType::Firewall)
            .count();
        let switch_count = sigs
            .iter()
            .filter(|s| s.device_type == DeviceType::Switch)
            .count();
        let lb_count = sigs
            .iter()
            .filter(|s| s.device_type == DeviceType::LoadBalancer)
            .count();

        assert!(router_count > 5, "Expected more router signatures");
        assert!(firewall_count > 5, "Expected more firewall signatures");
        assert!(switch_count > 2, "Expected more switch signatures");
        assert!(lb_count > 2, "Expected more load balancer signatures");
    }
}
