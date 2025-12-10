/// Linux OS Signatures
///
/// TCP/IP fingerprints for Linux kernel versions and distributions.

use super::types::*;

/// Add all Linux signatures to the database
pub fn signatures() -> Vec<OsSignature> {
    let mut sigs = Vec::with_capacity(200);

    // === KERNEL VERSIONS ===
    sigs.extend(kernel_signatures());

    // === DISTRIBUTIONS ===
    sigs.extend(ubuntu_signatures());
    sigs.extend(debian_signatures());
    sigs.extend(rhel_signatures());
    sigs.extend(fedora_signatures());
    sigs.extend(arch_signatures());
    sigs.extend(alpine_signatures());
    sigs.extend(suse_signatures());
    sigs.extend(gentoo_signatures());
    sigs.extend(embedded_linux_signatures());

    sigs
}

fn kernel_signatures() -> Vec<OsSignature> {
    vec![
        // Linux 6.x (Modern - 2022+)
        SignatureBuilder::new(1000, "Linux 6.x")
            .vendor("Linux")
            .family("Linux")
            .generation("6.x")
            .cpe("cpe:/o:linux:linux_kernel:6")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.95)
            .build(),

        // Linux 5.x (2019-2022)
        SignatureBuilder::new(1001, "Linux 5.x")
            .vendor("Linux")
            .family("Linux")
            .generation("5.x")
            .cpe("cpe:/o:linux:linux_kernel:5")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),

        // Linux 4.x (2015-2019)
        SignatureBuilder::new(1002, "Linux 4.x")
            .vendor("Linux")
            .family("Linux")
            .generation("4.x")
            .cpe("cpe:/o:linux:linux_kernel:4")
            .ttl_initial(64)
            .window_range(5840, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.90)
            .build(),

        // Linux 3.x (2011-2015)
        SignatureBuilder::new(1003, "Linux 3.x")
            .vendor("Linux")
            .family("Linux")
            .generation("3.x")
            .cpe("cpe:/o:linux:linux_kernel:3")
            .ttl_initial(64)
            .window_range(5840, 29200)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Linux 2.6.x (2003-2011)
        SignatureBuilder::new(1004, "Linux 2.6.x")
            .vendor("Linux")
            .family("Linux")
            .generation("2.6")
            .cpe("cpe:/o:linux:linux_kernel:2.6")
            .ttl_initial(64)
            .window_exact(5840)
            .mss_exact(1460)
            .ws(2)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Linux 2.4.x (2001-2004)
        SignatureBuilder::new(1005, "Linux 2.4.x")
            .vendor("Linux")
            .family("Linux")
            .generation("2.4")
            .cpe("cpe:/o:linux:linux_kernel:2.4")
            .ttl_initial(64)
            .window_exact(5840)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.80)
            .build(),
    ]
}

fn ubuntu_signatures() -> Vec<OsSignature> {
    vec![
        // Ubuntu 24.04 LTS (Noble Numbat)
        SignatureBuilder::new(1100, "Ubuntu 24.04 LTS")
            .vendor("Canonical")
            .family("Linux")
            .generation("24.04")
            .cpe("cpe:/o:canonical:ubuntu_linux:24.04")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),

        // Ubuntu 22.04 LTS (Jammy Jellyfish)
        SignatureBuilder::new(1101, "Ubuntu 22.04 LTS")
            .vendor("Canonical")
            .family("Linux")
            .generation("22.04")
            .cpe("cpe:/o:canonical:ubuntu_linux:22.04")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),

        // Ubuntu 20.04 LTS (Focal Fossa)
        SignatureBuilder::new(1102, "Ubuntu 20.04 LTS")
            .vendor("Canonical")
            .family("Linux")
            .generation("20.04")
            .cpe("cpe:/o:canonical:ubuntu_linux:20.04")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // Ubuntu 18.04 LTS (Bionic Beaver)
        SignatureBuilder::new(1103, "Ubuntu 18.04 LTS")
            .vendor("Canonical")
            .family("Linux")
            .generation("18.04")
            .cpe("cpe:/o:canonical:ubuntu_linux:18.04")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Ubuntu 16.04 LTS (Xenial Xerus)
        SignatureBuilder::new(1104, "Ubuntu 16.04 LTS")
            .vendor("Canonical")
            .family("Linux")
            .generation("16.04")
            .cpe("cpe:/o:canonical:ubuntu_linux:16.04")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Ubuntu Server (generic)
        SignatureBuilder::new(1110, "Ubuntu Server")
            .vendor("Canonical")
            .family("Linux")
            .cpe("cpe:/o:canonical:ubuntu_linux")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options_flex("MSWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .confidence(0.75)
            .build(),
    ]
}

fn debian_signatures() -> Vec<OsSignature> {
    vec![
        // Debian 12 (Bookworm)
        SignatureBuilder::new(1200, "Debian 12 (Bookworm)")
            .vendor("Debian")
            .family("Linux")
            .generation("12")
            .cpe("cpe:/o:debian:debian_linux:12")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),

        // Debian 11 (Bullseye)
        SignatureBuilder::new(1201, "Debian 11 (Bullseye)")
            .vendor("Debian")
            .family("Linux")
            .generation("11")
            .cpe("cpe:/o:debian:debian_linux:11")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // Debian 10 (Buster)
        SignatureBuilder::new(1202, "Debian 10 (Buster)")
            .vendor("Debian")
            .family("Linux")
            .generation("10")
            .cpe("cpe:/o:debian:debian_linux:10")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // Debian 9 (Stretch)
        SignatureBuilder::new(1203, "Debian 9 (Stretch)")
            .vendor("Debian")
            .family("Linux")
            .generation("9")
            .cpe("cpe:/o:debian:debian_linux:9")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),
    ]
}

fn rhel_signatures() -> Vec<OsSignature> {
    vec![
        // RHEL 9
        SignatureBuilder::new(1300, "RHEL 9")
            .vendor("Red Hat")
            .family("Linux")
            .generation("9")
            .cpe("cpe:/o:redhat:enterprise_linux:9")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),

        // RHEL 8
        SignatureBuilder::new(1301, "RHEL 8")
            .vendor("Red Hat")
            .family("Linux")
            .generation("8")
            .cpe("cpe:/o:redhat:enterprise_linux:8")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // RHEL 7
        SignatureBuilder::new(1302, "RHEL 7")
            .vendor("Red Hat")
            .family("Linux")
            .generation("7")
            .cpe("cpe:/o:redhat:enterprise_linux:7")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // CentOS Stream 9
        SignatureBuilder::new(1310, "CentOS Stream 9")
            .vendor("CentOS")
            .family("Linux")
            .generation("9")
            .cpe("cpe:/o:centos:centos:9")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // Rocky Linux 9
        SignatureBuilder::new(1320, "Rocky Linux 9")
            .vendor("Rocky Enterprise Software Foundation")
            .family("Linux")
            .generation("9")
            .cpe("cpe:/o:rockylinux:rocky:9")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // AlmaLinux 9
        SignatureBuilder::new(1330, "AlmaLinux 9")
            .vendor("AlmaLinux OS Foundation")
            .family("Linux")
            .generation("9")
            .cpe("cpe:/o:almalinux:almalinux:9")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // Oracle Linux 9
        SignatureBuilder::new(1340, "Oracle Linux 9")
            .vendor("Oracle")
            .family("Linux")
            .generation("9")
            .cpe("cpe:/o:oracle:linux:9")
            .ttl_initial(64)
            .window_range(64240, 65535)
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

fn fedora_signatures() -> Vec<OsSignature> {
    vec![
        // Fedora 40
        SignatureBuilder::new(1400, "Fedora 40")
            .vendor("Fedora Project")
            .family("Linux")
            .generation("40")
            .cpe("cpe:/o:fedoraproject:fedora:40")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.92)
            .build(),

        // Fedora 39
        SignatureBuilder::new(1401, "Fedora 39")
            .vendor("Fedora Project")
            .family("Linux")
            .generation("39")
            .cpe("cpe:/o:fedoraproject:fedora:39")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // Fedora 38
        SignatureBuilder::new(1402, "Fedora 38")
            .vendor("Fedora Project")
            .family("Linux")
            .generation("38")
            .cpe("cpe:/o:fedoraproject:fedora:38")
            .ttl_initial(64)
            .window_range(64240, 65535)
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

fn arch_signatures() -> Vec<OsSignature> {
    vec![
        // Arch Linux (rolling)
        SignatureBuilder::new(1500, "Arch Linux")
            .vendor("Arch Linux")
            .family("Linux")
            .cpe("cpe:/o:archlinux:arch_linux")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),

        // Manjaro Linux
        SignatureBuilder::new(1510, "Manjaro Linux")
            .vendor("Manjaro")
            .family("Linux")
            .cpe("cpe:/o:manjaro:manjaro_linux")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.85)
            .build(),

        // EndeavourOS
        SignatureBuilder::new(1520, "EndeavourOS")
            .vendor("EndeavourOS")
            .family("Linux")
            .cpe("cpe:/o:endeavouros:endeavouros")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.82)
            .build(),
    ]
}

fn alpine_signatures() -> Vec<OsSignature> {
    vec![
        // Alpine Linux 3.19
        SignatureBuilder::new(1600, "Alpine Linux 3.19")
            .vendor("Alpine Linux")
            .family("Linux")
            .generation("3.19")
            .cpe("cpe:/o:alpinelinux:alpine_linux:3.19")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.90)
            .build(),

        // Alpine Linux (Docker default)
        SignatureBuilder::new(1610, "Alpine Linux (Docker)")
            .vendor("Alpine Linux")
            .family("Linux")
            .device(DeviceType::Container)
            .cpe("cpe:/o:alpinelinux:alpine_linux")
            .ttl_initial(64)
            .window_range(29200, 65535)
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

fn suse_signatures() -> Vec<OsSignature> {
    vec![
        // openSUSE Tumbleweed
        SignatureBuilder::new(1700, "openSUSE Tumbleweed")
            .vendor("openSUSE")
            .family("Linux")
            .cpe("cpe:/o:opensuse:tumbleweed")
            .ttl_initial(64)
            .window_range(64240, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),

        // openSUSE Leap 15.5
        SignatureBuilder::new(1701, "openSUSE Leap 15.5")
            .vendor("openSUSE")
            .family("Linux")
            .generation("15.5")
            .cpe("cpe:/o:opensuse:leap:15.5")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),

        // SLES 15
        SignatureBuilder::new(1710, "SUSE Linux Enterprise Server 15")
            .vendor("SUSE")
            .family("Linux")
            .generation("15")
            .cpe("cpe:/o:suse:sles:15")
            .ttl_initial(64)
            .window_range(29200, 65535)
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

fn gentoo_signatures() -> Vec<OsSignature> {
    vec![
        // Gentoo Linux
        SignatureBuilder::new(1800, "Gentoo Linux")
            .vendor("Gentoo")
            .family("Linux")
            .cpe("cpe:/o:gentoo:linux")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.85)
            .build(),

        // Calculate Linux
        SignatureBuilder::new(1810, "Calculate Linux")
            .vendor("Calculate")
            .family("Linux")
            .cpe("cpe:/o:calculate:linux")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.80)
            .build(),
    ]
}

fn embedded_linux_signatures() -> Vec<OsSignature> {
    vec![
        // OpenWrt
        SignatureBuilder::new(1900, "OpenWrt")
            .vendor("OpenWrt")
            .family("Linux")
            .device(DeviceType::Router)
            .cpe("cpe:/o:openwrt:openwrt")
            .ttl_initial(64)
            .window_range(14600, 29200)
            .mss_exact(1460)
            .ws(5)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.88)
            .build(),

        // DD-WRT
        SignatureBuilder::new(1910, "DD-WRT")
            .vendor("DD-WRT")
            .family("Linux")
            .device(DeviceType::Router)
            .cpe("cpe:/o:dd-wrt:dd-wrt")
            .ttl_initial(64)
            .window_range(5840, 14600)
            .mss_exact(1460)
            .ws(4)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.85)
            .build(),

        // Raspbian / Raspberry Pi OS
        SignatureBuilder::new(1920, "Raspberry Pi OS")
            .vendor("Raspberry Pi Foundation")
            .family("Linux")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:raspberrypi:raspberry_pi_os")
            .ttl_initial(64)
            .window_range(29200, 65535)
            .mss_exact(1460)
            .ws(7)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(true)
            .confidence(0.88)
            .build(),

        // Buildroot
        SignatureBuilder::new(1930, "Buildroot Linux")
            .vendor("Buildroot")
            .family("Linux")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:buildroot:buildroot")
            .ttl_initial(64)
            .window_range(5840, 29200)
            .mss_exact(1460)
            .ws(5)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.80)
            .build(),

        // Yocto/Poky
        SignatureBuilder::new(1940, "Yocto Linux")
            .vendor("Yocto Project")
            .family("Linux")
            .device(DeviceType::IoT)
            .cpe("cpe:/o:yoctoproject:poky")
            .ttl_initial(64)
            .window_range(14600, 65535)
            .mss_exact(1460)
            .ws(6)
            .options("MSNWT")
            .df(true)
            .ip_id(IpIdPattern::Random)
            .ecn(false)
            .confidence(0.82)
            .build(),

        // BusyBox Linux
        SignatureBuilder::new(1950, "BusyBox Linux")
            .vendor("BusyBox")
            .family("Linux")
            .device(DeviceType::IoT)
            .cpe("cpe:/a:busybox:busybox")
            .ttl_initial(64)
            .window_range(4096, 8192)
            .mss_exact(1460)
            .ws(0)
            .options("MST")
            .df(true)
            .ip_id(IpIdPattern::Sequential)
            .ecn(false)
            .confidence(0.75)
            .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_signatures_count() {
        let sigs = signatures();
        assert!(sigs.len() >= 30, "Expected at least 30 Linux signatures, got {}", sigs.len());
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
    fn test_signature_builder() {
        let sig = SignatureBuilder::new(9999, "Test OS")
            .vendor("Test Vendor")
            .family("Test Family")
            .ttl_initial(64)
            .window_exact(65535)
            .mss_exact(1460)
            .ws(7)
            .confidence(0.95)
            .build();

        assert_eq!(sig.id, 9999);
        assert_eq!(sig.name, "Test OS");
        assert_eq!(sig.vendor, "Test Vendor");
        assert_eq!(sig.confidence_weight, 0.95);
    }
}
