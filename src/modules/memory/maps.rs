//! Memory region parsing from /proc/pid/maps
//!
//! Parses the Linux memory mapping format:
//! address           perms offset  dev   inode   pathname
//! 00400000-00452000 r-xp 00000000 08:02 173521  /usr/bin/ls

use std::fs;
use std::path::PathBuf;

/// Memory region permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool, // false = private
}

impl MemoryPermissions {
    pub fn from_str(s: &str) -> Self {
        let bytes = s.as_bytes();
        Self {
            read: bytes.get(0) == Some(&b'r'),
            write: bytes.get(1) == Some(&b'w'),
            execute: bytes.get(2) == Some(&b'x'),
            shared: bytes.get(3) == Some(&b's'),
        }
    }

    pub fn is_readable(&self) -> bool {
        self.read
    }

    pub fn is_writable(&self) -> bool {
        self.read && self.write
    }
}

impl std::fmt::Display for MemoryPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' }
        )
    }
}

/// Type of memory region
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionType {
    /// Anonymous memory (heap, stack, etc.)
    Anonymous,
    /// Memory-mapped file
    File(PathBuf),
    /// Stack region
    Stack,
    /// Heap region
    Heap,
    /// vDSO (virtual dynamic shared object)
    Vdso,
    /// vvar (kernel variables)
    Vvar,
    /// vsyscall region
    Vsyscall,
}

impl RegionType {
    pub fn is_scannable(&self) -> bool {
        matches!(
            self,
            RegionType::Anonymous | RegionType::Heap | RegionType::Stack
        )
    }
}

/// A memory region from /proc/pid/maps
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Start address
    pub start: usize,
    /// End address
    pub end: usize,
    /// Permissions
    pub perms: MemoryPermissions,
    /// File offset (if mapped from file)
    pub offset: usize,
    /// Device major:minor
    pub device: (u32, u32),
    /// Inode number
    pub inode: u64,
    /// Type of region
    pub region_type: RegionType,
}

impl MemoryRegion {
    /// Size of the region in bytes
    pub fn size(&self) -> usize {
        self.end - self.start
    }

    /// Check if region is readable
    pub fn is_readable(&self) -> bool {
        self.perms.read
    }

    /// Check if region is writable
    pub fn is_writable(&self) -> bool {
        self.perms.write
    }

    /// Check if this region is good for scanning (heap, stack, anonymous)
    pub fn is_scannable(&self) -> bool {
        self.perms.read && self.region_type.is_scannable()
    }

    /// Get human-readable name for the region
    pub fn name(&self) -> String {
        match &self.region_type {
            RegionType::Anonymous => "[anonymous]".to_string(),
            RegionType::File(path) => path.to_string_lossy().to_string(),
            RegionType::Stack => "[stack]".to_string(),
            RegionType::Heap => "[heap]".to_string(),
            RegionType::Vdso => "[vdso]".to_string(),
            RegionType::Vvar => "[vvar]".to_string(),
            RegionType::Vsyscall => "[vsyscall]".to_string(),
        }
    }
}

/// Parse /proc/pid/maps and return all memory regions
pub fn parse_maps(pid: i32) -> Result<Vec<MemoryRegion>, String> {
    let path = format!("/proc/{}/maps", pid);
    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {}", path, e))?;

    parse_maps_content(&content)
}

/// Parse maps content (for testing)
pub fn parse_maps_content(content: &str) -> Result<Vec<MemoryRegion>, String> {
    let mut regions = Vec::new();

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }

        if let Some(region) = parse_map_line(line) {
            regions.push(region);
        }
    }

    Ok(regions)
}

fn parse_map_line(line: &str) -> Option<MemoryRegion> {
    let mut parts = line.split_whitespace();

    // Parse address range: "00400000-00452000"
    let addr_range = parts.next()?;
    let (start_str, end_str) = addr_range.split_once('-')?;
    let start = usize::from_str_radix(start_str, 16).ok()?;
    let end = usize::from_str_radix(end_str, 16).ok()?;

    // Parse permissions: "r-xp"
    let perms_str = parts.next()?;
    let perms = MemoryPermissions::from_str(perms_str);

    // Parse offset: "00000000"
    let offset_str = parts.next()?;
    let offset = usize::from_str_radix(offset_str, 16).ok()?;

    // Parse device: "08:02"
    let device_str = parts.next()?;
    let device = parse_device(device_str).unwrap_or((0, 0));

    // Parse inode
    let inode_str = parts.next()?;
    let inode = inode_str.parse::<u64>().unwrap_or(0);

    // Remaining is the pathname (optional)
    let pathname: String = parts.collect::<Vec<_>>().join(" ");
    let region_type = classify_region(&pathname, inode);

    Some(MemoryRegion {
        start,
        end,
        perms,
        offset,
        device,
        inode,
        region_type,
    })
}

fn parse_device(s: &str) -> Option<(u32, u32)> {
    let (major, minor) = s.split_once(':')?;
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    Some((major, minor))
}

fn classify_region(pathname: &str, inode: u64) -> RegionType {
    let pathname = pathname.trim();

    if pathname.is_empty() {
        // Anonymous if no inode, otherwise deleted file
        return RegionType::Anonymous;
    }

    match pathname {
        "[stack]" => RegionType::Stack,
        "[heap]" => RegionType::Heap,
        "[vdso]" => RegionType::Vdso,
        "[vvar]" => RegionType::Vvar,
        "[vsyscall]" => RegionType::Vsyscall,
        _ if pathname.starts_with('[') => RegionType::Anonymous,
        _ => RegionType::File(PathBuf::from(pathname)),
    }
}

/// Filter regions suitable for scanning (readable, anonymous/heap/stack)
pub fn scannable_regions(regions: &[MemoryRegion]) -> Vec<&MemoryRegion> {
    regions.iter().filter(|r| r.is_scannable()).collect()
}

/// Filter regions by permission
pub fn writable_regions(regions: &[MemoryRegion]) -> Vec<&MemoryRegion> {
    regions.iter().filter(|r| r.is_writable()).collect()
}

/// Get total size of regions
pub fn total_size(regions: &[MemoryRegion]) -> usize {
    regions.iter().map(|r| r.size()).sum()
}

/// Print a summary of memory regions
pub fn summarize_regions(regions: &[MemoryRegion]) -> String {
    let mut summary = String::new();
    let total = total_size(regions);

    summary.push_str(&format!("Total regions: {}\n", regions.len()));
    summary.push_str(&format!(
        "Total size: {} bytes ({:.2} MB)\n",
        total,
        total as f64 / 1024.0 / 1024.0
    ));

    let scannable: Vec<_> = regions.iter().filter(|r| r.is_scannable()).collect();
    let scannable_size: usize = scannable.iter().map(|r| r.size()).sum();
    summary.push_str(&format!(
        "Scannable: {} regions, {} bytes ({:.2} MB)\n",
        scannable.len(),
        scannable_size,
        scannable_size as f64 / 1024.0 / 1024.0
    ));

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MAPS: &str = r#"
55b7c4a00000-55b7c4a28000 r--p 00000000 08:02 1234567    /usr/bin/example
55b7c4a28000-55b7c4a8c000 r-xp 00028000 08:02 1234567    /usr/bin/example
55b7c4c8c000-55b7c4c96000 rw-p 00000000 00:00 0          [heap]
7ffc12345000-7ffc12366000 rw-p 00000000 00:00 0          [stack]
7ffc12366000-7ffc1236a000 r--p 00000000 00:00 0          [vvar]
7ffc1236a000-7ffc1236c000 r-xp 00000000 00:00 0          [vdso]
"#;

    #[test]
    fn test_parse_maps() {
        let regions = parse_maps_content(SAMPLE_MAPS).unwrap();
        assert_eq!(regions.len(), 6);

        // Check heap
        let heap = regions
            .iter()
            .find(|r| matches!(r.region_type, RegionType::Heap))
            .unwrap();
        assert!(heap.is_scannable());
        assert!(heap.perms.read);
        assert!(heap.perms.write);

        // Check stack
        let stack = regions
            .iter()
            .find(|r| matches!(r.region_type, RegionType::Stack))
            .unwrap();
        assert!(stack.is_scannable());
    }

    #[test]
    fn test_permissions() {
        let perms = MemoryPermissions::from_str("r-xp");
        assert!(perms.read);
        assert!(!perms.write);
        assert!(perms.execute);
        assert!(!perms.shared);
    }
}
