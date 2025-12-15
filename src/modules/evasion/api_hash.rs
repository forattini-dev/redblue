//! API Hashing for Dynamic Resolution
//!
//! Instead of storing function names as strings (which AV can detect),
//! we store hashes and resolve them at runtime.
//!
//! # How it works
//! 1. Function names are hashed using a custom algorithm
//! 2. At runtime, we walk the export table and hash each export
//! 3. When hashes match, we have our function pointer
//!
//! # Common algorithms
//! - ROR13: Classic hash used in shellcode
//! - DJB2: Fast string hash
//! - FNV-1a: Fowler-Noll-Vo hash
//! - CRC32: Cyclic redundancy check

use std::collections::HashMap;

/// Hash algorithms for API resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// Rotate-right 13 (classic shellcode hash)
    Ror13,
    /// DJB2 hash (fast)
    Djb2,
    /// FNV-1a hash (good distribution)
    Fnv1a,
    /// CRC32 (collision resistant)
    Crc32,
    /// Custom XOR-based hash
    XorHash,
}

/// Calculate ROR13 hash (common in shellcode)
pub fn ror13_hash(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in s.bytes() {
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(c as u32);
    }
    hash
}

/// Calculate ROR13 hash for wide string (UTF-16)
pub fn ror13_hash_wide(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in s.encode_utf16() {
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(c as u32);
    }
    hash
}

/// Calculate DJB2 hash
pub fn djb2_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}

/// Calculate FNV-1a hash (32-bit)
pub fn fnv1a_hash(s: &str) -> u32 {
    const FNV_OFFSET: u32 = 2166136261;
    const FNV_PRIME: u32 = 16777619;

    let mut hash = FNV_OFFSET;
    for c in s.bytes() {
        hash ^= c as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Calculate CRC32 hash
pub fn crc32_hash(s: &str) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in s.bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Custom XOR-based hash (harder to reverse)
pub fn xor_hash(s: &str) -> u32 {
    let mut hash: u32 = 0x12345678;
    for (i, c) in s.bytes().enumerate() {
        let rotated = hash.rotate_left((i % 32) as u32);
        hash ^= rotated ^ ((c as u32) << ((i % 4) * 8));
    }
    hash
}

/// Hash a string using the specified algorithm
pub fn hash_api(s: &str, algo: HashAlgorithm) -> u32 {
    match algo {
        HashAlgorithm::Ror13 => ror13_hash(s),
        HashAlgorithm::Djb2 => djb2_hash(s),
        HashAlgorithm::Fnv1a => fnv1a_hash(s),
        HashAlgorithm::Crc32 => crc32_hash(s),
        HashAlgorithm::XorHash => xor_hash(s),
    }
}

/// Pre-computed hashes for common Windows APIs
pub struct WindowsApiHashes {
    algo: HashAlgorithm,
    hashes: HashMap<&'static str, u32>,
}

impl WindowsApiHashes {
    /// Create with specified algorithm
    pub fn new(algo: HashAlgorithm) -> Self {
        let mut hashes = HashMap::new();

        // Kernel32.dll exports
        let kernel32_apis = [
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualFree",
            "VirtualProtect",
            "VirtualProtectEx",
            "CreateThread",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "OpenProcess",
            "CreateProcessA",
            "CreateProcessW",
            "WinExec",
            "GetModuleHandleA",
            "GetModuleHandleW",
            "GetCurrentProcess",
            "GetCurrentThread",
            "TerminateProcess",
            "ExitProcess",
            "Sleep",
            "SleepEx",
            "WaitForSingleObject",
            "CloseHandle",
        ];

        // Ntdll.dll exports
        let ntdll_apis = [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtCreateThreadEx",
            "NtOpenProcess",
            "NtClose",
            "NtQueryInformationProcess",
            "NtQuerySystemInformation",
            "RtlMoveMemory",
            "RtlCopyMemory",
            "RtlZeroMemory",
        ];

        // User32.dll exports
        let user32_apis = [
            "MessageBoxA",
            "MessageBoxW",
            "GetAsyncKeyState",
            "GetKeyState",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
        ];

        // Advapi32.dll exports
        let advapi32_apis = [
            "OpenProcessToken",
            "AdjustTokenPrivileges",
            "LookupPrivilegeValueA",
            "RegOpenKeyExA",
            "RegSetValueExA",
            "RegCloseKey",
        ];

        for api in kernel32_apis.iter() {
            hashes.insert(*api, hash_api(api, algo));
        }
        for api in ntdll_apis.iter() {
            hashes.insert(*api, hash_api(api, algo));
        }
        for api in user32_apis.iter() {
            hashes.insert(*api, hash_api(api, algo));
        }
        for api in advapi32_apis.iter() {
            hashes.insert(*api, hash_api(api, algo));
        }

        Self { algo, hashes }
    }

    /// Get hash for an API name
    pub fn get_hash(&self, api_name: &str) -> Option<u32> {
        self.hashes.get(api_name).copied()
    }

    /// Calculate hash for any string
    pub fn hash(&self, s: &str) -> u32 {
        hash_api(s, self.algo)
    }

    /// Get all pre-computed hashes
    pub fn all_hashes(&self) -> &HashMap<&'static str, u32> {
        &self.hashes
    }

    /// Find API name by hash (for debugging)
    pub fn find_by_hash(&self, hash: u32) -> Option<&'static str> {
        self.hashes
            .iter()
            .find(|(_, &h)| h == hash)
            .map(|(&name, _)| name)
    }
}

/// DLL name hashes
pub struct DllHashes;

impl DllHashes {
    /// Get kernel32.dll hash
    pub fn kernel32(algo: HashAlgorithm) -> u32 {
        hash_api("kernel32.dll", algo)
    }

    /// Get ntdll.dll hash
    pub fn ntdll(algo: HashAlgorithm) -> u32 {
        hash_api("ntdll.dll", algo)
    }

    /// Get user32.dll hash
    pub fn user32(algo: HashAlgorithm) -> u32 {
        hash_api("user32.dll", algo)
    }

    /// Get advapi32.dll hash
    pub fn advapi32(algo: HashAlgorithm) -> u32 {
        hash_api("advapi32.dll", algo)
    }

    /// Get ws2_32.dll hash (Winsock)
    pub fn ws2_32(algo: HashAlgorithm) -> u32 {
        hash_api("ws2_32.dll", algo)
    }

    /// Get wininet.dll hash
    pub fn wininet(algo: HashAlgorithm) -> u32 {
        hash_api("wininet.dll", algo)
    }

    /// Get winhttp.dll hash
    pub fn winhttp(algo: HashAlgorithm) -> u32 {
        hash_api("winhttp.dll", algo)
    }
}

/// Generate Rust code for API hash constants
pub fn generate_api_hash_consts(api_names: &[&str], algo: HashAlgorithm) -> String {
    let mut code = String::new();
    code.push_str("// Auto-generated API hash constants\n");
    code.push_str(&format!("// Algorithm: {:?}\n\n", algo));

    for name in api_names {
        let hash = hash_api(name, algo);
        let const_name = name.to_uppercase();
        code.push_str(&format!(
            "pub const {}_HASH: u32 = 0x{:08X};\n",
            const_name, hash
        ));
    }

    code
}

/// Linux syscall numbers (for direct syscall)
pub struct LinuxSyscalls;

impl LinuxSyscalls {
    // x86_64 syscall numbers
    pub const SYS_READ: u64 = 0;
    pub const SYS_WRITE: u64 = 1;
    pub const SYS_OPEN: u64 = 2;
    pub const SYS_CLOSE: u64 = 3;
    pub const SYS_MMAP: u64 = 9;
    pub const SYS_MPROTECT: u64 = 10;
    pub const SYS_MUNMAP: u64 = 11;
    pub const SYS_FORK: u64 = 57;
    pub const SYS_EXECVE: u64 = 59;
    pub const SYS_EXIT: u64 = 60;
    pub const SYS_SOCKET: u64 = 41;
    pub const SYS_CONNECT: u64 = 42;
    pub const SYS_ACCEPT: u64 = 43;
    pub const SYS_BIND: u64 = 49;
    pub const SYS_LISTEN: u64 = 50;
    pub const SYS_CLONE: u64 = 56;
    pub const SYS_PTRACE: u64 = 101;
    pub const SYS_GETPID: u64 = 39;
    pub const SYS_GETUID: u64 = 102;
    pub const SYS_GETEUID: u64 = 107;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ror13_hash() {
        // Known values for testing
        let hash = ror13_hash("LoadLibraryA");
        assert_ne!(hash, 0);
        // Verify consistency
        assert_eq!(hash, ror13_hash("LoadLibraryA"));
    }

    #[test]
    fn test_djb2_hash() {
        let hash = djb2_hash("kernel32.dll");
        assert_ne!(hash, 0);
        assert_eq!(hash, djb2_hash("kernel32.dll"));
    }

    #[test]
    fn test_fnv1a_hash() {
        let hash = fnv1a_hash("VirtualAlloc");
        assert_ne!(hash, 0);
        assert_eq!(hash, fnv1a_hash("VirtualAlloc"));
    }

    #[test]
    fn test_crc32_hash() {
        let hash = crc32_hash("CreateThread");
        assert_ne!(hash, 0);
        assert_eq!(hash, crc32_hash("CreateThread"));
    }

    #[test]
    fn test_windows_api_hashes() {
        let hashes = WindowsApiHashes::new(HashAlgorithm::Ror13);

        // Check that common APIs are present
        assert!(hashes.get_hash("LoadLibraryA").is_some());
        assert!(hashes.get_hash("VirtualAlloc").is_some());

        // Check reverse lookup
        let hash = hashes.get_hash("CreateThread").unwrap();
        assert_eq!(hashes.find_by_hash(hash), Some("CreateThread"));
    }

    #[test]
    fn test_generate_consts() {
        let code =
            generate_api_hash_consts(&["LoadLibraryA", "GetProcAddress"], HashAlgorithm::Djb2);
        assert!(code.contains("LOADLIBRARYA_HASH"));
        assert!(code.contains("GETPROCADDRESS_HASH"));
    }

    #[test]
    fn test_dll_hashes() {
        let k32 = DllHashes::kernel32(HashAlgorithm::Ror13);
        let ntdll = DllHashes::ntdll(HashAlgorithm::Ror13);
        assert_ne!(k32, ntdll);
    }
}
