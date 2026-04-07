//! Binary Analysis Module
//!
//! Provides ELF/PE parsing, security feature detection (checksec),
//! ROP gadget discovery, and symbol resolution for exploit development.

mod checksec;
mod elf;
pub mod fmtstr;
pub mod got_targets;
mod packing;
mod pattern;
mod pe;
pub mod ret2dlresolve;
mod rop;
pub mod shellcode;

pub use checksec::{RelroLevel, SecurityFeatures};
pub use elf::{Elf32Header, Elf64Header, ElfHeader, ElfParser, RelocationEntry};
pub use fmtstr::FmtStr;
pub use packing::*;
pub use pattern::{Pattern, PatternGenerator};
pub use pe::{PeHeader, PeParser};
pub use ret2dlresolve::{Ret2dlresolve32, Ret2dlresolve64, Ret2dlresolvePayload};
pub use rop::{Gadget, GadgetClass, GadgetFinder, RopChain, SigreturnFrame};
pub use shellcode::{Encoder, LinuxX64, LinuxX86, ShellcodeBuilder};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Binary analysis error types
#[derive(Debug)]
pub enum BinaryError {
  IoError(std::io::Error),
  TooSmall,
  UnknownFormat,
  UnsupportedFormat,
  InvalidHeader(String),
  SectionNotFound(String),
  SymbolNotFound(String),
  ParseError(String),
  OutOfBounds,
}

impl std::fmt::Display for BinaryError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::IoError(e) => write!(f, "I/O error: {}", e),
      Self::TooSmall => write!(f, "File too small to be a valid binary"),
      Self::UnknownFormat => write!(f, "Unknown binary format"),
      Self::UnsupportedFormat => write!(f, "Unsupported binary format"),
      Self::InvalidHeader(s) => write!(f, "Invalid header: {}", s),
      Self::SectionNotFound(s) => write!(f, "Section not found: {}", s),
      Self::SymbolNotFound(s) => write!(f, "Symbol not found: {}", s),
      Self::ParseError(s) => write!(f, "Parse error: {}", s),
      Self::OutOfBounds => write!(f, "Out of bounds access"),
    }
  }
}

impl std::error::Error for BinaryError {}

impl From<std::io::Error> for BinaryError {
  fn from(e: std::io::Error) -> Self {
    Self::IoError(e)
  }
}

pub type BinaryResult<T> = Result<T, BinaryError>;

/// Binary format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
  Elf32,
  Elf64,
  Pe32,
  Pe64,
  Unknown,
}

impl std::fmt::Display for BinaryFormat {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Elf32 => write!(f, "ELF32"),
      Self::Elf64 => write!(f, "ELF64"),
      Self::Pe32 => write!(f, "PE32"),
      Self::Pe64 => write!(f, "PE32+"),
      Self::Unknown => write!(f, "Unknown"),
    }
  }
}

/// CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
  X86,
  X86_64,
  Arm,
  Arm64,
  Mips,
  PowerPc,
  RiscV,
  Unknown,
}

impl std::fmt::Display for Architecture {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::X86 => write!(f, "x86"),
      Self::X86_64 => write!(f, "x86-64"),
      Self::Arm => write!(f, "ARM"),
      Self::Arm64 => write!(f, "ARM64"),
      Self::Mips => write!(f, "MIPS"),
      Self::PowerPc => write!(f, "PowerPC"),
      Self::RiscV => write!(f, "RISC-V"),
      Self::Unknown => write!(f, "Unknown"),
    }
  }
}

/// Byte order (endianness)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
  Little,
  Big,
}

impl std::fmt::Display for Endianness {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Little => write!(f, "little-endian"),
      Self::Big => write!(f, "big-endian"),
    }
  }
}

/// Section flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SectionFlags(u32);

impl SectionFlags {
  pub const EXEC: u32 = 0x1;
  pub const WRITE: u32 = 0x2;
  pub const ALLOC: u32 = 0x4;

  pub fn new(flags: u32) -> Self {
    Self(flags)
  }

  pub fn is_exec(&self) -> bool {
    self.0 & Self::EXEC != 0
  }

  pub fn is_write(&self) -> bool {
    self.0 & Self::WRITE != 0
  }

  pub fn is_alloc(&self) -> bool {
    self.0 & Self::ALLOC != 0
  }

  pub fn bits(&self) -> u32 {
    self.0
  }
}

impl std::fmt::Display for SectionFlags {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut flags = String::new();
    if self.is_alloc() {
      flags.push('A');
    }
    if self.is_write() {
      flags.push('W');
    }
    if self.is_exec() {
      flags.push('X');
    }
    if flags.is_empty() {
      flags.push('-');
    }
    write!(f, "{}", flags)
  }
}

/// Binary section
#[derive(Debug, Clone)]
pub struct Section {
  pub name: String,
  pub vaddr: u64,
  pub offset: u64,
  pub size: u64,
  pub flags: SectionFlags,
  pub section_type: u32,
}

/// Symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
  NoType,
  Object,
  Func,
  Section,
  File,
  Common,
  Tls,
}

impl std::fmt::Display for SymbolType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::NoType => write!(f, "NOTYPE"),
      Self::Object => write!(f, "OBJECT"),
      Self::Func => write!(f, "FUNC"),
      Self::Section => write!(f, "SECTION"),
      Self::File => write!(f, "FILE"),
      Self::Common => write!(f, "COMMON"),
      Self::Tls => write!(f, "TLS"),
    }
  }
}

/// Symbol binding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
  Local,
  Global,
  Weak,
}

impl std::fmt::Display for SymbolBinding {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Local => write!(f, "LOCAL"),
      Self::Global => write!(f, "GLOBAL"),
      Self::Weak => write!(f, "WEAK"),
    }
  }
}

/// Binary symbol
#[derive(Debug, Clone)]
pub struct Symbol {
  pub name: String,
  pub value: u64,
  pub size: u64,
  pub sym_type: SymbolType,
  pub binding: SymbolBinding,
  pub section_index: u16,
}

/// Unified binary representation
#[derive(Debug)]
pub struct Binary {
  pub path: PathBuf,
  pub format: BinaryFormat,
  pub arch: Architecture,
  pub bits: u8,
  pub endian: Endianness,
  pub entry_point: u64,
  pub sections: Vec<Section>,
  pub symbols: Vec<Symbol>,
  pub plt: HashMap<String, u64>,
  pub got: HashMap<String, u64>,
  pub relocations: Vec<elf::RelocationEntry>,
  pub security: SecurityFeatures,
  data: Vec<u8>,
  pub(crate) program_headers: Vec<elf::ProgramHeader>,
  pub(crate) dynamic_entries: Vec<elf::DynamicEntry>,
  pub(crate) elf_type: u16,
}

impl Binary {
  /// Load and parse a binary file
  pub fn from_file<P: AsRef<Path>>(path: P) -> BinaryResult<Self> {
    let path = path.as_ref();
    let data = std::fs::read(path)?;
    let format = Self::detect_format(&data)?;

    match format {
      BinaryFormat::Elf32 | BinaryFormat::Elf64 => {
        ElfParser::parse(path.to_path_buf(), data, format)
      }
      BinaryFormat::Pe32 | BinaryFormat::Pe64 => PeParser::parse(path.to_path_buf(), data, format),
      BinaryFormat::Unknown => Err(BinaryError::UnknownFormat),
    }
  }

  /// Detect binary format from magic bytes
  pub fn detect_format(data: &[u8]) -> BinaryResult<BinaryFormat> {
    if data.len() < 64 {
      return Err(BinaryError::TooSmall);
    }

    // ELF magic: 0x7F 'E' 'L' 'F'
    if data.len() >= 5 && &data[0..4] == b"\x7FELF" {
      return Ok(if data[4] == 1 {
        BinaryFormat::Elf32
      } else {
        BinaryFormat::Elf64
      });
    }

    // PE magic: 'M' 'Z'
    if data.len() >= 0x40 && &data[0..2] == b"MZ" {
      let pe_offset = u32::from_le_bytes(
        data[0x3C..0x40]
          .try_into()
          .map_err(|_| BinaryError::InvalidHeader("PE offset".into()))?,
      ) as usize;

      if data.len() > pe_offset + 6 && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" {
        let machine = u16::from_le_bytes(
          data[pe_offset + 4..pe_offset + 6]
            .try_into()
            .map_err(|_| BinaryError::InvalidHeader("PE machine".into()))?,
        );
        return Ok(if machine == 0x8664 {
          BinaryFormat::Pe64
        } else {
          BinaryFormat::Pe32
        });
      }
    }

    Ok(BinaryFormat::Unknown)
  }

  pub fn data(&self) -> &[u8] {
    &self.data
  }

  pub fn read_section(&self, section: &Section) -> BinaryResult<&[u8]> {
    let start = section.offset as usize;
    let end = start + section.size as usize;
    if end > self.data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    Ok(&self.data[start..end])
  }

  pub fn find_section(&self, name: &str) -> Option<&Section> {
    self.sections.iter().find(|s| s.name == name)
  }

  pub fn find_symbol(&self, name: &str) -> Option<&Symbol> {
    self.symbols.iter().find(|s| s.name == name)
  }

  pub fn plt_address(&self, name: &str) -> Option<u64> {
    self.plt.get(name).copied()
  }

  pub fn got_address(&self, name: &str) -> Option<u64> {
    self.got.get(name).copied()
  }

  pub fn search_symbols(&self, pattern: &str) -> Vec<&Symbol> {
    let pattern_lower = pattern.to_lowercase();
    self
      .symbols
      .iter()
      .filter(|s| s.name.to_lowercase().contains(&pattern_lower))
      .collect()
  }

  pub fn executable_sections(&self) -> Vec<&Section> {
    self.sections.iter().filter(|s| s.flags.is_exec()).collect()
  }

  pub fn info(&self) -> String {
    let mut info = String::new();
    info.push_str(&format!("File:         {}\n", self.path.display()));
    info.push_str(&format!("Format:       {}\n", self.format));
    info.push_str(&format!("Architecture: {}\n", self.arch));
    info.push_str(&format!("Bits:         {}\n", self.bits));
    info.push_str(&format!("Endianness:   {}\n", self.endian));
    info.push_str(&format!("Entry Point:  0x{:x}\n", self.entry_point));
    info.push_str(&format!("Sections:     {}\n", self.sections.len()));
    info.push_str(&format!("Symbols:      {}\n", self.symbols.len()));
    info
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_detect_elf_format() {
    let elf64_magic = b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut data = elf64_magic.to_vec();
    data.extend(vec![0u8; 64]);
    let format = Binary::detect_format(&data).unwrap();
    assert_eq!(format, BinaryFormat::Elf64);
  }

  #[test]
  fn test_section_flags() {
    let flags = SectionFlags::new(SectionFlags::EXEC | SectionFlags::ALLOC);
    assert!(flags.is_exec());
    assert!(flags.is_alloc());
    assert!(!flags.is_write());
  }
}
