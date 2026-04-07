//! ELF format parsing
//!
//! Implements ELF32 and ELF64 parsing according to System V ABI.

use super::*;
use std::collections::HashMap;

// ELF Magic
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

// ELF Class (32/64 bit)
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

// ELF Data encoding
const ELFDATA2LSB: u8 = 1; // Little endian
const ELFDATA2MSB: u8 = 2; // Big endian

// ELF Type
const ET_EXEC: u16 = 2; // Executable
const ET_DYN: u16 = 3; // Shared object

// ELF Machine types
const EM_386: u16 = 3; // x86
const EM_ARM: u16 = 40; // ARM
const EM_X86_64: u16 = 62; // x86-64
const EM_AARCH64: u16 = 183; // ARM64
const EM_MIPS: u16 = 8; // MIPS
const EM_PPC: u16 = 20; // PowerPC
const EM_RISCV: u16 = 243; // RISC-V

// Program header types
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;

// Program header flags
const PF_X: u32 = 0x1; // Execute
const PF_W: u32 = 0x2; // Write
const PF_R: u32 = 0x4; // Read

// Section header types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;

// Section header flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

// Dynamic entry tags
const DT_NULL: u64 = 0;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_PLTGOT: u64 = 3;
const DT_JMPREL: u64 = 23;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6ffffffb;

// Section header types (additional)
const SHT_REL: u32 = 9;

// Dynamic entry tags (additional for relocation parsing)
const DT_PLTRELSZ: u64 = 2; // size of PLT relocation entries
const DT_RELAENT: u64 = 9; // size of RELA entry
const DT_SYMENT: u64 = 11; // size of symbol table entry
const DT_REL: u64 = 17; // .rel address
const DT_RELENT: u64 = 19; // size of REL entry
const DT_PLTREL: u64 = 20; // type of PLT relocs (DT_REL=17 or DT_RELA=7)

// Relocation types
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_386_JMP_SLOT: u32 = 7;

// Dynamic flags
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

// Symbol binding
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

// Symbol types
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_COMMON: u8 = 5;
const STT_TLS: u8 = 6;

/// ELF file header trait
pub trait ElfHeader {
  fn e_type(&self) -> u16;
  fn e_machine(&self) -> u16;
  fn e_entry(&self) -> u64;
  fn e_phoff(&self) -> u64;
  fn e_shoff(&self) -> u64;
  fn e_phentsize(&self) -> u16;
  fn e_phnum(&self) -> u16;
  fn e_shentsize(&self) -> u16;
  fn e_shnum(&self) -> u16;
  fn e_shstrndx(&self) -> u16;
}

/// ELF32 file header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf32Header {
  pub e_ident: [u8; 16],
  pub e_type: u16,
  pub e_machine: u16,
  pub e_version: u32,
  pub e_entry: u32,
  pub e_phoff: u32,
  pub e_shoff: u32,
  pub e_flags: u32,
  pub e_ehsize: u16,
  pub e_phentsize: u16,
  pub e_phnum: u16,
  pub e_shentsize: u16,
  pub e_shnum: u16,
  pub e_shstrndx: u16,
}

impl ElfHeader for Elf32Header {
  fn e_type(&self) -> u16 {
    self.e_type
  }
  fn e_machine(&self) -> u16 {
    self.e_machine
  }
  fn e_entry(&self) -> u64 {
    self.e_entry as u64
  }
  fn e_phoff(&self) -> u64 {
    self.e_phoff as u64
  }
  fn e_shoff(&self) -> u64 {
    self.e_shoff as u64
  }
  fn e_phentsize(&self) -> u16 {
    self.e_phentsize
  }
  fn e_phnum(&self) -> u16 {
    self.e_phnum
  }
  fn e_shentsize(&self) -> u16 {
    self.e_shentsize
  }
  fn e_shnum(&self) -> u16 {
    self.e_shnum
  }
  fn e_shstrndx(&self) -> u16 {
    self.e_shstrndx
  }
}

/// ELF64 file header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Header {
  pub e_ident: [u8; 16],
  pub e_type: u16,
  pub e_machine: u16,
  pub e_version: u32,
  pub e_entry: u64,
  pub e_phoff: u64,
  pub e_shoff: u64,
  pub e_flags: u32,
  pub e_ehsize: u16,
  pub e_phentsize: u16,
  pub e_phnum: u16,
  pub e_shentsize: u16,
  pub e_shnum: u16,
  pub e_shstrndx: u16,
}

impl ElfHeader for Elf64Header {
  fn e_type(&self) -> u16 {
    self.e_type
  }
  fn e_machine(&self) -> u16 {
    self.e_machine
  }
  fn e_entry(&self) -> u64 {
    self.e_entry
  }
  fn e_phoff(&self) -> u64 {
    self.e_phoff
  }
  fn e_shoff(&self) -> u64 {
    self.e_shoff
  }
  fn e_phentsize(&self) -> u16 {
    self.e_phentsize
  }
  fn e_phnum(&self) -> u16 {
    self.e_phnum
  }
  fn e_shentsize(&self) -> u16 {
    self.e_shentsize
  }
  fn e_shnum(&self) -> u16 {
    self.e_shnum
  }
  fn e_shstrndx(&self) -> u16 {
    self.e_shstrndx
  }
}

/// Program header
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramHeader {
  pub p_type: u32,
  pub p_flags: u32,
  pub p_offset: u64,
  pub p_vaddr: u64,
  pub p_paddr: u64,
  pub p_filesz: u64,
  pub p_memsz: u64,
  pub p_align: u64,
}

/// Section header
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionHeader {
  pub sh_name: u32,
  pub sh_type: u32,
  pub sh_flags: u64,
  pub sh_addr: u64,
  pub sh_offset: u64,
  pub sh_size: u64,
  pub sh_link: u32,
  pub sh_info: u32,
  pub sh_addralign: u64,
  pub sh_entsize: u64,
}

/// Dynamic entry
#[derive(Debug, Clone, Copy, Default)]
pub struct DynamicEntry {
  pub d_tag: u64,
  pub d_val: u64,
}

/// ELF symbol (internal)
#[derive(Debug, Clone, Default)]
struct ElfSymbol {
  st_name: u32,
  st_value: u64,
  st_size: u64,
  st_info: u8,
  st_other: u8,
  st_shndx: u16,
}

/// ELF relocation entry
#[derive(Debug, Clone)]
pub struct RelocationEntry {
  /// r_offset: GOT address where the resolved address will be written
  pub offset: u64,
  /// Symbol table index
  pub sym_index: u32,
  /// Relocation type
  pub rel_type: u32,
  /// r_addend (0 for REL, present for RELA)
  pub addend: i64,
  /// Resolved symbol name from .dynsym + .dynstr
  pub symbol_name: String,
}

/// ELF Parser
pub struct ElfParser;

impl ElfParser {
  /// Parse ELF binary
  pub fn parse(path: PathBuf, data: Vec<u8>, format: BinaryFormat) -> BinaryResult<Binary> {
    // Validate magic
    if data.len() < 16 || data[0..4] != ELF_MAGIC {
      return Err(BinaryError::InvalidHeader("Invalid ELF magic".into()));
    }

    let is_64bit = data[4] == ELFCLASS64;
    let is_le = data[5] == ELFDATA2LSB;
    let endian = if is_le {
      Endianness::Little
    } else {
      Endianness::Big
    };

    if is_64bit {
      Self::parse_elf64(path, data, endian)
    } else {
      Self::parse_elf32(path, data, endian)
    }
  }

  fn parse_elf64(path: PathBuf, data: Vec<u8>, endian: Endianness) -> BinaryResult<Binary> {
    if data.len() < 64 {
      return Err(BinaryError::TooSmall);
    }

    let header = Self::read_elf64_header(&data, endian)?;
    let arch = Self::machine_to_arch(header.e_machine);

    // Parse program headers
    let program_headers = Self::parse_program_headers_64(&data, &header, endian)?;

    // Parse section headers
    let section_headers = Self::parse_section_headers_64(&data, &header, endian)?;

    // Get section name string table
    let shstrtab = Self::get_string_table(&data, &section_headers, header.e_shstrndx as usize)?;

    // Build sections
    let sections = Self::build_sections(&section_headers, &shstrtab);

    // Parse dynamic section
    let dynamic_entries = Self::parse_dynamic_64(&data, &program_headers, endian)?;

    // Parse symbols and relocations
    let (symbols, plt, got, relocations) =
      Self::parse_symbols_64(&data, &section_headers, &dynamic_entries, &shstrtab, endian)?;

    // Build security features
    let mut binary = Binary {
      path,
      format: BinaryFormat::Elf64,
      arch,
      bits: 64,
      endian,
      entry_point: header.e_entry,
      sections,
      symbols,
      plt,
      got,
      relocations,
      security: SecurityFeatures::default(),
      data,
      program_headers,
      dynamic_entries,
      elf_type: header.e_type,
    };

    // Detect security features
    binary.security = SecurityFeatures::detect_elf(&binary);

    Ok(binary)
  }

  fn parse_elf32(path: PathBuf, data: Vec<u8>, endian: Endianness) -> BinaryResult<Binary> {
    if data.len() < 52 {
      return Err(BinaryError::TooSmall);
    }

    let header = Self::read_elf32_header(&data, endian)?;
    let arch = Self::machine_to_arch(header.e_machine);

    // Parse program headers
    let program_headers = Self::parse_program_headers_32(&data, &header, endian)?;

    // Parse section headers
    let section_headers = Self::parse_section_headers_32(&data, &header, endian)?;

    // Get section name string table
    let shstrtab = Self::get_string_table(&data, &section_headers, header.e_shstrndx as usize)?;

    // Build sections
    let sections = Self::build_sections(&section_headers, &shstrtab);

    // Parse dynamic section
    let dynamic_entries = Self::parse_dynamic_32(&data, &program_headers, endian)?;

    // Parse symbols and relocations
    let (symbols, plt, got, relocations) =
      Self::parse_symbols_32(&data, &section_headers, &dynamic_entries, &shstrtab, endian)?;

    let mut binary = Binary {
      path,
      format: BinaryFormat::Elf32,
      arch,
      bits: 32,
      endian,
      entry_point: header.e_entry as u64,
      sections,
      symbols,
      plt,
      got,
      relocations,
      security: SecurityFeatures::default(),
      data,
      program_headers,
      dynamic_entries,
      elf_type: header.e_type,
    };

    binary.security = SecurityFeatures::detect_elf(&binary);

    Ok(binary)
  }

  fn read_elf64_header(data: &[u8], endian: Endianness) -> BinaryResult<Elf64Header> {
    let read_u16 = |off: usize| Self::read_u16(data, off, endian);
    let read_u32 = |off: usize| Self::read_u32(data, off, endian);
    let read_u64 = |off: usize| Self::read_u64(data, off, endian);

    let mut e_ident = [0u8; 16];
    e_ident.copy_from_slice(&data[0..16]);

    Ok(Elf64Header {
      e_ident,
      e_type: read_u16(16)?,
      e_machine: read_u16(18)?,
      e_version: read_u32(20)?,
      e_entry: read_u64(24)?,
      e_phoff: read_u64(32)?,
      e_shoff: read_u64(40)?,
      e_flags: read_u32(48)?,
      e_ehsize: read_u16(52)?,
      e_phentsize: read_u16(54)?,
      e_phnum: read_u16(56)?,
      e_shentsize: read_u16(58)?,
      e_shnum: read_u16(60)?,
      e_shstrndx: read_u16(62)?,
    })
  }

  fn read_elf32_header(data: &[u8], endian: Endianness) -> BinaryResult<Elf32Header> {
    let read_u16 = |off: usize| Self::read_u16(data, off, endian);
    let read_u32 = |off: usize| Self::read_u32(data, off, endian);

    let mut e_ident = [0u8; 16];
    e_ident.copy_from_slice(&data[0..16]);

    Ok(Elf32Header {
      e_ident,
      e_type: read_u16(16)?,
      e_machine: read_u16(18)?,
      e_version: read_u32(20)?,
      e_entry: read_u32(24)?,
      e_phoff: read_u32(28)?,
      e_shoff: read_u32(32)?,
      e_flags: read_u32(36)?,
      e_ehsize: read_u16(40)?,
      e_phentsize: read_u16(42)?,
      e_phnum: read_u16(44)?,
      e_shentsize: read_u16(46)?,
      e_shnum: read_u16(48)?,
      e_shstrndx: read_u16(50)?,
    })
  }

  fn parse_program_headers_64(
    data: &[u8],
    header: &Elf64Header,
    endian: Endianness,
  ) -> BinaryResult<Vec<ProgramHeader>> {
    let mut phdrs = Vec::new();
    let phoff = header.e_phoff as usize;
    let phentsize = header.e_phentsize as usize;

    for i in 0..header.e_phnum as usize {
      let off = phoff + i * phentsize;
      if off + 56 > data.len() {
        break;
      }

      phdrs.push(ProgramHeader {
        p_type: Self::read_u32(data, off, endian)?,
        p_flags: Self::read_u32(data, off + 4, endian)?,
        p_offset: Self::read_u64(data, off + 8, endian)?,
        p_vaddr: Self::read_u64(data, off + 16, endian)?,
        p_paddr: Self::read_u64(data, off + 24, endian)?,
        p_filesz: Self::read_u64(data, off + 32, endian)?,
        p_memsz: Self::read_u64(data, off + 40, endian)?,
        p_align: Self::read_u64(data, off + 48, endian)?,
      });
    }

    Ok(phdrs)
  }

  fn parse_program_headers_32(
    data: &[u8],
    header: &Elf32Header,
    endian: Endianness,
  ) -> BinaryResult<Vec<ProgramHeader>> {
    let mut phdrs = Vec::new();
    let phoff = header.e_phoff as usize;
    let phentsize = header.e_phentsize as usize;

    for i in 0..header.e_phnum as usize {
      let off = phoff + i * phentsize;
      if off + 32 > data.len() {
        break;
      }

      phdrs.push(ProgramHeader {
        p_type: Self::read_u32(data, off, endian)?,
        p_offset: Self::read_u32(data, off + 4, endian)? as u64,
        p_vaddr: Self::read_u32(data, off + 8, endian)? as u64,
        p_paddr: Self::read_u32(data, off + 12, endian)? as u64,
        p_filesz: Self::read_u32(data, off + 16, endian)? as u64,
        p_memsz: Self::read_u32(data, off + 20, endian)? as u64,
        p_flags: Self::read_u32(data, off + 24, endian)?,
        p_align: Self::read_u32(data, off + 28, endian)? as u64,
      });
    }

    Ok(phdrs)
  }

  fn parse_section_headers_64(
    data: &[u8],
    header: &Elf64Header,
    endian: Endianness,
  ) -> BinaryResult<Vec<SectionHeader>> {
    let mut shdrs = Vec::new();
    let shoff = header.e_shoff as usize;
    let shentsize = header.e_shentsize as usize;

    for i in 0..header.e_shnum as usize {
      let off = shoff + i * shentsize;
      if off + 64 > data.len() {
        break;
      }

      shdrs.push(SectionHeader {
        sh_name: Self::read_u32(data, off, endian)?,
        sh_type: Self::read_u32(data, off + 4, endian)?,
        sh_flags: Self::read_u64(data, off + 8, endian)?,
        sh_addr: Self::read_u64(data, off + 16, endian)?,
        sh_offset: Self::read_u64(data, off + 24, endian)?,
        sh_size: Self::read_u64(data, off + 32, endian)?,
        sh_link: Self::read_u32(data, off + 40, endian)?,
        sh_info: Self::read_u32(data, off + 44, endian)?,
        sh_addralign: Self::read_u64(data, off + 48, endian)?,
        sh_entsize: Self::read_u64(data, off + 56, endian)?,
      });
    }

    Ok(shdrs)
  }

  fn parse_section_headers_32(
    data: &[u8],
    header: &Elf32Header,
    endian: Endianness,
  ) -> BinaryResult<Vec<SectionHeader>> {
    let mut shdrs = Vec::new();
    let shoff = header.e_shoff as usize;
    let shentsize = header.e_shentsize as usize;

    for i in 0..header.e_shnum as usize {
      let off = shoff + i * shentsize;
      if off + 40 > data.len() {
        break;
      }

      shdrs.push(SectionHeader {
        sh_name: Self::read_u32(data, off, endian)?,
        sh_type: Self::read_u32(data, off + 4, endian)?,
        sh_flags: Self::read_u32(data, off + 8, endian)? as u64,
        sh_addr: Self::read_u32(data, off + 12, endian)? as u64,
        sh_offset: Self::read_u32(data, off + 16, endian)? as u64,
        sh_size: Self::read_u32(data, off + 20, endian)? as u64,
        sh_link: Self::read_u32(data, off + 24, endian)?,
        sh_info: Self::read_u32(data, off + 28, endian)?,
        sh_addralign: Self::read_u32(data, off + 32, endian)? as u64,
        sh_entsize: Self::read_u32(data, off + 36, endian)? as u64,
      });
    }

    Ok(shdrs)
  }

  fn parse_dynamic_64(
    data: &[u8],
    phdrs: &[ProgramHeader],
    endian: Endianness,
  ) -> BinaryResult<Vec<DynamicEntry>> {
    let mut entries = Vec::new();

    // Find PT_DYNAMIC
    let dynamic_phdr = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC);
    let Some(phdr) = dynamic_phdr else {
      return Ok(entries);
    };

    let offset = phdr.p_offset as usize;
    let size = phdr.p_filesz as usize;

    let mut i = 0;
    while i + 16 <= size && offset + i + 16 <= data.len() {
      let d_tag = Self::read_u64(data, offset + i, endian)?;
      let d_val = Self::read_u64(data, offset + i + 8, endian)?;

      if d_tag == DT_NULL {
        break;
      }

      entries.push(DynamicEntry { d_tag, d_val });
      i += 16;
    }

    Ok(entries)
  }

  fn parse_dynamic_32(
    data: &[u8],
    phdrs: &[ProgramHeader],
    endian: Endianness,
  ) -> BinaryResult<Vec<DynamicEntry>> {
    let mut entries = Vec::new();

    let dynamic_phdr = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC);
    let Some(phdr) = dynamic_phdr else {
      return Ok(entries);
    };

    let offset = phdr.p_offset as usize;
    let size = phdr.p_filesz as usize;

    let mut i = 0;
    while i + 8 <= size && offset + i + 8 <= data.len() {
      let d_tag = Self::read_u32(data, offset + i, endian)? as u64;
      let d_val = Self::read_u32(data, offset + i + 4, endian)? as u64;

      if d_tag == DT_NULL {
        break;
      }

      entries.push(DynamicEntry { d_tag, d_val });
      i += 8;
    }

    Ok(entries)
  }

  fn parse_symbols_64(
    data: &[u8],
    shdrs: &[SectionHeader],
    dynamic: &[DynamicEntry],
    shstrtab: &[u8],
    endian: Endianness,
  ) -> BinaryResult<(
    Vec<Symbol>,
    HashMap<String, u64>,
    HashMap<String, u64>,
    Vec<RelocationEntry>,
  )> {
    let mut symbols = Vec::new();
    let mut plt = HashMap::new();
    let mut got = HashMap::new();

    // Find .dynsym and .symtab sections
    for shdr in shdrs.iter() {
      if shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM {
        continue;
      }

      // Get string table for this symbol table
      let strtab_idx = shdr.sh_link as usize;
      if strtab_idx >= shdrs.len() {
        continue;
      }

      let strtab_shdr = &shdrs[strtab_idx];
      let strtab_off = strtab_shdr.sh_offset as usize;
      let strtab_size = strtab_shdr.sh_size as usize;

      if strtab_off + strtab_size > data.len() {
        continue;
      }

      let strtab = &data[strtab_off..strtab_off + strtab_size];

      // Parse symbols
      let sym_off = shdr.sh_offset as usize;
      let sym_size = shdr.sh_size as usize;
      let entsize = if shdr.sh_entsize > 0 {
        shdr.sh_entsize as usize
      } else {
        24
      };

      let mut j = 0;
      while j + entsize <= sym_size && sym_off + j + entsize <= data.len() {
        let off = sym_off + j;

        let st_name = Self::read_u32(data, off, endian)?;
        let st_info = data[off + 4];
        let _st_other = data[off + 5];
        let st_shndx = Self::read_u16(data, off + 6, endian)?;
        let st_value = Self::read_u64(data, off + 8, endian)?;
        let st_size = Self::read_u64(data, off + 16, endian)?;

        let name = Self::read_string(strtab, st_name as usize);

        if !name.is_empty() {
          symbols.push(Symbol {
            name,
            value: st_value,
            size: st_size,
            sym_type: Self::info_to_type(st_info & 0xf),
            binding: Self::info_to_binding(st_info >> 4),
            section_index: st_shndx,
          });
        }

        j += entsize;
      }
    }

    // Parse relocations and build PLT/GOT maps
    let relocations = Self::parse_relocations_64(data, dynamic, shdrs, shstrtab, endian);

    // Find .plt section base address for computing PLT entry addresses
    let plt_base = shdrs
      .iter()
      .find(|shdr| Self::section_name(shdr, shstrtab) == ".plt")
      .map(|shdr| shdr.sh_addr);

    // PLT entry size is 16 bytes on x86_64
    let plt_entry_size: u64 = 16;

    for (idx, reloc) in relocations.iter().enumerate() {
      if reloc.rel_type == R_X86_64_JUMP_SLOT && !reloc.symbol_name.is_empty() {
        // GOT entry: r_offset is the GOT slot virtual address
        got.insert(reloc.symbol_name.clone(), reloc.offset);

        // PLT entry: first PLT entry is the resolver stub, actual entries start at index+1
        if let Some(base) = plt_base {
          let plt_addr = base + ((idx as u64) + 1) * plt_entry_size;
          plt.insert(reloc.symbol_name.clone(), plt_addr);
        }
      }
    }

    Ok((symbols, plt, got, relocations))
  }

  fn parse_symbols_32(
    data: &[u8],
    shdrs: &[SectionHeader],
    dynamic: &[DynamicEntry],
    shstrtab: &[u8],
    endian: Endianness,
  ) -> BinaryResult<(
    Vec<Symbol>,
    HashMap<String, u64>,
    HashMap<String, u64>,
    Vec<RelocationEntry>,
  )> {
    let mut symbols = Vec::new();
    let mut plt = HashMap::new();
    let mut got = HashMap::new();

    for shdr in shdrs.iter() {
      if shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM {
        continue;
      }

      let strtab_idx = shdr.sh_link as usize;
      if strtab_idx >= shdrs.len() {
        continue;
      }

      let strtab_shdr = &shdrs[strtab_idx];
      let strtab_off = strtab_shdr.sh_offset as usize;
      let strtab_size = strtab_shdr.sh_size as usize;

      if strtab_off + strtab_size > data.len() {
        continue;
      }

      let strtab = &data[strtab_off..strtab_off + strtab_size];

      let sym_off = shdr.sh_offset as usize;
      let sym_size = shdr.sh_size as usize;
      let entsize = if shdr.sh_entsize > 0 {
        shdr.sh_entsize as usize
      } else {
        16
      };

      let mut j = 0;
      while j + entsize <= sym_size && sym_off + j + entsize <= data.len() {
        let off = sym_off + j;

        let st_name = Self::read_u32(data, off, endian)?;
        let st_value = Self::read_u32(data, off + 4, endian)? as u64;
        let st_size = Self::read_u32(data, off + 8, endian)? as u64;
        let st_info = data[off + 12];
        let _st_other = data[off + 13];
        let st_shndx = Self::read_u16(data, off + 14, endian)?;

        let name = Self::read_string(strtab, st_name as usize);

        if !name.is_empty() {
          symbols.push(Symbol {
            name,
            value: st_value,
            size: st_size,
            sym_type: Self::info_to_type(st_info & 0xf),
            binding: Self::info_to_binding(st_info >> 4),
            section_index: st_shndx,
          });
        }

        j += entsize;
      }
    }

    // Parse relocations and build PLT/GOT maps
    let relocations = Self::parse_relocations_32(data, dynamic, shdrs, shstrtab, endian);

    // Find .plt section base address for computing PLT entry addresses
    let plt_base = shdrs
      .iter()
      .find(|shdr| Self::section_name(shdr, shstrtab) == ".plt")
      .map(|shdr| shdr.sh_addr);

    // PLT entry size is 16 bytes on x86
    let plt_entry_size: u64 = 16;

    for (idx, reloc) in relocations.iter().enumerate() {
      if reloc.rel_type == R_386_JMP_SLOT && !reloc.symbol_name.is_empty() {
        // GOT entry: r_offset is the GOT slot virtual address
        got.insert(reloc.symbol_name.clone(), reloc.offset);

        // PLT entry: first PLT entry is the resolver stub, actual entries start at index+1
        if let Some(base) = plt_base {
          let plt_addr = base + ((idx as u64) + 1) * plt_entry_size;
          plt.insert(reloc.symbol_name.clone(), plt_addr);
        }
      }
    }

    Ok((symbols, plt, got, relocations))
  }

  fn get_string_table(data: &[u8], shdrs: &[SectionHeader], index: usize) -> BinaryResult<Vec<u8>> {
    if index >= shdrs.len() {
      return Ok(Vec::new());
    }

    let shdr = &shdrs[index];
    let offset = shdr.sh_offset as usize;
    let size = shdr.sh_size as usize;

    if offset + size > data.len() {
      return Ok(Vec::new());
    }

    Ok(data[offset..offset + size].to_vec())
  }

  /// Convert a virtual address to a file offset using section headers.
  fn vaddr_to_offset(shdrs: &[SectionHeader], vaddr: u64) -> Option<usize> {
    for shdr in shdrs {
      if shdr.sh_size > 0 && shdr.sh_addr <= vaddr && vaddr < shdr.sh_addr + shdr.sh_size {
        return Some((shdr.sh_offset + (vaddr - shdr.sh_addr)) as usize);
      }
    }
    None
  }

  /// Get section name from section header using the section name string table.
  fn section_name(shdr: &SectionHeader, shstrtab: &[u8]) -> String {
    Self::read_string(shstrtab, shdr.sh_name as usize)
  }

  /// Parse 64-bit relocations from PLT relocation table.
  /// Handles both RELA (24 bytes: r_offset, r_info, r_addend) and
  /// REL (16 bytes: r_offset, r_info) formats.
  fn parse_relocations_64(
    data: &[u8],
    dynamic: &[DynamicEntry],
    shdrs: &[SectionHeader],
    shstrtab: &[u8],
    endian: Endianness,
  ) -> Vec<RelocationEntry> {
    let mut entries = Vec::new();

    // Extract dynamic entry values
    let mut jmprel_vaddr: Option<u64> = None;
    let mut pltrelsz: Option<u64> = None;
    let mut pltrel_type: Option<u64> = None;
    let mut symtab_vaddr: Option<u64> = None;
    let mut strtab_vaddr: Option<u64> = None;
    let mut strsz: Option<u64> = None;

    for d in dynamic {
      match d.d_tag {
        DT_JMPREL => jmprel_vaddr = Some(d.d_val),
        DT_PLTRELSZ => pltrelsz = Some(d.d_val),
        DT_PLTREL => pltrel_type = Some(d.d_val),
        DT_SYMTAB => symtab_vaddr = Some(d.d_val),
        DT_STRTAB => strtab_vaddr = Some(d.d_val),
        DT_STRSZ => strsz = Some(d.d_val),
        _ => {}
      }
    }

    // Strategy 1: Use DT_JMPREL + DT_PLTRELSZ from dynamic entries
    let (rel_offset, rel_size, is_rela) =
      if let (Some(jmprel), Some(sz), Some(ptype)) = (jmprel_vaddr, pltrelsz, pltrel_type) {
        let offset = match Self::vaddr_to_offset(shdrs, jmprel) {
          Some(o) => o,
          None => return entries,
        };
        // DT_PLTREL value of 7 (DT_RELA constant) means RELA, 17 (DT_REL) means REL
        let is_rela = ptype == 7;
        (offset, sz as usize, is_rela)
      } else {
        // Strategy 2 (fallback): Find .rela.plt or .rel.plt section
        let mut found = None;
        for shdr in shdrs {
          let name = Self::section_name(shdr, shstrtab);
          if name == ".rela.plt" && shdr.sh_type == SHT_RELA {
            found = Some((shdr.sh_offset as usize, shdr.sh_size as usize, true));
            break;
          } else if name == ".rel.plt" && shdr.sh_type == SHT_REL {
            found = Some((shdr.sh_offset as usize, shdr.sh_size as usize, false));
            break;
          }
        }
        match found {
          Some(v) => v,
          None => return entries,
        }
      };

    // Resolve .dynsym and .dynstr file offsets
    let (symtab_off, strtab_off, strtab_sz) =
      if let (Some(sv), Some(tv), Some(tsz)) = (symtab_vaddr, strtab_vaddr, strsz) {
        let so = match Self::vaddr_to_offset(shdrs, sv) {
          Some(o) => o,
          None => return entries,
        };
        let to = match Self::vaddr_to_offset(shdrs, tv) {
          Some(o) => o,
          None => return entries,
        };
        (so, to, tsz as usize)
      } else {
        // Fallback: find .dynsym and .dynstr sections directly
        let mut dynsym_off = None;
        let mut dynstr_off = None;
        let mut dynstr_sz = 0usize;
        for shdr in shdrs {
          if shdr.sh_type == SHT_DYNSYM {
            dynsym_off = Some(shdr.sh_offset as usize);
          }
          let name = Self::section_name(shdr, shstrtab);
          if name == ".dynstr" && shdr.sh_type == SHT_STRTAB {
            dynstr_off = Some(shdr.sh_offset as usize);
            dynstr_sz = shdr.sh_size as usize;
          }
        }
        match (dynsym_off, dynstr_off) {
          (Some(so), Some(to)) => (so, to, dynstr_sz),
          _ => return entries,
        }
      };

    if strtab_off + strtab_sz > data.len() {
      return entries;
    }
    let strtab = &data[strtab_off..strtab_off + strtab_sz];

    // Entry size: RELA = 24 bytes, REL = 16 bytes (64-bit)
    let entsize = if is_rela { 24usize } else { 16usize };
    // Symbol table entry size for 64-bit ELF is 24 bytes
    let sym_entsize = 24usize;

    let mut i = 0;
    while i + entsize <= rel_size && rel_offset + i + entsize <= data.len() {
      let off = rel_offset + i;

      let r_offset = match Self::read_u64(data, off, endian) {
        Ok(v) => v,
        Err(_) => break,
      };
      let r_info = match Self::read_u64(data, off + 8, endian) {
        Ok(v) => v,
        Err(_) => break,
      };
      let r_addend = if is_rela {
        match Self::read_u64(data, off + 16, endian) {
          Ok(v) => v as i64,
          Err(_) => break,
        }
      } else {
        0i64
      };

      // 64-bit: sym_index = upper 32 bits, rel_type = lower 32 bits
      let sym_index = (r_info >> 32) as u32;
      let rel_type = (r_info & 0xffffffff) as u32;

      // Look up symbol name from .dynsym + .dynstr
      let symbol_name = {
        let sym_off = symtab_off + (sym_index as usize) * sym_entsize;
        if sym_off + sym_entsize <= data.len() {
          let st_name = Self::read_u32(data, sym_off, endian).unwrap_or(0);
          Self::read_string(strtab, st_name as usize)
        } else {
          String::new()
        }
      };

      entries.push(RelocationEntry {
        offset: r_offset,
        sym_index,
        rel_type,
        addend: r_addend,
        symbol_name,
      });

      i += entsize;
    }

    entries
  }

  /// Parse 32-bit relocations from PLT relocation table.
  /// Handles both RELA (12 bytes: r_offset, r_info, r_addend) and
  /// REL (8 bytes: r_offset, r_info) formats.
  fn parse_relocations_32(
    data: &[u8],
    dynamic: &[DynamicEntry],
    shdrs: &[SectionHeader],
    shstrtab: &[u8],
    endian: Endianness,
  ) -> Vec<RelocationEntry> {
    let mut entries = Vec::new();

    // Extract dynamic entry values
    let mut jmprel_vaddr: Option<u64> = None;
    let mut pltrelsz: Option<u64> = None;
    let mut pltrel_type: Option<u64> = None;
    let mut symtab_vaddr: Option<u64> = None;
    let mut strtab_vaddr: Option<u64> = None;
    let mut strsz: Option<u64> = None;

    for d in dynamic {
      match d.d_tag {
        DT_JMPREL => jmprel_vaddr = Some(d.d_val),
        DT_PLTRELSZ => pltrelsz = Some(d.d_val),
        DT_PLTREL => pltrel_type = Some(d.d_val),
        DT_SYMTAB => symtab_vaddr = Some(d.d_val),
        DT_STRTAB => strtab_vaddr = Some(d.d_val),
        DT_STRSZ => strsz = Some(d.d_val),
        _ => {}
      }
    }

    // Strategy 1: Use DT_JMPREL + DT_PLTRELSZ from dynamic entries
    let (rel_offset, rel_size, is_rela) =
      if let (Some(jmprel), Some(sz), Some(ptype)) = (jmprel_vaddr, pltrelsz, pltrel_type) {
        let offset = match Self::vaddr_to_offset(shdrs, jmprel) {
          Some(o) => o,
          None => return entries,
        };
        let is_rela = ptype == 7;
        (offset, sz as usize, is_rela)
      } else {
        // Strategy 2 (fallback): Find .rel.plt or .rela.plt section
        let mut found = None;
        for shdr in shdrs {
          let name = Self::section_name(shdr, shstrtab);
          if name == ".rel.plt" && shdr.sh_type == SHT_REL {
            found = Some((shdr.sh_offset as usize, shdr.sh_size as usize, false));
            break;
          } else if name == ".rela.plt" && shdr.sh_type == SHT_RELA {
            found = Some((shdr.sh_offset as usize, shdr.sh_size as usize, true));
            break;
          }
        }
        match found {
          Some(v) => v,
          None => return entries,
        }
      };

    // Resolve .dynsym and .dynstr file offsets
    let (symtab_off, strtab_off, strtab_sz) =
      if let (Some(sv), Some(tv), Some(tsz)) = (symtab_vaddr, strtab_vaddr, strsz) {
        let so = match Self::vaddr_to_offset(shdrs, sv) {
          Some(o) => o,
          None => return entries,
        };
        let to = match Self::vaddr_to_offset(shdrs, tv) {
          Some(o) => o,
          None => return entries,
        };
        (so, to, tsz as usize)
      } else {
        let mut dynsym_off = None;
        let mut dynstr_off = None;
        let mut dynstr_sz = 0usize;
        for shdr in shdrs {
          if shdr.sh_type == SHT_DYNSYM {
            dynsym_off = Some(shdr.sh_offset as usize);
          }
          let name = Self::section_name(shdr, shstrtab);
          if name == ".dynstr" && shdr.sh_type == SHT_STRTAB {
            dynstr_off = Some(shdr.sh_offset as usize);
            dynstr_sz = shdr.sh_size as usize;
          }
        }
        match (dynsym_off, dynstr_off) {
          (Some(so), Some(to)) => (so, to, dynstr_sz),
          _ => return entries,
        }
      };

    if strtab_off + strtab_sz > data.len() {
      return entries;
    }
    let strtab = &data[strtab_off..strtab_off + strtab_sz];

    // Entry size: RELA = 12 bytes, REL = 8 bytes (32-bit)
    let entsize = if is_rela { 12usize } else { 8usize };
    // Symbol table entry size for 32-bit ELF is 16 bytes
    let sym_entsize = 16usize;

    let mut i = 0;
    while i + entsize <= rel_size && rel_offset + i + entsize <= data.len() {
      let off = rel_offset + i;

      let r_offset = match Self::read_u32(data, off, endian) {
        Ok(v) => v as u64,
        Err(_) => break,
      };
      let r_info = match Self::read_u32(data, off + 4, endian) {
        Ok(v) => v,
        Err(_) => break,
      };
      let r_addend = if is_rela {
        match Self::read_u32(data, off + 8, endian) {
          Ok(v) => v as i32 as i64,
          Err(_) => break,
        }
      } else {
        0i64
      };

      // 32-bit: sym_index = upper 24 bits, rel_type = lower 8 bits
      let sym_index = (r_info >> 8) as u32;
      let rel_type = (r_info & 0xff) as u32;

      // Look up symbol name from .dynsym + .dynstr
      let symbol_name = {
        let sym_off = symtab_off + (sym_index as usize) * sym_entsize;
        if sym_off + sym_entsize <= data.len() {
          let st_name = Self::read_u32(data, sym_off, endian).unwrap_or(0);
          Self::read_string(strtab, st_name as usize)
        } else {
          String::new()
        }
      };

      entries.push(RelocationEntry {
        offset: r_offset,
        sym_index,
        rel_type,
        addend: r_addend,
        symbol_name,
      });

      i += entsize;
    }

    entries
  }

  fn build_sections(shdrs: &[SectionHeader], strtab: &[u8]) -> Vec<Section> {
    shdrs
      .iter()
      .map(|shdr| {
        let name = Self::read_string(strtab, shdr.sh_name as usize);
        let mut flags = 0u32;
        if shdr.sh_flags & SHF_EXECINSTR != 0 {
          flags |= SectionFlags::EXEC;
        }
        if shdr.sh_flags & SHF_WRITE != 0 {
          flags |= SectionFlags::WRITE;
        }
        if shdr.sh_flags & SHF_ALLOC != 0 {
          flags |= SectionFlags::ALLOC;
        }

        Section {
          name,
          vaddr: shdr.sh_addr,
          offset: shdr.sh_offset,
          size: shdr.sh_size,
          flags: SectionFlags::new(flags),
          section_type: shdr.sh_type,
        }
      })
      .collect()
  }

  fn read_string(strtab: &[u8], offset: usize) -> String {
    if offset >= strtab.len() {
      return String::new();
    }

    let end = strtab[offset..]
      .iter()
      .position(|&b| b == 0)
      .map(|p| offset + p)
      .unwrap_or(strtab.len());

    String::from_utf8_lossy(&strtab[offset..end]).to_string()
  }

  fn machine_to_arch(machine: u16) -> Architecture {
    match machine {
      EM_386 => Architecture::X86,
      EM_X86_64 => Architecture::X86_64,
      EM_ARM => Architecture::Arm,
      EM_AARCH64 => Architecture::Arm64,
      EM_MIPS => Architecture::Mips,
      EM_PPC => Architecture::PowerPc,
      EM_RISCV => Architecture::RiscV,
      _ => Architecture::Unknown,
    }
  }

  fn info_to_type(info: u8) -> SymbolType {
    match info {
      STT_NOTYPE => SymbolType::NoType,
      STT_OBJECT => SymbolType::Object,
      STT_FUNC => SymbolType::Func,
      STT_SECTION => SymbolType::Section,
      STT_FILE => SymbolType::File,
      STT_COMMON => SymbolType::Common,
      STT_TLS => SymbolType::Tls,
      _ => SymbolType::NoType,
    }
  }

  fn info_to_binding(info: u8) -> SymbolBinding {
    match info {
      STB_LOCAL => SymbolBinding::Local,
      STB_GLOBAL => SymbolBinding::Global,
      STB_WEAK => SymbolBinding::Weak,
      _ => SymbolBinding::Local,
    }
  }

  // Byte reading helpers
  fn read_u16(data: &[u8], offset: usize, endian: Endianness) -> BinaryResult<u16> {
    if offset + 2 > data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    let bytes: [u8; 2] = data[offset..offset + 2].try_into().unwrap();
    Ok(match endian {
      Endianness::Little => u16::from_le_bytes(bytes),
      Endianness::Big => u16::from_be_bytes(bytes),
    })
  }

  fn read_u32(data: &[u8], offset: usize, endian: Endianness) -> BinaryResult<u32> {
    if offset + 4 > data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
    Ok(match endian {
      Endianness::Little => u32::from_le_bytes(bytes),
      Endianness::Big => u32::from_be_bytes(bytes),
    })
  }

  fn read_u64(data: &[u8], offset: usize, endian: Endianness) -> BinaryResult<u64> {
    if offset + 8 > data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
    Ok(match endian {
      Endianness::Little => u64::from_le_bytes(bytes),
      Endianness::Big => u64::from_be_bytes(bytes),
    })
  }
}

// Re-export constants for security checks
pub(crate) const PT_GNU_STACK_VAL: u32 = PT_GNU_STACK;
pub(crate) const PT_GNU_RELRO_VAL: u32 = PT_GNU_RELRO;
pub(crate) const PF_X_VAL: u32 = PF_X;
pub(crate) const DT_FLAGS_VAL: u64 = DT_FLAGS;
pub(crate) const DT_FLAGS_1_VAL: u64 = DT_FLAGS_1;
pub(crate) const DF_BIND_NOW_VAL: u64 = DF_BIND_NOW;
pub(crate) const DF_1_NOW_VAL: u64 = DF_1_NOW;
pub(crate) const ET_DYN_VAL: u16 = ET_DYN;
