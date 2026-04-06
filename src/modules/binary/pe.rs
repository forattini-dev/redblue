//! PE format parsing
//!
//! Implements PE32 and PE32+ (PE64) parsing according to Microsoft PE/COFF spec.

use super::*;
use std::collections::HashMap;

// DOS Header magic
const DOS_MAGIC: [u8; 2] = [b'M', b'Z'];

// PE Signature
const PE_SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];

// Machine types
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

// Optional header magic
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;

// Section flags
const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// DLL Characteristics
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040; // ASLR
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100; // DEP/NX
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400; // No SEH
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000; // Control Flow Guard

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

/// PE header information
#[derive(Debug, Clone)]
pub struct PeHeader {
  pub machine: u16,
  pub number_of_sections: u16,
  pub timestamp: u32,
  pub characteristics: u16,
  pub magic: u16,
  pub entry_point: u64,
  pub image_base: u64,
  pub section_alignment: u32,
  pub file_alignment: u32,
  pub size_of_image: u32,
  pub dll_characteristics: u16,
  pub data_directories: Vec<DataDirectory>,
}

/// Data directory entry
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
  pub virtual_address: u32,
  pub size: u32,
}

/// PE section header
#[derive(Debug, Clone)]
pub struct PeSectionHeader {
  pub name: String,
  pub virtual_size: u32,
  pub virtual_address: u32,
  pub size_of_raw_data: u32,
  pub pointer_to_raw_data: u32,
  pub characteristics: u32,
}

/// Import descriptor
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
  pub dll_name: String,
  pub functions: Vec<String>,
}

/// Export descriptor
#[derive(Debug, Clone)]
pub struct ExportDescriptor {
  pub name: String,
  pub ordinal: u16,
  pub address: u32,
}

/// PE Parser
pub struct PeParser;

impl PeParser {
  /// Parse PE binary
  pub fn parse(path: PathBuf, data: Vec<u8>, format: BinaryFormat) -> BinaryResult<Binary> {
    // Validate DOS header
    if data.len() < 64 || data[0..2] != DOS_MAGIC {
      return Err(BinaryError::InvalidHeader("Invalid DOS header".into()));
    }

    // Get PE header offset
    let pe_offset = u32::from_le_bytes(
      data[0x3C..0x40]
        .try_into()
        .map_err(|_| BinaryError::InvalidHeader("Invalid PE offset".into()))?,
    ) as usize;

    // Validate PE signature
    if data.len() < pe_offset + 4 || data[pe_offset..pe_offset + 4] != PE_SIGNATURE {
      return Err(BinaryError::InvalidHeader("Invalid PE signature".into()));
    }

    let coff_offset = pe_offset + 4;

    // Parse COFF header
    let machine = Self::read_u16(&data, coff_offset)?;
    let number_of_sections = Self::read_u16(&data, coff_offset + 2)?;
    let timestamp = Self::read_u32(&data, coff_offset + 4)?;
    let size_of_optional_header = Self::read_u16(&data, coff_offset + 16)?;
    let characteristics = Self::read_u16(&data, coff_offset + 18)?;

    let optional_offset = coff_offset + 20;

    // Parse optional header
    let magic = Self::read_u16(&data, optional_offset)?;
    let is_64bit = magic == PE32_PLUS_MAGIC;

    let (
      entry_point,
      image_base,
      section_alignment,
      file_alignment,
      size_of_image,
      dll_characteristics,
      data_dirs,
    ) = if is_64bit {
      Self::parse_optional_header_64(&data, optional_offset)?
    } else {
      Self::parse_optional_header_32(&data, optional_offset)?
    };

    let pe_header = PeHeader {
      machine,
      number_of_sections,
      timestamp,
      characteristics,
      magic,
      entry_point,
      image_base,
      section_alignment,
      file_alignment,
      size_of_image,
      dll_characteristics,
      data_directories: data_dirs,
    };

    // Parse section headers
    let section_offset = optional_offset + size_of_optional_header as usize;
    let section_headers = Self::parse_section_headers(&data, section_offset, number_of_sections)?;

    // Build sections
    let sections = Self::build_sections(&section_headers);

    // Parse imports
    let imports = Self::parse_imports(&data, &pe_header, &section_headers)?;

    // Build symbols from imports
    let mut symbols = Vec::new();
    let mut plt = HashMap::new();

    for import in &imports {
      for func in &import.functions {
        symbols.push(Symbol {
          name: func.clone(),
          value: 0,
          size: 0,
          sym_type: SymbolType::Func,
          binding: SymbolBinding::Global,
          section_index: 0,
        });
        // Use import as PLT-like entry
        plt.insert(func.clone(), 0);
      }
    }

    // Detect architecture
    let arch = Self::machine_to_arch(machine);
    let bits = if is_64bit { 64 } else { 32 };

    // Build security features
    let security = SecurityFeatures::detect_pe(&pe_header);

    Ok(Binary {
      path,
      format,
      arch,
      bits,
      endian: Endianness::Little, // PE is always little-endian
      entry_point: image_base + entry_point,
      sections,
      symbols,
      plt,
      got: HashMap::new(),
      security,
      data,
      program_headers: Vec::new(),
      dynamic_entries: Vec::new(),
      elf_type: 0,
    })
  }

  fn parse_optional_header_32(
    data: &[u8],
    offset: usize,
  ) -> BinaryResult<(u64, u64, u32, u32, u32, u16, Vec<DataDirectory>)> {
    let entry_point = Self::read_u32(data, offset + 16)? as u64;
    let image_base = Self::read_u32(data, offset + 28)? as u64;
    let section_alignment = Self::read_u32(data, offset + 32)?;
    let file_alignment = Self::read_u32(data, offset + 36)?;
    let size_of_image = Self::read_u32(data, offset + 56)?;
    let dll_characteristics = Self::read_u16(data, offset + 70)?;

    let num_data_dirs = Self::read_u32(data, offset + 92)? as usize;
    let data_dirs_offset = offset + 96;

    let mut data_dirs = Vec::new();
    for i in 0..num_data_dirs.min(16) {
      let dir_offset = data_dirs_offset + i * 8;
      if dir_offset + 8 > data.len() {
        break;
      }
      data_dirs.push(DataDirectory {
        virtual_address: Self::read_u32(data, dir_offset)?,
        size: Self::read_u32(data, dir_offset + 4)?,
      });
    }

    Ok((
      entry_point,
      image_base,
      section_alignment,
      file_alignment,
      size_of_image,
      dll_characteristics,
      data_dirs,
    ))
  }

  fn parse_optional_header_64(
    data: &[u8],
    offset: usize,
  ) -> BinaryResult<(u64, u64, u32, u32, u32, u16, Vec<DataDirectory>)> {
    let entry_point = Self::read_u32(data, offset + 16)? as u64;
    let image_base = Self::read_u64(data, offset + 24)?;
    let section_alignment = Self::read_u32(data, offset + 32)?;
    let file_alignment = Self::read_u32(data, offset + 36)?;
    let size_of_image = Self::read_u32(data, offset + 56)?;
    let dll_characteristics = Self::read_u16(data, offset + 70)?;

    let num_data_dirs = Self::read_u32(data, offset + 108)? as usize;
    let data_dirs_offset = offset + 112;

    let mut data_dirs = Vec::new();
    for i in 0..num_data_dirs.min(16) {
      let dir_offset = data_dirs_offset + i * 8;
      if dir_offset + 8 > data.len() {
        break;
      }
      data_dirs.push(DataDirectory {
        virtual_address: Self::read_u32(data, dir_offset)?,
        size: Self::read_u32(data, dir_offset + 4)?,
      });
    }

    Ok((
      entry_point,
      image_base,
      section_alignment,
      file_alignment,
      size_of_image,
      dll_characteristics,
      data_dirs,
    ))
  }

  fn parse_section_headers(
    data: &[u8],
    offset: usize,
    count: u16,
  ) -> BinaryResult<Vec<PeSectionHeader>> {
    let mut headers = Vec::new();

    for i in 0..count as usize {
      let sec_offset = offset + i * 40;
      if sec_offset + 40 > data.len() {
        break;
      }

      // Read name (8 bytes, null-padded)
      let name_bytes = &data[sec_offset..sec_offset + 8];
      let name = String::from_utf8_lossy(name_bytes)
        .trim_end_matches('\0')
        .to_string();

      headers.push(PeSectionHeader {
        name,
        virtual_size: Self::read_u32(data, sec_offset + 8)?,
        virtual_address: Self::read_u32(data, sec_offset + 12)?,
        size_of_raw_data: Self::read_u32(data, sec_offset + 16)?,
        pointer_to_raw_data: Self::read_u32(data, sec_offset + 20)?,
        characteristics: Self::read_u32(data, sec_offset + 36)?,
      });
    }

    Ok(headers)
  }

  fn build_sections(headers: &[PeSectionHeader]) -> Vec<Section> {
    headers
      .iter()
      .map(|h| {
        let mut flags = 0u32;
        if h.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
          flags |= SectionFlags::EXEC;
        }
        if h.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
          flags |= SectionFlags::WRITE;
        }
        if h.characteristics & IMAGE_SCN_MEM_READ != 0 {
          flags |= SectionFlags::ALLOC;
        }

        Section {
          name: h.name.clone(),
          vaddr: h.virtual_address as u64,
          offset: h.pointer_to_raw_data as u64,
          size: h.size_of_raw_data as u64,
          flags: SectionFlags::new(flags),
          section_type: h.characteristics,
        }
      })
      .collect()
  }

  fn parse_imports(
    data: &[u8],
    header: &PeHeader,
    sections: &[PeSectionHeader],
  ) -> BinaryResult<Vec<ImportDescriptor>> {
    let mut imports = Vec::new();

    if header.data_directories.len() <= IMAGE_DIRECTORY_ENTRY_IMPORT {
      return Ok(imports);
    }

    let import_dir = &header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
      return Ok(imports);
    }

    // RVA to file offset
    let Some(file_offset) = Self::rva_to_file_offset(import_dir.virtual_address, sections) else {
      return Ok(imports);
    };

    // Parse import descriptors
    let mut offset = file_offset;
    loop {
      if offset + 20 > data.len() {
        break;
      }

      let original_first_thunk = Self::read_u32(data, offset)?;
      let name_rva = Self::read_u32(data, offset + 12)?;

      // End of import descriptors
      if name_rva == 0 {
        break;
      }

      // Get DLL name
      let dll_name = if let Some(name_offset) = Self::rva_to_file_offset(name_rva, sections) {
        Self::read_string(data, name_offset)
      } else {
        String::new()
      };

      // Parse function names from Original First Thunk (Import Name Table)
      let mut functions = Vec::new();
      if original_first_thunk != 0 {
        if let Some(int_offset) = Self::rva_to_file_offset(original_first_thunk, sections) {
          let mut func_offset = int_offset;
          loop {
            if func_offset + 4 > data.len() {
              break;
            }

            let hint_name_rva = Self::read_u32(data, func_offset)?;
            if hint_name_rva == 0 {
              break;
            }

            // Check if ordinal import (high bit set)
            if hint_name_rva & 0x80000000 == 0 {
              if let Some(hint_offset) = Self::rva_to_file_offset(hint_name_rva, sections) {
                // Skip hint (2 bytes), read name
                let func_name = Self::read_string(data, hint_offset + 2);
                if !func_name.is_empty() {
                  functions.push(func_name);
                }
              }
            }

            func_offset += 4;
          }
        }
      }

      if !dll_name.is_empty() {
        imports.push(ImportDescriptor {
          dll_name,
          functions,
        });
      }

      offset += 20;
    }

    Ok(imports)
  }

  fn rva_to_file_offset(rva: u32, sections: &[PeSectionHeader]) -> Option<usize> {
    for section in sections {
      let start = section.virtual_address;
      let end = start + section.virtual_size;
      if rva >= start && rva < end {
        let offset_in_section = rva - start;
        return Some((section.pointer_to_raw_data + offset_in_section) as usize);
      }
    }
    None
  }

  fn read_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
      return String::new();
    }

    let end = data[offset..]
      .iter()
      .position(|&b| b == 0)
      .map(|p| offset + p)
      .unwrap_or(data.len().min(offset + 256));

    String::from_utf8_lossy(&data[offset..end]).to_string()
  }

  fn machine_to_arch(machine: u16) -> Architecture {
    match machine {
      IMAGE_FILE_MACHINE_I386 => Architecture::X86,
      IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
      IMAGE_FILE_MACHINE_ARM => Architecture::Arm,
      IMAGE_FILE_MACHINE_ARM64 => Architecture::Arm64,
      _ => Architecture::Unknown,
    }
  }

  // Byte reading helpers
  fn read_u16(data: &[u8], offset: usize) -> BinaryResult<u16> {
    if offset + 2 > data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    let bytes: [u8; 2] = data[offset..offset + 2].try_into().unwrap();
    Ok(u16::from_le_bytes(bytes))
  }

  fn read_u32(data: &[u8], offset: usize) -> BinaryResult<u32> {
    if offset + 4 > data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
    Ok(u32::from_le_bytes(bytes))
  }

  fn read_u64(data: &[u8], offset: usize) -> BinaryResult<u64> {
    if offset + 8 > data.len() {
      return Err(BinaryError::OutOfBounds);
    }
    let bytes: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
    Ok(u64::from_le_bytes(bytes))
  }
}

// PE security constants for checksec
pub(crate) const DLL_CHAR_DYNAMIC_BASE: u16 = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
pub(crate) const DLL_CHAR_NX_COMPAT: u16 = IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
pub(crate) const DLL_CHAR_NO_SEH: u16 = IMAGE_DLLCHARACTERISTICS_NO_SEH;
pub(crate) const DLL_CHAR_GUARD_CF: u16 = IMAGE_DLLCHARACTERISTICS_GUARD_CF;
