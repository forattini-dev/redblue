//! Security feature detection (checksec)
//!
//! Detects binary security protections like RELRO, canary, NX, PIE, ASLR, DEP.

use super::elf::*;
use super::pe::*;
use super::*;

/// RELRO protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelroLevel {
    /// No RELRO protection
    #[default]
    None,
    /// Partial RELRO (GOT writable)
    Partial,
    /// Full RELRO (GOT read-only)
    Full,
}

impl std::fmt::Display for RelroLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "No RELRO"),
            Self::Partial => write!(f, "Partial RELRO"),
            Self::Full => write!(f, "Full RELRO"),
        }
    }
}

/// Security features of a binary
#[derive(Debug, Clone, Default)]
pub struct SecurityFeatures {
    /// RELRO level (ELF only)
    pub relro: RelroLevel,
    /// Stack canary present
    pub canary: bool,
    /// Non-executable stack/DEP
    pub nx: bool,
    /// Position Independent Executable / ASLR
    pub pie: bool,
    /// FORTIFY_SOURCE enabled
    pub fortify: bool,
    /// RPATH set (potential hijack)
    pub rpath: Option<String>,
    /// RUNPATH set (potential hijack)
    pub runpath: Option<String>,
    /// Control Flow Guard (PE only)
    pub cfg: bool,
    /// SafeSEH (PE only)
    pub safe_seh: bool,
    /// Authenticode signed (PE only)
    pub signed: bool,
}

impl SecurityFeatures {
    /// Detect security features for ELF binary
    pub fn detect_elf(binary: &Binary) -> Self {
        Self {
            relro: Self::detect_relro(binary),
            canary: Self::detect_canary(binary),
            nx: Self::detect_nx(binary),
            pie: Self::detect_pie(binary),
            fortify: Self::detect_fortify(binary),
            rpath: Self::detect_rpath(binary),
            runpath: Self::detect_runpath(binary),
            cfg: false,
            safe_seh: false,
            signed: false,
        }
    }

    /// Detect security features for PE binary
    pub fn detect_pe(header: &PeHeader) -> Self {
        Self {
            relro: RelroLevel::None, // N/A for PE
            canary: false,           // Would need to analyze code
            nx: header.dll_characteristics & DLL_CHAR_NX_COMPAT != 0,
            pie: header.dll_characteristics & DLL_CHAR_DYNAMIC_BASE != 0,
            fortify: false, // Would need to analyze imports
            rpath: None,
            runpath: None,
            cfg: header.dll_characteristics & DLL_CHAR_GUARD_CF != 0,
            safe_seh: header.dll_characteristics & DLL_CHAR_NO_SEH != 0,
            signed: false, // Would need to check security directory
        }
    }

    fn detect_relro(binary: &Binary) -> RelroLevel {
        // Check for PT_GNU_RELRO program header
        let has_relro = binary
            .program_headers
            .iter()
            .any(|ph| ph.p_type == PT_GNU_RELRO_VAL);

        if !has_relro {
            return RelroLevel::None;
        }

        // Check for BIND_NOW in dynamic section
        let has_bind_now = binary.dynamic_entries.iter().any(|d| {
            (d.d_tag == DT_FLAGS_VAL && (d.d_val & DF_BIND_NOW_VAL) != 0)
                || (d.d_tag == DT_FLAGS_1_VAL && (d.d_val & DF_1_NOW_VAL) != 0)
        });

        if has_bind_now {
            RelroLevel::Full
        } else {
            RelroLevel::Partial
        }
    }

    fn detect_canary(binary: &Binary) -> bool {
        // Look for __stack_chk_fail or __stack_chk_guard in symbols
        binary.symbols.iter().any(|s| {
            s.name == "__stack_chk_fail"
                || s.name == "__stack_chk_guard"
                || s.name == "__stack_smash_handler"
        })
    }

    fn detect_nx(binary: &Binary) -> bool {
        // Check PT_GNU_STACK flags
        binary
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_GNU_STACK_VAL)
            .map(|ph| (ph.p_flags & PF_X_VAL) == 0)
            .unwrap_or(true) // Default to NX if no PT_GNU_STACK
    }

    fn detect_pie(binary: &Binary) -> bool {
        // PIE if ET_DYN and has entry point
        binary.elf_type == ET_DYN_VAL && binary.entry_point != 0
    }

    fn detect_fortify(binary: &Binary) -> bool {
        // Look for *_chk functions
        binary
            .symbols
            .iter()
            .any(|s| s.name.ends_with("_chk") || s.name.contains("__fortify"))
    }

    fn detect_rpath(_binary: &Binary) -> Option<String> {
        // Would need to parse DT_RPATH from dynamic section
        None
    }

    fn detect_runpath(_binary: &Binary) -> Option<String> {
        // Would need to parse DT_RUNPATH from dynamic section
        None
    }

    /// Display checksec output in classic format
    pub fn display(&self) -> String {
        let mut output = String::new();

        output.push_str("RELRO           STACK CANARY      NX            PIE             ");
        if self.cfg || self.safe_seh {
            output.push_str("CFG           SafeSEH\n");
        } else {
            output.push('\n');
        }

        // RELRO
        let relro_str = match self.relro {
            RelroLevel::Full => "Full RELRO",
            RelroLevel::Partial => "Partial RELRO",
            RelroLevel::None => "No RELRO",
        };
        output.push_str(&format!("{:<16}", relro_str));

        // Canary
        let canary_str = if self.canary {
            "Canary found"
        } else {
            "No canary"
        };
        output.push_str(&format!("{:<18}", canary_str));

        // NX
        let nx_str = if self.nx { "NX enabled" } else { "NX disabled" };
        output.push_str(&format!("{:<14}", nx_str));

        // PIE
        let pie_str = if self.pie { "PIE enabled" } else { "No PIE" };
        output.push_str(&format!("{:<16}", pie_str));

        // PE-specific
        if self.cfg || self.safe_seh {
            let cfg_str = if self.cfg { "CFG enabled" } else { "No CFG" };
            output.push_str(&format!("{:<14}", cfg_str));

            let seh_str = if self.safe_seh {
                "SafeSEH"
            } else {
                "No SafeSEH"
            };
            output.push_str(seh_str);
        }

        output
    }

    /// Convert to JSON
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"relro":"{}","canary":{},"nx":{},"pie":{},"fortify":{},"cfg":{},"safe_seh":{}}}"#,
            self.relro, self.canary, self.nx, self.pie, self.fortify, self.cfg, self.safe_seh
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relro_display() {
        assert_eq!(format!("{}", RelroLevel::Full), "Full RELRO");
        assert_eq!(format!("{}", RelroLevel::Partial), "Partial RELRO");
        assert_eq!(format!("{}", RelroLevel::None), "No RELRO");
    }

    #[test]
    fn test_security_features_default() {
        let sec = SecurityFeatures::default();
        assert_eq!(sec.relro, RelroLevel::None);
        assert!(!sec.canary);
        assert!(!sec.nx);
        assert!(!sec.pie);
    }
}
