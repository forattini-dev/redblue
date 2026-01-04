//! Kerberos Flag Types
//!
//! Bit flag structures for KDC options, ticket flags, and AP options.

use super::encoding::encode_bit_string_32;

/// KDC option flags
#[derive(Debug, Clone, Copy, Default)]
pub struct KdcOptions(pub u32);

impl KdcOptions {
    pub const FORWARDABLE: u32 = 0x40000000;
    pub const FORWARDED: u32 = 0x20000000;
    pub const PROXIABLE: u32 = 0x10000000;
    pub const PROXY: u32 = 0x08000000;
    pub const ALLOW_POSTDATE: u32 = 0x04000000;
    pub const POSTDATED: u32 = 0x02000000;
    pub const RENEWABLE: u32 = 0x00800000;
    pub const OPT_HARDWARE_AUTH: u32 = 0x00100000;
    pub const CONSTRAINED_DELEGATION: u32 = 0x00020000;
    pub const CANONICALIZE: u32 = 0x00010000;
    pub const REQUEST_ANONYMOUS: u32 = 0x00008000;
    pub const DISABLE_TRANSITED_CHECK: u32 = 0x00000020;
    pub const RENEWABLE_OK: u32 = 0x00000010;
    pub const ENC_TKT_IN_SKEY: u32 = 0x00000008;
    pub const RENEW: u32 = 0x00000002;
    pub const VALIDATE: u32 = 0x00000001;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with(mut self, flag: u32) -> Self {
        self.0 |= flag;
        self
    }

    pub fn encode_der(&self) -> Vec<u8> {
        encode_bit_string_32(self.0)
    }

    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// Ticket flags
#[derive(Debug, Clone, Copy, Default)]
pub struct TicketFlags(pub u32);

impl TicketFlags {
    pub const FORWARDABLE: u32 = 0x40000000;
    pub const FORWARDED: u32 = 0x20000000;
    pub const PROXIABLE: u32 = 0x10000000;
    pub const PROXY: u32 = 0x08000000;
    pub const MAY_POSTDATE: u32 = 0x04000000;
    pub const POSTDATED: u32 = 0x02000000;
    pub const INVALID: u32 = 0x01000000;
    pub const RENEWABLE: u32 = 0x00800000;
    pub const INITIAL: u32 = 0x00400000;
    pub const PRE_AUTHENT: u32 = 0x00200000;
    pub const HW_AUTHENT: u32 = 0x00100000;
    pub const TRANSITED_POLICY_CHECKED: u32 = 0x00080000;
    pub const OK_AS_DELEGATE: u32 = 0x00040000;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with(mut self, flag: u32) -> Self {
        self.0 |= flag;
        self
    }

    pub fn encode_der(&self) -> Vec<u8> {
        encode_bit_string_32(self.0)
    }

    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// AP-REQ options flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApOptions(pub u32);

impl ApOptions {
    pub const USE_SESSION_KEY: u32 = 0x40000000;
    pub const MUTUAL_REQUIRED: u32 = 0x20000000;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with(mut self, flag: u32) -> Self {
        self.0 |= flag;
        self
    }

    pub fn encode_der(&self) -> Vec<u8> {
        encode_bit_string_32(self.0)
    }
}
