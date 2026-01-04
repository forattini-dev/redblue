//! Kerberos Protocol Enumerations
//!
//! Message types, encryption algorithms, checksum types, and name types.

/// Kerberos message types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    AsReq = 10,
    AsRep = 11,
    TgsReq = 12,
    TgsRep = 13,
    ApReq = 14,
    ApRep = 15,
    KrbSafe = 20,
    KrbPriv = 21,
    KrbCred = 22,
    KrbError = 30,
}

impl MessageType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            10 => Some(Self::AsReq),
            11 => Some(Self::AsRep),
            12 => Some(Self::TgsReq),
            13 => Some(Self::TgsRep),
            14 => Some(Self::ApReq),
            15 => Some(Self::ApRep),
            20 => Some(Self::KrbSafe),
            21 => Some(Self::KrbPriv),
            22 => Some(Self::KrbCred),
            30 => Some(Self::KrbError),
            _ => None,
        }
    }
}

/// Encryption types
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    /// DES-CBC-CRC (deprecated)
    DesCbcCrc = 1,
    /// DES-CBC-MD5 (deprecated)
    DesCbcMd5 = 3,
    /// DES3-CBC-SHA1 (deprecated)
    Des3CbcSha1 = 16,
    /// AES128-CTS-HMAC-SHA1-96
    Aes128CtsHmacSha1 = 17,
    /// AES256-CTS-HMAC-SHA1-96
    Aes256CtsHmacSha1 = 18,
    /// AES128-CTS-HMAC-SHA256-128
    Aes128CtsHmacSha256 = 19,
    /// AES256-CTS-HMAC-SHA384-192
    Aes256CtsHmacSha384 = 20,
    /// RC4-HMAC (arcfour-hmac-md5)
    Rc4Hmac = 23,
    /// RC4-HMAC-EXP (export, 40-bit)
    Rc4HmacExp = 24,
}

impl EncryptionType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::DesCbcCrc),
            3 => Some(Self::DesCbcMd5),
            16 => Some(Self::Des3CbcSha1),
            17 => Some(Self::Aes128CtsHmacSha1),
            18 => Some(Self::Aes256CtsHmacSha1),
            19 => Some(Self::Aes128CtsHmacSha256),
            20 => Some(Self::Aes256CtsHmacSha384),
            23 => Some(Self::Rc4Hmac),
            24 => Some(Self::Rc4HmacExp),
            _ => None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::DesCbcCrc | Self::DesCbcMd5 => 8,
            Self::Des3CbcSha1 => 24,
            Self::Aes128CtsHmacSha1 | Self::Aes128CtsHmacSha256 => 16,
            Self::Aes256CtsHmacSha1 | Self::Aes256CtsHmacSha384 => 32,
            Self::Rc4Hmac | Self::Rc4HmacExp => 16,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::DesCbcCrc | Self::DesCbcMd5 | Self::Des3CbcSha1 => 8,
            Self::Aes128CtsHmacSha1
            | Self::Aes256CtsHmacSha1
            | Self::Aes128CtsHmacSha256
            | Self::Aes256CtsHmacSha384 => 16,
            Self::Rc4Hmac | Self::Rc4HmacExp => 1,
        }
    }
}

/// Checksum types
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumType {
    /// HMAC-SHA1-96-AES128
    HmacSha1Aes128 = 15,
    /// HMAC-SHA1-96-AES256
    HmacSha1Aes256 = 16,
    /// HMAC-MD5 (for RC4-HMAC)
    HmacMd5 = -138,
}

impl ChecksumType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            15 => Some(Self::HmacSha1Aes128),
            16 => Some(Self::HmacSha1Aes256),
            -138 => Some(Self::HmacMd5),
            _ => None,
        }
    }
}

/// Principal name types
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    Unknown = 0,
    Principal = 1,
    SrvInst = 2, // NT-SRV-INST (service and instance)
    SrvXhst = 3, // NT-SRV-XHST
    Uid = 4,
    X500Principal = 5,
    SmtpName = 6,
    Enterprise = 10,
}

impl NameType {
    // Aliases for compatibility
    pub const SRV_HST: Self = Self::SrvInst; // NT-SRV-HST is same as NT-SRV-INST
    pub const SERVICE: Self = Self::SrvInst; // Common alias
    #[allow(non_upper_case_globals)]
    pub const Service: Self = Self::SrvInst; // CamelCase alias for mod.rs compatibility
}

impl NameType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::Principal),
            2 => Some(Self::SrvInst),
            3 => Some(Self::SrvXhst),
            4 => Some(Self::Uid),
            5 => Some(Self::X500Principal),
            6 => Some(Self::SmtpName),
            10 => Some(Self::Enterprise),
            _ => None,
        }
    }
}

/// Pre-authentication data types
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaDataType {
    None = 0,
    TgsReq = 1,
    EncTimestamp = 2,
    PwSalt = 3,
    EncUnixTime = 5,
    Sandia = 6,
    Sesame = 7,
    OsfDce = 8,
    Cybersafe = 9,
    Afs3Salt = 10,
    EtypeInfo = 11,
    SamChallenge = 12,
    SamResponse = 13,
    PkAsReqOld = 14,
    PkAsRepOld = 15,
    PkAsReq = 16,
    PkAsRep = 17,
    EtypeInfo2 = 19,
    UseSpecifiedKvno = 20, // Also used for SvrReferralInfo
    SamRedirect = 21,
    GetFromTypedData = 22,
    SamEtypeInfo = 23,
    AltPrinc = 24,
    ServerReferral = 25,
    SamChallenge2 = 30,
    SamResponse2 = 31,
    ExtraTgt = 41,
    PacRequest = 128,
    ForUser = 129,     // S4U2Self
    S4uX509User = 130, // Also used for ForCheckReqs
    AsChecksum = 132,
    FxCookie = 133,
    AuthenticationSet = 134,
    AuthSetSelected = 135,
    FxFast = 136,
    FxError = 137,
    EncryptedChallenge = 138,
    PkinitKx = 147,
    SupportedEtypes = 165,
    PacOptions = 167,
}

impl PaDataType {
    // Aliases for duplicate values
    pub const SVR_REFERRAL_INFO: Self = Self::UseSpecifiedKvno;
    pub const FOR_CHECK_REQS: Self = Self::S4uX509User;
    pub const PA_TGS_REQ: Self = Self::TgsReq; // Alias for mod.rs
    #[allow(non_upper_case_globals)]
    pub const PaTgsReq: Self = Self::TgsReq; // CamelCase alias for mod.rs compatibility
}

impl PaDataType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::TgsReq),
            2 => Some(Self::EncTimestamp),
            3 => Some(Self::PwSalt),
            11 => Some(Self::EtypeInfo),
            16 => Some(Self::PkAsReq),
            17 => Some(Self::PkAsRep),
            19 => Some(Self::EtypeInfo2),
            128 => Some(Self::PacRequest),
            129 => Some(Self::ForUser),
            130 => Some(Self::S4uX509User),
            _ => None,
        }
    }
}

/// Address types for HostAddress
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Ipv4 = 2,
    Directional = 3,
    ChaosNet = 5,
    Xns = 6,
    Iso = 7,
    DecnetPhase4 = 12,
    AppleTalk = 16,
    NetBios = 20,
    Ipv6 = 24,
}
