use boring::error::ErrorStack;
use boring::ssl::{SslConnectorBuilder, SslContextBuilder, SslMethod, SslOptions, SslVersion};

/// Defines which browser fingerprint to mimic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsProfile {
    Chrome120,
    Firefox120,
    Safari16,
}

impl TlsProfile {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chrome" | "chrome120" => Some(Self::Chrome120),
            "firefox" | "firefox120" => Some(Self::Firefox120),
            "safari" | "safari16" => Some(Self::Safari16),
            _ => None,
        }
    }

    /// Applies the profile settings to a BoringSSL ConnectorBuilder.
    pub fn apply_connector(&self, builder: &mut SslConnectorBuilder) -> Result<(), ErrorStack> {
        self.apply_generic(builder)
    }

    /// Applies the profile settings to a BoringSSL ContextBuilder (used in ConnectionPool).
    pub fn apply_context(&self, builder: &mut SslContextBuilder) -> Result<(), ErrorStack> {
        self.apply_generic(builder)
    }

    fn apply_generic<T: TlsConfigurable>(&self, builder: &mut T) -> Result<(), ErrorStack> {
        match self {
            TlsProfile::Chrome120 => self.apply_chrome_120(builder),
            TlsProfile::Firefox120 => self.apply_firefox_120(builder),
            TlsProfile::Safari16 => self.apply_safari_16(builder),
        }
    }

    fn apply_chrome_120<T: TlsConfigurable>(&self, builder: &mut T) -> Result<(), ErrorStack> {
        builder.cfg_set_grease_enabled(true);
        builder.cfg_set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.cfg_set_max_proto_version(Some(SslVersion::TLS1_3))?;

        let cipher_list = [
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "AES256-SHA",
        ]
        .join(":");
        builder.cfg_set_cipher_list(&cipher_list)?;

        builder.cfg_set_groups_list("X25519:P-256:P-384")?;
        builder.cfg_set_alpn_protos(b"\x02h2\x08http/1.1")?;
        builder.cfg_enable_ocsp_stapling();
        builder.cfg_enable_signed_cert_timestamps();
        builder.cfg_set_options(SslOptions::NO_COMPRESSION);
        Ok(())
    }

    fn apply_firefox_120<T: TlsConfigurable>(&self, builder: &mut T) -> Result<(), ErrorStack> {
        builder.cfg_set_grease_enabled(true);
        builder.cfg_set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.cfg_set_max_proto_version(Some(SslVersion::TLS1_3))?;

        let cipher_list = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
        ]
        .join(":");
        builder.cfg_set_cipher_list(&cipher_list)?;

        builder.cfg_set_groups_list("X25519:P-256:P-384:P-521")?;
        builder.cfg_set_alpn_protos(b"\x02h2\x08http/1.1")?;
        builder.cfg_enable_ocsp_stapling();
        builder.cfg_enable_signed_cert_timestamps();
        builder.cfg_set_options(SslOptions::NO_COMPRESSION);
        Ok(())
    }

    fn apply_safari_16<T: TlsConfigurable>(&self, builder: &mut T) -> Result<(), ErrorStack> {
        builder.cfg_set_grease_enabled(true);
        builder.cfg_set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.cfg_set_max_proto_version(Some(SslVersion::TLS1_3))?;

        let cipher_list = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
        ]
        .join(":");
        builder.cfg_set_cipher_list(&cipher_list)?;

        builder.cfg_set_groups_list("X25519:P-256:P-384:P-521")?;
        builder.cfg_set_alpn_protos(b"\x02h2\x08http/1.1")?;
        builder.cfg_enable_ocsp_stapling();
        builder.cfg_enable_signed_cert_timestamps();
        builder.cfg_set_options(SslOptions::NO_COMPRESSION);
        Ok(())
    }
}

/// Helper trait to abstract over SslConnectorBuilder and SslContextBuilder
trait TlsConfigurable {
    fn cfg_set_grease_enabled(&mut self, enabled: bool);
    fn cfg_set_min_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack>;
    fn cfg_set_max_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack>;
    fn cfg_set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack>;
    fn cfg_set_groups_list(&mut self, groups_list: &str) -> Result<(), ErrorStack>;
    fn cfg_set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack>;
    fn cfg_enable_ocsp_stapling(&mut self);
    fn cfg_enable_signed_cert_timestamps(&mut self);
    fn cfg_set_options(&mut self, option: SslOptions);
}

impl TlsConfigurable for SslConnectorBuilder {
    fn cfg_set_grease_enabled(&mut self, enabled: bool) {
        self.set_grease_enabled(enabled);
    }
    fn cfg_set_min_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        self.set_min_proto_version(version)
    }
    fn cfg_set_max_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        self.set_max_proto_version(version)
    }
    fn cfg_set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        self.set_cipher_list(cipher_list)
    }
    fn cfg_set_groups_list(&mut self, _groups_list: &str) -> Result<(), ErrorStack> {
        // self.set_groups_list(groups_list) // Method missing in boring crate
        Ok(())
    }
    fn cfg_set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        self.set_alpn_protos(protocols)
    }
    fn cfg_enable_ocsp_stapling(&mut self) {
        self.enable_ocsp_stapling();
    }
    fn cfg_enable_signed_cert_timestamps(&mut self) {
        self.enable_signed_cert_timestamps();
    }
    fn cfg_set_options(&mut self, option: SslOptions) {
        self.set_options(option);
    }
}

impl TlsConfigurable for SslContextBuilder {
    fn cfg_set_grease_enabled(&mut self, enabled: bool) {
        self.set_grease_enabled(enabled);
    }
    fn cfg_set_min_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        self.set_min_proto_version(version)
    }
    fn cfg_set_max_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        self.set_max_proto_version(version)
    }
    fn cfg_set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        self.set_cipher_list(cipher_list)
    }
    fn cfg_set_groups_list(&mut self, _groups_list: &str) -> Result<(), ErrorStack> {
        // self.set_groups_list(groups_list) // Method missing in boring crate
        Ok(())
    }
    fn cfg_set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        self.set_alpn_protos(protocols)
    }
    fn cfg_enable_ocsp_stapling(&mut self) {
        self.enable_ocsp_stapling();
    }
    fn cfg_enable_signed_cert_timestamps(&mut self) {
        self.enable_signed_cert_timestamps();
    }
    fn cfg_set_options(&mut self, option: SslOptions) {
        self.set_options(option);
    }
}
