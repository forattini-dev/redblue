//! MIME Type Detection
//!
//! Auto-detect MIME types from file extensions.

use std::path::Path;

/// MIME type representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeType {
    pub type_: &'static str,
    pub subtype: &'static str,
    pub charset: Option<&'static str>,
}

impl MimeType {
    /// Create a new MIME type
    pub const fn new(type_: &'static str, subtype: &'static str) -> Self {
        Self {
            type_,
            subtype,
            charset: None,
        }
    }

    /// Create with charset
    pub const fn with_charset(
        type_: &'static str,
        subtype: &'static str,
        charset: &'static str,
    ) -> Self {
        Self {
            type_,
            subtype,
            charset: Some(charset),
        }
    }

    /// Get the full MIME type string
    pub fn as_str(&self) -> String {
        match self.charset {
            Some(cs) => format!("{}/{}; charset={}", self.type_, self.subtype, cs),
            None => format!("{}/{}", self.type_, self.subtype),
        }
    }

    /// Detect MIME type from file path
    pub fn from_path(path: &Path) -> Self {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        Self::from_extension(&ext)
    }

    /// Detect MIME type from extension string
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            // Text
            "html" | "htm" => TEXT_HTML,
            "css" => TEXT_CSS,
            "js" | "mjs" => APPLICATION_JAVASCRIPT,
            "json" => APPLICATION_JSON,
            "xml" => APPLICATION_XML,
            "txt" => TEXT_PLAIN,
            "csv" => TEXT_CSV,
            "md" | "markdown" => TEXT_MARKDOWN,

            // Images
            "png" => IMAGE_PNG,
            "jpg" | "jpeg" => IMAGE_JPEG,
            "gif" => IMAGE_GIF,
            "svg" => IMAGE_SVG,
            "ico" => IMAGE_ICO,
            "webp" => IMAGE_WEBP,
            "bmp" => IMAGE_BMP,

            // Audio
            "mp3" => AUDIO_MPEG,
            "wav" => AUDIO_WAV,
            "ogg" => AUDIO_OGG,
            "flac" => AUDIO_FLAC,

            // Video
            "mp4" => VIDEO_MP4,
            "webm" => VIDEO_WEBM,
            "avi" => VIDEO_AVI,
            "mkv" => VIDEO_MKV,

            // Fonts
            "woff" => FONT_WOFF,
            "woff2" => FONT_WOFF2,
            "ttf" => FONT_TTF,
            "otf" => FONT_OTF,
            "eot" => FONT_EOT,

            // Archives
            "zip" => APPLICATION_ZIP,
            "gz" | "gzip" => APPLICATION_GZIP,
            "tar" => APPLICATION_TAR,
            "7z" => APPLICATION_7Z,
            "rar" => APPLICATION_RAR,

            // Documents
            "pdf" => APPLICATION_PDF,
            "doc" => APPLICATION_MSWORD,
            "docx" => APPLICATION_DOCX,
            "xls" => APPLICATION_EXCEL,
            "xlsx" => APPLICATION_XLSX,
            "ppt" => APPLICATION_PPT,
            "pptx" => APPLICATION_PPTX,

            // Code
            "rs" => TEXT_RUST,
            "py" => TEXT_PYTHON,
            "rb" => TEXT_RUBY,
            "go" => TEXT_GO,
            "java" => TEXT_JAVA,
            "c" | "h" => TEXT_C,
            "cpp" | "cc" | "hpp" => TEXT_CPP,
            "sh" | "bash" => TEXT_SHELL,
            "yaml" | "yml" => TEXT_YAML,
            "toml" => TEXT_TOML,

            // Binaries
            "exe" => APPLICATION_EXE,
            "dll" => APPLICATION_DLL,
            "so" => APPLICATION_SO,
            "dylib" => APPLICATION_DYLIB,
            "wasm" => APPLICATION_WASM,

            // Default
            _ => APPLICATION_OCTET_STREAM,
        }
    }

    /// Check if this is a text type (should be served with charset)
    pub fn is_text(&self) -> bool {
        self.type_ == "text"
            || (self.type_ == "application"
                && (self.subtype == "javascript"
                    || self.subtype == "json"
                    || self.subtype == "xml"))
    }
}

impl std::fmt::Display for MimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// Common MIME types
pub const TEXT_HTML: MimeType = MimeType::with_charset("text", "html", "utf-8");
pub const TEXT_CSS: MimeType = MimeType::with_charset("text", "css", "utf-8");
pub const TEXT_PLAIN: MimeType = MimeType::with_charset("text", "plain", "utf-8");
pub const TEXT_CSV: MimeType = MimeType::with_charset("text", "csv", "utf-8");
pub const TEXT_MARKDOWN: MimeType = MimeType::with_charset("text", "markdown", "utf-8");

pub const APPLICATION_JAVASCRIPT: MimeType =
    MimeType::with_charset("application", "javascript", "utf-8");
pub const APPLICATION_JSON: MimeType = MimeType::with_charset("application", "json", "utf-8");
pub const APPLICATION_XML: MimeType = MimeType::with_charset("application", "xml", "utf-8");
pub const APPLICATION_OCTET_STREAM: MimeType = MimeType::new("application", "octet-stream");

pub const IMAGE_PNG: MimeType = MimeType::new("image", "png");
pub const IMAGE_JPEG: MimeType = MimeType::new("image", "jpeg");
pub const IMAGE_GIF: MimeType = MimeType::new("image", "gif");
pub const IMAGE_SVG: MimeType = MimeType::with_charset("image", "svg+xml", "utf-8");
pub const IMAGE_ICO: MimeType = MimeType::new("image", "x-icon");
pub const IMAGE_WEBP: MimeType = MimeType::new("image", "webp");
pub const IMAGE_BMP: MimeType = MimeType::new("image", "bmp");

pub const AUDIO_MPEG: MimeType = MimeType::new("audio", "mpeg");
pub const AUDIO_WAV: MimeType = MimeType::new("audio", "wav");
pub const AUDIO_OGG: MimeType = MimeType::new("audio", "ogg");
pub const AUDIO_FLAC: MimeType = MimeType::new("audio", "flac");

pub const VIDEO_MP4: MimeType = MimeType::new("video", "mp4");
pub const VIDEO_WEBM: MimeType = MimeType::new("video", "webm");
pub const VIDEO_AVI: MimeType = MimeType::new("video", "x-msvideo");
pub const VIDEO_MKV: MimeType = MimeType::new("video", "x-matroska");

pub const FONT_WOFF: MimeType = MimeType::new("font", "woff");
pub const FONT_WOFF2: MimeType = MimeType::new("font", "woff2");
pub const FONT_TTF: MimeType = MimeType::new("font", "ttf");
pub const FONT_OTF: MimeType = MimeType::new("font", "otf");
pub const FONT_EOT: MimeType = MimeType::new("application", "vnd.ms-fontobject");

pub const APPLICATION_ZIP: MimeType = MimeType::new("application", "zip");
pub const APPLICATION_GZIP: MimeType = MimeType::new("application", "gzip");
pub const APPLICATION_TAR: MimeType = MimeType::new("application", "x-tar");
pub const APPLICATION_7Z: MimeType = MimeType::new("application", "x-7z-compressed");
pub const APPLICATION_RAR: MimeType = MimeType::new("application", "x-rar-compressed");

pub const APPLICATION_PDF: MimeType = MimeType::new("application", "pdf");
pub const APPLICATION_MSWORD: MimeType = MimeType::new("application", "msword");
pub const APPLICATION_DOCX: MimeType = MimeType::new(
    "application",
    "vnd.openxmlformats-officedocument.wordprocessingml.document",
);
pub const APPLICATION_EXCEL: MimeType = MimeType::new("application", "vnd.ms-excel");
pub const APPLICATION_XLSX: MimeType = MimeType::new(
    "application",
    "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
);
pub const APPLICATION_PPT: MimeType = MimeType::new("application", "vnd.ms-powerpoint");
pub const APPLICATION_PPTX: MimeType = MimeType::new(
    "application",
    "vnd.openxmlformats-officedocument.presentationml.presentation",
);

pub const TEXT_RUST: MimeType = MimeType::with_charset("text", "x-rust", "utf-8");
pub const TEXT_PYTHON: MimeType = MimeType::with_charset("text", "x-python", "utf-8");
pub const TEXT_RUBY: MimeType = MimeType::with_charset("text", "x-ruby", "utf-8");
pub const TEXT_GO: MimeType = MimeType::with_charset("text", "x-go", "utf-8");
pub const TEXT_JAVA: MimeType = MimeType::with_charset("text", "x-java-source", "utf-8");
pub const TEXT_C: MimeType = MimeType::with_charset("text", "x-c", "utf-8");
pub const TEXT_CPP: MimeType = MimeType::with_charset("text", "x-c++src", "utf-8");
pub const TEXT_SHELL: MimeType = MimeType::with_charset("text", "x-shellscript", "utf-8");
pub const TEXT_YAML: MimeType = MimeType::with_charset("text", "x-yaml", "utf-8");
pub const TEXT_TOML: MimeType = MimeType::with_charset("text", "x-toml", "utf-8");

pub const APPLICATION_EXE: MimeType = MimeType::new("application", "x-msdownload");
pub const APPLICATION_DLL: MimeType = MimeType::new("application", "x-msdownload");
pub const APPLICATION_SO: MimeType = MimeType::new("application", "x-sharedlib");
pub const APPLICATION_DYLIB: MimeType = MimeType::new("application", "x-sharedlib");
pub const APPLICATION_WASM: MimeType = MimeType::new("application", "wasm");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_mime_from_extension() {
        assert_eq!(
            MimeType::from_extension("html").as_str(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            MimeType::from_extension("js").as_str(),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(MimeType::from_extension("png").as_str(), "image/png");
        assert_eq!(
            MimeType::from_extension("unknown").as_str(),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_mime_from_path() {
        let path = Path::new("/var/www/index.html");
        assert_eq!(
            MimeType::from_path(path).as_str(),
            "text/html; charset=utf-8"
        );

        let path = Path::new("script.js");
        assert_eq!(
            MimeType::from_path(path).as_str(),
            "application/javascript; charset=utf-8"
        );
    }

    #[test]
    fn test_is_text() {
        assert!(TEXT_HTML.is_text());
        assert!(APPLICATION_JAVASCRIPT.is_text());
        assert!(APPLICATION_JSON.is_text());
        assert!(!IMAGE_PNG.is_text());
        assert!(!APPLICATION_OCTET_STREAM.is_text());
    }
}
