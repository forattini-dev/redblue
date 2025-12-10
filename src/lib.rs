pub mod cli;
pub mod compression; // Native gzip/DEFLATE decompression (RFC 1952/1951)
pub mod config;
pub mod core;
pub mod crypto;
pub mod error;
pub mod intelligence;
pub mod mcp;
pub mod modules;
pub mod protocols;
pub mod scripts; // Zero-dependency scripting engine for security checks
pub mod storage;
pub mod ui; // Terminal graphics library (Braille canvas, charts, colors)
pub mod utils;
pub mod wordlists;
