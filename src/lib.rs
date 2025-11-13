//! Sentinel AV - Enterprise Antivirus Engine for Windows
//!
//! A high-performance, multi-layered antivirus engine designed for enterprise environments.
//!
//! # Features
//!
//! - Real-time file system monitoring
//! - Multi-engine detection (signatures, heuristics, behavioral)
//! - PE (Portable Executable) analysis
//! - Process and memory scanning
//! - Quarantine management
//! - RESTful API for enterprise integration
//! - Anti-ransomware protection
//! - Automatic definition updates

pub mod config;
pub mod core;
pub mod detection;
pub mod scanner;
pub mod quarantine;
pub mod monitor;
pub mod process;
pub mod api;
pub mod updater;
pub mod database;
pub mod utils;

pub use config::Config;
pub use core::{Engine, EngineError};

/// Result type used throughout the library
pub type Result<T> = std::result::Result<T, anyhow::Error>;

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Detection verdict
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious(ThreatInfo),
}

/// Information about detected threat
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreatInfo {
    pub name: String,
    pub level: ThreatLevel,
    pub category: String,
    pub description: String,
    pub detected_by: Vec<String>,
}

/// Scan statistics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub threats_found: u64,
    pub files_quarantined: u64,
    pub scan_duration_ms: u64,
    pub bytes_scanned: u64,
}
