//! Configuration management for Sentinel AV

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub engine: EngineConfig,
    pub scanner: ScannerConfig,
    pub monitor: MonitorConfig,
    pub quarantine: QuarantineConfig,
    pub api: ApiConfig,
    pub updater: UpdaterConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub enabled_detectors: Vec<String>,
    pub max_file_size_mb: u64,
    pub max_threads: usize,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub recursive: bool,
    pub follow_symlinks: bool,
    pub scan_archives: bool,
    pub scan_memory: bool,
    pub excluded_paths: Vec<PathBuf>,
    pub excluded_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub enabled: bool,
    pub monitored_paths: Vec<PathBuf>,
    pub real_time_protection: bool,
    pub auto_quarantine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub path: PathBuf,
    pub max_size_gb: u64,
    pub retention_days: u64,
    pub encrypt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterConfig {
    pub enabled: bool,
    pub update_url: String,
    pub check_interval_hours: u64,
    pub auto_update: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: PathBuf,
    pub max_size_mb: u64,
    pub rotate_daily: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            engine: EngineConfig {
                enabled_detectors: vec![
                    "signature".to_string(),
                    "heuristic".to_string(),
                    "behavioral".to_string(),
                ],
                max_file_size_mb: 500,
                max_threads: num_cpus::get(),
                timeout_seconds: 300,
            },
            scanner: ScannerConfig {
                recursive: true,
                follow_symlinks: false,
                scan_archives: true,
                scan_memory: true,
                excluded_paths: vec![
                    PathBuf::from(r"C:\Windows\WinSxS"),
                    PathBuf::from(r"C:\$Recycle.Bin"),
                ],
                excluded_extensions: vec![
                    "tmp".to_string(),
                    "log".to_string(),
                ],
            },
            monitor: MonitorConfig {
                enabled: true,
                monitored_paths: vec![
                    PathBuf::from(r"C:\Users"),
                    PathBuf::from(r"C:\Program Files"),
                    PathBuf::from(r"C:\Program Files (x86)"),
                ],
                real_time_protection: true,
                auto_quarantine: true,
            },
            quarantine: QuarantineConfig {
                path: PathBuf::from(r"C:\ProgramData\SentinelAV\Quarantine"),
                max_size_gb: 10,
                retention_days: 30,
                encrypt: true,
            },
            api: ApiConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 8443,
                api_key: None,
                tls_enabled: false,
            },
            updater: UpdaterConfig {
                enabled: true,
                update_url: "https://definitions.sentinelav.local/updates".to_string(),
                check_interval_hours: 6,
                auto_update: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: PathBuf::from(r"C:\ProgramData\SentinelAV\Logs\sentinel.log"),
                max_size_mb: 100,
                rotate_daily: true,
            },
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context("Failed to read config file")?;

        let config: Config = toml::from_str(&content)
            .context("Failed to parse config file")?;

        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }

        std::fs::write(path, content)
            .context("Failed to write config file")?;

        Ok(())
    }

    /// Create default config
    pub fn create_default() -> Self {
        Self::default()
    }
}

// Helper to get number of CPUs (fallback implementation)
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}
