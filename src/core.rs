//! Core engine implementation

use crate::{Config, Result, Verdict, ScanStats};
use crate::detection::{SignatureDetector, HeuristicDetector, BehavioralDetector};
use crate::scanner::FileScanner;
use crate::quarantine::QuarantineManager;
use crate::database::Database;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Engine not initialized")]
    NotInitialized,

    #[error("Detector error: {0}")]
    DetectorError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Main antivirus engine
pub struct Engine {
    config: Arc<RwLock<Config>>,
    signature_detector: Arc<SignatureDetector>,
    heuristic_detector: Arc<HeuristicDetector>,
    behavioral_detector: Arc<BehavioralDetector>,
    file_scanner: Arc<FileScanner>,
    quarantine: Arc<QuarantineManager>,
    database: Arc<Database>,
}

impl Engine {
    /// Create and initialize a new engine
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing Sentinel AV Engine v{}", env!("CARGO_PKG_VERSION"));

        // Initialize database
        let db_path = std::env::current_dir()?.join("sentinel.db");
        let database = Arc::new(Database::new(&db_path)?);
        database.initialize()?;

        // Initialize detectors
        let signature_detector = Arc::new(SignatureDetector::new(database.clone()).await?);
        let heuristic_detector = Arc::new(HeuristicDetector::new());
        let behavioral_detector = Arc::new(BehavioralDetector::new());

        // Initialize scanner
        let file_scanner = Arc::new(FileScanner::new(
            signature_detector.clone(),
            heuristic_detector.clone(),
        ));

        // Initialize quarantine manager
        let quarantine = Arc::new(QuarantineManager::new(&config.quarantine.path)?);

        info!("Engine initialized successfully");

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            signature_detector,
            heuristic_detector,
            behavioral_detector,
            file_scanner,
            quarantine,
            database,
        })
    }

    /// Scan a file
    pub async fn scan_file(&self, path: &Path) -> Result<Verdict> {
        info!("Scanning file: {}", path.display());

        match self.file_scanner.scan(path).await {
            Ok(verdict) => {
                if let Verdict::Malicious(ref threat) = verdict {
                    warn!("Threat detected in {}: {}", path.display(), threat.name);

                    // Log to database
                    let _ = self.database.log_detection(
                        path.to_str().unwrap_or("unknown"),
                        &threat.name,
                        &threat.category,
                        &threat.level,
                    );
                }
                Ok(verdict)
            }
            Err(e) => {
                error!("Scan error for {}: {}", path.display(), e);
                Err(e)
            }
        }
    }

    /// Scan a directory recursively
    pub async fn scan_directory(&self, path: &Path) -> Result<ScanStats> {
        info!("Scanning directory: {}", path.display());

        let mut stats = ScanStats::default();
        let start_time = std::time::Instant::now();

        let config = self.config.read().await;
        let excluded_paths = &config.scanner.excluded_paths;
        let excluded_extensions = &config.scanner.excluded_extensions;

        let entries: Vec<_> = walkdir::WalkDir::new(path)
            .follow_links(config.scanner.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                // Apply exclusions
                let path = e.path();

                // Check excluded paths
                if excluded_paths.iter().any(|ex| path.starts_with(ex)) {
                    return false;
                }

                // Check excluded extensions
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy();
                    if excluded_extensions.iter().any(|ex| ext_str == ex.as_str()) {
                        return false;
                    }
                }

                true
            })
            .collect();

        info!("Found {} files to scan", entries.len());

        // Parallel scanning using rayon
        use rayon::prelude::*;

        let results: Vec<_> = entries.par_iter()
            .map(|entry| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let verdict = rt.block_on(self.scan_file(entry.path()));
                (entry.path().to_path_buf(), verdict)
            })
            .collect();

        // Process results
        for (path, result) in results {
            stats.files_scanned += 1;

            if let Ok(metadata) = std::fs::metadata(&path) {
                stats.bytes_scanned += metadata.len();
            }

            if let Ok(Verdict::Malicious(threat)) = result {
                stats.threats_found += 1;

                // Auto-quarantine if enabled
                if config.monitor.auto_quarantine {
                    match self.quarantine.add(&path, &threat.name).await {
                        Ok(_) => {
                            stats.files_quarantined += 1;
                            info!("File quarantined: {}", path.display());
                        }
                        Err(e) => {
                            error!("Failed to quarantine {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        stats.scan_duration_ms = start_time.elapsed().as_millis() as u64;

        info!("Scan complete: {} files scanned, {} threats found in {}ms",
            stats.files_scanned, stats.threats_found, stats.scan_duration_ms);

        Ok(stats)
    }

    /// Quarantine a file
    pub async fn quarantine_file(&self, path: &Path, reason: &str) -> Result<()> {
        self.quarantine.add(path, reason).await?;
        Ok(())
    }

    /// Restore a file from quarantine
    pub async fn restore_file(&self, quarantine_id: &str) -> Result<()> {
        self.quarantine.restore(quarantine_id).await
    }

    /// Restore all files from quarantine
    pub async fn restore_all_files(&self) -> Result<crate::quarantine::RestoreAllResult> {
        self.quarantine.restore_all().await
    }

    /// Update threat definitions
    pub async fn update_definitions(&self) -> Result<u64> {
        info!("Updating threat definitions...");

        // This would connect to update server in production
        // For now, we'll simulate an update

        let count = self.signature_detector.update_signatures().await?;

        info!("Updated {} threat definitions", count);
        Ok(count)
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> Result<EngineStats> {
        let db_stats = self.database.get_statistics()?;

        Ok(EngineStats {
            total_scans: db_stats.total_scans,
            total_detections: db_stats.total_detections,
            signature_count: self.signature_detector.signature_count().await,
            quarantine_count: self.quarantine.count().await?,
        })
    }

    /// Shutdown the engine
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down Sentinel AV Engine");
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineStats {
    pub total_scans: u64,
    pub total_detections: u64,
    pub signature_count: usize,
    pub quarantine_count: usize,
}
