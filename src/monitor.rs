//! Real-time file system monitoring

use crate::{Config, Verdict};
use crate::scanner::FileScanner;
use crate::quarantine::QuarantineManager;
use anyhow::Result;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};

/// Real-time file system monitor
pub struct FileSystemMonitor {
    config: Arc<Config>,
    scanner: Arc<FileScanner>,
    quarantine: Arc<QuarantineManager>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl FileSystemMonitor {
    pub fn new(
        config: Arc<Config>,
        scanner: Arc<FileScanner>,
        quarantine: Arc<QuarantineManager>,
    ) -> Self {
        Self {
            config,
            scanner,
            quarantine,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    /// Start real-time monitoring
    pub async fn start(&self) -> Result<()> {
        if !self.config.monitor.enabled {
            info!("Real-time monitoring is disabled in config");
            return Ok(());
        }

        *self.running.write().await = true;

        info!("Starting real-time file system monitoring");

        let (tx, mut rx) = mpsc::channel(100);

        // Create file system watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    let _ = tx.blocking_send(event);
                }
                Err(e) => {
                    error!("Watch error: {:?}", e);
                }
            }
        })?;

        // Watch configured paths
        for path in &self.config.monitor.monitored_paths {
            if path.exists() {
                info!("Monitoring path: {}", path.display());
                watcher.watch(path, RecursiveMode::Recursive)?;
            } else {
                warn!("Monitored path does not exist: {}", path.display());
            }
        }

        // Process events
        let scanner = self.scanner.clone();
        let quarantine = self.quarantine.clone();
        let auto_quarantine = self.config.monitor.auto_quarantine;
        let running = self.running.clone();

        tokio::spawn(async move {
            while *running.read().await {
                if let Some(event) = rx.recv().await {
                    if let Err(e) = Self::handle_event(
                        event,
                        scanner.clone(),
                        quarantine.clone(),
                        auto_quarantine,
                    )
                    .await
                    {
                        error!("Error handling file event: {}", e);
                    }
                }
            }
        });

        // Keep watcher alive
        tokio::spawn(async move {
            let _watcher = watcher;
            tokio::signal::ctrl_c().await.ok();
        });

        Ok(())
    }

    /// Handle a file system event
    async fn handle_event(
        event: Event,
        scanner: Arc<FileScanner>,
        quarantine: Arc<QuarantineManager>,
        auto_quarantine: bool,
    ) -> Result<()> {
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                for path in event.paths {
                    if path.is_file() {
                        Self::scan_and_quarantine(
                            &path,
                            scanner.clone(),
                            quarantine.clone(),
                            auto_quarantine,
                        )
                        .await?;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Scan a file and quarantine if malicious
    async fn scan_and_quarantine(
        path: &Path,
        scanner: Arc<FileScanner>,
        quarantine: Arc<QuarantineManager>,
        auto_quarantine: bool,
    ) -> Result<()> {
        // Skip if file is too large or doesn't exist
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > 500 * 1024 * 1024 {
                debug!("Skipping large file: {}", path.display());
                return Ok(());
            }
        } else {
            return Ok(());
        }

        debug!("Real-time scan: {}", path.display());

        match scanner.scan(path).await {
            Ok(Verdict::Malicious(threat)) => {
                warn!(
                    "THREAT DETECTED: {} in {} - {}",
                    threat.name,
                    path.display(),
                    threat.description
                );

                if auto_quarantine {
                    match quarantine.add(path, &threat.name).await {
                        Ok(_) => {
                            info!("File automatically quarantined: {}", path.display());
                        }
                        Err(e) => {
                            error!("Failed to quarantine {}: {}", path.display(), e);
                        }
                    }
                }
            }
            Ok(Verdict::Suspicious) => {
                warn!("Suspicious file detected: {}", path.display());
            }
            Ok(Verdict::Clean) => {
                debug!("File clean: {}", path.display());
            }
            Err(e) => {
                debug!("Scan error for {}: {}", path.display(), e);
            }
        }

        Ok(())
    }

    /// Stop monitoring
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping real-time monitoring");
        *self.running.write().await = false;
        Ok(())
    }

    /// Check if monitoring is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}
