//! File scanner module

use crate::{Verdict, ThreatInfo, ThreatLevel};
use crate::detection::{SignatureDetector, HeuristicDetector};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, warn};

/// Multi-engine file scanner
pub struct FileScanner {
    signature_detector: Arc<SignatureDetector>,
    heuristic_detector: Arc<HeuristicDetector>,
}

impl FileScanner {
    pub fn new(
        signature_detector: Arc<SignatureDetector>,
        heuristic_detector: Arc<HeuristicDetector>,
    ) -> Self {
        Self {
            signature_detector,
            heuristic_detector,
        }
    }

    /// Scan a file using all detection engines
    pub async fn scan(&self, path: &Path) -> Result<Verdict> {
        debug!("Multi-engine scan: {}", path.display());

        // Check if file exists and is readable
        if !path.exists() {
            return Err(anyhow::anyhow!("File does not exist: {}", path.display()));
        }

        if !path.is_file() {
            return Err(anyhow::anyhow!("Not a file: {}", path.display()));
        }

        // Check file size
        let metadata = std::fs::metadata(path)
            .context("Failed to get file metadata")?;

        if metadata.len() == 0 {
            debug!("Skipping empty file: {}", path.display());
            return Ok(Verdict::Clean);
        }

        // Signature detection (highest priority)
        match self.signature_detector.scan(path).await {
            Ok(Verdict::Malicious(threat)) => {
                return Ok(Verdict::Malicious(threat));
            }
            Ok(_) => {}
            Err(e) => {
                warn!("Signature detection error for {}: {}", path.display(), e);
            }
        }

        // Heuristic detection
        match self.heuristic_detector.scan(path).await {
            Ok(verdict @ Verdict::Malicious(_)) => {
                return Ok(verdict);
            }
            Ok(verdict @ Verdict::Suspicious) => {
                return Ok(verdict);
            }
            Ok(_) => {}
            Err(e) => {
                warn!("Heuristic detection error for {}: {}", path.display(), e);
            }
        }

        // If all engines report clean
        Ok(Verdict::Clean)
    }

    /// Quick scan (signature only)
    pub async fn quick_scan(&self, path: &Path) -> Result<Verdict> {
        debug!("Quick scan: {}", path.display());
        self.signature_detector.scan(path).await
    }

    /// Deep scan (all engines with maximum sensitivity)
    pub async fn deep_scan(&self, path: &Path) -> Result<Verdict> {
        debug!("Deep scan: {}", path.display());

        let mut all_threats = Vec::new();
        let mut max_level = ThreatLevel::Low;

        // Run all detectors
        if let Ok(Verdict::Malicious(threat)) = self.signature_detector.scan(path).await {
            max_level = max_level.max(threat.level);
            all_threats.push(threat);
        }

        if let Ok(Verdict::Malicious(threat)) = self.heuristic_detector.scan(path).await {
            max_level = max_level.max(threat.level);
            all_threats.push(threat);
        }

        // If any threats found, return the most severe
        if !all_threats.is_empty() {
            let combined_detectors: Vec<_> = all_threats
                .iter()
                .flat_map(|t| t.detected_by.clone())
                .collect();

            let threat_names: Vec<_> = all_threats
                .iter()
                .map(|t| t.name.as_str())
                .collect();

            return Ok(Verdict::Malicious(ThreatInfo {
                name: threat_names.join(", "),
                level: max_level,
                category: all_threats[0].category.clone(),
                description: format!(
                    "Multiple threats detected by {} engines",
                    all_threats.len()
                ),
                detected_by: combined_detectors,
            }));
        }

        Ok(Verdict::Clean)
    }
}
