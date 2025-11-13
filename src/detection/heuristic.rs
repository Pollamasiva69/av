//! Heuristic detection engine

use crate::{Verdict, ThreatInfo, ThreatLevel};
use crate::detection::pe_analyzer::{PEAnalyzer, PEAnalysis};
use anyhow::Result;
use std::path::Path;
use tracing::debug;

/// Heuristic-based detector
pub struct HeuristicDetector {
    pe_analyzer: PEAnalyzer,
}

impl HeuristicDetector {
    pub fn new() -> Self {
        Self {
            pe_analyzer: PEAnalyzer::new(),
        }
    }

    /// Scan a file using heuristic analysis
    pub async fn scan(&self, path: &Path) -> Result<Verdict> {
        debug!("Heuristic scan: {}", path.display());

        let mut threat_score = 0u32;
        let mut detected_by = Vec::new();
        let mut threat_categories = Vec::new();

        // Check file extension
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            threat_score += self.check_extension(&ext_str, &mut detected_by);
        }

        // Analyze PE files
        if PEAnalyzer::is_pe_file(path) {
            if let Ok(pe_analysis) = self.pe_analyzer.analyze(path) {
                threat_score += self.analyze_pe(&pe_analysis, &mut detected_by, &mut threat_categories);
            }
        }

        // Check file size anomalies
        if let Ok(metadata) = std::fs::metadata(path) {
            let size = metadata.len();

            // Very small executables are suspicious
            if path.extension().map(|e| e == "exe").unwrap_or(false) && size < 2048 {
                threat_score += 15;
                detected_by.push("Heuristic: Unusually small executable".to_string());
            }

            // Extremely large files
            if size > 500 * 1024 * 1024 {
                threat_score += 5;
                detected_by.push("Heuristic: Extremely large file".to_string());
            }
        }

        // Check filename patterns
        threat_score += self.check_filename(path, &mut detected_by);

        // Determine verdict based on threat score
        self.score_to_verdict(threat_score, detected_by, threat_categories)
    }

    /// Check file extension for suspicious patterns
    fn check_extension(&self, ext: &str, detected_by: &mut Vec<String>) -> u32 {
        let mut score = 0;

        // Double extensions (e.g., .pdf.exe)
        let suspicious_double_extensions = [
            "exe", "scr", "pif", "bat", "cmd", "com", "vbs", "js",
        ];

        for sus_ext in &suspicious_double_extensions {
            if ext.contains(sus_ext) && ext != *sus_ext {
                score += 25;
                detected_by.push(format!("Heuristic: Double extension .{}", sus_ext));
            }
        }

        // Executable scripts
        let script_extensions = ["vbs", "js", "wsf", "hta", "ps1"];
        if script_extensions.contains(&ext) {
            score += 10;
            detected_by.push("Heuristic: Script file".to_string());
        }

        score
    }

    /// Analyze PE file for suspicious indicators
    fn analyze_pe(&self, pe: &PEAnalysis, detected_by: &mut Vec<String>, categories: &mut Vec<String>) -> u32 {
        let mut score = 0;

        // Check suspicious indicators from PE analysis
        for indicator in &pe.suspicious_indicators {
            score += indicator.severity as u32 * 3;
            detected_by.push(format!("PE: {}", indicator.description));

            if !categories.contains(&indicator.category) {
                categories.push(indicator.category.clone());
            }
        }

        // Packed executables are suspicious
        if let Some(packer) = &pe.packer_detected {
            score += 20;
            detected_by.push(format!("Heuristic: Packed with {}", packer));
            categories.push("Packing".to_string());
        }

        // High entropy
        if pe.entropy > 7.5 {
            score += 15;
            detected_by.push(format!("Heuristic: High entropy ({:.2})", pe.entropy));
        }

        // Unusual section count
        if pe.sections.len() > 10 {
            score += 10;
            detected_by.push("Heuristic: Unusual number of sections".to_string());
        } else if pe.sections.is_empty() {
            score += 20;
            detected_by.push("Heuristic: No sections found".to_string());
        }

        // Check for suspicious section names
        for section in &pe.sections {
            if self.is_suspicious_section_name(&section.name) {
                score += 15;
                detected_by.push(format!("Heuristic: Suspicious section name '{}'", section.name));
            }
        }

        // No imports (might be packed or use runtime loading)
        if pe.imports.is_empty() {
            score += 20;
            detected_by.push("Heuristic: No imports (possible runtime loading)".to_string());
        }

        score
    }

    /// Check for suspicious section names
    fn is_suspicious_section_name(&self, name: &str) -> bool {
        let suspicious = [
            ".packed", ".upx", ".aspack", ".mew",
            ".nsp", ".petite", ".boom", ".crypto",
        ];

        let name_lower = name.to_lowercase();
        suspicious.iter().any(|s| name_lower.contains(s))
    }

    /// Check filename for suspicious patterns
    fn check_filename(&self, path: &Path, detected_by: &mut Vec<String>) -> u32 {
        let mut score = 0;

        if let Some(filename) = path.file_name() {
            let filename_str = filename.to_string_lossy().to_lowercase();

            // Suspicious keywords in filename
            let suspicious_keywords = [
                "crack", "keygen", "patch", "hack", "trojan",
                "virus", "malware", "backdoor", "rootkit", "ransomware",
                "cryptor", "payload", "exploit", "shellcode",
            ];

            for keyword in &suspicious_keywords {
                if filename_str.contains(keyword) {
                    score += 30;
                    detected_by.push(format!("Heuristic: Suspicious keyword '{}' in filename", keyword));
                    break;
                }
            }

            // Suspicious patterns
            if filename_str.contains("svchost") && !path.starts_with(r"C:\Windows\System32") {
                score += 40;
                detected_by.push("Heuristic: svchost outside System32".to_string());
            }

            if filename_str.contains("lsass") && !path.starts_with(r"C:\Windows\System32") {
                score += 40;
                detected_by.push("Heuristic: lsass outside System32".to_string());
            }
        }

        score
    }

    /// Convert threat score to verdict
    fn score_to_verdict(&self, score: u32, detected_by: Vec<String>, categories: Vec<String>) -> Result<Verdict> {
        let verdict = match score {
            0..=20 => Verdict::Clean,
            21..=50 => Verdict::Suspicious,
            _ => {
                let level = match score {
                    51..=70 => ThreatLevel::Low,
                    71..=90 => ThreatLevel::Medium,
                    91..=120 => ThreatLevel::High,
                    _ => ThreatLevel::Critical,
                };

                let category = if categories.is_empty() {
                    "Unknown".to_string()
                } else {
                    categories.join(", ")
                };

                Verdict::Malicious(ThreatInfo {
                    name: "Heuristic.Suspicious.Generic".to_string(),
                    level,
                    category,
                    description: format!("Detected by heuristic analysis (score: {})", score),
                    detected_by,
                })
            }
        };

        Ok(verdict)
    }
}

impl Default for HeuristicDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_check() {
        let detector = HeuristicDetector::new();
        let mut detected = Vec::new();

        let score = detector.check_extension("pdf.exe", &mut detected);
        assert!(score > 0);
        assert!(!detected.is_empty());
    }
}
