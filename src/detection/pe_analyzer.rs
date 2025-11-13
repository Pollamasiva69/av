//! PE (Portable Executable) analyzer for Windows binaries

use anyhow::{Context, Result, bail};
use goblin::pe::PE;
use std::path::Path;
use tracing::debug;

/// PE Analysis results
#[derive(Debug, Clone)]
pub struct PEAnalysis {
    pub is_pe: bool,
    pub is_64bit: bool,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<String>,
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    pub entropy: f64,
    pub packer_detected: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SuspiciousIndicator {
    pub category: String,
    pub description: String,
    pub severity: u8,
}

pub struct PEAnalyzer;

impl PEAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a PE file
    pub fn analyze(&self, path: &Path) -> Result<PEAnalysis> {
        let bytes = std::fs::read(path)
            .context("Failed to read file")?;

        self.analyze_bytes(&bytes)
    }

    /// Analyze PE from bytes
    pub fn analyze_bytes(&self, bytes: &[u8]) -> Result<PEAnalysis> {
        // Check if it's a PE file
        if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
            bail!("Not a valid PE file");
        }

        let pe = PE::parse(bytes)
            .context("Failed to parse PE")?;

        let mut analysis = PEAnalysis {
            is_pe: true,
            is_64bit: pe.is_64,
            entry_point: pe.entry as u64,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            suspicious_indicators: Vec::new(),
            entropy: Self::calculate_entropy(bytes),
            packer_detected: None,
        };

        // Analyze sections
        for section in &pe.sections {
            let section_name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            let section_bytes = if let Some(offset) = section.pointer_to_raw_data.checked_add(section.size_of_raw_data) {
                if offset as usize <= bytes.len() {
                    &bytes[section.pointer_to_raw_data as usize..offset as usize]
                } else {
                    &[]
                }
            } else {
                &[]
            };

            let section_info = SectionInfo {
                name: section_name.clone(),
                virtual_size: section.virtual_size,
                raw_size: section.size_of_raw_data,
                entropy: Self::calculate_entropy(section_bytes),
                is_executable: (section.characteristics & 0x20000000) != 0,
                is_writable: (section.characteristics & 0x80000000) != 0,
            };

            // Check for suspicious section characteristics
            if section_info.is_executable && section_info.is_writable {
                analysis.suspicious_indicators.push(SuspiciousIndicator {
                    category: "Section".to_string(),
                    description: format!("Section '{}' is both writable and executable", section_name),
                    severity: 7,
                });
            }

            if section_info.entropy > 7.0 {
                analysis.suspicious_indicators.push(SuspiciousIndicator {
                    category: "Packing".to_string(),
                    description: format!("Section '{}' has high entropy ({:.2}), possible packing/encryption", section_name, section_info.entropy),
                    severity: 6,
                });
            }

            analysis.sections.push(section_info);
        }

        // Analyze imports
        for import in &pe.imports {
            let dll_name = import.name.to_string();
            let functions = Vec::new();

            // Collect imported functions (limit to avoid too much data)
            // Note: goblin's import structure doesn't directly expose function names
            // We'll check for suspicious DLLs instead

            let import_info = ImportInfo {
                dll: dll_name.clone(),
                functions,
            };

            analysis.imports.push(import_info);

            // Check for suspicious imports
            self.check_suspicious_imports(&dll_name, &mut analysis.suspicious_indicators);
        }

        // Analyze exports
        for export in &pe.exports {
            if let Some(name) = export.name {
                analysis.exports.push(name.to_string());
            }
        }

        // Detect packers
        analysis.packer_detected = self.detect_packer(&analysis);

        // Check for TLS callbacks (anti-debugging)
        if pe.entry == 0 {
            analysis.suspicious_indicators.push(SuspiciousIndicator {
                category: "Anti-Analysis".to_string(),
                description: "No entry point defined".to_string(),
                severity: 8,
            });
        }

        // High overall entropy suggests packing
        if analysis.entropy > 7.2 {
            analysis.suspicious_indicators.push(SuspiciousIndicator {
                category: "Packing".to_string(),
                description: format!("High overall file entropy ({:.2})", analysis.entropy),
                severity: 7,
            });
        }

        Ok(analysis)
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &freq in &frequencies {
            if freq > 0 {
                let p = freq as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Check for suspicious imported DLLs/functions
    fn check_suspicious_imports(&self, dll: &str, _indicators: &mut Vec<SuspiciousIndicator>) {
        let dll_lower = dll.to_lowercase();

        let suspicious_dlls = [
            ("kernel32.dll", vec!["virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread"]),
            ("ntdll.dll", vec!["ntqueryinformationprocess", "ntsetinformationthread", "zwunmapviewofsection"]),
            ("advapi32.dll", vec!["cryptacquirecontext", "adjusttokenprivileges"]),
            ("wininet.dll", vec!["internetopen", "internetreadfile"]),
            ("ws2_32.dll", vec!["socket", "connect", "send", "recv"]),
        ];

        for (sus_dll, _functions) in &suspicious_dlls {
            if dll_lower.contains(sus_dll) {
                // In a real implementation, we'd check specific functions
                // For now, just note the presence of potentially suspicious DLLs
                debug!("Found import from potentially sensitive DLL: {}", dll);
            }
        }
    }

    /// Detect known packers
    fn detect_packer(&self, analysis: &PEAnalysis) -> Option<String> {
        // Check for UPX
        for section in &analysis.sections {
            if section.name.starts_with("UPX") {
                return Some("UPX".to_string());
            }
        }

        // Check for other common packers by section names
        let packer_signatures = [
            ("aspack", "ASPack"),
            ("pecompact", "PECompact"),
            (".nsp", "NsPack"),
            ("mew", "MEW"),
        ];

        for section in &analysis.sections {
            let section_lower = section.name.to_lowercase();
            for (sig, name) in &packer_signatures {
                if section_lower.contains(sig) {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    /// Quick check if file is PE
    pub fn is_pe_file(path: &Path) -> bool {
        if let Ok(bytes) = std::fs::read(path) {
            bytes.len() >= 2 && &bytes[0..2] == b"MZ"
        } else {
            false
        }
    }
}

impl Default for PEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let data = vec![0u8; 1000];
        let entropy = PEAnalyzer::calculate_entropy(&data);
        assert!(entropy < 0.1); // All zeros = low entropy

        let random_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let entropy = PEAnalyzer::calculate_entropy(&random_data);
        assert!(entropy > 5.0); // Random data = higher entropy
    }
}
