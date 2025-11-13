//! Quarantine management system

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use tracing::{info, error, warn};
use sha2::Digest;

/// Quarantine entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub threat_name: String,
    pub quarantine_date: DateTime<Utc>,
    pub file_size: u64,
    pub file_hash: String,
}

/// Quarantine manager
pub struct QuarantineManager {
    quarantine_dir: PathBuf,
    metadata_file: PathBuf,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new(quarantine_dir: &Path) -> Result<Self> {
        // Create quarantine directory if it doesn't exist
        std::fs::create_dir_all(quarantine_dir)
            .context("Failed to create quarantine directory")?;

        let metadata_file = quarantine_dir.join("metadata.json");

        Ok(Self {
            quarantine_dir: quarantine_dir.to_path_buf(),
            metadata_file,
        })
    }

    /// Add a file to quarantine
    pub async fn add(&self, file_path: &Path, threat_name: &str) -> Result<String> {
        if !file_path.exists() {
            anyhow::bail!("File does not exist: {}", file_path.display());
        }

        let id = Uuid::new_v4().to_string();

        // Calculate file hash
        let file_bytes = std::fs::read(file_path)
            .context("Failed to read file for quarantine")?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&file_bytes);
        let file_hash = format!("{:x}", hasher.finalize());
        let file_size = file_bytes.len() as u64;

        // Create quarantine file path
        let quarantine_filename = format!("{}_{}", id, file_path.file_name()
            .unwrap_or_default()
            .to_string_lossy());

        let quarantine_path = self.quarantine_dir.join(quarantine_filename);

        // Encrypt file content (simple XOR for now, use proper encryption in production)
        let encrypted = self.encrypt_bytes(&file_bytes);

        // Write encrypted file
        std::fs::write(&quarantine_path, encrypted)
            .context("Failed to write quarantined file")?;

        // Create metadata entry
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: file_path.to_path_buf(),
            quarantine_path: quarantine_path.clone(),
            threat_name: threat_name.to_string(),
            quarantine_date: Utc::now(),
            file_size,
            file_hash,
        };

        // Save metadata
        self.save_entry(&entry)?;

        // Delete original file
        if let Err(e) = std::fs::remove_file(file_path) {
            error!("Failed to delete original file {}: {}", file_path.display(), e);
            // Try to restore from quarantine
            if let Err(e2) = std::fs::remove_file(&quarantine_path) {
                error!("Failed to cleanup quarantine file: {}", e2);
            }
            anyhow::bail!("Failed to delete original file: {}", e);
        }

        info!(
            "File quarantined: {} -> {} (ID: {})",
            file_path.display(),
            quarantine_path.display(),
            id
        );

        Ok(id)
    }

    /// Restore a file from quarantine
    pub async fn restore(&self, id: &str) -> Result<()> {
        let entries = self.load_entries()?;

        let entry = entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow::anyhow!("Quarantine entry not found: {}", id))?;

        // Read encrypted file
        let encrypted = std::fs::read(&entry.quarantine_path)
            .context("Failed to read quarantined file")?;

        // Decrypt
        let decrypted = self.decrypt_bytes(&encrypted);

        // Restore to original location (or ask user for location)
        let restore_path = &entry.original_path;

        // Check if original path exists
        if restore_path.exists() {
            warn!(
                "Original path already exists: {}. File will be restored with .restored extension",
                restore_path.display()
            );

            let mut new_path = restore_path.clone();
            new_path.set_extension("restored");

            std::fs::write(&new_path, decrypted)
                .context("Failed to restore file")?;

            info!("File restored to: {}", new_path.display());
        } else {
            // Create parent directories if needed
            if let Some(parent) = restore_path.parent() {
                std::fs::create_dir_all(parent)
                    .context("Failed to create parent directories")?;
            }

            std::fs::write(restore_path, decrypted)
                .context("Failed to restore file")?;

            info!("File restored to: {}", restore_path.display());
        }

        // Remove from quarantine
        std::fs::remove_file(&entry.quarantine_path)
            .context("Failed to remove quarantine file")?;

        // Remove from metadata
        self.remove_entry(id)?;

        Ok(())
    }

    /// Delete a quarantined file permanently
    pub async fn delete(&self, id: &str) -> Result<()> {
        let entries = self.load_entries()?;

        let entry = entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow::anyhow!("Quarantine entry not found: {}", id))?;

        // Delete quarantine file
        std::fs::remove_file(&entry.quarantine_path)
            .context("Failed to delete quarantine file")?;

        // Remove from metadata
        self.remove_entry(id)?;

        info!("Quarantined file permanently deleted: {}", id);

        Ok(())
    }

    /// List all quarantined files
    pub async fn list(&self) -> Result<Vec<QuarantineEntry>> {
        self.load_entries()
    }

    /// Get count of quarantined files
    pub async fn count(&self) -> Result<usize> {
        Ok(self.load_entries()?.len())
    }

    /// Simple XOR encryption (use proper encryption in production)
    fn encrypt_bytes(&self, data: &[u8]) -> Vec<u8> {
        let key = b"SentinelAV-Quarantine-Key-2024"; // In production, use proper key management

        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }

    /// Simple XOR decryption
    fn decrypt_bytes(&self, data: &[u8]) -> Vec<u8> {
        // XOR is symmetric
        self.encrypt_bytes(data)
    }

    /// Load all quarantine entries
    fn load_entries(&self) -> Result<Vec<QuarantineEntry>> {
        if !self.metadata_file.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&self.metadata_file)
            .context("Failed to read metadata file")?;

        let entries: Vec<QuarantineEntry> = serde_json::from_str(&content)
            .context("Failed to parse metadata")?;

        Ok(entries)
    }

    /// Save a quarantine entry
    fn save_entry(&self, entry: &QuarantineEntry) -> Result<()> {
        let mut entries = self.load_entries()?;
        entries.push(entry.clone());

        let content = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize metadata")?;

        std::fs::write(&self.metadata_file, content)
            .context("Failed to write metadata file")?;

        Ok(())
    }

    /// Remove an entry from metadata
    fn remove_entry(&self, id: &str) -> Result<()> {
        let mut entries = self.load_entries()?;
        entries.retain(|e| e.id != id);

        let content = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize metadata")?;

        std::fs::write(&self.metadata_file, content)
            .context("Failed to write metadata file")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption() {
        let manager = QuarantineManager {
            quarantine_dir: PathBuf::from("/tmp"),
            metadata_file: PathBuf::from("/tmp/metadata.json"),
        };

        let original = b"This is a test file with sensitive data";
        let encrypted = manager.encrypt_bytes(original);
        let decrypted = manager.decrypt_bytes(&encrypted);

        assert_eq!(original, decrypted.as_slice());
    }
}
