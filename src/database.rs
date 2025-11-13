//! Database management for threat signatures and logs

use crate::ThreatLevel;
use crate::detection::signature::ThreatSignature;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::info;

/// Database manager
pub struct Database {
    conn: std::sync::Mutex<Connection>,
}

impl Database {
    /// Create a new database connection
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .context("Failed to open database")?;

        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Initialize database schema
    pub fn initialize(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                level INTEGER NOT NULL,
                description TEXT NOT NULL,
                added_date TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                category TEXT NOT NULL,
                level INTEGER NOT NULL,
                detection_date TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                files_scanned INTEGER NOT NULL,
                threats_found INTEGER NOT NULL,
                scan_date TEXT NOT NULL,
                duration_ms INTEGER NOT NULL
            )",
            [],
        )?;

        info!("Database initialized");
        Ok(())
    }

    /// Add a threat signature
    pub fn add_signature(&self, sig: &ThreatSignature) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO signatures (hash, name, category, level, description, added_date)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))",
            params![
                sig.hash,
                sig.name,
                sig.category,
                sig.level as u32,
                sig.description,
            ],
        )?;

        Ok(())
    }

    /// Get all signatures
    pub fn get_all_signatures(&self) -> Result<Vec<ThreatSignature>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT hash, name, category, level, description FROM signatures"
        )?;

        let signatures = stmt.query_map([], |row| {
            let level_int: u32 = row.get(3)?;
            let level = match level_int {
                0 => ThreatLevel::Low,
                1 => ThreatLevel::Medium,
                2 => ThreatLevel::High,
                _ => ThreatLevel::Critical,
            };

            Ok(ThreatSignature {
                hash: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                level,
                description: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        Ok(signatures)
    }

    /// Log a detection
    pub fn log_detection(
        &self,
        file_path: &str,
        threat_name: &str,
        category: &str,
        level: &ThreatLevel,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO detections (file_path, threat_name, category, level, detection_date)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))",
            params![
                file_path,
                threat_name,
                category,
                *level as u32,
            ],
        )?;

        Ok(())
    }

    /// Get recent detections
    pub fn get_recent_detections(&self, limit: usize) -> Result<Vec<DetectionRecord>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, file_path, threat_name, category, level, detection_date
             FROM detections
             ORDER BY detection_date DESC
             LIMIT ?1"
        )?;

        let records = stmt.query_map([limit], |row| {
            let level_int: u32 = row.get(4)?;
            let level = match level_int {
                0 => ThreatLevel::Low,
                1 => ThreatLevel::Medium,
                2 => ThreatLevel::High,
                _ => ThreatLevel::Critical,
            };

            Ok(DetectionRecord {
                id: row.get(0)?,
                file_path: row.get(1)?,
                threat_name: row.get(2)?,
                category: row.get(3)?,
                level,
                detection_date: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Get statistics
    pub fn get_statistics(&self) -> Result<DatabaseStats> {
        let conn = self.conn.lock().unwrap();

        let total_scans: u64 = conn.query_row(
            "SELECT COALESCE(SUM(files_scanned), 0) FROM scan_history",
            [],
            |row| row.get(0),
        )?;

        let total_detections: u64 = conn.query_row(
            "SELECT COUNT(*) FROM detections",
            [],
            |row| row.get(0),
        )?;

        let signature_count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM signatures",
            [],
            |row| row.get(0),
        )?;

        Ok(DatabaseStats {
            total_scans,
            total_detections,
            signature_count,
        })
    }

    /// Log a scan
    pub fn log_scan(
        &self,
        scan_type: &str,
        files_scanned: u64,
        threats_found: u64,
        duration_ms: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO scan_history (scan_type, files_scanned, threats_found, scan_date, duration_ms)
             VALUES (?1, ?2, ?3, datetime('now'), ?4)",
            params![
                scan_type,
                files_scanned,
                threats_found,
                duration_ms,
            ],
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DetectionRecord {
    pub id: i64,
    pub file_path: String,
    pub threat_name: String,
    pub category: String,
    pub level: ThreatLevel,
    pub detection_date: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_scans: u64,
    pub total_detections: u64,
    pub signature_count: u64,
}
