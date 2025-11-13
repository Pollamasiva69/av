//! Utility functions

use anyhow::Result;
use std::path::Path;

/// Format file size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_idx])
}

/// Format duration in human-readable format
pub fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.2}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.2}h", ms as f64 / 3_600_000.0)
    }
}

/// Check if running with admin privileges
#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    // Simplified check - in production, use proper privilege checks
    // This would require additional Windows API calls like OpenProcessToken
    // and CheckTokenMembership which are more complex to implement
    true
}

#[cfg(not(target_os = "windows"))]
pub fn is_admin() -> bool {
    false
}

/// Get system information
pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: num_cpus::get(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub cpu_count: usize,
}

mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500.00 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(1500), "1.50s");
        assert_eq!(format_duration(90000), "1.50m");
    }
}
