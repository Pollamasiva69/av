//! Behavioral detection engine

use crate::{Verdict, ThreatInfo, ThreatLevel};
use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Behavioral patterns that indicate malicious activity
#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub name: String,
    pub description: String,
    pub level: ThreatLevel,
    pub indicators: Vec<String>,
}

/// Behavioral detector
pub struct BehavioralDetector {
    patterns: Arc<RwLock<HashMap<String, BehaviorPattern>>>,
    observed_behaviors: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl BehavioralDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            patterns: Arc::new(RwLock::new(HashMap::new())),
            observed_behaviors: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize default behavioral patterns
        detector.init_patterns();

        detector
    }

    /// Initialize behavioral detection patterns
    fn init_patterns(&mut self) {
        let patterns = vec![
            BehaviorPattern {
                name: "Ransomware.Encryption".to_string(),
                description: "Rapid file encryption behavior".to_string(),
                level: ThreatLevel::Critical,
                indicators: vec![
                    "rapid_file_modification".to_string(),
                    "file_extension_change".to_string(),
                    "high_file_write_rate".to_string(),
                ],
            },
            BehaviorPattern {
                name: "Trojan.DataExfiltration".to_string(),
                description: "Suspicious data exfiltration".to_string(),
                level: ThreatLevel::High,
                indicators: vec![
                    "unusual_network_connection".to_string(),
                    "large_data_transfer".to_string(),
                    "connection_to_suspicious_ip".to_string(),
                ],
            },
            BehaviorPattern {
                name: "Rootkit.Persistence".to_string(),
                description: "Persistence mechanism installation".to_string(),
                level: ThreatLevel::High,
                indicators: vec![
                    "registry_autorun_modification".to_string(),
                    "service_installation".to_string(),
                    "scheduled_task_creation".to_string(),
                ],
            },
            BehaviorPattern {
                name: "Keylogger.Activity".to_string(),
                description: "Keystroke logging behavior".to_string(),
                level: ThreatLevel::High,
                indicators: vec![
                    "keyboard_hook_installation".to_string(),
                    "frequent_log_writes".to_string(),
                    "clipboard_monitoring".to_string(),
                ],
            },
        ];

        // In a real implementation, this would be async
        // For now, we'll use a blocking approach during initialization
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut pattern_map = self.patterns.write().await;
            for pattern in patterns {
                pattern_map.insert(pattern.name.clone(), pattern);
            }
        });

        info!("Initialized behavioral detection patterns");
    }

    /// Observe a behavior for a process/file
    pub async fn observe_behavior(&self, entity_id: &str, behavior: &str) {
        let mut behaviors = self.observed_behaviors.write().await;

        behaviors
            .entry(entity_id.to_string())
            .or_insert_with(Vec::new)
            .push(behavior.to_string());

        debug!("Observed behavior '{}' for entity '{}'", behavior, entity_id);
    }

    /// Analyze observed behaviors for an entity
    pub async fn analyze(&self, entity_id: &str) -> Result<Verdict> {
        let behaviors = self.observed_behaviors.read().await;

        let observed = match behaviors.get(entity_id) {
            Some(b) => b,
            None => return Ok(Verdict::Clean),
        };

        let patterns = self.patterns.read().await;

        // Check if observed behaviors match any malicious patterns
        for (_, pattern) in patterns.iter() {
            let matches = pattern.indicators.iter()
                .filter(|indicator| observed.contains(indicator))
                .count();

            let threshold = (pattern.indicators.len() as f32 * 0.6).ceil() as usize;

            if matches >= threshold {
                return Ok(Verdict::Malicious(ThreatInfo {
                    name: pattern.name.clone(),
                    level: pattern.level,
                    category: "Behavioral".to_string(),
                    description: pattern.description.clone(),
                    detected_by: vec![format!("Behavioral Analysis ({} indicators)", matches)],
                }));
            }
        }

        Ok(Verdict::Clean)
    }

    /// Clear observed behaviors for an entity
    pub async fn clear_observations(&self, entity_id: &str) {
        let mut behaviors = self.observed_behaviors.write().await;
        behaviors.remove(entity_id);
    }

    /// Scan file for behavioral indicators (static analysis)
    pub async fn scan(&self, path: &Path) -> Result<Verdict> {
        debug!("Behavioral scan: {}", path.display());

        // For static analysis, we look for indicators in the file itself
        // In a real-time system, this would monitor actual process behavior

        // For now, return clean as behavioral detection primarily works on running processes
        Ok(Verdict::Clean)
    }
}

impl Default for BehavioralDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_behavior_detection() {
        let detector = BehavioralDetector::new();

        let entity_id = "process_1234";

        // Observe ransomware-like behaviors
        detector.observe_behavior(entity_id, "rapid_file_modification").await;
        detector.observe_behavior(entity_id, "file_extension_change").await;
        detector.observe_behavior(entity_id, "high_file_write_rate").await;

        let verdict = detector.analyze(entity_id).await.unwrap();

        match verdict {
            Verdict::Malicious(threat) => {
                assert!(threat.name.contains("Ransomware"));
            }
            _ => panic!("Expected malicious verdict"),
        }
    }
}
