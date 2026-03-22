//! Configuration system for RECC rules engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use crate::Result;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub rules: RulesConfig,
    pub escalation: EscalationConfig,
    pub clustering: ClusteringConfig,
    pub symbolize: SymbolizeConfig,
    pub mode: Mode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub debounce_ms: u32,
    pub cooldowns: HashMap<String, u32>, // rule_id -> cooldown_ms
    pub confidence_hi: f64,
    pub confidence_lo: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    pub timeouts: HashMap<String, u32>, // tool -> timeout_sec
    pub default_timeout: u32,
    pub max_total_budget: u32, // total seconds per run
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusteringConfig {
    pub window_s: f64,
    pub top_k: usize,
    pub enabled: bool,
    pub max_clusters: usize,
    pub confidence_merge_threshold: f64,
    pub similarity_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolizeConfig {
    pub enabled: bool,
    pub max_frames: usize,
    pub redact_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Mode {
    Vm,
    Native,
}

impl Default for Config {
    fn default() -> Self {
        let mut cooldowns = HashMap::new();
        cooldowns.insert("R-memcpy-oob".to_string(), 10000);
        cooldowns.insert("R-double-free".to_string(), 0);
        cooldowns.insert("R-invalid-free".to_string(), 5000);
        cooldowns.insert("R-uaf-hint".to_string(), 5000);

        let mut timeouts = HashMap::new();
        timeouts.insert("asan".to_string(), 120);
        timeouts.insert("valgrind".to_string(), 300);
        timeouts.insert("gdb".to_string(), 60);

        Self {
            rules: RulesConfig {
                debounce_ms: 1500,
                cooldowns,
                confidence_hi: 0.8,
                confidence_lo: 0.5,
            },
            escalation: EscalationConfig {
                timeouts,
                default_timeout: 120,
                max_total_budget: 600, // 10 minutes
            },
            clustering: ClusteringConfig {
                window_s: 1.5,
                top_k: 3,
                enabled: true,
                max_clusters: 1000,
                confidence_merge_threshold: 0.8,
                similarity_threshold: 0.9,
            },
            symbolize: SymbolizeConfig {
                enabled: true,
                max_frames: 5,
                redact_paths: vec!["/workspace".to_string(), "/tmp".to_string()],
            },
            mode: Mode::Native,
        }
    }
}

impl Config {
    /// Load configuration from file, with environment variable overrides
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut config = if path.as_ref().exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content).map_err(|e| crate::RuleEngineError::Config(e.to_string()))?
        } else {
            Self::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();
        Ok(config)
    }

    /// Apply environment variable overrides (RE_* prefix)
    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("RE_DEBOUNCE_MS") {
            if let Ok(ms) = val.parse() {
                self.rules.debounce_ms = ms;
            }
        }

        if let Ok(val) = std::env::var("RE_CONFIDENCE_HI") {
            if let Ok(conf) = val.parse() {
                self.rules.confidence_hi = conf;
            }
        }

        if let Ok(val) = std::env::var("RE_CONFIDENCE_LO") {
            if let Ok(conf) = val.parse() {
                self.rules.confidence_lo = conf;
            }
        }

        if let Ok(val) = std::env::var("RE_CLUSTERING_WINDOW_S") {
            if let Ok(window) = val.parse() {
                self.clustering.window_s = window;
            }
        }

        if let Ok(val) = std::env::var("RE_CLUSTERING_TOP_K") {
            if let Ok(k) = val.parse() {
                self.clustering.top_k = k;
            }
        }

        if let Ok(val) = std::env::var("RE_MODE") {
            self.mode = match val.to_lowercase().as_str() {
                "vm" => Mode::Vm,
                "native" => Mode::Native,
                _ => Mode::Native,
            };
        }

        if let Ok(val) = std::env::var("RE_SYMBOLIZE_ENABLED") {
            self.symbolize.enabled = val.to_lowercase() == "true";
        }
    }

    /// Get cooldown for a specific rule
    pub fn get_cooldown(&self, rule_id: &str) -> Duration {
        Duration::from_millis(
            self.rules.cooldowns
                .get(rule_id)
                .copied()
                .unwrap_or(5000) as u64
        )
    }

    /// Get timeout for a specific escalation tool
    pub fn get_escalation_timeout(&self, tool: &str) -> Duration {
        Duration::from_secs(
            self.escalation.timeouts
                .get(tool)
                .copied()
                .unwrap_or(self.escalation.default_timeout) as u64
        )
    }
}

/// Generate a default configuration file
pub fn generate_default_config<P: AsRef<Path>>(path: P) -> Result<()> {
    let config = Config::default();
    let content = toml::to_string_pretty(&config)
        .map_err(|e| crate::RuleEngineError::Config(e.to_string()))?;
    
    std::fs::write(path, content)?;
    Ok(())
}
