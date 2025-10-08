//! Configuration management for escalation runner

use crate::{EscalationConfig, Result};
use std::fs;
use std::path::Path;

impl EscalationConfig {
    /// Load configuration from a TOML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: EscalationConfig = toml::from_str(&content)
            .map_err(|e| crate::EscalationError::Config(format!("Failed to parse config: {}", e)))?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::EscalationError::Config(format!("Failed to serialize config: {}", e)))?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Generate a default configuration file
    pub fn generate_default_config<P: AsRef<Path>>(path: P) -> Result<()> {
        let config = EscalationConfig::default();
        config.save_to_file(path)?;
        Ok(())
    }
}
