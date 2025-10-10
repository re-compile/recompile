//! Event structures and processing
//! 
//! Simplified event processing for the Rust agent

use anyhow::Result;
use log::info;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;

use crate::Config;

/// Simplified event structure for rule processing
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedEvent {
    pub event_type: String,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub addr: u64,
    pub size: u32,
    pub len: u32,
    pub alloc_size: u32,
    pub api: String,
    pub free_status: Option<String>,
}

/// Event processor handles normalization and finding emission
pub struct EventProcessor {
    config: Config,
    findings_buffer: Vec<String>,
}

impl EventProcessor {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            findings_buffer: Vec::new(),
        }
    }
    
    /// Parse BPF event from log line
    pub fn parse_bpf_event(&self, line: &str) -> Result<NormalizedEvent> {
        // For now, create a simplified event based on the log line
        // In the future, this will parse actual BPF event data
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;
        
        // Extract information from the log line
        let event_type = if line.contains("free") {
            "free".to_string()
        } else if line.contains("malloc") {
            "malloc".to_string()
        } else if line.contains("memcpy") {
            "memcpy".to_string()
        } else {
            "unknown".to_string()
        };
        
        let api = event_type.clone();
        
        // Extract address if present
        let addr = if let Some(start) = line.find("0x") {
            if let Some(end) = line[start+2..].find(|c: char| !c.is_ascii_hexdigit()) {
                let addr_str = &line[start+2..start+2+end];
                u64::from_str_radix(addr_str, 16).unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };
        
        Ok(NormalizedEvent {
            event_type,
            pid: 0, // Will be extracted from BPF data
            tid: 0, // Will be extracted from BPF data
            timestamp,
            addr,
            size: 0,
            len: 0,
            alloc_size: 0,
            api,
            free_status: None,
        })
    }
    
    pub async fn emit_finding(&mut self, finding: &str) -> Result<()> {
        // Buffer finding for batch writing
        self.findings_buffer.push(finding.to_string());
        
        // Also write to virtio channel immediately
        if self.config.output_path != "/dev/null" {
            self.write_to_virtio(finding).await?;
        }
        
        Ok(())
    }
    
    async fn write_to_virtio(&self, finding: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.output_path)?;
        
        writeln!(file, "RE:FINDING: {}", finding)?;
        file.flush()?;
        
        Ok(())
    }
    
    pub async fn finalize(&mut self) -> Result<()> {
        // Write all buffered findings to crashpack
        if !self.findings_buffer.is_empty() {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&self.config.findings_path)?;
            
            // Write as JSON array
            writeln!(file, "[")?;
            for (i, finding) in self.findings_buffer.iter().enumerate() {
                if i > 0 {
                    writeln!(file, ",")?;
                }
                write!(file, "{}", finding)?;
            }
            writeln!(file, "\n]")?;
            
            info!("Wrote {} findings to {}", self.findings_buffer.len(), self.config.findings_path);
        }
        
        Ok(())
    }
}