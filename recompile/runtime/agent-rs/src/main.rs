//! RECC Sentinel Agent - Rust Implementation
//! 
//! This agent replaces the C agent (re-mini.c) and provides:
//! - Event processing and normalization
//! - Rule engine integration
//! - Findings emission and crashpack generation
//! 
//! For now, this is a simplified version that works alongside the existing C agent
//! and can be compiled inside the Linux VM.

use anyhow::Result;
use log::info;
use std::env;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use tokio::fs;
use tokio::time::{sleep, Duration};

mod events;
mod rules;

use events::EventProcessor;
use rules::RuleEngine;

/// Agent configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub target_binary: Option<String>,
    pub libc_path: Option<String>,
    pub output_path: String,
    pub findings_path: String,
    pub symbolize: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_binary: None,
            libc_path: None,
            output_path: "/dev/virtio-ports/re.findings".to_string(),
            findings_path: "/host/build/crashpack/findings.json".to_string(),
            symbolize: true,
        }
    }
}

impl Config {
    pub fn from_args() -> Result<Self> {
        let args: Vec<String> = env::args().collect();
        let mut config = Config::default();
        
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--binary" => {
                    i += 1;
                    if i < args.len() {
                        config.target_binary = Some(args[i].clone());
                    }
                }
                "--libc" => {
                    i += 1;
                    if i < args.len() {
                        config.libc_path = Some(args[i].clone());
                    }
                }
                "--out" => {
                    i += 1;
                    if i < args.len() {
                        config.output_path = args[i].clone();
                    }
                }
                "--findings" => {
                    i += 1;
                    if i < args.len() {
                        config.findings_path = args[i].clone();
                    }
                }
                "--no-symbolize" => {
                    config.symbolize = false;
                }
                _ => {
                    if !args[i].starts_with("--") {
                        // Positional argument - assume it's the target binary
                        config.target_binary = Some(args[i].clone());
                    }
                }
            }
            i += 1;
        }
        
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let config = Config::from_args()?;
    info!("Starting RECC Sentinel Agent (Rust)");
    info!("Config: {:?}", config);
    
    // Initialize event processor
    let mut event_processor = EventProcessor::new(config.clone());
    info!("Event processor initialized");
    
    // Initialize rule engine
    let mut rule_engine = RuleEngine::new();
    info!("Rule engine initialized");
    
    // Create crashpack directory
    if let Some(parent) = Path::new(&config.findings_path).parent() {
        fs::create_dir_all(parent).await?;
    }
    
    // For now, simulate the agent by processing events from a log file
    // In the future, this will consume from ringbuf directly
    info!("Starting event processing loop");
    
    // Monitor the re-findings.log file for events
    let log_path = "/host/build/re-findings.log";
    let mut last_position = 0u64;
    
    loop {
        // Check if log file exists and get its size
        if let Ok(metadata) = fs::metadata(log_path).await {
            let current_size = metadata.len();
            
            if current_size > last_position {
                // Read new content
                let file = std::fs::File::open(log_path)?;
                let mut reader = BufReader::new(file);
                
                // Skip to last position
                reader.seek(SeekFrom::Start(last_position))?;
                
                let mut buffer = String::new();
                while reader.read_line(&mut buffer)? > 0 {
                    // Process each line
                    if buffer.starts_with("RE:LIBBPF:") {
                        // Parse BPF event
                        if let Ok(event) = event_processor.parse_bpf_event(&buffer) {
                            if let Some(findings) = rule_engine.process_event(&event).await? {
                                for finding in findings {
                                    let finding_json = serde_json::to_string(&finding)?;
                                    event_processor.emit_finding(&finding_json).await?;
                                }
                            }
                        }
                    }
                    buffer.clear();
                }
                
                last_position = current_size;
            }
        }
        
        // Sleep briefly
        sleep(Duration::from_millis(100)).await;
    }
}