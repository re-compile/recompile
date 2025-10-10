//! Rule engine integration
//! 
//! Simplified rule engine for anomaly detection

use anyhow::Result;
// use log::{info, warn, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::events::NormalizedEvent;

/// Rule engine wrapper for the agent
pub struct RuleEngine {
    alloc_tracker: HashMap<u64, AllocInfo>,
    finding_count: u32,
}

#[derive(Debug, Clone)]
struct AllocInfo {
    size: u32,
    timestamp: u64,
}

/// Finding structure matching the v1 schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub kind: String,
    pub confidence: f64,
    pub timestamp: u64,
    pub pid: u32,
    pub evidence: Evidence,
    pub fix_hints: Vec<String>,
    pub related: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub memory: Option<MemoryEvidence>,
    pub stacks: Option<StacksEvidence>,
    pub alloc_site: Option<String>,
    pub event_sequence: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEvidence {
    pub ptr: String,
    pub size: u32,
    pub len: u32,
    pub alloc_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StacksEvidence {
    pub alloc: Vec<String>,
    pub call: Vec<String>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            alloc_tracker: HashMap::new(),
            finding_count: 0,
        }
    }
    
    pub async fn process_event(&mut self, event: &NormalizedEvent) -> Result<Option<Vec<Finding>>> {
        match event.event_type.as_str() {
            "malloc" => {
                self.handle_malloc(event);
                Ok(None)
            }
            "free" => {
                if let Some(finding) = self.handle_free(event).await? {
                    Ok(Some(vec![finding]))
                } else {
                    Ok(None)
                }
            }
            "memcpy" => {
                if let Some(finding) = self.handle_memcpy(event).await? {
                    Ok(Some(vec![finding]))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
    
    fn handle_malloc(&mut self, event: &NormalizedEvent) {
        self.alloc_tracker.insert(event.addr, AllocInfo {
            size: event.size,
            timestamp: event.timestamp,
        });
    }
    
    async fn handle_free(&mut self, event: &NormalizedEvent) -> Result<Option<Finding>> {
        match event.free_status.as_deref() {
            Some("double") => {
                // Double free detected
                Ok(Some(self.create_double_free_finding(event).await?))
            }
            Some("invalid") => {
                // Invalid free detected
                Ok(Some(self.create_invalid_free_finding(event).await?))
            }
            Some("ok") | None => {
                // Check if address is tracked
                if self.alloc_tracker.contains_key(&event.addr) {
                    self.alloc_tracker.remove(&event.addr);
                    Ok(None)
                } else {
                    // Untracked free - treat as invalid
                    Ok(Some(self.create_invalid_free_finding(event).await?))
                }
            }
            _ => Ok(None),
        }
    }
    
    async fn handle_memcpy(&mut self, event: &NormalizedEvent) -> Result<Option<Finding>> {
        if let Some(alloc_info) = self.alloc_tracker.get(&event.addr).cloned() {
            // Check for overflow
            if event.len > alloc_info.size {
                Ok(Some(self.create_heap_overflow_finding(event, &alloc_info).await?))
            } else {
                Ok(None)
            }
        } else {
            // Access to untracked memory - potential UAF
            Ok(Some(self.create_uaf_finding(event).await?))
        }
    }
    
    async fn create_double_free_finding(&mut self, event: &NormalizedEvent) -> Result<Finding> {
        self.finding_count += 1;
        
        let evidence = Evidence {
            memory: Some(MemoryEvidence {
                ptr: format!("{:#x}", event.addr),
                size: event.size,
                len: 0,
                alloc_size: event.size,
            }),
            stacks: Some(StacksEvidence {
                alloc: vec![],
                call: vec![],
            }),
            alloc_site: None,
            event_sequence: Some(vec![
                "malloc".to_string(),
                "free".to_string(),
                "free".to_string(),
            ]),
        };
        
        Ok(Finding {
            id: Uuid::new_v4().to_string(),
            kind: "double_free".to_string(),
            confidence: 1.0,
            timestamp: event.timestamp,
            pid: event.pid,
            evidence,
            fix_hints: vec![
                "Check for duplicate free() calls on the same pointer".to_string(),
                "Use RAII or smart pointers to manage memory lifecycle".to_string(),
                "Consider using AddressSanitizer for additional detection".to_string(),
            ],
            related: vec![],
        })
    }
    
    async fn create_invalid_free_finding(&mut self, event: &NormalizedEvent) -> Result<Finding> {
        self.finding_count += 1;
        
        let evidence = Evidence {
            memory: Some(MemoryEvidence {
                ptr: format!("{:#x}", event.addr),
                size: 0,
                len: 0,
                alloc_size: 0,
            }),
            stacks: Some(StacksEvidence {
                alloc: vec![],
                call: vec![],
            }),
            alloc_site: None,
            event_sequence: Some(vec![
                "free".to_string(),
            ]),
        };
        
        Ok(Finding {
            id: Uuid::new_v4().to_string(),
            kind: "invalid_free".to_string(),
            confidence: 1.0,
            timestamp: event.timestamp,
            pid: event.pid,
            evidence,
            fix_hints: vec![
                "Ensure pointer was allocated with malloc/calloc/realloc".to_string(),
                "Check for stack variable being passed to free()".to_string(),
                "Verify pointer is not null or already freed".to_string(),
            ],
            related: vec![],
        })
    }
    
    async fn create_heap_overflow_finding(&mut self, event: &NormalizedEvent, alloc_info: &AllocInfo) -> Result<Finding> {
        self.finding_count += 1;
        
        let evidence = Evidence {
            memory: Some(MemoryEvidence {
                ptr: format!("{:#x}", event.addr),
                size: alloc_info.size,
                len: event.len,
                alloc_size: alloc_info.size,
            }),
            stacks: Some(StacksEvidence {
                alloc: vec![],
                call: vec![],
            }),
            alloc_site: None,
            event_sequence: Some(vec![
                "malloc".to_string(),
                event.api.clone(),
            ]),
        };
        
        Ok(Finding {
            id: Uuid::new_v4().to_string(),
            kind: "heap_overflow".to_string(),
            confidence: 1.0,
            timestamp: event.timestamp,
            pid: event.pid,
            evidence,
            fix_hints: vec![
                format!("Copy operation writes {} bytes but allocation is only {} bytes", event.len, alloc_info.size),
                "Check buffer bounds before copy operations".to_string(),
                "Consider using safer alternatives like strlcpy or bounds-checked functions".to_string(),
            ],
            related: vec![],
        })
    }
    
    async fn create_uaf_finding(&mut self, event: &NormalizedEvent) -> Result<Finding> {
        self.finding_count += 1;
        
        let evidence = Evidence {
            memory: Some(MemoryEvidence {
                ptr: format!("{:#x}", event.addr),
                size: 0,
                len: event.len,
                alloc_size: 0,
            }),
            stacks: Some(StacksEvidence {
                alloc: vec![],
                call: vec![],
            }),
            alloc_site: None,
            event_sequence: Some(vec![
                event.api.clone(),
            ]),
        };
        
        Ok(Finding {
            id: Uuid::new_v4().to_string(),
            kind: "use_after_free".to_string(),
            confidence: 0.7, // Lower confidence as it might be legitimate access
            timestamp: event.timestamp,
            pid: event.pid,
            evidence,
            fix_hints: vec![
                "Access to memory that may have been freed".to_string(),
                "Ensure memory is still valid before access".to_string(),
                "Consider using RAII or smart pointers".to_string(),
            ],
            related: vec![],
        })
    }
    
    pub async fn update_state(&mut self) -> Result<()> {
        // TODO: Implement state updates, cooldowns, etc.
        Ok(())
    }
    
    pub fn get_finding_count(&self) -> u32 {
        self.finding_count
    }
}