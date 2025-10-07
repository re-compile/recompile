//! Hardcoded rules for anomaly detection

use crate::{
    AnomalyClass, Confidence, Severity, SentinelEvent, EventType, 
    Evidence, MemoryEvidence
};
use std::collections::HashMap;

/// Individual rule definition
pub struct Rule {
    pub id: String,
    pub name: String,
    pub class: AnomalyClass,
    pub confidence: Confidence,
    pub severity: Severity,
    pub debounce: DebounceConfig,
    pub escalation: EscalationConfig,
    pub matcher: Box<dyn RuleMatcher + Send + Sync>,
}

#[derive(Debug, Clone)]
pub struct DebounceConfig {
    pub min_hits: u32,
    pub window_ms: u32,
}

#[derive(Debug, Clone)]
pub struct EscalationConfig {
    pub tool: String,
    pub reason: String,
    pub estimated_cost: String,
    pub cooldown_ms: u32,
}

/// Trait for rule matching logic
pub trait RuleMatcher {
    fn matches(&self, events: &[SentinelEvent]) -> bool;
    fn extract_evidence(&self, events: &[SentinelEvent]) -> Evidence;
}

/// Registry of all available rules
pub struct RuleRegistry {
    rules: HashMap<String, Rule>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            rules: HashMap::new(),
        };
        registry.register_default_rules();
        registry
    }

    fn register_default_rules(&mut self) {
        // Rule 1: memcpy/memmove length > alloc size
        self.rules.insert("R-memcpy-oob".to_string(), Rule {
            id: "R-memcpy-oob".to_string(),
            name: "Heap Overflow via memcpy".to_string(),
            class: AnomalyClass::HeapOverflow,
            confidence: Confidence::High,
            severity: Severity::High,
            debounce: DebounceConfig {
                min_hits: 2,
                window_ms: 1500,
            },
            escalation: EscalationConfig {
                tool: "asan".to_string(),
                reason: "len>alloc_size".to_string(),
                estimated_cost: "low".to_string(),
                cooldown_ms: 10000,
            },
            matcher: Box::new(MemcpyOobMatcher),
        });

        // Rule 2: double free
        self.rules.insert("R-double-free".to_string(), Rule {
            id: "R-double-free".to_string(),
            name: "Double Free".to_string(),
            class: AnomalyClass::DoubleFree,
            confidence: Confidence::Certain,
            severity: Severity::Critical,
            debounce: DebounceConfig {
                min_hits: 1,
                window_ms: 0,
            },
            escalation: EscalationConfig {
                tool: "asan".to_string(),
                reason: "double_free_detected".to_string(),
                estimated_cost: "low".to_string(),
                cooldown_ms: 0,
            },
            matcher: Box::new(DoubleFreeMatcher),
        });

        // Rule 3: invalid free (free of non-tracked pointer)
        self.rules.insert("R-invalid-free".to_string(), Rule {
            id: "R-invalid-free".to_string(),
            name: "Invalid Free".to_string(),
            class: AnomalyClass::InvalidFree,
            confidence: Confidence::High,
            severity: Severity::High,
            debounce: DebounceConfig {
                min_hits: 1,
                window_ms: 0,
            },
            escalation: EscalationConfig {
                tool: "asan".to_string(),
                reason: "invalid_free_detected".to_string(),
                estimated_cost: "low".to_string(),
                cooldown_ms: 5000,
            },
            matcher: Box::new(InvalidFreeMatcher),
        });

        // Rule 4: use after free hint (memcpy to freed pointer)
        self.rules.insert("R-uaf-hint".to_string(), Rule {
            id: "R-uaf-hint".to_string(),
            name: "Use After Free Hint".to_string(),
            class: AnomalyClass::UseAfterFree,
            confidence: Confidence::Medium,
            severity: Severity::High,
            debounce: DebounceConfig {
                min_hits: 2,
                window_ms: 2000,
            },
            escalation: EscalationConfig {
                tool: "asan".to_string(),
                reason: "memcpy_to_freed_ptr".to_string(),
                estimated_cost: "medium".to_string(),
                cooldown_ms: 5000,
            },
            matcher: Box::new(UafHintMatcher),
        });
    }

    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.get(id)
    }

    pub fn all_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values()
    }

    pub fn rules_for_class(&self, class: &AnomalyClass) -> Vec<&Rule> {
        self.rules.values()
            .filter(|rule| &rule.class == class)
            .collect()
    }
}

// Rule matchers

struct MemcpyOobMatcher;

impl RuleMatcher for MemcpyOobMatcher {
    fn matches(&self, events: &[SentinelEvent]) -> bool {
        events.iter().any(|event| {
            matches!(event.event_type, EventType::Memcpy | EventType::Memmove) &&
            event.alloc_size > 0 &&
            event.len > event.alloc_size
        })
    }

    fn extract_evidence(&self, events: &[SentinelEvent]) -> Evidence {
        let memcpy_event = events.iter()
            .find(|e| matches!(e.event_type, EventType::Memcpy | EventType::Memmove) && e.len > e.alloc_size)
            .expect("memcpy event should exist if rule matches");

        Evidence {
            memory: Some(MemoryEvidence {
                ptr: memcpy_event.addr,
                size: memcpy_event.len,
                alloc_size: memcpy_event.alloc_size,
                operation: format!("{:?}", memcpy_event.event_type),
            }),
            stacks: None, // Will be filled by symbolization
            alloc_site: None, // Will be filled by symbolization
            event_sequence: vec![memcpy_event.clone()],
        }
    }
}

struct DoubleFreeMatcher;

impl RuleMatcher for DoubleFreeMatcher {
    fn matches(&self, events: &[SentinelEvent]) -> bool {
        let mut freed_ptrs = std::collections::HashSet::new();
        
        for event in events {
            if event.event_type == EventType::Free {
                if !freed_ptrs.insert(event.addr) {
                    return true; // Second free of same pointer
                }
            }
        }
        false
    }

    fn extract_evidence(&self, events: &[SentinelEvent]) -> Evidence {
        let mut freed_ptrs = std::collections::HashSet::new();
        let mut double_free_event = None;
        
        for event in events {
            if event.event_type == EventType::Free {
                if !freed_ptrs.insert(event.addr) {
                    double_free_event = Some(event.clone());
                    break;
                }
            }
        }

        let event = double_free_event.expect("double free event should exist if rule matches");

        Evidence {
            memory: Some(MemoryEvidence {
                ptr: event.addr,
                size: 0, // Size unknown for double free
                alloc_size: 0,
                operation: "double_free".to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: vec![event],
        }
    }
}

struct InvalidFreeMatcher;

impl RuleMatcher for InvalidFreeMatcher {
    fn matches(&self, events: &[SentinelEvent]) -> bool {
        let mut allocated_ptrs = std::collections::HashSet::new();
        
        // Track all allocated pointers
        for event in events {
            match event.event_type {
                EventType::Malloc | EventType::Mmap => {
                    allocated_ptrs.insert(event.addr);
                }
                EventType::Free | EventType::Munmap => {
                    if !allocated_ptrs.contains(&event.addr) {
                        return true; // Free of non-allocated pointer
                    }
                    allocated_ptrs.remove(&event.addr);
                }
                _ => {}
            }
        }
        false
    }

    fn extract_evidence(&self, events: &[SentinelEvent]) -> Evidence {
        let mut allocated_ptrs = std::collections::HashSet::new();
        let mut invalid_free_event = None;
        
        for event in events {
            match event.event_type {
                EventType::Malloc | EventType::Mmap => {
                    allocated_ptrs.insert(event.addr);
                }
                EventType::Free | EventType::Munmap => {
                    if !allocated_ptrs.contains(&event.addr) {
                        invalid_free_event = Some(event.clone());
                        break;
                    }
                    allocated_ptrs.remove(&event.addr);
                }
                _ => {}
            }
        }

        let event = invalid_free_event.expect("invalid free event should exist if rule matches");

        Evidence {
            memory: Some(MemoryEvidence {
                ptr: event.addr,
                size: 0,
                alloc_size: 0,
                operation: "invalid_free".to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: vec![event],
        }
    }
}

struct UafHintMatcher;

impl RuleMatcher for UafHintMatcher {
    fn matches(&self, events: &[SentinelEvent]) -> bool {
        let mut freed_ptrs = std::collections::HashSet::new();
        
        // First pass: collect freed pointers
        for event in events {
            if event.event_type == EventType::Free {
                freed_ptrs.insert(event.addr);
            }
        }
        
        // Second pass: check for memcpy to freed pointers
        events.iter().any(|event| {
            matches!(event.event_type, EventType::Memcpy | EventType::Memmove) &&
            freed_ptrs.contains(&event.addr)
        })
    }

    fn extract_evidence(&self, events: &[SentinelEvent]) -> Evidence {
        let mut freed_ptrs = std::collections::HashSet::new();
        let mut uaf_event = None;
        
        // Collect freed pointers
        for event in events {
            if event.event_type == EventType::Free {
                freed_ptrs.insert(event.addr);
            }
        }
        
        // Find memcpy to freed pointer
        for event in events {
            if matches!(event.event_type, EventType::Memcpy | EventType::Memmove) &&
               freed_ptrs.contains(&event.addr) {
                uaf_event = Some(event.clone());
                break;
            }
        }

        let event = uaf_event.expect("UAF event should exist if rule matches");

        Evidence {
            memory: Some(MemoryEvidence {
                ptr: event.addr,
                size: event.len,
                alloc_size: event.alloc_size,
                operation: "use_after_free".to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: vec![event],
        }
    }
}
