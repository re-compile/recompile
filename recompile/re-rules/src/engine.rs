//! Rule engine that processes events and generates findings

use crate::{
    Config, RuleRegistry, SentinelEvent, Finding, AnomalyClass, 
    EscalationPlan, Result
};
use std::collections::{HashMap, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Rule engine state for processing events
pub struct RuleEngine {
    config: Config,
    registry: RuleRegistry,
    event_buffer: VecDeque<SentinelEvent>,
    active_clusters: HashMap<String, ClusterState>,
    cooldowns: HashMap<String, Instant>,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
struct ClusterState {
    rule_id: String,
    events: Vec<SentinelEvent>,
    hits: u32,
    first_seen: Instant,
    last_seen: Instant,
    fingerprint: String,
}

impl RuleEngine {
    pub fn new(config: Config) -> Self {
        Self {
            registry: RuleRegistry::new(),
            event_buffer: VecDeque::new(),
            active_clusters: HashMap::new(),
            cooldowns: HashMap::new(),
            findings: Vec::new(),
            config,
        }
    }

    /// Process a new event and potentially generate findings
    pub fn process_event(&mut self, event: SentinelEvent) -> Result<Vec<Finding>> {
        let mut new_findings = Vec::new();
        
        // Add event to buffer
        self.event_buffer.push_back(event.clone());
        
        // Maintain buffer size (keep last N seconds of events)
        let cutoff_time = event.ts_ns - (self.config.clustering.window_s * 1_000_000_000.0) as u64;
        while let Some(front) = self.event_buffer.front() {
            if front.ts_ns < cutoff_time {
                self.event_buffer.pop_front();
            } else {
                break;
            }
        }

        // Check all rules against current event window
        let rule_ids: Vec<String> = self.registry.all_rules().map(|r| r.id.clone()).collect();
        for rule_id in rule_ids {
            if let Some(finding) = self.check_rule_by_id(&rule_id, &event)? {
                new_findings.push(finding);
            }
        }

        self.findings.extend(new_findings.clone());
        Ok(new_findings)
    }

    /// Check a specific rule by ID against the current event window
    fn check_rule_by_id(&mut self, rule_id: &str, trigger_event: &SentinelEvent) -> Result<Option<Finding>> {
        // Get events in debounce window
        let window_start = trigger_event.ts_ns - 1500 * 1_000_000; // 1.5s default window
        let relevant_events: Vec<SentinelEvent> = self.event_buffer
            .iter()
            .filter(|e| e.ts_ns >= window_start)
            .cloned()
            .collect();

        // Get rule info without borrowing self
        let rule_info = match rule_id {
            "R-memcpy-oob" => Some(("R-memcpy-oob", "memcpy", 2, 1500)),
            "R-double-free" => Some(("R-double-free", "double_free", 1, 0)),
            "R-invalid-free" => Some(("R-invalid-free", "invalid_free", 1, 0)),
            "R-uaf-hint" => Some(("R-uaf-hint", "uaf", 2, 2000)),
            _ => None,
        };

        let (id, rule_type, min_hits, window_ms) = match rule_info {
            Some(info) => info,
            None => return Ok(None),
        };

        // Check cooldown
        if let Some(cooldown_until) = self.cooldowns.get(id) {
            if cooldown_until > &Instant::now() {
                return Ok(None);
            }
        }

        // Simple rule matching logic
        let matches = match rule_type {
            "memcpy" => relevant_events.iter().any(|e| {
                matches!(e.event_type, crate::EventType::Memcpy | crate::EventType::Memmove) &&
                e.alloc_size > 0 && e.len > e.alloc_size
            }),
            "double_free" => {
                let mut freed_ptrs = std::collections::HashSet::new();
                relevant_events.iter().any(|e| {
                    if e.event_type == crate::EventType::Free {
                        !freed_ptrs.insert(e.addr)
                    } else {
                        false
                    }
                })
            },
            "invalid_free" => {
                let mut allocated_ptrs = std::collections::HashSet::new();
                relevant_events.iter().any(|e| {
                    match e.event_type {
                        crate::EventType::Malloc | crate::EventType::Mmap => {
                            allocated_ptrs.insert(e.addr);
                            false
                        }
                        crate::EventType::Free | crate::EventType::Munmap => {
                            !allocated_ptrs.contains(&e.addr)
                        }
                        _ => false
                    }
                })
            },
            "uaf" => {
                let mut freed_ptrs = std::collections::HashSet::new();
                for e in &relevant_events {
                    if e.event_type == crate::EventType::Free {
                        freed_ptrs.insert(e.addr);
                    }
                }
                relevant_events.iter().any(|e| {
                    matches!(e.event_type, crate::EventType::Memcpy | crate::EventType::Memmove) &&
                    freed_ptrs.contains(&e.addr)
                })
            },
            _ => false,
        };

        if !matches {
            return Ok(None);
        }

        // Check debounce requirements
        let cluster_key = format!("{}-{:04x}-{:08x}", id, (trigger_event.addr >> 12) & 0xFFFF, trigger_event.stack_fp);
        let should_generate = {
            let cluster = self.active_clusters.entry(cluster_key.clone()).or_insert_with(|| {
                ClusterState {
                    rule_id: id.to_string(),
                    events: Vec::new(),
                    hits: 0,
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                    fingerprint: cluster_key.clone(),
                }
            });

            cluster.hits += 1;
            cluster.last_seen = Instant::now();
            cluster.events.extend(relevant_events.clone());
            cluster.hits >= min_hits
        };

        if !should_generate {
            return Ok(None);
        }

        // Generate finding
        let finding = self.create_simple_finding(id, rule_type, &relevant_events, trigger_event)?;
        
        // Set cooldown
        let cooldown_duration = self.config.get_cooldown(id);
        self.cooldowns.insert(id.to_string(), Instant::now() + cooldown_duration);
        
        // Clear cluster
        self.active_clusters.remove(&cluster_key);

        Ok(Some(finding))
    }

    /// Check a specific rule against the current event window
    fn check_rule(&mut self, rule: &crate::Rule, trigger_event: &SentinelEvent) -> Result<Option<Finding>> {
        // Check cooldown
        if let Some(cooldown_until) = self.cooldowns.get(&rule.id) {
            if cooldown_until > &Instant::now() {
                return Ok(None);
            }
        }

        // Get events in debounce window
        let window_start = trigger_event.ts_ns - (rule.debounce.window_ms as u64 * 1_000_000);
        let relevant_events: Vec<SentinelEvent> = self.event_buffer
            .iter()
            .filter(|e| e.ts_ns >= window_start)
            .cloned()
            .collect();

        // Check if rule matches
        if !rule.matcher.matches(&relevant_events) {
            return Ok(None);
        }

        // Check debounce requirements
        let cluster_key = self.generate_cluster_key(rule, trigger_event);
        let should_generate_finding = {
            let cluster = self.active_clusters.entry(cluster_key.clone()).or_insert_with(|| {
                ClusterState {
                    rule_id: rule.id.clone(),
                    events: Vec::new(),
                    hits: 0,
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                    fingerprint: cluster_key.clone(),
                }
            });

            cluster.hits += 1;
            cluster.last_seen = Instant::now();
            cluster.events.extend(relevant_events.clone());

            // Check if debounce threshold is met
            cluster.hits >= rule.debounce.min_hits
        };

        if !should_generate_finding {
            return Ok(None);
        }

        // Generate finding using events from cluster
        let cluster_events = self.active_clusters.get(&cluster_key)
            .map(|c| c.events.clone())
            .unwrap_or_else(|| relevant_events);
        
        let finding = self.create_finding(rule, &cluster_events)?;
        
        // Set cooldown
        let cooldown_duration = self.config.get_cooldown(&rule.id);
        self.cooldowns.insert(rule.id.clone(), Instant::now() + cooldown_duration);
        
        // Clear cluster (or mark as processed)
        self.active_clusters.remove(&cluster_key);

        Ok(Some(finding))
    }

    /// Generate a cluster key for grouping related events
    fn generate_cluster_key(&self, rule: &crate::Rule, event: &SentinelEvent) -> String {
        // Simple fingerprint: rule_id + top stack frame + ptr bucket
        let ptr_bucket = (event.addr >> 12) & 0xFFFF; // 4KB page bucket
        let stack_fp = event.stack_fp;
        
        format!("{}-{:04x}-{:08x}", rule.id, ptr_bucket, stack_fp)
    }

    /// Create a simple finding without using the rule registry
    fn create_simple_finding(&self, rule_id: &str, rule_type: &str, events: &[SentinelEvent], trigger_event: &SentinelEvent) -> Result<Finding> {
        let (class, confidence, severity) = match rule_type {
            "memcpy" => (AnomalyClass::HeapOverflow, crate::Confidence::High, crate::Severity::High),
            "double_free" => (AnomalyClass::DoubleFree, crate::Confidence::Certain, crate::Severity::Critical),
            "invalid_free" => (AnomalyClass::InvalidFree, crate::Confidence::High, crate::Severity::High),
            "uaf" => (AnomalyClass::UseAfterFree, crate::Confidence::Medium, crate::Severity::High),
            _ => return Err(crate::RuleEngineError::RuleEvaluation(format!("Unknown rule type: {}", rule_type))),
        };

        let evidence = crate::Evidence {
            memory: Some(crate::MemoryEvidence {
                ptr: trigger_event.addr,
                size: trigger_event.len,
                alloc_size: trigger_event.alloc_size,
                operation: rule_type.to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: events.to_vec(),
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let finding_id = self.generate_finding_id(&class, events);
        
        let escalation = if confidence.as_f64() >= self.config.rules.confidence_lo {
            Some(EscalationPlan {
                tool: "asan".to_string(),
                reason: format!("{}_detected", rule_type),
                estimated_cost: "low".to_string(),
                cooldown_ms: 5000,
            })
        } else {
            None
        };

        Ok(Finding {
            id: finding_id,
            schema_version: "1.0".to_string(),
            class,
            confidence,
            severity,
            timestamp,
            pid: trigger_event.pid,
            evidence,
            escalation,
            related: Vec::new(),
        })
    }

    /// Create a finding from a rule match
    fn create_finding(&self, rule: &crate::Rule, events: &[SentinelEvent]) -> Result<Finding> {
        let evidence = rule.matcher.extract_evidence(events);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let finding_id = self.generate_finding_id(&rule.class, events);
        
        let escalation = if self.should_escalate(rule) {
            Some(EscalationPlan {
                tool: rule.escalation.tool.clone(),
                reason: rule.escalation.reason.clone(),
                estimated_cost: rule.escalation.estimated_cost.clone(),
                cooldown_ms: rule.escalation.cooldown_ms,
            })
        } else {
            None
        };

        Ok(Finding {
            id: finding_id,
            schema_version: "1.0".to_string(),
            class: rule.class.clone(),
            confidence: rule.confidence,
            severity: rule.severity,
            timestamp,
            pid: events.first().map(|e| e.pid).unwrap_or(0),
            evidence,
            escalation,
            related: Vec::new(),
        })
    }

    /// Generate a unique finding ID
    fn generate_finding_id(&self, class: &AnomalyClass, events: &[SentinelEvent]) -> String {
        let class_str = match class {
            AnomalyClass::HeapOverflow => "heap-overflow",
            AnomalyClass::DoubleFree => "double-free",
            AnomalyClass::InvalidFree => "invalid-free",
            AnomalyClass::UseAfterFree => "use-after-free",
            AnomalyClass::UninitToIo => "uninit-to-io",
            AnomalyClass::LockCycle => "lock-cycle",
            AnomalyClass::UndefinedBehavior => "undefined-behavior",
            AnomalyClass::MemoryLeak => "memory-leak",
        };

        let hash = if let Some(event) = events.first() {
            // Simple hash of first event's key fields
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};
            event.addr.hash(&mut hasher);
            event.stack_fp.hash(&mut hasher);
            event.ts_ns.hash(&mut hasher);
            hasher.finish()
        } else {
            0
        };

        format!("F-{}-{:08x}-{}", class_str, hash, 
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
    }

    /// Determine if a finding should be escalated
    fn should_escalate(&self, rule: &crate::Rule) -> bool {
        let confidence_value = rule.confidence.as_f64();
        confidence_value >= self.config.rules.confidence_lo
    }

    /// Get all findings generated so far
    pub fn get_findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Clear all findings (for testing)
    pub fn clear_findings(&mut self) {
        self.findings.clear();
        self.active_clusters.clear();
        self.cooldowns.clear();
    }

    /// Get statistics about rule engine performance
    pub fn get_stats(&self) -> RuleEngineStats {
        RuleEngineStats {
            total_events: self.event_buffer.len(),
            active_clusters: self.active_clusters.len(),
            total_findings: self.findings.len(),
            findings_by_class: self.get_findings_by_class(),
        }
    }

    fn get_findings_by_class(&self) -> HashMap<AnomalyClass, usize> {
        let mut counts = HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.class.clone()).or_insert(0) += 1;
        }
        counts
    }
}

#[derive(Debug, Clone)]
pub struct RuleEngineStats {
    pub total_events: usize,
    pub active_clusters: usize,
    pub total_findings: usize,
    pub findings_by_class: HashMap<AnomalyClass, usize>,
}
