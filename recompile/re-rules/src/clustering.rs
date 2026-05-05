//! Clustering and deduplication module
//! 
//! Provides advanced clustering, fingerprinting, and Top-K selection for findings

use crate::{Finding, AnomalyClass, Confidence, SentinelEvent};
use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::{Ordering, Reverse};

/// Cluster manager for deduplication and Top-K selection
pub struct ClusterManager {
    clusters: HashMap<String, Cluster>,
    config: ClusteringConfig,
    top_k_heap: BinaryHeap<Reverse<ClusterScore>>,
}

#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: String,
    pub fingerprint: String,
    pub findings: Vec<Finding>,
    pub hit_count: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub confidence_sum: f64,
    pub max_confidence: f64,
    pub related_clusters: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClusterScore {
    pub confidence: f64,
    pub severity_weight: f64,
    pub hit_count: u32,
    pub recency: f64,
}

#[derive(Debug, Clone)]
pub struct ClusteringConfig {
    pub window_s: f64,
    pub max_clusters: usize,
    pub top_k: usize,
    pub confidence_merge_threshold: f64,
    pub similarity_threshold: f64,
}

impl Default for ClusteringConfig {
    fn default() -> Self {
        Self {
            window_s: 10.0,
            max_clusters: 1000,
            top_k: 3,
            confidence_merge_threshold: 0.8,
            similarity_threshold: 0.9,
        }
    }
}

impl PartialOrd for ClusterScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Higher confidence and severity gets higher priority
        let self_score = self.confidence * self.severity_weight + (self.hit_count as f64 * 0.1) + self.recency;
        let other_score = other.confidence * other.severity_weight + (other.hit_count as f64 * 0.1) + other.recency;
        self_score.partial_cmp(&other_score)
    }
}

impl Ord for ClusterScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Equal)
    }
}

impl Eq for ClusterScore {}

impl ClusterManager {
    pub fn new(config: ClusteringConfig) -> Self {
        Self {
            clusters: HashMap::new(),
            config,
            top_k_heap: BinaryHeap::new(),
        }
    }

    /// Add a finding to the appropriate cluster
    pub fn add_finding(&mut self, finding: Finding, events: &[SentinelEvent]) -> Option<Finding> {
        let fingerprint = self.generate_fingerprint(&finding, events);
        
        // Check for existing cluster
        if let Some(cluster_id) = self.find_similar_cluster(&fingerprint) {
            // Merge with existing cluster
            return self.merge_into_cluster(&cluster_id, finding);
        }

        // Create new cluster
        let cluster_id = self.create_new_cluster(finding.clone(), fingerprint, events);
        
        // Check if we need to evict clusters
        if self.clusters.len() > self.config.max_clusters {
            self.evict_oldest_cluster();
        }

        // Add to Top-K heap
        self.update_top_k_heap(&cluster_id);

        None // New cluster, no merged finding to return
    }

    /// Generate fingerprint for clustering
    fn generate_fingerprint(&self, finding: &Finding, _events: &[SentinelEvent]) -> String {
        let mut components = Vec::new();
        
        // Rule type
        components.push(format!("{:?}", finding.class));
        
        // Top 2 stack frames (if available)
        if let Some(stacks) = &finding.evidence.stacks {
            let alloc_frames = &stacks.alloc_stack;
            let call_frames = &stacks.call_stack;
            
            // Use top 2 frames from allocation or call stack
            let top_frames = if !alloc_frames.is_empty() {
                alloc_frames.iter().take(2)
            } else {
                call_frames.iter().take(2)
            };
            
            for frame in top_frames {
                components.push(format!("{}:{}", frame.module, frame.function));
            }
        }
        
        // Pointer bucket (4KB page)
        if let Some(memory) = &finding.evidence.memory {
            let ptr_bucket = (memory.ptr >> 12) & 0xFFFF;
            components.push(format!("ptr:{:04x}", ptr_bucket));
        }
        
        // PID (for process isolation)
        components.push(format!("pid:{}", finding.pid));
        
        // Join components with delimiter
        components.join("|")
    }

    /// Find similar cluster based on fingerprint
    fn find_similar_cluster(&self, fingerprint: &str) -> Option<String> {
        for (id, cluster) in &self.clusters {
            if self.calculate_similarity(fingerprint, &cluster.fingerprint) >= self.config.similarity_threshold {
                return Some(id.clone());
            }
        }
        None
    }

    /// Calculate similarity between two fingerprints
    fn calculate_similarity(&self, fp1: &str, fp2: &str) -> f64 {
        let parts1: HashSet<&str> = fp1.split('|').collect();
        let parts2: HashSet<&str> = fp2.split('|').collect();
        
        let intersection = parts1.intersection(&parts2).count();
        let union = parts1.union(&parts2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Create new cluster
    fn create_new_cluster(&mut self, finding: Finding, fingerprint: String, events: &[SentinelEvent]) -> String {
        let cluster_id = format!("C-{}-{:08x}", 
            finding.class.clone() as u8,
            finding.timestamp
        );
        
        let confidence_value = finding.confidence.as_f64();
        let cluster = Cluster {
            id: cluster_id.clone(),
            fingerprint,
            findings: vec![finding],
            hit_count: 1,
            first_seen: events.first().map(|e| e.ts_ns).unwrap_or(0),
            last_seen: events.last().map(|e| e.ts_ns).unwrap_or(0),
            confidence_sum: confidence_value,
            max_confidence: confidence_value,
            related_clusters: HashSet::new(),
        };
        
        self.clusters.insert(cluster_id.clone(), cluster);
        cluster_id
    }

    /// Merge finding into existing cluster
    fn merge_into_cluster(&mut self, cluster_id: &str, finding: Finding) -> Option<Finding> {
        // Check if we need to merge
        let should_merge = {
            let cluster = self.clusters.get(cluster_id)?;
            finding.confidence.as_f64() > cluster.findings[0].confidence.as_f64()
        };
        
        if let Some(cluster) = self.clusters.get_mut(cluster_id) {
            cluster.hit_count += 1;
            cluster.last_seen = finding.timestamp;
            
            // Update confidence
            cluster.confidence_sum += finding.confidence.as_f64();
            cluster.max_confidence = cluster.max_confidence.max(finding.confidence.as_f64());
            
            if should_merge {
                // Create merged finding
                let merged_finding = Self::create_merged_finding_from_cluster_static(cluster, &finding);
                cluster.findings[0] = merged_finding.clone();
                return Some(merged_finding);
            } else {
                // Keep the existing finding but update metadata
                cluster.findings[0].related.push(finding.id.clone());
            }
        }
        None
    }

    /// Create merged finding with higher confidence (static method to avoid borrow issues)
    fn create_merged_finding_from_cluster_static(cluster: &Cluster, new_finding: &Finding) -> Finding {
        let mut merged = new_finding.clone();
        
        // Update confidence based on multiple hits
        let avg_confidence = cluster.confidence_sum / cluster.hit_count as f64;
        let boosted_confidence = (avg_confidence + new_finding.confidence.as_f64()) / 2.0;
        
        // Set confidence to the higher of current or boosted
        merged.confidence = if boosted_confidence >= 0.9 {
            Confidence::Certain
        } else if boosted_confidence >= 0.7 {
            Confidence::High
        } else if boosted_confidence >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        
        // Add related findings
        merged.related.extend(cluster.findings.iter().map(|f| f.id.clone()));
        
        merged
    }

    /// Update Top-K heap
    fn update_top_k_heap(&mut self, cluster_id: &str) {
        if let Some(cluster) = self.clusters.get(cluster_id) {
            let score = ClusterScore {
                confidence: cluster.max_confidence,
                severity_weight: self.get_severity_weight(&cluster.findings[0]),
                hit_count: cluster.hit_count,
                recency: self.calculate_recency(cluster.last_seen),
            };
            
            self.top_k_heap.push(Reverse(score));
            
            // Maintain Top-K size
            if self.top_k_heap.len() > self.config.top_k {
                self.top_k_heap.pop();
            }
        }
    }

    /// Get severity weight for scoring
    fn get_severity_weight(&self, finding: &Finding) -> f64 {
        match finding.severity {
            crate::Severity::Critical => 4.0,
            crate::Severity::High => 3.0,
            crate::Severity::Medium => 2.0,
            crate::Severity::Low => 1.0,
        }
    }

    /// Calculate recency score (newer is better)
    fn calculate_recency(&self, timestamp: u64) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age_seconds = now.saturating_sub(timestamp);
        
        // Exponential decay: newer findings get higher scores
        if age_seconds == 0 {
            1.0
        } else {
            1.0 / (1.0 + age_seconds as f64 / 3600.0) // 1-hour half-life
        }
    }

    /// Evict oldest cluster when limit is reached
    fn evict_oldest_cluster(&mut self) {
        let oldest_id = self.clusters.iter()
            .min_by_key(|(_, cluster)| cluster.first_seen)
            .map(|(id, _)| id.clone());
        
        if let Some(id) = oldest_id {
            self.clusters.remove(&id);
        }
    }

    /// Get Top-K findings
    pub fn get_top_k_findings(&self) -> Vec<Finding> {
        let mut results = Vec::new();
        let mut heap = self.top_k_heap.clone();
        
        while let Some(Reverse(score)) = heap.pop() {
            // Find cluster with this score
            if let Some((_, cluster)) = self.clusters.iter()
                .find(|(_, c)| {
                    c.max_confidence == score.confidence &&
                    c.hit_count == score.hit_count
                })
            {
                results.extend(cluster.findings.iter().cloned());
            }
            
            if results.len() >= self.config.top_k {
                break;
            }
        }
        
        results
    }

    /// Get all findings with clustering metadata
    pub fn get_all_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for cluster in self.clusters.values() {
            findings.extend(cluster.findings.iter().cloned());
        }
        
        // Sort by confidence and recency
        findings.sort_by(|a, b| {
            let a_score = a.confidence.as_f64() * self.get_severity_weight(a) + self.calculate_recency(a.timestamp);
            let b_score = b.confidence.as_f64() * self.get_severity_weight(b) + self.calculate_recency(b.timestamp);
            b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        findings
    }

    /// Get cluster statistics
    pub fn get_stats(&self) -> ClusteringStats {
        let mut class_counts = HashMap::new();
        let mut total_confidence = 0.0;
        let mut total_findings = 0;
        
        for cluster in self.clusters.values() {
            *class_counts.entry(cluster.findings[0].class.clone()).or_insert(0) += 1;
            total_confidence += cluster.confidence_sum;
            total_findings += cluster.findings.len();
        }
        
        ClusteringStats {
            total_clusters: self.clusters.len(),
            total_findings,
            average_confidence: if total_findings > 0 { total_confidence / total_findings as f64 } else { 0.0 },
            findings_by_class: class_counts,
            top_k_available: self.top_k_heap.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClusteringStats {
    pub total_clusters: usize,
    pub total_findings: usize,
    pub average_confidence: f64,
    pub findings_by_class: HashMap<AnomalyClass, usize>,
    pub top_k_available: usize,
}
