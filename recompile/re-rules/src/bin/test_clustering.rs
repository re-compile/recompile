//! Test script for clustering functionality

use re_rules::{
    Config, RuleEngine, SentinelEvent, EventType
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing RECC Rule Engine Clustering...");
    
    // Create rule engine with default config
    let config = Config::default();
    let mut engine = RuleEngine::new(config);
    
    // Create test events
    let events = create_test_events();
    
    println!("Processing {} test events...", events.len());
    
    // Process events
    let mut total_findings = 0;
    for event in events {
        let findings = engine.process_event(event)?;
        total_findings += findings.len();
        
        if !findings.is_empty() {
            println!("Generated {} findings", findings.len());
            for finding in &findings {
                println!("  - {}: {:?} (confidence: {:?}, severity: {:?})", 
                    finding.id, finding.class, finding.confidence, finding.severity);
            }
        }
    }
    
    // Get final statistics
    let stats = engine.get_stats();
    let cluster_stats = engine.get_clustering_stats();
    let top_k = engine.get_top_k_findings();
    
    println!("\n=== Final Statistics ===");
    println!("Total events processed: {}", stats.total_events);
    println!("Total findings generated: {}", stats.total_findings);
    println!("Total findings observed in this run: {}", total_findings);
    println!("Active clusters: {}", stats.active_clusters);
    println!("Findings by class: {:?}", stats.findings_by_class);
    
    println!("\n=== Clustering Statistics ===");
    println!("Total clusters: {}", cluster_stats.total_clusters);
    println!("Total findings in clusters: {}", cluster_stats.total_findings);
    println!("Average confidence: {:.2}", cluster_stats.average_confidence);
    println!("Top-K findings available: {}", cluster_stats.top_k_available);
    
    println!("\n=== Top-K Findings ===");
    for (i, finding) in top_k.iter().enumerate() {
        println!("{}. {}: {:?} (confidence: {:?})", 
            i + 1, finding.id, finding.class, finding.confidence);
    }
    
    println!("\nTest completed successfully!");
    Ok(())
}

fn create_test_events() -> Vec<SentinelEvent> {
    let mut events = Vec::new();
    let base_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    // Event 1: malloc
    events.push(SentinelEvent {
        version: 1,
        seq: 1,
        pid: 1000,
        tid: 1000,
        ts_ns: base_time,
        event_type: EventType::Malloc,
        site_id: 1,
        stack_id: 100,
        stack_fp: 0x1234,
        addr: 0x1000,
        len: 0,
        alloc_size: 100,
        fd: -1,
        bytes_ret: 0,
        errno_code: 0,
        lock_kind: 0,
        lock_addr: 0,
        lock_site_id: 0,
        flags: 0,
        drop_count: 0,
        extra_kv: vec![],
    });
    
    // Event 2: memcpy with overflow
    events.push(SentinelEvent {
        version: 1,
        seq: 2,
        pid: 1000,
        tid: 1000,
        ts_ns: base_time + 1_000_000, // 1ms later
        event_type: EventType::Memcpy,
        site_id: 2,
        stack_id: 101,
        stack_fp: 0x1234,
        addr: 0x1000,
        len: 150, // Overflow: 150 > 100
        alloc_size: 100,
        fd: -1,
        bytes_ret: 150,
        errno_code: 0,
        lock_kind: 0,
        lock_addr: 0,
        lock_site_id: 0,
        flags: 0,
        drop_count: 0,
        extra_kv: vec![],
    });
    
    // Event 3: Another malloc
    events.push(SentinelEvent {
        version: 1,
        seq: 3,
        pid: 1000,
        tid: 1000,
        ts_ns: base_time + 2_000_000, // 2ms later
        event_type: EventType::Malloc,
        site_id: 3,
        stack_id: 102,
        stack_fp: 0x5678,
        addr: 0x2000,
        len: 0,
        alloc_size: 200,
        fd: -1,
        bytes_ret: 0,
        errno_code: 0,
        lock_kind: 0,
        lock_addr: 0,
        lock_site_id: 0,
        flags: 0,
        drop_count: 0,
        extra_kv: vec![],
    });
    
    // Event 4: Double free
    events.push(SentinelEvent {
        version: 1,
        seq: 4,
        pid: 1000,
        tid: 1000,
        ts_ns: base_time + 3_000_000, // 3ms later
        event_type: EventType::Free,
        site_id: 4,
        stack_id: 103,
        stack_fp: 0x5678,
        addr: 0x2000,
        len: 0,
        alloc_size: 200,
        fd: -1,
        bytes_ret: 0,
        errno_code: 0,
        lock_kind: 0,
        lock_addr: 0,
        lock_site_id: 0,
        flags: 0,
        drop_count: 0,
        extra_kv: vec![],
    });
    
    // Event 5: Second free (double free)
    events.push(SentinelEvent {
        version: 1,
        seq: 5,
        pid: 1000,
        tid: 1000,
        ts_ns: base_time + 4_000_000, // 4ms later
        event_type: EventType::Free,
        site_id: 5,
        stack_id: 104,
        stack_fp: 0x5678,
        addr: 0x2000, // Same address as previous free
        len: 0,
        alloc_size: 200,
        fd: -1,
        bytes_ret: 0,
        errno_code: 0,
        lock_kind: 0,
        lock_addr: 0,
        lock_site_id: 0,
        flags: 0,
        drop_count: 0,
        extra_kv: vec![],
    });
    
    events
}
