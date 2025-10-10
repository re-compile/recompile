use anyhow::Result;
use re_harness::{
    HarnessGenerator, HarnessConfig, Finding, AnomalyClass, Confidence, Severity,
    Evidence, MemoryEvidence, SentinelEvent
};

fn main() -> Result<()> {
    env_logger::init();
    println!("Testing RECC Harness Generation...");

    let config = HarnessConfig::default();
    let mut generator = HarnessGenerator::new(config);
    generator.load_templates()?;

    // Create a test finding for heap overflow
    let finding = Finding {
        id: "test-heap-overflow-001".to_string(),
        schema_version: "1.0".to_string(),
        class: AnomalyClass::HeapOverflow,
        confidence: Confidence::High,
        severity: Severity::High,
        timestamp: 1234567890,
        pid: 1234,
        evidence: Evidence {
            memory: Some(MemoryEvidence {
                ptr: "0x7fff12345678".to_string(),
                size: 100,
                alloc_size: 100,
                operation: "malloc".to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: vec![
                SentinelEvent {
                    version: 1,
                    seq: 1,
                    pid: 1234,
                    tid: 1234,
                    ts_ns: 1234567890000000,
                    event_type: 1, // Malloc
                    site_id: 1,
                    stack_id: 1,
                    stack_fp: 0x1234,
                    addr: 0x7fff12345678,
                    len: 100,
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
                },
            ],
        },
        escalation: None,
        related: vec![],
    };

    println!("Generating harness for finding: {}", finding.id);
    let output = generator.generate_harness(&finding)?;

    println!("Generated harness:");
    println!("  Name: {}", output.harness_name);
    println!("  C file size: {} bytes", output.harness_c.len());
    println!("  Build script: {}", output.build_script.is_some());

    // Write the harness to a test directory
    let test_dir = "/tmp/re-harness-test";
    output.write_files(test_dir)?;

    println!("Harness written to: {}", test_dir);
    println!("Files created:");
    println!("  {}/{}.c", test_dir, output.harness_name);
    if output.build_script.is_some() {
        println!("  {}/{}.sh", test_dir, output.harness_name);
    }

    // Test with a double free finding
    let double_free_finding = Finding {
        id: "test-double-free-002".to_string(),
        schema_version: "1.0".to_string(),
        class: AnomalyClass::DoubleFree,
        confidence: Confidence::Certain,
        severity: Severity::Critical,
        timestamp: 1234567891,
        pid: 1235,
        evidence: Evidence {
            memory: Some(MemoryEvidence {
                ptr: "0x7fff87654321".to_string(),
                size: 0,
                alloc_size: 200,
                operation: "free".to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: vec![],
        },
        escalation: None,
        related: vec![],
    };

    println!("\nGenerating harness for double free finding: {}", double_free_finding.id);
    let double_free_output = generator.generate_harness(&double_free_finding)?;

    println!("Generated double free harness:");
    println!("  Name: {}", double_free_output.harness_name);
    println!("  C file size: {} bytes", double_free_output.harness_c.len());

    double_free_output.write_files(test_dir)?;
    println!("Double free harness written to: {}", test_dir);

    // Test with an invalid free finding
    let invalid_free_finding = Finding {
        id: "test-invalid-free-003".to_string(),
        schema_version: "1.0".to_string(),
        class: AnomalyClass::InvalidFree,
        confidence: Confidence::High,
        severity: Severity::High,
        timestamp: 1234567892,
        pid: 1236,
        evidence: Evidence {
            memory: Some(MemoryEvidence {
                ptr: "0x7fff11111111".to_string(),
                size: 0,
                alloc_size: 0,
                operation: "free".to_string(),
            }),
            stacks: None,
            alloc_site: None,
            event_sequence: vec![],
        },
        escalation: None,
        related: vec![],
    };

    println!("\nGenerating harness for invalid free finding: {}", invalid_free_finding.id);
    let invalid_free_output = generator.generate_harness(&invalid_free_finding)?;

    println!("Generated invalid free harness:");
    println!("  Name: {}", invalid_free_output.harness_name);
    println!("  C file size: {} bytes", invalid_free_output.harness_c.len());

    invalid_free_output.write_files(test_dir)?;
    println!("Invalid free harness written to: {}", test_dir);

    println!("\nAll harness generation tests completed successfully!");
    Ok(())
}
