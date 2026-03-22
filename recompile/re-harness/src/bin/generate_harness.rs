use anyhow::{anyhow, Context, Result};
use re_harness::{
    AnomalyClass, Confidence, Evidence, Finding, HarnessConfig, HarnessGenerator,
    MemoryEvidence, Severity, StackEvidence,
};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Args {
    findings_file: PathBuf,
    output_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
struct InputFinding {
    id: String,
    schema_version: String,
    class: String,
    confidence: String,
    severity: String,
    timestamp: u64,
    pid: u32,
    evidence: InputEvidence,
    escalation: Option<InputEscalationPlan>,
    related: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct InputEvidence {
    memory: Option<InputMemoryEvidence>,
    stacks: Option<InputStackEvidence>,
    alloc_site: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InputMemoryEvidence {
    ptr: Value,
    size: u32,
    alloc_size: u32,
    operation: String,
}

#[derive(Debug, Deserialize)]
struct InputStackEvidence {
    alloc: Option<Vec<String>>,
    call: Option<Vec<String>>,
    alloc_stack: Option<Vec<String>>,
    call_stack: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct InputEscalationPlan {
    tool: String,
    reason: String,
    estimated_cost: String,
    cooldown_ms: u32,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = parse_args()?;

    let findings = parse_findings(&args.findings_file)?;
    if findings.is_empty() {
        return Err(anyhow!("no findings were found in the input file"));
    }

    let mut generator = HarnessGenerator::new(HarnessConfig::default());
    generator.load_templates()?;

    fs::create_dir_all(&args.output_dir)?;

    let mut generated = 0usize;
    for finding in findings {
        let output = generator.generate_harness(&finding)?;
        let harness_dir = args.output_dir.join(&output.harness_name);
        output.write_files(harness_dir.to_str().ok_or_else(|| anyhow!("invalid output path"))?)?;
        generated += 1;
        println!("generated {}", harness_dir.display());
    }

    println!("Generated {} harness(es)", generated);
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let first = it
        .next()
        .ok_or_else(|| anyhow!("usage: generate_harness <findings_file> <output_dir>"))?;
    if first == "--help" || first == "-h" {
        print_usage();
        std::process::exit(0);
    }

    let second = it
        .next()
        .ok_or_else(|| anyhow!("usage: generate_harness <findings_file> <output_dir>"))?;

    if let Some(extra) = it.next() {
        return Err(anyhow!("unexpected argument: {}", extra));
    }

    Ok(Args {
        findings_file: PathBuf::from(first),
        output_dir: PathBuf::from(second),
    })
}

fn print_usage() {
    eprintln!("usage: generate_harness <findings_file> <output_dir>");
}

fn parse_findings(path: &Path) -> Result<Vec<Finding>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read findings file: {}", path.display()))?;

    if let Ok(findings) = serde_json::from_str::<Vec<InputFinding>>(&content) {
        return findings.into_iter().map(convert_finding).collect();
    }

    if let Ok(finding) = serde_json::from_str::<InputFinding>(&content) {
        return Ok(vec![convert_finding(finding)?]);
    }

    let mut findings = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let json_part = line
            .strip_prefix("RE:FINDING:")
            .map(str::trim)
            .unwrap_or(line);

        if let Ok(finding) = serde_json::from_str::<InputFinding>(json_part) {
            findings.push(convert_finding(finding)?);
        }
    }

    Ok(findings)
}

fn convert_finding(input: InputFinding) -> Result<Finding> {
    Ok(Finding {
        id: input.id,
        schema_version: input.schema_version,
        class: parse_class(&input.class)?,
        confidence: parse_confidence(&input.confidence)?,
        severity: parse_severity(&input.severity)?,
        timestamp: input.timestamp,
        pid: input.pid,
        evidence: Evidence {
            memory: input.evidence.memory.map(|memory| MemoryEvidence {
                ptr: value_to_ptr_string(memory.ptr),
                size: memory.size,
                alloc_size: memory.alloc_size,
                operation: memory.operation,
            }),
            stacks: input.evidence.stacks.map(|stacks| StackEvidence {
                alloc_stack: stacks.alloc_stack.or(stacks.alloc).unwrap_or_default(),
                call_stack: stacks.call_stack.or(stacks.call).unwrap_or_default(),
            }),
            alloc_site: input.evidence.alloc_site,
            event_sequence: Vec::new(),
        },
        escalation: input.escalation.map(|esc| re_harness::EscalationPlan {
            tool: esc.tool,
            reason: esc.reason,
            estimated_cost: esc.estimated_cost,
            cooldown_ms: esc.cooldown_ms,
        }),
        related: input.related,
    })
}

fn parse_class(class: &str) -> Result<AnomalyClass> {
    match class {
        "heap_overflow" | "HeapOverflow" => Ok(AnomalyClass::HeapOverflow),
        "double_free" | "DoubleFree" => Ok(AnomalyClass::DoubleFree),
        "invalid_free" | "InvalidFree" => Ok(AnomalyClass::InvalidFree),
        "use_after_free" | "UseAfterFree" => Ok(AnomalyClass::UseAfterFree),
        "uninit_to_io" | "UninitToIo" => Ok(AnomalyClass::UninitToIo),
        "lock_cycle" | "LockCycle" => Ok(AnomalyClass::LockCycle),
        "undefined_behavior" | "UndefinedBehavior" => Ok(AnomalyClass::UndefinedBehavior),
        "memory_leak" | "MemoryLeak" => Ok(AnomalyClass::MemoryLeak),
        other => Err(anyhow!("unknown anomaly class: {}", other)),
    }
}

fn parse_confidence(confidence: &str) -> Result<Confidence> {
    match confidence {
        "low" | "Low" => Ok(Confidence::Low),
        "medium" | "Medium" => Ok(Confidence::Medium),
        "high" | "High" => Ok(Confidence::High),
        "certain" | "Certain" => Ok(Confidence::Certain),
        other => Err(anyhow!("unknown confidence level: {}", other)),
    }
}

fn parse_severity(severity: &str) -> Result<Severity> {
    match severity {
        "low" | "Low" => Ok(Severity::Low),
        "medium" | "Medium" => Ok(Severity::Medium),
        "high" | "High" => Ok(Severity::High),
        "critical" | "Critical" => Ok(Severity::Critical),
        "warning" | "Warning" => Ok(Severity::Medium),
        "error" | "Error" => Ok(Severity::High),
        other => Err(anyhow!("unknown severity level: {}", other)),
    }
}

fn value_to_ptr_string(value: Value) -> String {
    match value {
        Value::String(s) => s,
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                format!("0x{:x}", u)
            } else if let Some(i) = n.as_i64() {
                format!("0x{:x}", i)
            } else if let Some(f) = n.as_f64() {
                format!("{}", f)
            } else {
                "0x0".to_string()
            }
        }
        other => other.to_string(),
    }
}
