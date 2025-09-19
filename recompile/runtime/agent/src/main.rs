use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmPolicy { stack_depth: u32, ringbuf_mb: u32 }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    binary: String,
    argv: Vec<String>,
    env: serde_json::Value,
    build_id: String,
    dsos: Vec<String>,
    cwd: String,
    policy: VmPolicy,
}

fn main() -> Result<()> {
    // Read manifest from a known path (e.g., /etc/re/manifest.json or stdin in real flow)
    let path = std::env::args().nth(1).unwrap_or("/etc/re/manifest.json".to_string());
    let s = fs::read_to_string(&path)?;
    let m: Manifest = serde_json::from_str(&s)?;

    eprintln!("agent: manifest loaded for {}", m.binary);

    // TODO: load BPF objects, attach uprobes, run target under supervision, consume ringbuf, symbolize stacks.
    // For now, print a minimal JSON Finding to stdout to exercise downstream tooling.
    let finding = serde_json::json!({
        "id": "F-sample-001",
        "origin": "ebpf",
        "kind": "heap_overflow",
        "severity": "error",
        "primaryLocation": {"uri": "file:///examples/memcpy_overflow.c", "range": {"start": {"line": 23, "character": 10}, "end": {"line": 23, "character": 16}}},
        "evidence": {"api": "memcpy", "len": 64, "dest_alloc": {"ptr": "0x0", "size": 32}, "stacks": {"alloc": [], "call": []}},
        "fixHints": ["Bound len to capacity", "Allocate len bytes"]
    });
    println!("RE:FINDING: {}", serde_json::to_string(&finding)?);
    Ok(())
}


