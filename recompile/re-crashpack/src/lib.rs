//! Crashpack data model and writer helpers for re:compile.
//!
//! The active runtime path is `rerun observe` / `rerun run --native`; this crate
//! provides shared artifact types and writer utilities used by that path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use writer::CrashpackWriter;

pub mod capture;
pub mod manifest;
pub mod writer;

/// Main crashpack structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crashpack {
    pub id: String,
    pub version: String,
    pub created_at: u64,
    pub findings: Vec<Finding>,
    pub environment: Environment,
    pub binaries: Vec<BinaryInfo>,
    pub manifest: Manifest,
}

/// Canonical v1 finding shape used by runtime and escalation artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: String,
    pub id: String,
    pub class: String,
    pub confidence: String,
    pub severity: String,
    pub timestamp: u64,
    pub pid: u32,
    pub evidence: Evidence,
    pub escalation: Option<EscalationPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<FindingProvenance>,
    pub related: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crash: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stacks: Option<StackEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alloc_site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_sequence: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEvidence {
    pub ptr: u64,
    pub size: u32,
    pub alloc_size: u32,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackEvidence {
    #[serde(default)]
    pub alloc: Vec<String>,
    #[serde(default)]
    pub call: Vec<String>,
    #[serde(default)]
    pub open: Vec<String>,
    #[serde(default)]
    pub action: Vec<String>,
    #[serde(default)]
    pub crash: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub module: String,
    pub function: String,
    pub offset: u64,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPlan {
    pub tool: String,
    pub reason: String,
    pub estimated_cost: String,
    pub cooldown_ms: u32,
}

/// Environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub system: SystemInfo,
    pub runtime: RuntimeInfo,
    pub tools: ToolVersions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub uname: String,
    pub kernel: String,
    pub architecture: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub argv: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: String,
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolVersions {
    #[serde(alias = "recc_version")]
    pub tool_version: String,
    pub clang_version: Option<String>,
    pub llvm_symbolizer_version: Option<String>,
    pub asan_version: Option<String>,
    pub valgrind_version: Option<String>,
    pub gdb_version: Option<String>,
}

/// Binary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    pub build_id: Option<String>,
    pub debug_info: bool,
    pub size: u64,
    pub sha256: Option<String>,
}

/// Crashpack manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    #[serde(alias = "recc_version")]
    pub tool_version: String,
    pub kernel_version: String,
    pub commit_hash: Option<String>,
    pub toolchain: String,
    pub created_by: String,
    pub total_findings: usize,
    pub high_confidence_findings: usize,
    pub escalation_tools_used: Vec<String>,
}

/// Crashpack generation errors
#[derive(Error, Debug)]
pub enum CrashpackError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Environment capture error: {0}")]
    Environment(String),
    #[error("Binary analysis error: {0}")]
    Binary(String),
    #[error("Manifest generation error: {0}")]
    Manifest(String),
}

pub type Result<T> = std::result::Result<T, CrashpackError>;

impl Crashpack {
    /// Create a new crashpack
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            version: "1.0".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            findings: Vec::new(),
            environment: Environment::capture().unwrap_or_else(|_| Environment {
                system: SystemInfo {
                    uname: "unknown".to_string(),
                    kernel: "unknown".to_string(),
                    architecture: "unknown".to_string(),
                    hostname: "unknown".to_string(),
                },
                runtime: RuntimeInfo {
                    argv: Vec::new(),
                    env: HashMap::new(),
                    cwd: "unknown".to_string(),
                    pid: 0,
                    start_time: 0,
                },
                tools: ToolVersions {
                    tool_version: "unknown".to_string(),
                    clang_version: None,
                    llvm_symbolizer_version: None,
                    asan_version: None,
                    valgrind_version: None,
                    gdb_version: None,
                },
            }),
            binaries: Vec::new(),
            manifest: Manifest::default(),
        }
    }

    /// Add a finding to the crashpack
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add binary information
    pub fn add_binary(&mut self, binary: BinaryInfo) {
        self.binaries.push(binary);
    }

    /// Generate the complete crashpack structure
    pub fn generate(&mut self, output_dir: &Path) -> Result<()> {
        // Update manifest with current state
        self.manifest.total_findings = self.findings.len();
        self.manifest.high_confidence_findings = self
            .findings
            .iter()
            .filter(|f| f.confidence == "high" || f.confidence == "certain")
            .count();

        // Create crashpack writer
        let writer = CrashpackWriter::new(output_dir)?;

        // Write all artifacts
        writer.write_findings(&self.findings)?;
        writer.write_environment(&self.environment)?;
        writer.write_binaries(&self.binaries)?;
        writer.write_manifest(&self.manifest)?;
        writer.write_console_log()?;
        writer.write_repro_script(&self.findings, &self.binaries)?;

        Ok(())
    }
}

impl Default for Crashpack {
    fn default() -> Self {
        Self::new()
    }
}
