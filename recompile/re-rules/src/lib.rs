//! Deferred rule-engine primitives.
//!
//! The active finding engine is the native runtime agent. This crate remains in
//! the workspace for shared types, symbolization utilities, and possible future
//! rule experiments; it is not the supported runtime detector.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod clustering;
pub mod config;
pub mod engine;
pub mod rules;
pub mod symbolizer;

pub use clustering::{ClusterManager, ClusteringConfig as ClusterConfig, ClusteringStats};
pub use config::{
    ClusteringConfig, Config, EscalationConfig as ConfigEscalationConfig, Mode, RulesConfig,
    SymbolizeConfig,
};
pub use engine::{RuleEngine, RuleEngineStats};
pub use rules::{DebounceConfig, EscalationConfig, Rule, RuleMatcher, RuleRegistry};
pub use symbolizer::{
    Addr2lineSymbolizer, CompositeSymbolizer, Frame, LlvmSymbolizer, Symbolizer, SymbolizerConfig,
};

/// Event types from the eBPF sentinel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum EventType {
    Malloc = 1,
    Free = 2,
    Mmap = 3,
    Munmap = 4,
    Memcpy = 5,
    Memmove = 6,
    Strcpy = 7,
    Strlen = 8,
    Read = 9,
    Write = 10,
    Send = 11,
    Recv = 12,
    Dup = 13,
    Pipe = 14,
    EpollCtl = 15,
    InotifyAdd = 16,
    LockAcq = 20,
    LockRel = 21,
    FutexWait = 22,
    FutexWake = 23,
    SignalEnter = 30,
    SignalForbiddenCall = 31,
    Segv = 40,
    MarkFlush = 50,
}

/// Anomaly classes that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyClass {
    HeapOverflow,
    DoubleFree,
    InvalidFree,
    UseAfterFree,
    UninitToIo,
    LockCycle,
    UndefinedBehavior,
    MemoryLeak,
}

/// Confidence levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low = 1,     // 0.3-0.5: Heuristic hint, needs escalation
    Medium = 2,  // 0.5-0.7: Strong evidence, auto-escalate
    High = 3,    // 0.7-0.9: Very strong evidence
    Certain = 4, // 0.9-1.0: Deterministic proof
}

impl Confidence {
    pub fn as_f64(self) -> f64 {
        match self {
            Confidence::Low => 0.4,
            Confidence::Medium => 0.6,
            Confidence::High => 0.8,
            Confidence::Certain => 0.95,
        }
    }
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low = 1,      // Leaks, minor UB
    Medium = 2,   // Uninit data, races
    High = 3,     // OOB, UAF
    Critical = 4, // Double free, immediate crash
}

/// Raw event from eBPF sentinel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEvent {
    pub version: u16,
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub event_type: EventType,
    pub site_id: u32,
    pub stack_id: i32,
    pub stack_fp: u32,
    pub addr: u64,
    pub len: u32,
    pub alloc_size: u32,
    pub fd: i32,
    pub bytes_ret: i32,
    pub errno_code: i32,
    pub lock_kind: u8,
    pub lock_addr: u64,
    pub lock_site_id: u32,
    pub flags: u16,
    pub drop_count: u32,
    pub extra_kv: Vec<ExtraKv>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraKv {
    pub k: u8,
    pub v_len: u8,
    pub v: [u8; 32],
}

/// Processed finding with classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub schema_version: String,
    pub class: AnomalyClass,
    pub confidence: Confidence,
    pub severity: Severity,
    pub timestamp: u64,
    pub pid: u32,
    pub evidence: Evidence,
    pub escalation: Option<EscalationPlan>,
    pub related: Vec<String>, // IDs of related findings
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub memory: Option<MemoryEvidence>,
    pub stacks: Option<StackEvidence>,
    pub alloc_site: Option<String>,
    pub event_sequence: Vec<SentinelEvent>,
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
    pub alloc_stack: Vec<StackFrame>,
    pub call_stack: Vec<StackFrame>,
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

/// Rule engine errors
#[derive(Error, Debug)]
pub enum RuleEngineError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Rule evaluation error: {0}")]
    RuleEvaluation(String),
    #[error("Event processing error: {0}")]
    EventProcessing(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RuleEngineError>;
