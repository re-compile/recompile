//! RECC Escalation Runner
//!
//! Automatically escalates findings to appropriate debugging tools (ASan, TSan, MSan, Valgrind, GDB)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod asan;
pub mod config;
pub mod runner;
pub mod ubsan;
pub mod valgrind;

pub use asan::*;
pub use runner::*;
pub use ubsan::*;
pub use valgrind::*;

/// Escalation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationResult {
    pub id: String,
    pub finding_id: String,
    pub tool: String,
    pub success: bool,
    pub tool_available: bool,
    pub duration_ms: u64,
    pub output_path: Option<String>,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
    pub report_path: Option<String>,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub confirmed: bool,
    pub error: Option<String>,
    pub findings_detected: Vec<String>,
    pub timestamp: u64,
}

/// Parsed escalation evidence from a tool run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscalationDetection {
    pub class: String,
    pub summary: String,
    pub line: Option<usize>,
}

/// Escalation plan from a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPlan {
    pub tool: String,
    pub reason: String,
    pub estimated_cost: String,
    pub cooldown_ms: u32,
}

/// Finding from the rule engine (re-exported from re-crashpack for consistency)
pub use re_crashpack::{Evidence, Finding, FindingProvenance, MemoryEvidence, StackEvidence};

/// Escalation runner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    pub tools: ToolConfig,
    pub timeouts: TimeoutConfig,
    pub cooldowns: CooldownConfig,
    pub output_dir: String,
    pub binary_path: Option<String>,
    pub source_file: Option<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    pub asan: AsanConfig,
    #[serde(default)]
    pub ubsan: UbsanConfig,
    pub valgrind: ValgrindConfig,
    pub gdb: GdbConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsanConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub compile_flags: Vec<String>,
    pub runtime_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbsanConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub runtime_flags: Vec<String>,
}

impl Default for UbsanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_ms: 30000,
            runtime_flags: vec![
                "print_stacktrace=1".to_string(),
                "halt_on_error=1".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValgrindConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbConfig {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    pub default_ms: u64,
    pub compile_ms: u64,
    pub run_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooldownConfig {
    pub default_ms: u32,
    pub per_tool: HashMap<String, u32>,
}

/// Escalation errors
#[derive(Error, Debug)]
pub enum EscalationError {
    #[error("Tool execution failed: {0}")]
    ToolExecution(String),
    #[error("Compilation failed: {0}")]
    Compilation(String),
    #[error("Timeout exceeded: {0}")]
    Timeout(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Output parsing error: {0}")]
    OutputParsing(String),
}

pub type Result<T> = std::result::Result<T, EscalationError>;

impl Default for EscalationConfig {
    fn default() -> Self {
        let mut cooldown_per_tool = HashMap::new();
        cooldown_per_tool.insert("asan".to_string(), 5000);
        cooldown_per_tool.insert("ubsan".to_string(), 5000);
        cooldown_per_tool.insert("valgrind".to_string(), 10000);
        cooldown_per_tool.insert("gdb".to_string(), 3000);

        Self {
            tools: ToolConfig {
                asan: AsanConfig {
                    enabled: true,
                    timeout_ms: 30000,
                    compile_flags: vec![
                        "-fsanitize=address".to_string(),
                        "-fsanitize-recover=address".to_string(),
                        "-fno-omit-frame-pointer".to_string(),
                        "-g".to_string(),
                        "-O1".to_string(),
                    ],
                    runtime_flags: vec![
                        "detect_leaks=1".to_string(),
                        "abort_on_error=1".to_string(),
                        "check_initialization_order=1".to_string(),
                    ],
                },
                ubsan: UbsanConfig::default(),
                valgrind: ValgrindConfig {
                    enabled: true,
                    timeout_ms: 60000,
                    flags: vec![
                        "--error-exitcode=99".to_string(),
                        "--leak-check=full".to_string(),
                        "--track-origins=yes".to_string(),
                        "--track-fds=yes".to_string(),
                        "--show-leak-kinds=all".to_string(),
                    ],
                },
                gdb: GdbConfig {
                    enabled: true,
                    timeout_ms: 15000,
                    commands: vec![
                        "run".to_string(),
                        "bt".to_string(),
                        "info reg".to_string(),
                        "quit".to_string(),
                    ],
                },
            },
            timeouts: TimeoutConfig {
                default_ms: 30000,
                compile_ms: 60000,
                run_ms: 30000,
            },
            cooldowns: CooldownConfig {
                default_ms: 5000,
                per_tool: cooldown_per_tool,
            },
            output_dir: "build/escalations".to_string(),
            binary_path: None,
            source_file: None,
            cwd: None,
            args: Vec::new(),
        }
    }
}
