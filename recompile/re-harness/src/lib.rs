//! RECC Harness Generation
//! 
//! Generates minimal C repro harnesses from findings to reproduce bugs deterministically.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use chrono::Utc;

/// A finding that can be used to generate a harness
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
    pub related: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Certain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
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
    pub ptr: String,
    pub size: u32,
    pub alloc_size: u32,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackEvidence {
    pub alloc_stack: Vec<String>,
    pub call_stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEvent {
    pub version: u16,
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub event_type: u16,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPlan {
    pub tool: String,
    pub reason: String,
    pub estimated_cost: String,
    pub cooldown_ms: u32,
}

/// Configuration for harness generation
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub template_dir: String,
    pub output_dir: String,
    pub include_debug_info: bool,
    pub add_sanitizer_flags: bool,
    pub generate_build_script: bool,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            template_dir: "templates".to_string(),
            output_dir: "harnesses".to_string(),
            include_debug_info: true,
            add_sanitizer_flags: true,
            generate_build_script: true,
        }
    }
}

/// Template context for harness generation
#[derive(Debug, Clone, Serialize)]
pub struct HarnessContext {
    pub finding_id: String,
    pub anomaly_class: String,
    pub confidence: String,
    pub severity: String,
    pub generated_at: String,
    pub memory_evidence: Option<MemoryEvidence>,
    pub stack_evidence: Option<StackEvidence>,
    pub event_sequence: Vec<SentinelEvent>,
    pub harness_name: String,
    pub build_flags: Vec<String>,
}

impl HarnessContext {
    pub fn from_finding(finding: &Finding) -> Self {
        let generated_at = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let harness_name = format!("repro_{}", finding.id);
        
        // Determine build flags based on anomaly class
        let build_flags = match finding.class {
            AnomalyClass::HeapOverflow => vec![
                "-fsanitize=address".to_string(),
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::DoubleFree => vec![
                "-fsanitize=address".to_string(),
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::InvalidFree => vec![
                "-fsanitize=address".to_string(),
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::UseAfterFree => vec![
                "-fsanitize=address".to_string(),
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::UninitToIo => vec![
                "-fsanitize=memory".to_string(),
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::LockCycle => vec![
                "-fsanitize=thread".to_string(),
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::UndefinedBehavior => vec![
                "-fsanitize=undefined".to_string(),
                "-g".to_string(),
            ],
            AnomalyClass::MemoryLeak => vec![
                "-fsanitize=address".to_string(),
                "-fsanitize=leak".to_string(),
                "-g".to_string(),
            ],
        };

        Self {
            finding_id: finding.id.clone(),
            anomaly_class: format!("{:?}", finding.class),
            confidence: format!("{:?}", finding.confidence),
            severity: format!("{:?}", finding.severity),
            generated_at,
            memory_evidence: finding.evidence.memory.clone(),
            stack_evidence: finding.evidence.stacks.clone(),
            event_sequence: finding.evidence.event_sequence.clone(),
            harness_name,
            build_flags,
        }
    }
}

/// Harness generator that creates C repro harnesses from findings
pub struct HarnessGenerator {
    config: HarnessConfig,
    templates: HashMap<String, String>,
}

impl HarnessGenerator {
    pub fn new(config: HarnessConfig) -> Self {
        Self {
            config,
            templates: HashMap::new(),
        }
    }

    /// Load templates from the template directory
    pub fn load_templates(&mut self) -> Result<()> {
        // For now, we'll use built-in templates
        // In a real implementation, these would be loaded from files
        self.templates.insert("harness.c".to_string(), include_str!("../templates/harness.c").to_string());
        self.templates.insert("build.sh".to_string(), include_str!("../templates/build.sh").to_string());
        Ok(())
    }

    /// Generate a harness for a specific finding
    pub fn generate_harness(&self, finding: &Finding) -> Result<HarnessOutput> {
        let context = HarnessContext::from_finding(finding);
        let harness_name = &context.harness_name;

        // Generate the C harness
        let harness_c = self.generate_c_harness(&context)?;
        
        // Generate the build script
        let build_sh = if self.config.generate_build_script {
            Some(self.generate_build_script(&context)?)
        } else {
            None
        };

        Ok(HarnessOutput {
            finding_id: finding.id.clone(),
            harness_name: harness_name.clone(),
            harness_c,
            build_script: build_sh,
            config: self.config.clone(),
        })
    }

    fn generate_c_harness(&self, context: &HarnessContext) -> Result<String> {
        match context.anomaly_class.as_str() {
            "HeapOverflow" => self.generate_heap_overflow_harness(context),
            "DoubleFree" => self.generate_double_free_harness(context),
            "InvalidFree" => self.generate_invalid_free_harness(context),
            "UseAfterFree" => self.generate_use_after_free_harness(context),
            "UninitToIo" => self.generate_uninit_to_io_harness(context),
            "LockCycle" => self.generate_lock_cycle_harness(context),
            "UndefinedBehavior" => self.generate_undefined_behavior_harness(context),
            "MemoryLeak" => self.generate_memory_leak_harness(context),
            _ => Err(anyhow!("Unknown anomaly class: {}", context.anomaly_class)),
        }
    }

    fn generate_heap_overflow_harness(&self, context: &HarnessContext) -> Result<String> {
        let size = context.memory_evidence.as_ref()
            .map(|m| m.alloc_size)
            .unwrap_or(100);
        let overflow_size = size + 50; // Overflow by 50 bytes

        Ok(format!(
            r#"// Generated harness for heap overflow finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    printf("Reproducing heap overflow from finding {}\\n");
    
    // Allocate memory
    char *ptr = malloc({});
    if (!ptr) {{
        fprintf(stderr, "malloc failed\\n");
        return 1;
    }}
    
    printf("Allocated %u bytes at %p\\n", {}, ptr);
    
    // Perform the overflow (this should trigger the sanitizer)
    printf("Writing %u bytes (overflowing by %u bytes)...\\n", {}, {});
    memset(ptr, 0x41, {}); // Write past the end
    
    printf("Heap overflow completed\\n");
    
    // Clean up
    free(ptr);
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id,
            size,
            size,
            overflow_size,
            overflow_size - size,
            overflow_size
        ))
    }

    fn generate_double_free_harness(&self, context: &HarnessContext) -> Result<String> {
        let size = context.memory_evidence.as_ref()
            .map(|m| m.alloc_size)
            .unwrap_or(100);

        Ok(format!(
            r#"// Generated harness for double free finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>

int main() {{
    printf("Reproducing double free from finding {}\\n");
    
    // Allocate memory
    char *ptr = malloc({});
    if (!ptr) {{
        fprintf(stderr, "malloc failed\\n");
        return 1;
    }}
    
    printf("Allocated {} bytes at %p\\n", {}, ptr);
    
    // First free (legitimate)
    printf("First free...\\n");
    free(ptr);
    
    // Second free (double free - should trigger sanitizer)
    printf("Second free (double free)...\\n");
    free(ptr);
    
    printf("Double free completed\\n");
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id,
            size,
            size,
            size
        ))
    }

    fn generate_invalid_free_harness(&self, context: &HarnessContext) -> Result<String> {
        Ok(format!(
            r#"// Generated harness for invalid free finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>

int main() {{
    printf("Reproducing invalid free from finding {}\\n");
    
    // Create a stack variable
    int stack_var = 42;
    printf("Stack variable at %p\\n", &stack_var);
    
    // Try to free the stack variable (invalid free - should trigger sanitizer)
    printf("Attempting to free stack variable...\\n");
    free(&stack_var);
    
    printf("Invalid free completed\\n");
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id
        ))
    }

    fn generate_use_after_free_harness(&self, context: &HarnessContext) -> Result<String> {
        let size = context.memory_evidence.as_ref()
            .map(|m| m.alloc_size)
            .unwrap_or(100);

        Ok(format!(
            r#"// Generated harness for use after free finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    printf("Reproducing use after free from finding {}\\n");
    
    // Allocate memory
    char *ptr = malloc({});
    if (!ptr) {{
        fprintf(stderr, "malloc failed\\n");
        return 1;
    }}
    
    printf("Allocated {} bytes at %p\\n", {}, ptr);
    
    // Initialize the memory
    strcpy(ptr, "Hello, World!");
    printf("Initialized: %s\\n", ptr);
    
    // Free the memory
    printf("Freeing memory...\\n");
    free(ptr);
    
    // Use after free (should trigger sanitizer)
    printf("Using memory after free...\\n");
    printf("Content: %s\\n", ptr);
    
    printf("Use after free completed\\n");
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id,
            size,
            size,
            size
        ))
    }

    fn generate_uninit_to_io_harness(&self, context: &HarnessContext) -> Result<String> {
        Ok(format!(
            r#"// Generated harness for uninitialized to I/O finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {{
    printf("Reproducing uninitialized to I/O from finding {}\\n");
    
    // Allocate uninitialized memory
    char *ptr = malloc(100);
    if (!ptr) {{
        fprintf(stderr, "malloc failed\\n");
        return 1;
    }}
    
    printf("Allocated 100 bytes at %p (uninitialized)\\n", ptr);
    
    // Write uninitialized data to stdout (should trigger sanitizer)
    printf("Writing uninitialized data to stdout...\\n");
    write(1, ptr, 100);
    
    printf("Uninitialized to I/O completed\\n");
    
    free(ptr);
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id
        ))
    }

    fn generate_lock_cycle_harness(&self, context: &HarnessContext) -> Result<String> {
        Ok(format!(
            r#"// Generated harness for lock cycle finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

void* thread_func(void* arg) {{
    printf("Thread acquiring mutex2...\\n");
    pthread_mutex_lock(&mutex2);
    
    printf("Thread acquiring mutex1...\\n");
    pthread_mutex_lock(&mutex1);
    
    printf("Thread releasing mutex1...\\n");
    pthread_mutex_unlock(&mutex1);
    
    printf("Thread releasing mutex2...\\n");
    pthread_mutex_unlock(&mutex2);
    
    return NULL;
}}

int main() {{
    printf("Reproducing lock cycle from finding {}\\n");
    
    pthread_t thread;
    
    printf("Main thread acquiring mutex1...\\n");
    pthread_mutex_lock(&mutex1);
    
    // Create thread that will try to acquire mutex2 then mutex1
    pthread_create(&thread, NULL, thread_func, NULL);
    
    // Give thread time to acquire mutex2
    sleep(1);
    
    printf("Main thread acquiring mutex2...\\n");
    pthread_mutex_lock(&mutex2); // This should deadlock
    
    printf("Lock cycle completed\\n");
    
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
    pthread_join(thread, NULL);
    
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id
        ))
    }

    fn generate_undefined_behavior_harness(&self, context: &HarnessContext) -> Result<String> {
        Ok(format!(
            r#"// Generated harness for undefined behavior finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main() {{
    printf("Reproducing undefined behavior from finding {}\\n");
    
    // Integer overflow (undefined behavior)
    int a = INT_MAX;
    printf("a = %d (INT_MAX)\\n", a);
    
    printf("Performing a + 1 (undefined behavior)...\\n");
    int b = a + 1; // This should trigger UBSan
    
    printf("Result: %d\\n", b);
    
    // Division by zero (undefined behavior)
    printf("Performing division by zero...\\n");
    int c = 1 / 0; // This should trigger UBSan
    
    printf("Result: %d\\n", c);
    
    printf("Undefined behavior completed\\n");
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id
        ))
    }

    fn generate_memory_leak_harness(&self, context: &HarnessContext) -> Result<String> {
        Ok(format!(
            r#"// Generated harness for memory leak finding: {}
// Generated at: {}
// Anomaly: {} (confidence: {}, severity: {})

#include <stdio.h>
#include <stdlib.h>

int main() {{
    printf("Reproducing memory leak from finding {}\\n");
    
    // Allocate memory but don't free it (memory leak)
    char *ptr = malloc(1024);
    if (!ptr) {{
        fprintf(stderr, "malloc failed\\n");
        return 1;
    }}
    
    printf("Allocated 1024 bytes at %p\\n", ptr);
    printf("Memory leak: not calling free()\\n");
    
    printf("Memory leak completed\\n");
    return 0;
}}
"#,
            context.finding_id,
            context.generated_at,
            context.anomaly_class,
            context.confidence,
            context.severity,
            context.finding_id
        ))
    }

    fn generate_build_script(&self, context: &HarnessContext) -> Result<String> {
        let flags = context.build_flags.join(" ");
        
        Ok(format!(
            r#"#!/bin/bash
# Generated build script for harness: {}
# Generated at: {}

set -e

HARNESS_NAME="{}"
SOURCE_FILE="${{HARNESS_NAME}}.c"
BINARY_FILE="${{HARNESS_NAME}}"

echo "Building harness: ${{HARNESS_NAME}}"

if [ ! -f "${{SOURCE_FILE}}" ]; then
    echo "Error: Source file ${{SOURCE_FILE}} not found"
    exit 1
fi

# Compile with sanitizer flags
echo "Compiling with flags: {}"
gcc {} -o "${{BINARY_FILE}}" "${{SOURCE_FILE}}"

echo "Build completed: ${{BINARY_FILE}}"
echo "Run with: ./${{BINARY_FILE}}"
"#,
            context.finding_id,
            context.generated_at,
            context.harness_name,
            flags,
            flags
        ))
    }
}

/// Output of harness generation
#[derive(Debug, Clone)]
pub struct HarnessOutput {
    pub finding_id: String,
    pub harness_name: String,
    pub harness_c: String,
    pub build_script: Option<String>,
    pub config: HarnessConfig,
}

impl HarnessOutput {
    /// Write the harness files to disk
    pub fn write_files(&self, output_dir: &str) -> Result<()> {
        use std::fs;
        use std::path::Path;
        use std::os::unix::fs::PermissionsExt;

        // Create output directory if it doesn't exist
        fs::create_dir_all(output_dir)?;

        // Write the C harness
        let harness_path = Path::new(output_dir).join(format!("{}.c", self.harness_name));
        fs::write(&harness_path, &self.harness_c)?;

        // Write the build script if provided
        if let Some(ref build_script) = self.build_script {
            let build_path = Path::new(output_dir).join(format!("{}.sh", self.harness_name));
            fs::write(&build_path, build_script)?;
            
            // Make the build script executable
            let mut perms = fs::metadata(&build_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&build_path, perms)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_context_creation() {
        let finding = Finding {
            id: "test-finding".to_string(),
            schema_version: "1.0".to_string(),
            class: AnomalyClass::HeapOverflow,
            confidence: Confidence::High,
            severity: Severity::High,
            timestamp: 1234567890,
            pid: 1234,
            evidence: Evidence {
                memory: Some(MemoryEvidence {
                    ptr: "0x1234".to_string(),
                    size: 100,
                    alloc_size: 100,
                    operation: "malloc".to_string(),
                }),
                stacks: None,
                alloc_site: None,
                event_sequence: vec![],
            },
            escalation: None,
            related: vec![],
        };

        let context = HarnessContext::from_finding(&finding);
        assert_eq!(context.finding_id, "test-finding");
        assert_eq!(context.anomaly_class, "HeapOverflow");
        assert!(context.build_flags.contains(&"-fsanitize=address".to_string()));
    }

    #[test]
    fn test_heap_overflow_harness_generation() {
        let config = HarnessConfig::default();
        let generator = HarnessGenerator::new(config);
        
        let finding = Finding {
            id: "test-heap-overflow".to_string(),
            schema_version: "1.0".to_string(),
            class: AnomalyClass::HeapOverflow,
            confidence: Confidence::High,
            severity: Severity::High,
            timestamp: 1234567890,
            pid: 1234,
            evidence: Evidence {
                memory: Some(MemoryEvidence {
                    ptr: "0x1234".to_string(),
                    size: 100,
                    alloc_size: 100,
                    operation: "malloc".to_string(),
                }),
                stacks: None,
                alloc_site: None,
                event_sequence: vec![],
            },
            escalation: None,
            related: vec![],
        };

        let output = generator.generate_harness(&finding).unwrap();
        assert_eq!(output.finding_id, "test-heap-overflow");
        assert_eq!(output.harness_name, "repro_test-heap-overflow");
        assert!(output.harness_c.contains("malloc"));
        assert!(output.harness_c.contains("memset"));
        assert!(output.build_script.is_some());
    }
}
