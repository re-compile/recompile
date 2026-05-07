//! Binary and dynamic dependency metadata for observation runs.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryDependencyMetadata {
    pub schema_version: String,
    pub purpose: String,
    pub binary_path: String,
    pub file_size: Option<u64>,
    pub readelf: ToolStatus,
    pub ldd: ToolStatus,
    pub elf: ElfMetadata,
    pub dynamic_dependencies: Vec<DynamicDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStatus {
    pub tool: String,
    pub status: ToolAvailability,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAvailability {
    Available,
    Unavailable,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfMetadata {
    pub class: Option<String>,
    pub machine: Option<String>,
    pub interpreter: Option<String>,
    pub build_id: Option<String>,
    pub debug_info: Option<bool>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicDependency {
    pub name: String,
    pub path: Option<String>,
    pub status: DependencyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStatus {
    Resolved,
    Missing,
    Loader,
    Unknown,
}

impl ToolStatus {
    fn available(tool: &str) -> Self {
        Self {
            tool: tool.to_string(),
            status: ToolAvailability::Available,
            error: None,
        }
    }

    fn unavailable(tool: &str, error: impl Into<String>) -> Self {
        Self {
            tool: tool.to_string(),
            status: ToolAvailability::Unavailable,
            error: Some(error.into()),
        }
    }

    fn failed(tool: &str, error: impl Into<String>) -> Self {
        Self {
            tool: tool.to_string(),
            status: ToolAvailability::Failed,
            error: Some(error.into()),
        }
    }
}

pub fn capture_binary_dependency_metadata(binary_path: &Path) -> BinaryDependencyMetadata {
    let mut metadata = BinaryDependencyMetadata {
        schema_version: "1.0".to_string(),
        purpose: "binary_dependency_metadata".to_string(),
        binary_path: binary_path.display().to_string(),
        file_size: std::fs::metadata(binary_path)
            .ok()
            .map(|metadata| metadata.len()),
        readelf: ToolStatus::unavailable("readelf", "not run"),
        ldd: ToolStatus::unavailable("ldd", "not run"),
        elf: ElfMetadata::default(),
        dynamic_dependencies: Vec::new(),
    };

    match Command::new("readelf").arg("-h").arg(binary_path).output() {
        Ok(output) if output.status.success() => {
            metadata.readelf = ToolStatus::available("readelf");
            metadata.elf = parse_readelf_header(&String::from_utf8_lossy(&output.stdout));
        }
        Ok(output) => {
            metadata.readelf = ToolStatus::failed(
                "readelf",
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            metadata.readelf = ToolStatus::unavailable("readelf", "readelf not found in PATH");
        }
        Err(error) => {
            metadata.readelf = ToolStatus::failed("readelf", error.to_string());
        }
    }

    if metadata.readelf.status == ToolAvailability::Available {
        enrich_with_readelf_notes(binary_path, &mut metadata);
        enrich_with_readelf_dynamic(binary_path, &mut metadata);
    }

    match Command::new("ldd").arg(binary_path).output() {
        Ok(output) if output.status.success() => {
            metadata.ldd = ToolStatus::available("ldd");
            metadata.dynamic_dependencies =
                parse_ldd_output(&String::from_utf8_lossy(&output.stdout));
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            metadata.ldd =
                ToolStatus::failed("ldd", if stderr.is_empty() { stdout } else { stderr });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            metadata.ldd = ToolStatus::unavailable("ldd", "ldd not found in PATH");
        }
        Err(error) => {
            metadata.ldd = ToolStatus::failed("ldd", error.to_string());
        }
    }

    metadata
}

fn enrich_with_readelf_notes(binary_path: &Path, metadata: &mut BinaryDependencyMetadata) {
    if let Ok(output) = Command::new("readelf").arg("-n").arg(binary_path).output() {
        if output.status.success() {
            metadata.elf.build_id = parse_build_id(&String::from_utf8_lossy(&output.stdout));
        }
    }
}

fn enrich_with_readelf_dynamic(binary_path: &Path, metadata: &mut BinaryDependencyMetadata) {
    if let Ok(output) = Command::new("readelf").arg("-l").arg(binary_path).output() {
        if output.status.success() {
            metadata.elf.interpreter = parse_interpreter(&String::from_utf8_lossy(&output.stdout));
        }
    }
    if let Ok(output) = Command::new("readelf").arg("-S").arg(binary_path).output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            metadata.elf.debug_info =
                Some(text.contains(".debug_info") || text.contains(".debug_line"));
        }
    }
    if let Ok(output) = Command::new("readelf").arg("-d").arg(binary_path).output() {
        if output.status.success() {
            let (rpath, runpath) = parse_rpath_runpath(&String::from_utf8_lossy(&output.stdout));
            metadata.elf.rpath = rpath;
            metadata.elf.runpath = runpath;
        }
    }
}

fn parse_readelf_header(text: &str) -> ElfMetadata {
    let mut metadata = ElfMetadata::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Class" => metadata.class = Some(value.to_string()),
            "Machine" => metadata.machine = Some(value.to_string()),
            _ => {}
        }
    }
    metadata
}

fn parse_build_id(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.split_once("Build ID:")
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn parse_interpreter(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (_, value) = line.split_once("Requesting program interpreter:")?;
        Some(
            value
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
        )
        .filter(|value| !value.is_empty())
    })
}

fn parse_rpath_runpath(text: &str) -> (Option<String>, Option<String>) {
    let mut rpath = None;
    let mut runpath = None;
    for line in text.lines() {
        if line.contains("(RPATH)") {
            rpath = bracketed_value(line);
        } else if line.contains("(RUNPATH)") {
            runpath = bracketed_value(line);
        }
    }
    (rpath, runpath)
}

fn bracketed_value(line: &str) -> Option<String> {
    let start = line.rfind('[')?;
    let end = line.rfind(']')?;
    if end <= start {
        return None;
    }
    Some(line[start + 1..end].trim().to_string()).filter(|value| !value.is_empty())
}

fn parse_ldd_output(text: &str) -> Vec<DynamicDependency> {
    text.lines().filter_map(parse_ldd_line).collect()
}

fn parse_ldd_line(line: &str) -> Option<DynamicDependency> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("statically linked") {
        return None;
    }

    if let Some((name, _)) = line.split_once("=> not found") {
        return Some(DynamicDependency {
            name: name.trim().to_string(),
            path: None,
            status: DependencyStatus::Missing,
        });
    }

    if let Some((name, rest)) = line.split_once("=>") {
        let path = rest.split_whitespace().next().map(str::to_string);
        return Some(DynamicDependency {
            name: name.trim().to_string(),
            status: if path.is_some() {
                DependencyStatus::Resolved
            } else {
                DependencyStatus::Unknown
            },
            path,
        });
    }

    let first = line.split_whitespace().next()?;
    Some(DynamicDependency {
        name: first.to_string(),
        path: Some(first.to_string()).filter(|value| value.starts_with('/')),
        status: if first.starts_with('/') {
            DependencyStatus::Loader
        } else {
            DependencyStatus::Unknown
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_readelf_header_fields() {
        let metadata = parse_readelf_header(
            "  Class:                             ELF64\n  Machine:                           AArch64\n",
        );
        assert_eq!(metadata.class.as_deref(), Some("ELF64"));
        assert_eq!(metadata.machine.as_deref(), Some("AArch64"));
    }

    #[test]
    fn parses_readelf_notes_and_interpreter() {
        assert_eq!(
            parse_build_id("    Build ID: abc123\n").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            parse_interpreter("[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n")
                .as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }

    #[test]
    fn parses_rpath_and_runpath() {
        let (rpath, runpath) = parse_rpath_runpath(
            "0x000000000000000f (RPATH) Library rpath: [/opt/lib]\n0x000000000000001d (RUNPATH) Library runpath: [$ORIGIN/lib]\n",
        );
        assert_eq!(rpath.as_deref(), Some("/opt/lib"));
        assert_eq!(runpath.as_deref(), Some("$ORIGIN/lib"));
    }

    #[test]
    fn parses_ldd_resolved_missing_and_loader_lines() {
        let deps = parse_ldd_output(
            "linux-vdso.so.1 (0x0000)\nlibc.so.6 => /lib/libc.so.6 (0x1000)\nlibmissing.so => not found\n/lib64/ld-linux-x86-64.so.2 (0x2000)\n",
        );
        assert_eq!(deps.len(), 4);
        assert_eq!(deps[0].status, DependencyStatus::Unknown);
        assert_eq!(deps[1].name, "libc.so.6");
        assert_eq!(deps[1].path.as_deref(), Some("/lib/libc.so.6"));
        assert_eq!(deps[1].status, DependencyStatus::Resolved);
        assert_eq!(deps[2].name, "libmissing.so");
        assert_eq!(deps[2].status, DependencyStatus::Missing);
        assert_eq!(deps[3].status, DependencyStatus::Loader);
    }
}
