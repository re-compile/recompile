//! Symbolizer abstraction for resolving addresses to source code locations

use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// A stack frame with symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub module: String,
    pub function: String,
    pub offset: u64,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub source_column: Option<u32>,
}

/// Configuration for the symbolizer
#[derive(Debug, Clone)]
pub struct SymbolizerConfig {
    pub use_llvm_symbolizer: bool,
    pub use_addr2line: bool,
    pub cache_size: usize,
    pub demangle: bool,
    pub inlining: bool,
}

impl Default for SymbolizerConfig {
    fn default() -> Self {
        Self {
            use_llvm_symbolizer: true,
            use_addr2line: true,
            cache_size: 10000,
            demangle: true,
            inlining: true,
        }
    }
}

/// Trait for symbolizing addresses
pub trait Symbolizer {
    fn symbolize(&mut self, binary: &str, addresses: &[u64]) -> Result<Vec<Vec<Frame>>>;
    fn symbolize_single(&mut self, binary: &str, address: u64) -> Result<Vec<Frame>>;
}

/// LLVM Symbolizer implementation
pub struct LlvmSymbolizer {
    config: SymbolizerConfig,
    cache: HashMap<(String, u64), Vec<Frame>>,
}

impl LlvmSymbolizer {
    pub fn new(config: SymbolizerConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
        }
    }

    fn check_llvm_symbolizer() -> bool {
        Command::new("llvm-symbolizer")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn symbolize_with_llvm(&self, binary: &str, addresses: &[u64]) -> Result<Vec<Vec<Frame>>> {
        let mut cmd = Command::new("llvm-symbolizer");
        
        if self.config.demangle {
            cmd.arg("-demangle");
        }
        
        if self.config.inlining {
            cmd.arg("-inlining");
        }
        
        cmd.arg("-obj").arg(binary);

        // Add all addresses as arguments
        for addr in addresses {
            cmd.arg(&format!("0x{:x}", addr));
        }

        let output = cmd.output()?;
        
        if !output.status.success() {
            return Err(anyhow!("llvm-symbolizer failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_llvm_output(&stdout, addresses.len())
    }

    fn parse_llvm_output(&self, output: &str, num_addresses: usize) -> Result<Vec<Vec<Frame>>> {
        let mut results = Vec::new();
        let lines: Vec<&str> = output.lines().collect();
        
        let _i = 0;
        let mut current_frames = Vec::new();
        
        for line in lines {
            if line.trim().is_empty() {
                // Empty line indicates end of frames for current address
                if !current_frames.is_empty() {
                    results.push(current_frames);
                    current_frames = Vec::new();
                }
            } else {
                // Parse frame line
                if let Some(frame) = self.parse_llvm_frame_line(line) {
                    current_frames.push(frame);
                }
            }
        }
        
        // Don't forget the last set of frames
        if !current_frames.is_empty() {
            results.push(current_frames);
        }
        
        // Ensure we have the right number of results
        while results.len() < num_addresses {
            results.push(Vec::new());
        }
        
        Ok(results)
    }

    fn parse_llvm_frame_line(&self, line: &str) -> Option<Frame> {
        // LLVM symbolizer output format:
        // function_name
        // source_file:line:column
        
        let parts: Vec<&str> = line.split('\n').collect();
        if parts.len() < 2 {
            return None;
        }
        
        let function_line = parts[0].trim();
        let location_line = parts[1].trim();
        
        let mut frame = Frame {
            module: String::new(),
            function: function_line.to_string(),
            offset: 0,
            source_file: None,
            source_line: None,
            source_column: None,
        };
        
        // Parse location line: file:line:column
        if let Some(colon_pos) = location_line.find(':') {
            let file_part = &location_line[..colon_pos];
            let rest = &location_line[colon_pos + 1..];
            
            frame.source_file = Some(file_part.to_string());
            
            if let Some(second_colon_pos) = rest.find(':') {
                let line_part = &rest[..second_colon_pos];
                let column_part = &rest[second_colon_pos + 1..];
                
                frame.source_line = u32::from_str(line_part).ok();
                frame.source_column = u32::from_str(column_part).ok();
            } else {
                frame.source_line = u32::from_str(rest).ok();
            }
        }
        
        Some(frame)
    }
}

impl Symbolizer for LlvmSymbolizer {
    fn symbolize(&mut self, binary: &str, addresses: &[u64]) -> Result<Vec<Vec<Frame>>> {
        if !Self::check_llvm_symbolizer() {
            return Err(anyhow!("llvm-symbolizer not available"));
        }
        
        let mut results = Vec::new();
        
        for addr in addresses {
            let cache_key = (binary.to_string(), *addr);
            
            if let Some(cached) = self.cache.get(&cache_key) {
                results.push(cached.clone());
                continue;
            }
            
            let frames = self.symbolize_single(binary, *addr)?;
            
            // Cache the result
            if self.cache.len() < self.config.cache_size {
                self.cache.insert(cache_key, frames.clone());
            }
            
            results.push(frames);
        }
        
        Ok(results)
    }

    fn symbolize_single(&mut self, binary: &str, address: u64) -> Result<Vec<Frame>> {
        let results = self.symbolize(binary, &[address])?;
        Ok(results.into_iter().next().unwrap_or_default())
    }
}

/// Addr2line implementation as fallback
pub struct Addr2lineSymbolizer {
    config: SymbolizerConfig,
    cache: HashMap<(String, u64), Vec<Frame>>,
}

impl Addr2lineSymbolizer {
    pub fn new(config: SymbolizerConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
        }
    }

    fn check_addr2line() -> bool {
        Command::new("addr2line")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn symbolize_with_addr2line(&self, binary: &str, addresses: &[u64]) -> Result<Vec<Vec<Frame>>> {
        let mut cmd = Command::new("addr2line");
        
        if self.config.demangle {
            cmd.arg("-C");
        }
        
        cmd.arg("-f").arg("-e").arg(binary);

        // Add all addresses as arguments
        for addr in addresses {
            cmd.arg(&format!("0x{:x}", addr));
        }

        let output = cmd.output()?;
        
        if !output.status.success() {
            return Err(anyhow!("addr2line failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_addr2line_output(&stdout, addresses.len())
    }

    fn parse_addr2line_output(&self, output: &str, num_addresses: usize) -> Result<Vec<Vec<Frame>>> {
        let mut results = Vec::new();
        let lines: Vec<&str> = output.lines().collect();
        
        // Addr2line outputs function name and location in pairs
        for i in (0..lines.len()).step_by(2) {
            if i + 1 >= lines.len() {
                break;
            }
            
            let function_line = lines[i].trim();
            let location_line = lines[i + 1].trim();
            
            let mut frame = Frame {
                module: String::new(),
                function: function_line.to_string(),
                offset: 0,
                source_file: None,
                source_line: None,
                source_column: None,
            };
            
            // Parse location line: file:line
            if let Some(colon_pos) = location_line.find(':') {
                let file_part = &location_line[..colon_pos];
                let line_part = &location_line[colon_pos + 1..];
                
                frame.source_file = Some(file_part.to_string());
                frame.source_line = u32::from_str(line_part).ok();
            }
            
            results.push(vec![frame]);
        }
        
        // Ensure we have the right number of results
        while results.len() < num_addresses {
            results.push(Vec::new());
        }
        
        Ok(results)
    }
}

impl Symbolizer for Addr2lineSymbolizer {
    fn symbolize(&mut self, binary: &str, addresses: &[u64]) -> Result<Vec<Vec<Frame>>> {
        if !Self::check_addr2line() {
            return Err(anyhow!("addr2line not available"));
        }
        
        let mut results = Vec::new();
        
        for addr in addresses {
            let cache_key = (binary.to_string(), *addr);
            
            if let Some(cached) = self.cache.get(&cache_key) {
                results.push(cached.clone());
                continue;
            }
            
            let frames = self.symbolize_single(binary, *addr)?;
            
            // Cache the result
            if self.cache.len() < self.config.cache_size {
                self.cache.insert(cache_key, frames.clone());
            }
            
            results.push(frames);
        }
        
        Ok(results)
    }

    fn symbolize_single(&mut self, binary: &str, address: u64) -> Result<Vec<Frame>> {
        let results = self.symbolize(binary, &[address])?;
        Ok(results.into_iter().next().unwrap_or_default())
    }
}

/// Composite symbolizer that tries multiple backends
pub struct CompositeSymbolizer {
    llvm: LlvmSymbolizer,
    addr2line: Addr2lineSymbolizer,
    config: SymbolizerConfig,
}

impl CompositeSymbolizer {
    pub fn new(config: SymbolizerConfig) -> Self {
        Self {
            llvm: LlvmSymbolizer::new(config.clone()),
            addr2line: Addr2lineSymbolizer::new(config.clone()),
            config,
        }
    }
}

impl Symbolizer for CompositeSymbolizer {
    fn symbolize(&mut self, binary: &str, addresses: &[u64]) -> Result<Vec<Vec<Frame>>> {
        // Try llvm-symbolizer first if enabled
        if self.config.use_llvm_symbolizer {
            if let Ok(results) = self.llvm.symbolize(binary, addresses) {
                return Ok(results);
            }
        }
        
        // Fall back to addr2line if enabled
        if self.config.use_addr2line {
            if let Ok(results) = self.addr2line.symbolize(binary, addresses) {
                return Ok(results);
            }
        }
        
        // If both fail, return empty results
        Ok(vec![Vec::new(); addresses.len()])
    }

    fn symbolize_single(&mut self, binary: &str, address: u64) -> Result<Vec<Frame>> {
        let results = self.symbolize(binary, &[address])?;
        Ok(results.into_iter().next().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llvm_symbolizer_config() {
        let config = SymbolizerConfig::default();
        assert!(config.use_llvm_symbolizer);
        assert!(config.use_addr2line);
        assert!(config.demangle);
        assert!(config.inlining);
    }

    #[test]
    fn test_llvm_frame_parsing() {
        let config = SymbolizerConfig::default();
        let symbolizer = LlvmSymbolizer::new(config);
        
        let output = "main\n/tmp/test.c:10:5\n";
        let results = symbolizer.parse_llvm_output(output, 1).unwrap();
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].len(), 1);
        
        let frame = &results[0][0];
        assert_eq!(frame.function, "main");
        assert_eq!(frame.source_file, Some("/tmp/test.c".to_string()));
        assert_eq!(frame.source_line, Some(10));
        assert_eq!(frame.source_column, Some(5));
    }

    #[test]
    fn test_addr2line_frame_parsing() {
        let config = SymbolizerConfig::default();
        let symbolizer = Addr2lineSymbolizer::new(config);
        
        let output = "main\n/tmp/test.c:10\n";
        let results = symbolizer.parse_addr2line_output(output, 1).unwrap();
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].len(), 1);
        
        let frame = &results[0][0];
        assert_eq!(frame.function, "main");
        assert_eq!(frame.source_file, Some("/tmp/test.c".to_string()));
        assert_eq!(frame.source_line, Some(10));
    }
}
