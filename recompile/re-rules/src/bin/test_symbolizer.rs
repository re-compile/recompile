use anyhow::Result;
use re_rules::{
    Symbolizer, LlvmSymbolizer, Addr2lineSymbolizer, CompositeSymbolizer,
    SymbolizerConfig
};

fn main() -> Result<()> {
    env_logger::init();
    println!("Testing RECC Symbolizer...");

    let config = SymbolizerConfig::default();
    
    // Test with a simple binary (using the invalid_free example)
    let binary = "/tmp/invalid_free";
    let test_addresses = vec![0x730u64]; // Example address from the stack trace

    println!("Testing LLVM Symbolizer...");
    let mut llvm_symbolizer = LlvmSymbolizer::new(config.clone());
    
    match llvm_symbolizer.symbolize_single(binary, test_addresses[0]) {
        Ok(frames) => {
            println!("LLVM Symbolizer found {} frames:", frames.len());
            for (i, frame) in frames.iter().enumerate() {
                println!("  Frame {}: {} in {} (offset: 0x{:x})", 
                    i, frame.function, frame.module, frame.offset);
                if let Some(file) = &frame.source_file {
                    println!("    Source: {}:{}:{}", 
                        file, 
                        frame.source_line.unwrap_or(0),
                        frame.source_column.unwrap_or(0));
                }
            }
        }
        Err(e) => {
            println!("LLVM Symbolizer failed: {}", e);
        }
    }

    println!("\nTesting Addr2line Symbolizer...");
    let mut addr2line_symbolizer = Addr2lineSymbolizer::new(config.clone());
    
    match addr2line_symbolizer.symbolize_single(binary, test_addresses[0]) {
        Ok(frames) => {
            println!("Addr2line Symbolizer found {} frames:", frames.len());
            for (i, frame) in frames.iter().enumerate() {
                println!("  Frame {}: {} in {} (offset: 0x{:x})", 
                    i, frame.function, frame.module, frame.offset);
                if let Some(file) = &frame.source_file {
                    println!("    Source: {}:{}", 
                        file, 
                        frame.source_line.unwrap_or(0));
                }
            }
        }
        Err(e) => {
            println!("Addr2line Symbolizer failed: {}", e);
        }
    }

    println!("\nTesting Composite Symbolizer...");
    let mut composite_symbolizer = CompositeSymbolizer::new(config);
    
    match composite_symbolizer.symbolize_single(binary, test_addresses[0]) {
        Ok(frames) => {
            println!("Composite Symbolizer found {} frames:", frames.len());
            for (i, frame) in frames.iter().enumerate() {
                println!("  Frame {}: {} in {} (offset: 0x{:x})", 
                    i, frame.function, frame.module, frame.offset);
                if let Some(file) = &frame.source_file {
                    println!("    Source: {}:{}:{}", 
                        file, 
                        frame.source_line.unwrap_or(0),
                        frame.source_column.unwrap_or(0));
                }
            }
        }
        Err(e) => {
            println!("Composite Symbolizer failed: {}", e);
        }
    }

    println!("\nSymbolizer test completed!");
    Ok(())
}
