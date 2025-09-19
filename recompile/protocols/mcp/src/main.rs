use serde_json::Value;
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            let l = l.trim(); if l.is_empty() { continue; }
            if let Ok(mut v) = serde_json::from_str::<Value>(l) {
                // Minimal tool handler: echo with ack field
                if let Some(obj) = v.as_object_mut() { obj.insert("ack".into(), Value::Bool(true)); }
                println!("{}", serde_json::to_string(&v).unwrap());
                io::stdout().flush().ok();
            }
        }
    }
}


