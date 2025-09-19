use std::io::{self, Read};

fn main() {
    // Minimal stub: read stdin to keep process alive for LSP handshake testing
    let mut _buf = String::new();
    let _ = io::stdin().read_to_string(&mut _buf);
}


