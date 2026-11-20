//! Writes `spec/vectors.json`: `cargo run --bin gen-vectors [-- <path>]`.

fn main() {
    let default = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors.json");
    let path = std::env::args().nth(1).unwrap_or_else(|| default.to_string());
    let mut text = serde_json::to_string_pretty(&signafaide_core::vectors::generate()).expect("serialize");
    text.push('\n');
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {path}: {e}"));
    println!("wrote {path}");
}
