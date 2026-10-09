//! Score a JSON corpus with Azoth's reproducible red-team detector.

use azoth_analysis::detector::{CorpusSample, evaluate_corpus};
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1);
    let mut input = String::new();
    match path.as_deref() {
        Some("-") | None => {
            std::io::stdin().read_to_string(&mut input)?;
        }
        Some(path) => {
            input = std::fs::read_to_string(path)?;
        }
    }
    let samples: Vec<CorpusSample> = serde_json::from_str(&input)?;
    let report = evaluate_corpus(&samples)?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}
