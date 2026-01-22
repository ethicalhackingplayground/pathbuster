use std::error::Error;

use pathbuster::detector::ResponseFilterConfig;
use pathbuster::runner::{Options, PayloadSource, Runner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let runner = Runner::new(Options {
        urls: vec!["https://example.com/app/".to_string()],
        payloads: PayloadSource::FilePath("./payloads/traversals.txt".to_string()),
        skip_brute: true,
        rate: 10,
        concurrency: 10,
        timeout_seconds: 5,
        max_depth: 2,
        validate_filters: ResponseFilterConfig {
            status: "404".to_string(),
            size: String::new(),
            words: String::new(),
            lines: String::new(),
            regex: String::new(),
        },
        fingerprint_filters: ResponseFilterConfig {
            status: "403,429".to_string(),
            size: String::new(),
            words: String::new(),
            lines: String::new(),
            regex: String::new(),
        },
        ..Options::default()
    })?;

    let result = runner.run().await?;

    println!("Targets: {}", result.fingerprints.len());
    println!("Matches: {}", result.matches.len());
    Ok(())
}
