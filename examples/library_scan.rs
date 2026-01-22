use pathbuster::runner::{Options, PayloadSource, Runner};
use std::error::Error;

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
        ..Options::default()
    })?;
    let result = runner.run().await?;

    println!("Targets: {}", result.fingerprints.len());
    println!("Matches: {}", result.matches.len());
    for m in result.matches.iter() {
        println!("{} {} {}", m.base_url, m.status, m.result_url);
    }

    Ok(())
}
