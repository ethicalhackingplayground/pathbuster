use std::error::Error;

use pathbuster::runner::{Options, PayloadSource, Runner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let raw_request_path = std::env::temp_dir().join(format!(
        "pathbuster_example_raw_request_{}.txt",
        std::process::id()
    ));
    std::fs::write(
        &raw_request_path,
        "GET /app/* HTTP/1.1\nHost: example.com\nUser-Agent: pathbuster\nAccept: */*\n\n",
    )?;

    let runner = Runner::new(Options {
        urls: Vec::new(),
        raw_request: Some(raw_request_path.to_string_lossy().to_string()),
        payloads: PayloadSource::Inline(vec!["../".to_string(), "..%2f".to_string()]),
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
