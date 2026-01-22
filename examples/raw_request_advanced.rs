use std::error::Error;

use pathbuster::detector::parse_raw_request_template;
use pathbuster::runner::{Options, PayloadSource, Runner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let raw_request = concat!(
        "POST /api/* HTTP/1.1\n",
        "Host: example.com\n",
        "User-Agent: pathbuster\n",
        "X-Forwarded-For: *\n",
        "Content-Type: application/json\n",
        "\n",
        "{\"path\":\"*\"}\n"
    );

    let template = parse_raw_request_template(raw_request)
        .map_err(|e| format!("invalid raw request template: {e}"))?;
    println!("Injection points: {}", template.injection_points_len());

    let raw_request_path = std::env::temp_dir().join(format!(
        "pathbuster_example_raw_request_{}_advanced.txt",
        std::process::id()
    ));
    std::fs::write(&raw_request_path, raw_request)?;

    let runner = Runner::new(Options {
        urls: Vec::new(),
        raw_request: Some(raw_request_path.to_string_lossy().to_string()),
        payloads: PayloadSource::Inline(vec![
            "../".to_string(),
            "..%2f".to_string(),
            "%2e%2e%2f".to_string(),
        ]),
        skip_brute: true,
        rate: 10,
        concurrency: 10,
        timeout_seconds: 5,
        max_depth: 1,
        ..Options::default()
    })?;

    let result = runner.run().await?;
    println!("Targets: {}", result.fingerprints.len());
    println!("Matches: {}", result.matches.len());

    Ok(())
}
