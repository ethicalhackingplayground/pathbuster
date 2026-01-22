use std::error::Error;

use pathbuster::runner::{Options, PayloadSource, Runner, WordlistSource};
use pathbuster::utils::{SmartJoinCase, SmartJoinSpec, WordlistManipulation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let runner = Runner::new(Options {
        urls: vec!["https://example.com/app/".to_string()],
        payloads: PayloadSource::Inline(vec!["../".to_string()]),
        skip_validation: true,
        skip_brute: false,
        wordlist: Some(WordlistSource::Inline(vec![
            "AdminPanel".to_string(),
            "admin-panel".to_string(),
            "admin_panel".to_string(),
            "login".to_string(),
        ])),
        wordlist_manipulation: WordlistManipulation {
            sort: true,
            unique: true,
            smart_join: Some(SmartJoinSpec {
                case: SmartJoinCase::Lower,
                separator: "_".to_string(),
            }),
            ..WordlistManipulation::default()
        },
        rate: 10,
        concurrency: 10,
        timeout_seconds: 5,
        max_depth: 2,
        ..Options::default()
    })?;

    let result = runner.run().await?;

    println!("Targets: {}", result.fingerprints.len());
    println!("Matches: {}", result.matches.len());
    println!("Discovered routes: {}", result.discovered_routes.len());
    Ok(())
}
