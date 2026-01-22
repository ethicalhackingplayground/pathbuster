use std::collections::{HashMap, HashSet};

use tokio::sync::mpsc;

#[test]
fn parse_threshold_range_ok() {
    let t = crate::utils::parse_sift3_threshold_range("5-1000").unwrap();
    assert_eq!(t.start, 5.0);
    assert_eq!(t.end, 1000.0);
}

#[test]
fn parse_threshold_range_rejects_invalid() {
    assert!(crate::utils::parse_sift3_threshold_range("500").is_err());
    assert!(crate::utils::parse_sift3_threshold_range("500-").is_err());
    assert!(crate::utils::parse_sift3_threshold_range("-500").is_err());
    assert!(crate::utils::parse_sift3_threshold_range("500-100").is_err());
}

#[test]
fn detect_cloudflare_from_headers() {
    let wafs = crate::fingerprint::detect_waf_for_tests(
        403,
        HashMap::from([
            ("server".to_string(), "cloudflare".to_string()),
            ("cf-ray".to_string(), "123".to_string()),
        ]),
        "Attention Required! | Cloudflare".to_string(),
        None,
    );
    assert!(wafs
        .iter()
        .any(|w| w.name == "Cloudflare" && w.confidence > 0.5));
}

#[test]
fn urlencode_encodes_dots_and_slashes() {
    let payloads = crate::transform::generate_payloads("../..//etc/passwd", &[], 1, &[], false);
    assert!(payloads.iter().any(|p| {
        p.family == "urlencode" && p.mutated.contains("%2e") && p.mutated.contains("%2f")
    }));
}

#[test]
fn generator_deduplicates() {
    let payloads = crate::transform::generate_payloads(
        "../../../etc/passwd",
        &["ModSecurity".to_string()],
        2,
        &[],
        false,
    );
    let uniques: HashSet<_> = payloads.iter().map(|p| p.mutated.clone()).collect();
    assert_eq!(uniques.len(), payloads.len());
}

#[test]
fn minimal_urlencode_keeps_letters() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 1, &[], false);
    let has_min = payloads.iter().any(|p| {
        p.family == "urlencode_min"
            && p.mutated.contains("etc")
            && (p.mutated.contains("%2e") || p.mutated.contains("%2E"))
    });
    assert!(has_min);
}

#[test]
fn bypass_level_2_adds_overlong_utf8() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 2, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "overlong_utf8" && p.mutated.contains("%c0%ae")));
}

#[test]
fn bypass_level_2_adds_unicode_u_encoding() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 2, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "unicode_u" && p.mutated.contains("%u002e")));
}

#[test]
fn bypass_level_3_adds_multi_layer_encoding() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 3, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "multi_layer_encoding" && p.mutated.contains("%252f")));
}

#[test]
fn bypass_level_3_adds_advanced_null_byte() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 3, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "advanced_null_byte" && p.mutated.contains("%00")));
}

#[test]
fn bypass_level_3_adds_path_normalization() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 3, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "path_normalization" && p.mutated.contains("%2e%2e%2f")));
}

#[test]
fn bypass_level_3_adds_mixed_slash_techniques() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 3, &[], false);
    assert!(payloads.iter().any(|p| p.family == "mixed_slash"
        && (p.mutated.contains("%2f%5c") || p.mutated.contains("/\\"))));
}

#[test]
fn bypass_level_3_adds_protocol_relative() {
    let payloads =
        crate::transform::generate_payloads("http://example.com/../etc/passwd", &[], 3, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "protocol_relative" && p.mutated.starts_with("//")));
}

#[test]
fn bypass_level_3_adds_rfc3986_edge_cases() {
    let payloads = crate::transform::generate_payloads("../etc/passwd", &[], 3, &[], false);
    assert!(payloads
        .iter()
        .any(|p| p.family == "rfc3986_edge_cases" && p.mutated.contains("%252f")));
}

#[test]
fn bypass_level_3_generates_more_payloads_than_level_2() {
    let payloads_level_2 = crate::transform::generate_payloads("../etc/passwd", &[], 2, &[], false);
    let payloads_level_3 = crate::transform::generate_payloads("../etc/passwd", &[], 3, &[], false);
    assert!(payloads_level_3.len() > payloads_level_2.len());
}

#[test]
fn wordlist_smart_break_splits_common_styles() {
    assert_eq!(crate::utils::smart_break("adminNew"), vec!["admin", "New"]);
    assert_eq!(crate::utils::smart_break("admin_new"), vec!["admin", "new"]);
    assert_eq!(crate::utils::smart_break("admin-old"), vec!["admin", "old"]);
}

#[test]
fn wordlist_smart_join_parsing_and_apply() {
    let spec = crate::utils::parse_smart_join_spec("c:_").unwrap();
    let cfg = crate::utils::WordlistManipulation {
        smart_join: Some(spec),
        ..Default::default()
    };
    let out = crate::utils::apply_wordlist_manipulations(vec!["admin-old".to_string()], &cfg);
    assert_eq!(out, vec!["admin_Old"]);
}

#[tokio::test]
async fn path_parameter_produces_single_wordlist_entry() {
    let fingerprints: HashMap<String, crate::fingerprint::TargetFingerprint> = HashMap::new();
    let cfg = crate::runner::WordlistLoadConfig {
        path: Some("admin"),
        wordlist_dir: None,
        tech_override: None,
        manipulation: &crate::utils::WordlistManipulation::default(),
        extensions: &[],
        dirsearch_compat: false,
        skip_brute: false,
        skip_validation: false,
    };
    let (wordlist, loaded) = crate::runner::load_wordlist(None, &fingerprints, cfg)
        .await
        .unwrap();
    assert_eq!(wordlist, vec!["admin".to_string()]);
    assert!(loaded.is_empty());
}

#[tokio::test]
async fn bruteforce_queue_deduplicates_discoveries_and_enqueues_words() {
    let (job_tx, mut job_rx) = mpsc::channel::<crate::bruteforcer::BruteJob>(16);
    let (disc_tx, disc_rx) = mpsc::channel::<String>(16);

    disc_tx
        .send("http://example.com/".to_string())
        .await
        .unwrap();
    disc_tx
        .send("http://example.com/".to_string())
        .await
        .unwrap();
    drop(disc_tx);

    let wordlists = vec!["admin".to_string(), "login".to_string()];
    let sender = crate::bruteforcer::send_word_to_url_queue(job_tx, disc_rx, wordlists, 1000);

    let mut jobs = Vec::new();
    tokio::select! {
        _ = sender => {
            while let Some(job) = job_rx.recv().await {
                jobs.push(job);
            }
        }
    }

    let urls: Vec<_> = jobs.iter().map(|j| j.url.clone().unwrap()).collect();
    let words: Vec<_> = jobs.iter().map(|j| j.word.clone().unwrap()).collect();

    assert_eq!(urls, vec!["http://example.com/".to_string(); 2]);
    assert!(words.contains(&"admin".to_string()));
    assert!(words.contains(&"login".to_string()));
}
