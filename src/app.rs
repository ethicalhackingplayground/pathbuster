use std::collections::{HashMap, HashSet};
use std::time::Duration;

use clap::{error::ErrorKind, CommandFactory, Parser};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use tokio::time::Instant;
use tokio::{fs::File, io::AsyncBufReadExt, io::BufReader};

use crate::bruteforcer::{BruteJob, BruteResult};
use crate::cli::args::CliArgs;
use crate::cli::validation;
use crate::config::{self, ConfigFile};
use crate::detector::{self, Job, JobResultMeta, TargetUrl};

fn print_banner(no_color: bool) {
    let _ = no_color;
    const BANNER: &str = r#"                             
                 __  __    __               __           
    ____  ____ _/ /_/ /_  / /_  __  _______/ /____  _____
   / __ \/ __ `/ __/ __ \/ __ \/ / / / ___/ __/ _ \/ ___/
  / /_/ / /_/ / /_/ / / / /_/ / /_/ (__  ) /_/  __/ /    
 / .___/\__,_/\__/_/ /_/_.___/\__,_/____/\__/\___/_/     
/_/                                                          
       v0.5.6 - path normalization pentesting tool                 
    "#;
    print!("{}", BANNER);
    println!();
}

fn normalize_trailing_slash(url: &str) -> (String, String) {
    let original = url.to_string();
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return (original, url.to_string()),
    };
    if parsed.path() == "/" {
        return (original, url.to_string());
    }
    let mut normalized = url.to_string();
    while normalized.ends_with('/') {
        normalized.pop();
    }
    (original, normalized)
}

fn trim_url(url: &str) -> String {
    url.trim().to_string()
}

fn format_kv_line(label: &str, value: &str) {
    println!(":: {:<10}: {}", label, value);
}

fn render_custom_help() -> String {
    let cmd = CliArgs::command();
    let mut out = String::new();

    if let Some(version) = cmd.get_version() {
        out.push_str(cmd.get_name());
        out.push(' ');
        out.push_str(version);
        out.push('\n');
    } else {
        out.push_str(cmd.get_name());
        out.push('\n');
    }

    if let Some(about) = cmd.get_about() {
        out.push_str(&about.to_string());
        out.push('\n');
    }

    if let Some(long_about) = cmd.get_long_about() {
        out.push('\n');
        out.push_str(&long_about.to_string());
        out.push('\n');
    }

    out.push('\n');
    out.push_str("Usage: ");
    out.push_str(cmd.get_name());
    out.push_str(" [OPTIONS]\n\n");

    let mut sections: Vec<(String, Vec<&clap::Arg>)> = Vec::new();
    let mut section_idx: HashMap<String, usize> = HashMap::new();

    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }

        let heading = arg.get_help_heading().unwrap_or("Options").to_string();

        let idx = match section_idx.get(&heading).copied() {
            Some(i) => i,
            None => {
                sections.push((heading.clone(), Vec::new()));
                let i = sections.len() - 1;
                section_idx.insert(heading, i);
                i
            }
        };

        sections[idx].1.push(arg);
    }

    for (heading, args) in sections {
        out.push_str(&heading);
        out.push_str(":\n");

        for arg in args {
            let mut parts: Vec<String> = Vec::new();

            if let Some(short) = arg.get_short() {
                parts.push(format!("-{short}"));
            }

            if let Some(long) = arg.get_long() {
                parts.push(format!("--{long}"));
            }

            if let Some(aliases) = arg.get_visible_aliases() {
                for alias in aliases {
                    let rendered = format!("--{alias}");
                    if !parts.iter().any(|p| p == &rendered) {
                        parts.push(rendered);
                    }
                }
            }

            let mut flags = parts.join(", ");

            if arg.get_action().takes_values() {
                let value_name = arg
                    .get_value_names()
                    .and_then(|names| names.first())
                    .map(|name| name.as_str())
                    .unwrap_or("VALUE");
                let placeholder = format!("<{value_name}>");
                let min_values = arg.get_num_args().map(|r| r.min_values()).unwrap_or(1);

                if min_values == 0 {
                    flags.push(' ');
                    flags.push('[');
                    flags.push_str(&placeholder);
                    flags.push(']');
                } else {
                    flags.push(' ');
                    flags.push_str(&placeholder);
                }
            }

            out.push_str("  ");
            out.push_str(&flags);
            out.push('\n');

            if let Some(help) = arg.get_help() {
                let help = help.to_string();
                if !help.trim().is_empty() {
                    out.push_str("          ");
                    out.push_str(help.trim());
                    out.push('\n');
                }
            }

            out.push('\n');
        }
    }

    out
}

fn format_opt_value<'a>(v: &'a str, default: &'a str) -> &'a str {
    if v.trim().is_empty() {
        default
    } else {
        v
    }
}

fn summarize_filters(
    status: &str,
    size: &str,
    words: &str,
    lines: &str,
    regex: &str,
) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if !status.trim().is_empty() {
        parts.push(format!("status={}", status.trim()));
    }
    if !size.trim().is_empty() {
        parts.push(format!("size={}", size.trim()));
    }
    if !words.trim().is_empty() {
        parts.push(format!("words={}", words.trim()));
    }
    if !lines.trim().is_empty() {
        parts.push(format!("lines={}", lines.trim()));
    }
    if !regex.trim().is_empty() {
        parts.push("regex=...".to_string());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn split_stage_prefixed_csv(input: &str) -> (String, String) {
    let mut v: Vec<String> = Vec::new();
    let mut f: Vec<String> = Vec::new();
    let mut stage: Option<char> = None;
    for raw in input.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        if let Some(rest) = item.strip_prefix("V:").or_else(|| item.strip_prefix("v:")) {
            stage = Some('V');
            let rest = rest.trim();
            if !rest.is_empty() {
                v.push(rest.to_string());
            }
            continue;
        }
        if let Some(rest) = item.strip_prefix("F:").or_else(|| item.strip_prefix("f:")) {
            stage = Some('F');
            let rest = rest.trim();
            if !rest.is_empty() {
                f.push(rest.to_string());
            }
            continue;
        }
        match stage {
            Some('V') => v.push(item.to_string()),
            Some('F') => f.push(item.to_string()),
            _ => {
                v.push(item.to_string());
                f.push(item.to_string());
            }
        }
    }
    (v.join(","), f.join(","))
}

#[cfg(test)]
mod tests {
    use super::split_stage_prefixed_csv;

    #[test]
    fn stage_prefixed_csv_groups_until_next_prefix() {
        let (v, f) = split_stage_prefixed_csv("V:301,302,F:404,500");
        assert_eq!(v, "301,302");
        assert_eq!(f, "404,500");
    }

    #[test]
    fn stage_prefixed_csv_unprefixed_applies_to_both_before_prefix() {
        let (v, f) = split_stage_prefixed_csv("301,V:302,F:404");
        assert_eq!(v, "301,302");
        assert_eq!(f, "301,404");
    }
}

fn split_stage_prefixed_regex(values: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v: Vec<String> = Vec::new();
    let mut f: Vec<String> = Vec::new();
    for raw in values.iter() {
        let item = raw.trim();
        if let Some(rest) = item.strip_prefix("V:").or_else(|| item.strip_prefix("v:")) {
            let rest = rest.trim();
            if !rest.is_empty() {
                v.push(rest.to_string());
            }
            continue;
        }
        if let Some(rest) = item.strip_prefix("F:").or_else(|| item.strip_prefix("f:")) {
            let rest = rest.trim();
            if !rest.is_empty() {
                f.push(rest.to_string());
            }
            continue;
        }
        if !item.is_empty() {
            v.push(item.to_string());
            f.push(item.to_string());
        }
    }
    (v, f)
}

fn combine_regexes(values: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    for v in values.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        out.push(format!("(?:{v})"));
    }
    out.join("|")
}

fn format_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn traversal_strategy_label(strategy: detector::TraversalStrategy) -> &'static str {
    match strategy {
        detector::TraversalStrategy::Greedy => "greedy",
        detector::TraversalStrategy::Quick => "quick",
    }
}

#[derive(Clone, Debug)]
struct RunConfig {
    urls: Vec<TargetUrl>,
    input_file_path: Option<String>,
    rate: u32,
    concurrency: u32,
    timeout: usize,
    workers: usize,
    output: Option<String>,
    output_format: Option<String>,
    http_proxy: String,
    header: String,
    methods: Vec<reqwest::Method>,
    drop_after_fail: String,
    validate_status: String,
    validate_status_set: HashSet<u16>,
    fingerprint_status: String,
    validate_filter_status: String,
    validate_filter_size: String,
    validate_filter_words: String,
    validate_filter_lines: String,
    validate_filter_regex: String,
    fingerprint_filter_status: String,
    fingerprint_filter_size: String,
    fingerprint_filter_words: String,
    fingerprint_filter_lines: String,
    fingerprint_filter_regex: String,
    payloads_path: String,
    raw_request_path: Option<String>,
    wordlist_path: Option<String>,
    extensions: Vec<String>,
    dirsearch_compat: bool,
    path: Option<String>,
    wordlist_dir: String,
    wordlist_manipulation: crate::utils::WordlistManipulation,
    tech_override: Option<String>,
    no_color: bool,
    disable_show_all: bool,
    ignore_trailing_slash: bool,
    skip_validation: bool,
    skip_brute: bool,
    auto_collab: bool,
    wordlist_status: HashSet<u16>,
    brute_queue_concurrency: u32,
    enable_fingerprinting: bool,
    waf_test: Option<String>,
    disable_waf_bypass: bool,
    bypass_level: u8,
    bypass_transforms: Vec<String>,
    start_depth: usize,
    max_depth: usize,
    traversal_strategy: detector::TraversalStrategy,
    follow_redirects: bool,
    sift3_threshold: crate::utils::ResponseChangeThreshold,
}

fn build_run_config(args: CliArgs, cfg: ConfigFile) -> Result<RunConfig, String> {
    validation::validate(&args)?;

    let no_color = if args.color {
        false
    } else {
        args.no_color || cfg.no_color.unwrap_or(false)
    };
    let disable_show_all = args
        .disable_show_all
        .or(cfg.disable_show_all)
        .unwrap_or(false);

    let rate = args.rate.or(cfg.rate).unwrap_or(1000);
    let concurrency = args.concurrency.or(cfg.concurrency).unwrap_or(1000);
    let timeout = args.timeout.or(cfg.timeout).unwrap_or(10);
    let workers = args.workers.or(cfg.workers).unwrap_or(10);

    let http_proxy = args.proxy.or(cfg.proxy).unwrap_or_default();
    let follow_redirects = args.follow_redirects || cfg.follow_redirects.unwrap_or(false);

    let skip_validation = args.skip_validation || cfg.skip_validation.unwrap_or(false);
    let skip_brute = args.skip_brute || cfg.skip_brute.unwrap_or(false);

    let auto_collab = args.auto_collab || cfg.auto_collab.unwrap_or(false);
    let wordlist_status_raw = args
        .wordlist_status
        .or(cfg.wordlist_status)
        .unwrap_or_else(|| "200".to_string());
    let wordlist_status = crate::utils::parse_u16_set_csv(&wordlist_status_raw)
        .map_err(|e| format!("invalid --wordlist-status '{wordlist_status_raw}': {e}"))?;
    let brute_queue_concurrency = args
        .brute_queue_concurrency
        .or(cfg.brute_queue_concurrency)
        .unwrap_or(0);

    let drop_after_fail = args
        .drop_after_fail
        .or(cfg.drop_after_fail)
        .unwrap_or_else(|| "302,301".to_string());
    crate::utils::parse_u16_set_csv(&drop_after_fail)
        .map_err(|e| format!("invalid --drop-after-fail '{drop_after_fail}': {e}"))?;

    let validate_status = args
        .validate_status
        .or(cfg.validate_status)
        .unwrap_or_else(|| "404".to_string());
    let validate_status_set = crate::utils::parse_u16_set_csv(&validate_status)
        .map_err(|e| format!("invalid --validate-status '{validate_status}': {e}"))?;

    let fingerprint_status = args
        .fingerprint_status
        .or(cfg.fingerprint_status)
        .unwrap_or_else(|| "400,500".to_string());
    crate::utils::parse_u16_set_csv(&fingerprint_status)
        .map_err(|e| format!("invalid --fingerprint-status '{fingerprint_status}': {e}"))?;

    let filter_status = args.filter_status.or(cfg.filter_status).unwrap_or_default();
    let filter_size = args.filter_size.or(cfg.filter_size).unwrap_or_default();
    let filter_words = args.filter_words.or(cfg.filter_words).unwrap_or_default();
    let filter_lines = args.filter_lines.or(cfg.filter_lines).unwrap_or_default();
    let filter_regex = if args.filter_regex.is_empty() {
        cfg.filter_regex.unwrap_or_default()
    } else {
        args.filter_regex.clone()
    };

    let (validate_filter_status, fingerprint_filter_status) =
        split_stage_prefixed_csv(filter_status.as_str());
    let (validate_filter_size, fingerprint_filter_size) =
        split_stage_prefixed_csv(filter_size.as_str());
    let (validate_filter_words, fingerprint_filter_words) =
        split_stage_prefixed_csv(filter_words.as_str());
    let (validate_filter_lines, fingerprint_filter_lines) =
        split_stage_prefixed_csv(filter_lines.as_str());

    let (validate_regexes, fingerprint_regexes) = split_stage_prefixed_regex(&filter_regex);
    let validate_filter_regex = combine_regexes(&validate_regexes);
    let fingerprint_filter_regex = combine_regexes(&fingerprint_regexes);

    let payloads_path = config::expand_tilde_string(
        args.payloads
            .or(cfg.payloads)
            .unwrap_or_else(|| "./payloads/traversals.txt".to_string())
            .as_str(),
    );

    let wordlist_dir = config::expand_tilde_string(
        args.wordlist_dir
            .or(cfg.wordlist_dir)
            .unwrap_or_else(|| "./wordlists/targeted".to_string())
            .as_str(),
    );

    let cli_wordlist_path = args.wordlist.map(|p| config::expand_tilde_string(&p));
    let cli_path = args.path.map(|p| p.trim().to_string());
    let cli_path = match cli_path {
        Some(p) if p.is_empty() => None,
        other => other,
    };
    if cli_wordlist_path.is_some() && cli_path.is_some() {
        return Err("use either --wordlist or --path, not both".to_string());
    }

    let cfg_wordlist_path = cfg.wordlist.map(|p| config::expand_tilde_string(&p));
    let cfg_path = cfg.path.map(|p| p.trim().to_string());
    let cfg_path = match cfg_path {
        Some(p) if p.is_empty() => None,
        other => other,
    };
    if cfg_wordlist_path.is_some() && cfg_path.is_some() {
        return Err("use either --wordlist or --path, not both".to_string());
    }

    let (wordlist_path, path) = if cli_path.is_some() {
        (None, cli_path)
    } else if cli_wordlist_path.is_some() {
        (cli_wordlist_path, None)
    } else {
        (cfg_wordlist_path, cfg_path)
    };
    if !skip_brute && wordlist_path.is_none() && path.is_none() {
        return Err("wordlist (or --path) is required unless --skip-brute is set".to_string());
    }

    let wordlist_manipulation_raw = args
        .wordlist_manipulation
        .or(cfg.wordlist_manipulation)
        .unwrap_or_default();
    let wordlist_manipulation =
        crate::utils::parse_wordlist_manipulation_list(wordlist_manipulation_raw.as_str())
            .map_err(|e| {
                format!("invalid --wordlist-manipulation '{wordlist_manipulation_raw}': {e}")
            })?;

    let traversal_strategy_str = args
        .traversal_strategy
        .or(cfg.traversal_strategy)
        .unwrap_or_else(|| "greedy".to_string());
    let traversal_strategy = detector::TraversalStrategy::parse(&traversal_strategy_str)
        .unwrap_or(detector::TraversalStrategy::Greedy);

    let disable_fingerprinting =
        args.disable_fingerprinting || cfg.disable_fingerprinting.unwrap_or(false);
    let enable_fingerprinting = !disable_fingerprinting;
    let waf_test = args.waf_test.or(cfg.waf_test);

    let tech_override = args.tech.or(cfg.tech);

    let disable_waf_bypass = args.disable_waf_bypass || cfg.disable_waf_bypass.unwrap_or(false);
    let bypass_level = args.bypass_level.or(cfg.bypass_level).unwrap_or(1);
    if bypass_level > 3 {
        return Err("invalid bypass-level, expected 0, 1, 2 or 3".to_string());
    }
    let bypass_transforms = if !args.bypass_transform.is_empty() {
        args.bypass_transform
    } else {
        cfg.bypass_transform.unwrap_or_default()
    };

    let start_depth = args.start_depth.or(cfg.start_depth).unwrap_or(0);
    let max_depth = args.max_depth.or(cfg.max_depth).unwrap_or(5);
    if max_depth == 0 {
        return Err("invalid max-depth, expected positive integer".to_string());
    }

    let response_diff_threshold = args
        .response_diff_threshold
        .as_deref()
        .or(cfg.response_diff_threshold.as_deref());
    let sift3_threshold = match response_diff_threshold {
        Some(v) => crate::utils::parse_sift3_threshold_range(v)
            .map_err(|e| format!("invalid response-diff-threshold: {e}"))?,
        None => crate::utils::DEFAULT_SIFT3_THRESHOLD,
    };

    let header = args.header.or(cfg.header).unwrap_or_default();

    let methods = match args.methods.or(cfg.methods) {
        Some(raw) => crate::utils::parse_http_methods_csv(&raw)
            .map_err(|e| format!("invalid methods '{raw}': {e}"))?,
        None => vec![reqwest::Method::GET],
    };

    let ignore_trailing_slash =
        args.ignore_trailing_slash || cfg.ignore_trailing_slash.unwrap_or(false);

    let raw_request_path = args.raw_request.map(|p| config::expand_tilde_string(&p));

    let output = args
        .output
        .or(cfg.output)
        .map(|p| config::expand_tilde_string(&p));
    let output_format = args.output_format.or(cfg.output_format);

    let mut urls: Vec<TargetUrl> = vec![];
    for u in args.url.into_iter() {
        let u = trim_url(&u);
        urls.push(TargetUrl {
            original: u.clone(),
            normalized: u,
        });
    }
    let input_file_path = args
        .input_file
        .or(cfg.input_file)
        .map(|p| config::expand_tilde_string(&p));
    if let Some(extra_urls) = cfg.urls {
        for u in extra_urls {
            let u = trim_url(&u);
            urls.push(TargetUrl {
                original: u.clone(),
                normalized: u,
            });
        }
    }

    let extensions_raw = args.extensions.or(cfg.extensions).unwrap_or_default();
    let extensions = if extensions_raw.trim().is_empty() {
        Vec::new()
    } else {
        crate::utils::parse_extensions_csv(&extensions_raw)
            .map_err(|e| format!("invalid --extensions '{extensions_raw}': {e}"))?
    };
    let dirsearch_compat = args.dirsearch_compat || cfg.dirsearch_compat.unwrap_or(false);
    if dirsearch_compat && extensions.is_empty() {
        return Err("dirsearch mode requires --extensions".to_string());
    }

    Ok(RunConfig {
        urls,
        input_file_path,
        rate,
        concurrency,
        timeout,
        workers,
        output,
        output_format,
        http_proxy,
        header,
        methods,
        drop_after_fail,
        validate_status,
        validate_status_set,
        fingerprint_status,
        validate_filter_status,
        validate_filter_size,
        validate_filter_words,
        validate_filter_lines,
        validate_filter_regex,
        fingerprint_filter_status,
        fingerprint_filter_size,
        fingerprint_filter_words,
        fingerprint_filter_lines,
        fingerprint_filter_regex,
        payloads_path,
        raw_request_path,
        wordlist_path,
        extensions,
        dirsearch_compat,
        path,
        wordlist_dir,
        wordlist_manipulation,
        tech_override,
        no_color,
        disable_show_all,
        ignore_trailing_slash,
        skip_validation,
        skip_brute,
        auto_collab,
        wordlist_status,
        brute_queue_concurrency,
        enable_fingerprinting,
        waf_test,
        disable_waf_bypass,
        bypass_level,
        bypass_transforms,
        start_depth,
        max_depth,
        traversal_strategy,
        follow_redirects,
        sift3_threshold,
    })
}

async fn run_async(run: RunConfig) -> Result<(), String> {
    if run.no_color {
        colored::control::set_override(false);
    }
    print_banner(run.no_color);

    let payloads_handle = File::open(&run.payloads_path)
        .await
        .map_err(|e| format!("failed to open payloads file: {e}"))?;

    let mut payloads = vec![];
    let payload_buf = BufReader::new(payloads_handle);
    let mut payload_lines = payload_buf.lines();
    while let Ok(Some(payload)) = payload_lines.next_line().await {
        payloads.push(payload);
    }

    let mut urls: Vec<TargetUrl> = run.urls.clone();
    if let Some(input_file_path) = run.input_file_path.as_ref() {
        let urls_handle = File::open(input_file_path)
            .await
            .map_err(|e| format!("failed to open input file: {e}"))?;
        let urls_buf = BufReader::new(urls_handle);
        let mut urls_lines = urls_buf.lines();
        while let Ok(Some(url)) = urls_lines.next_line().await {
            let url = trim_url(&url);
            urls.push(TargetUrl {
                original: url.clone(),
                normalized: url,
            });
        }
    }

    let raw_request_template = if let Some(path) = run.raw_request_path.as_deref() {
        let raw = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("failed to read raw request file {path}: {e}"))?;
        if urls.is_empty() {
            let inferred = detector::infer_target_url_from_raw_request(&raw)
                .map_err(|e| format!("failed to infer target URL from raw request: {e}"))?;
            urls.push(TargetUrl {
                original: inferred.clone(),
                normalized: inferred,
            });
        }
        let template = detector::parse_raw_request_template(&raw)
            .map_err(|e| format!("invalid raw request template: {e}"))?;
        Some(Arc::new(template))
    } else {
        None
    };

    if urls.is_empty() {
        return Err(
            "at least one input mode must be specified (--url, --input-file, or --raw-request)"
                .to_string(),
        );
    }
    for url in urls.iter() {
        if reqwest::Url::parse(&url.original).is_err() {
            return Err(format!("invalid URL: {}", url.original));
        }
    }

    if run.ignore_trailing_slash {
        for url in urls.iter_mut() {
            let (original, normalized) = normalize_trailing_slash(&url.original);
            url.original = original;
            url.normalized = normalized;
        }
    }

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );
    let fingerprint_client = if run.http_proxy.is_empty() {
        reqwest::Client::builder()
            .default_headers(headers)
            .redirect(if run.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .timeout(Duration::from_secs(run.timeout.try_into().unwrap_or(10)))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?
    } else {
        let proxy = reqwest::Proxy::all(run.http_proxy.clone())
            .map_err(|e| format!("Could not setup proxy, err: {e}"))?;
        reqwest::Client::builder()
            .default_headers(headers)
            .redirect(if run.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .timeout(Duration::from_secs(run.timeout.try_into().unwrap_or(10)))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .proxy(proxy)
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?
    };

    let fingerprint_options = crate::fingerprint::FingerprintOptions {
        enable_fingerprinting: run.enable_fingerprinting,
        waf_test: run.waf_test.clone(),
    };
    let mut fingerprints: HashMap<String, crate::fingerprint::TargetFingerprint> = HashMap::new();
    for url in urls.iter() {
        let fp = crate::fingerprint::fingerprint_target(
            &fingerprint_client,
            &url.normalized,
            &fingerprint_options,
        )
        .await;
        fingerprints.insert(url.normalized.clone(), fp);
    }

    if let Some(url) = urls.first() {
        let fp = fingerprints
            .get(&url.normalized)
            .cloned()
            .unwrap_or_default();
        let display_url = if url.original != url.normalized {
            format!("{} -> {}", url.original, url.normalized)
        } else {
            url.normalized.clone()
        };
        let tech = if fp.tech.products.is_empty() {
            None
        } else {
            Some(fp.tech.products.join(","))
        };
        let waf = if fp.wafs.is_empty() {
            None
        } else {
            Some(
                fp.wafs
                    .iter()
                    .map(|w| format!("{}({:.0}%)", w.name, w.confidence * 100.0))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        };
        let mut parts: Vec<String> = vec![display_url];
        if let Some(tech) = tech {
            parts.push(format!("tech={}", tech));
        }
        if let Some(waf) = waf {
            parts.push(format!("waf={}", waf));
        }
        format_kv_line("Target", &parts.join(" "));
    }

    let mut wordlist: Vec<String> = vec![];
    let mut targeted_wordlists_loaded: Vec<String> = vec![];
    if !run.skip_brute || run.path.is_some() || run.wordlist_path.is_some() {
        if let Some(path) = run.path.as_ref() {
            wordlist.push(path.clone());
        } else {
            if let Some(wordlist_path) = run.wordlist_path.as_ref() {
                let wordlist_handle = File::open(wordlist_path)
                    .await
                    .map_err(|e| format!("failed to open wordlist: {e}"))?;
                let wordlist_buf = BufReader::new(wordlist_handle);
                let mut wordlist_lines = wordlist_buf.lines();
                while let Ok(Some(word)) = wordlist_lines.next_line().await {
                    wordlist.push(word);
                }
            }

            if run.skip_brute {
                targeted_wordlists_loaded.sort();
                targeted_wordlists_loaded.dedup();
            } else {
                let mut tech_keys: Vec<String> = vec![];
                if let Some(tech_override) = run.tech_override.as_ref() {
                    tech_keys.push(tech_override.to_lowercase());
                } else {
                    for fp in fingerprints.values() {
                        for product in fp.tech.products.iter() {
                            let p = product.to_lowercase();
                            if p.contains("tomcat") {
                                tech_keys.push("tomcat".to_string());
                            } else if p.contains("spring boot") || p.contains("spring") {
                                tech_keys.push("spring".to_string());
                            } else if p == "iis" || p.contains("microsoft-iis") {
                                tech_keys.push("iis".to_string());
                            } else if p.contains("nginx") {
                                tech_keys.push("nginx".to_string());
                            } else if p.contains("apache") {
                                tech_keys.push("apache".to_string());
                            } else if p.contains("php") {
                                tech_keys.push("php".to_string());
                            } else if p.contains("express") || p.contains("node") {
                                tech_keys.push("node".to_string());
                            } else if p.contains("cloudflare") {
                                tech_keys.push("cloudflare".to_string());
                            }
                        }
                    }
                }
                tech_keys.sort();
                tech_keys.dedup();

                for key in tech_keys.iter() {
                    let flat_path = format!("{}/{}.txt", run.wordlist_dir, key);
                    if let Ok(handle) = File::open(flat_path.clone()).await {
                        targeted_wordlists_loaded.push(flat_path);
                        let buf = BufReader::new(handle);
                        let mut lines = buf.lines();
                        while let Ok(Some(word)) = lines.next_line().await {
                            if !word.trim().is_empty() {
                                wordlist.push(word);
                            }
                        }
                    }

                    let dir_path = format!("{}/{}", run.wordlist_dir, key);
                    if let Ok(mut rd) = tokio::fs::read_dir(&dir_path).await {
                        while let Ok(Some(entry)) = rd.next_entry().await {
                            let path = entry.path();
                            if path.extension().and_then(|e| e.to_str()) != Some("txt") {
                                continue;
                            }
                            let path_str = path.to_string_lossy().to_string();
                            let handle = match File::open(path_str.clone()).await {
                                Ok(handle) => handle,
                                Err(_) => continue,
                            };
                            targeted_wordlists_loaded.push(path_str);
                            let buf = BufReader::new(handle);
                            let mut lines = buf.lines();
                            while let Ok(Some(word)) = lines.next_line().await {
                                if !word.trim().is_empty() {
                                    wordlist.push(word);
                                }
                            }
                        }
                    }
                }
                targeted_wordlists_loaded.sort();
                targeted_wordlists_loaded.dedup();
            }
        }
    }

    wordlist = crate::utils::apply_wordlist_extensions(
        wordlist,
        &run.extensions,
        run.dirsearch_compat,
    );
    wordlist = crate::utils::apply_wordlist_manipulations(wordlist, &run.wordlist_manipulation);

    let wordlist_summary = if run.skip_brute {
        "disabled (--skip-brute)".to_string()
    } else if let Some(path) = run.path.as_ref() {
        format!("1 single={}", path)
    } else if run.wordlist_path.is_none() && targeted_wordlists_loaded.is_empty() {
        "0 (no --wordlist/--path and no targeted wordlists found)".to_string()
    } else {
        let mut parts = vec![format!("{}", wordlist.len())];
        if let Some(wordlist_path) = run.wordlist_path.as_ref() {
            parts.push(format!("primary={}", wordlist_path));
        }
        if !targeted_wordlists_loaded.is_empty() {
            parts.push(format!(
                "targeted_files={}",
                targeted_wordlists_loaded.len()
            ));
        }
        parts.join(" ")
    };

    format_kv_line(
        "Scan",
        &format!(
            "urls={} payloads={} wordlist={} strategy={} depth={}-{} validate={} brute={}",
            urls.len(),
            payloads.len(),
            wordlist_summary,
            traversal_strategy_label(run.traversal_strategy),
            run.start_depth,
            run.max_depth,
            format_bool(!run.skip_validation),
            format_bool(!run.skip_brute),
        ),
    );
    format_kv_line(
        "HTTP",
        &format!(
            "rate={} conc={} workers={} timeout={}s redirects={} proxy={} methods={}",
            run.rate,
            run.concurrency,
            run.workers,
            run.timeout,
            format_bool(run.follow_redirects),
            if run.http_proxy.is_empty() {
                "off"
            } else {
                "on"
            },
            run.methods
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    );
    format_kv_line(
        "Match",
        &format!(
            "V={} F={} drop={} diff={}-{}",
            format_opt_value(&run.validate_status, "none"),
            format_opt_value(&run.fingerprint_status, "none"),
            format_opt_value(&run.drop_after_fail, "none"),
            run.sift3_threshold.start,
            run.sift3_threshold.end
        ),
    );
    let v_filters = summarize_filters(
        &run.validate_filter_status,
        &run.validate_filter_size,
        &run.validate_filter_words,
        &run.validate_filter_lines,
        &run.validate_filter_regex,
    );
    let f_filters = summarize_filters(
        &run.fingerprint_filter_status,
        &run.fingerprint_filter_size,
        &run.fingerprint_filter_words,
        &run.fingerprint_filter_lines,
        &run.fingerprint_filter_regex,
    );
    let filters_line = match (v_filters, f_filters) {
        (None, None) => "none".to_string(),
        (Some(v), None) => format!("V:{}", v),
        (None, Some(f)) => format!("F:{}", f),
        (Some(v), Some(f)) => format!("V:{} F:{}", v, f),
    };
    format_kv_line(
        "Fingerprint",
        &format!(
            "enabled={} waf-test={} bypass={} transforms={} filters={}",
            format_bool(run.enable_fingerprinting),
            run.waf_test.clone().unwrap_or_else(|| "none".to_string()),
            run.bypass_level,
            if run.bypass_transforms.is_empty() {
                "auto".to_string()
            } else {
                run.bypass_transforms.join(",")
            },
            filters_line
        ),
    );
    println!();

    let mut bar_length: u64 = 0;
    if run.skip_validation {
        for url in urls.iter() {
            let waf_names = fingerprints
                .get(&url.normalized)
                .map(|fp| fp.wafs.iter().map(|w| w.name.clone()).collect::<Vec<_>>())
                .unwrap_or_default();
            for payload in payloads.iter() {
                let tcount = crate::transform::generate_payloads(
                    payload,
                    &waf_names,
                    run.bypass_level,
                    &run.bypass_transforms,
                    run.disable_waf_bypass,
                )
                .len();
                bar_length += (tcount * wordlist.len()) as u64;
            }
        }
    } else {
        let word_factor = std::cmp::max(1, wordlist.len()) as u64;
        for url in urls.iter() {
            let waf_names = fingerprints
                .get(&url.normalized)
                .map(|fp| fp.wafs.iter().map(|w| w.name.clone()).collect::<Vec<_>>())
                .unwrap_or_default();
            for payload in payloads.iter() {
                let tcount = crate::transform::generate_payloads(
                    payload,
                    &waf_names,
                    run.bypass_level,
                    &run.bypass_transforms,
                    run.disable_waf_bypass,
                )
                .len();
                bar_length += (tcount as u64) * word_factor;
            }
        }
    }
    if bar_length == 0 {
        bar_length = 1;
    }

    let pb = ProgressBar::new(bar_length);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.enable_steady_tick(Duration::from_millis(200));
    pb.set_style(
        ProgressStyle::with_template(
            ":: Progress: [{pos}/{len}] :: {per_sec} :: Duration: [{elapsed_precise}] :: {msg}",
        )
        .map_err(|e| format!("failed to build progress bar style: {e}"))?
        .progress_chars(r#"#>-"#),
    );

    let now = Instant::now();
    let (job_tx, mut job_rx) = mpsc::channel::<Job>(1024);
    let (result_tx, mut result_rx) = mpsc::channel::<JobResultMeta>(1024);
    let (discovery_tx, discovery_rx) = mpsc::channel::<String>(1024);

    let waf_names_by_url: HashMap<String, Vec<String>> = fingerprints
        .iter()
        .map(|(k, v)| (k.clone(), v.wafs.iter().map(|w| w.name.clone()).collect()))
        .collect();

    let mut worker_job_rxs = Vec::new();
    let worker_count = run.concurrency.max(1) as usize;
    let mut worker_job_txs = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let (tx, rx) = mpsc::channel::<Job>(1024);
        worker_job_txs.push(tx);
        worker_job_rxs.push(rx);
    }
    let dispatch_jobs_handle = tokio::spawn(async move {
        let mut idx = 0usize;
        while let Some(job) = job_rx.recv().await {
            if worker_job_txs.is_empty() {
                break;
            }
            let tx = worker_job_txs[idx % worker_job_txs.len()].clone();
            let _ = tx.send(job).await;
            idx = idx.wrapping_add(1);
        }
    });

    let send_urls_handle = tokio::spawn({
        let discovery_tx_for_detector = discovery_tx.clone();
        let urls_for_detector = urls.clone();
        let payloads_for_detector = payloads.clone();
        let wordlists_for_detector = if run.skip_validation {
            wordlist.clone()
        } else {
            Vec::new()
        };
        let bypass_transforms = run.bypass_transforms.clone();
        let raw_request_template = raw_request_template.clone();
        let methods = run.methods.clone();
        let rate = run.rate;
        let int_status = run.validate_status.clone();
        let pub_status = run.fingerprint_status.clone();
        let drop_after_fail = run.drop_after_fail.clone();
        let skip_validation = run.skip_validation;
        let disable_show_all = run.disable_show_all;
        let header = run.header.clone();
        let ignore_trailing_slash = run.ignore_trailing_slash;
        let start_depth = run.start_depth;
        let max_depth = run.max_depth;
        let traversal_strategy = run.traversal_strategy;
        let sift3_threshold = run.sift3_threshold;
        let validate_filters = detector::ResponseFilterConfig {
            status: run.validate_filter_status.clone(),
            size: run.validate_filter_size.clone(),
            words: run.validate_filter_words.clone(),
            lines: run.validate_filter_lines.clone(),
            regex: run.validate_filter_regex.clone(),
        };
        let fingerprint_filters = detector::ResponseFilterConfig {
            status: run.fingerprint_filter_status.clone(),
            size: run.fingerprint_filter_size.clone(),
            words: run.fingerprint_filter_words.clone(),
            lines: run.fingerprint_filter_lines.clone(),
            regex: run.fingerprint_filter_regex.clone(),
        };
        let wordlist_status = run.wordlist_status.clone();
        let bypass_level = run.bypass_level;
        let disable_waf_bypass = run.disable_waf_bypass;
        async move {
            let _ = detector::send_url(
                job_tx,
                detector::SendUrlConfig {
                    urls: urls_for_detector,
                    payloads: payloads_for_detector,
                    wordlists: wordlists_for_detector,
                    rate,
                    methods,
                    int_status,
                    pub_status,
                    drop_after_fail,
                    skip_validation,
                    disable_show_all,
                    header,
                    ignore_trailing_slash,
                    start_depth,
                    max_depth,
                    traversal_strategy,
                    sift3_threshold,
                    validate_filters,
                    fingerprint_filters,
                    discovery_tx: discovery_tx_for_detector,
                    wordlist_status,
                    waf_names_by_url,
                    bypass_level,
                    bypass_transforms,
                    disable_waf_bypass,
                    raw_request: raw_request_template,
                },
            )
            .await;
        }
    });
    drop(discovery_tx);

    let discovery_collect_handle = task::spawn(async move {
        let mut out: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut rx = discovery_rx;
        while let Some(url) = rx.recv().await {
            if seen.insert(url.clone()) {
                out.push(url);
            }
        }
        out
    });

    let job_pb = pb.clone();
    let workers = FuturesUnordered::new();
    for jrx in worker_job_rxs {
        let http_proxy = run.http_proxy.clone();
        let jtx: mpsc::Sender<JobResultMeta> = result_tx.clone();
        let jpb = job_pb.clone();
        let timeout = run.timeout;
        let follow_redirects = run.follow_redirects;
        workers.push(task::spawn(async move {
            detector::run_tester(jpb, jrx, jtx, timeout, http_proxy, follow_redirects).await
        }));
    }

    let collect_handle = task::spawn(async move {
        let mut out: Vec<JobResultMeta> = vec![];
        while let Some(result) = result_rx.recv().await {
            if result.result_url.is_empty() {
                continue;
            }
            out.push(result);
        }
        out
    });
    drop(result_tx);

    let _ = send_urls_handle.await;
    let _ = dispatch_jobs_handle.await;
    let _worker_results: Vec<_> = workers.collect().await;
    let mut validate_results: Vec<JobResultMeta> = collect_handle.await.unwrap_or_default();
    validate_results.sort_by(|a, b| {
        a.base_url
            .cmp(&b.base_url)
            .then(a.result_url.cmp(&b.result_url))
            .then(a.payload_mutated.cmp(&b.payload_mutated))
            .then(a.depth.cmp(&b.depth))
    });
    validate_results.dedup_by(|a, b| {
        a.base_url == b.base_url
            && a.result_url == b.result_url
            && a.payload_mutated == b.payload_mutated
            && a.depth == b.depth
    });

    let mut discovered_for_brute: Vec<String> = discovery_collect_handle.await.unwrap_or_default();
    discovered_for_brute.retain(|u| !u.trim().is_empty());
    discovered_for_brute.sort();
    discovered_for_brute.dedup();

    if !run.skip_brute {
        let outfile_path_brute = "discovered-routes.txt".to_string();
        let batch_size = if run.brute_queue_concurrency == 0 {
            discovered_for_brute.len().max(1)
        } else {
            run.brute_queue_concurrency as usize
        };

        for discovered_batch in discovered_for_brute.chunks(batch_size) {
            let brute_results: Arc<Mutex<HashMap<String, String>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let brute_workers = FuturesUnordered::new();

            let outfile_handle_brute = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&outfile_path_brute)
                .await
                .map_err(|e| format!("failed to open brute output file: {e}"))?;

            let (brute_job_tx, mut brute_job_rx) = mpsc::channel::<BruteJob>(1024);
            let (brute_result_tx, mut brute_result_rx) = mpsc::channel::<BruteResult>(run.workers);

            let brute_collect_handle = task::spawn({
                let brute_results_for_task = brute_results.clone();
                async move {
                    let mut outfile = outfile_handle_brute;
                    while let Some(result) = brute_result_rx.recv().await {
                        if result.data.is_empty() {
                            continue;
                        }
                        brute_results_for_task
                            .lock()
                            .await
                            .insert(result.data.clone(), result.rs.clone());
                        let mut outbuf = result.data.as_bytes().to_owned();
                        outbuf.extend_from_slice(b"\n");
                        let _ = outfile.write(&outbuf).await;
                    }
                }
            });

            let (brute_discovery_tx, brute_discovery_rx) = mpsc::channel::<String>(1024);
            let discovered_urls_to_send: Vec<String> = discovered_batch.to_vec();
            let discovery_send_handle = task::spawn(async move {
                for url in discovered_urls_to_send {
                    if brute_discovery_tx.send(url).await.is_err() {
                        break;
                    }
                }
            });

            let brute_wordlist = wordlist.clone();
            let brute_enqueue_handle = task::spawn(async move {
                let _ = crate::bruteforcer::send_word_to_url_queue(
                    brute_job_tx,
                    brute_discovery_rx,
                    brute_wordlist,
                    run.rate,
                )
                .await;
            });

            let mut brute_worker_rxs = Vec::new();
            let brute_worker_count = run.concurrency.max(1) as usize;
            let mut brute_worker_txs = Vec::with_capacity(brute_worker_count);
            for _ in 0..brute_worker_count {
                let (tx, rx) = mpsc::channel::<BruteJob>(1024);
                brute_worker_txs.push(tx);
                brute_worker_rxs.push(rx);
            }

            let brute_dispatch_handle = tokio::spawn(async move {
                let mut idx = 0usize;
                while let Some(job) = brute_job_rx.recv().await {
                    if brute_worker_txs.is_empty() {
                        break;
                    }
                    let tx = brute_worker_txs[idx % brute_worker_txs.len()].clone();
                    let _ = tx.send(job).await;
                    idx = idx.wrapping_add(1);
                }
            });

            let methods = run.methods.clone();
            let auto_collab = run.auto_collab;
            let validate_status_set = run.validate_status_set.clone();
            let wordlist_status = run.wordlist_status.clone();
            for brx in brute_worker_rxs {
                let http_proxy = run.http_proxy.clone();
                let btx: mpsc::Sender<BruteResult> = brute_result_tx.clone();
                let bpb = pb.clone();
                let timeout = run.timeout;
                let sift3_threshold = run.sift3_threshold;
                let follow_redirects = run.follow_redirects;
                let methods = methods.clone();
                let validate_status = validate_status_set.clone();
                let wordlist_status = wordlist_status.clone();
                brute_workers.push(task::spawn(async move {
                    let config = crate::bruteforcer::BruteforcerConfig {
                        timeout,
                        http_proxy,
                        sift3_threshold,
                        follow_redirects,
                        methods,
                        auto_collab,
                        validate_status,
                        wordlist_status,
                    };
                    crate::bruteforcer::run_bruteforcer(bpb, brx, btx, config).await
                }));
            }
            drop(brute_result_tx);

            let _ = discovery_send_handle.await;
            let _ = brute_enqueue_handle.await;
            let _ = brute_dispatch_handle.await;
            let _: Vec<_> = brute_workers.collect().await;
            let _ = brute_collect_handle.await;
        }
    }

    if let Some(outfile_path) = run.output.as_ref() {
        let output_format = run
            .output_format
            .as_deref()
            .and_then(crate::output::OutputFormat::parse)
            .or_else(|| crate::output::infer_format_from_path(outfile_path))
            .unwrap_or(crate::output::OutputFormat::Text);

        let records = crate::output::build_records(&validate_results, &fingerprints);
        let rendered = match output_format {
            crate::output::OutputFormat::Text => crate::output::render_text(&records),
            crate::output::OutputFormat::Json => crate::output::render_json(&records),
            crate::output::OutputFormat::Xml => crate::output::render_xml(&records),
            crate::output::OutputFormat::Html => crate::output::render_html(&records),
        };

        let mut outfile = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(outfile_path)
            .await
            .map_err(|e| format!("failed to open output file: {e}"))?;
        outfile
            .write_all(&rendered)
            .await
            .map_err(|_| "failed to write output file".to_string())?;
    }

    let elapsed_time = now.elapsed();

    println!();
    println!(":: Completed :: scan took {}s ::", elapsed_time.as_secs());

    Ok(())
}

pub fn run_cli() -> Result<(), String> {
    let args = match CliArgs::try_parse() {
        Ok(args) => args,
        Err(e) => match e.kind() {
            ErrorKind::DisplayHelp => {
                print!("{}", render_custom_help());
                return Ok(());
            }
            ErrorKind::DisplayVersion => {
                let cmd = CliArgs::command();
                print!("{}", cmd.render_version());
                return Ok(());
            }
            _ => return Err(e.to_string()),
        },
    };

    let user_config_path = args.config.clone().map(|p| config::expand_tilde(&p));
    let cfg = match user_config_path.as_ref() {
        Some(path) => config::load_config(path, false)?,
        None => ConfigFile::default(),
    };

    let run = build_run_config(args, cfg)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(run.workers)
        .build()
        .map_err(|e| format!("failed to build runtime: {e}"))?;

    rt.block_on(run_async(run))?;
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn disable_show_all_defaults_to_false() {
        let args = CliArgs::parse_from(["pathbuster", "-u", "http://example.com/", "--skip-brute"]);
        let cfg = ConfigFile::default();
        let run = build_run_config(args, cfg).unwrap();
        assert!(!run.disable_show_all);
    }

    #[test]
    fn disable_show_all_can_be_set_true() {
        let args = CliArgs::parse_from([
            "pathbuster",
            "-u",
            "http://example.com/",
            "--skip-brute",
            "--disable-show-all",
        ]);
        let cfg = ConfigFile::default();
        let run = build_run_config(args, cfg).unwrap();
        assert!(run.disable_show_all);
    }
}
