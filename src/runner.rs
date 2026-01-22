use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use indicatif::ProgressBar;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::Instant;

use crate::bruteforcer::{BruteJob, BruteResult};
use crate::detector::{self, Job, JobResultMeta, TargetUrl};
use crate::fingerprint::{FingerprintOptions, TargetFingerprint};
use crate::utils;

#[derive(Clone, Debug)]
pub enum PayloadSource {
    FilePath(String),
    Inline(Vec<String>),
}

#[derive(Clone, Debug)]
pub enum WordlistSource {
    FilePath(String),
    Inline(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct Options {
    pub urls: Vec<String>,
    pub input_file: Option<String>,
    pub payloads: PayloadSource,
    pub raw_request: Option<String>,
    pub wordlist: Option<WordlistSource>,
    pub path: Option<String>,
    pub wordlist_dir: Option<String>,
    pub wordlist_manipulation: utils::WordlistManipulation,
    pub extensions: Vec<String>,
    pub dirsearch_compat: bool,
    pub rate: u32,
    pub concurrency: u32,
    pub timeout_seconds: usize,
    pub proxy: Option<String>,
    pub follow_redirects: bool,
    pub header: Option<String>,
    pub methods: Vec<reqwest::Method>,
    pub drop_after_fail: String,
    pub validate_status: String,
    pub fingerprint_status: String,
    pub validate_filters: detector::ResponseFilterConfig,
    pub fingerprint_filters: detector::ResponseFilterConfig,
    pub disable_show_all: bool,
    pub ignore_trailing_slash: bool,
    pub skip_validation: bool,
    pub skip_brute: bool,
    pub auto_collab: bool,
    pub wordlist_status: HashSet<u16>,
    pub enable_fingerprinting: bool,
    pub waf_test: Option<String>,
    pub tech_override: Option<String>,
    pub disable_waf_bypass: bool,
    pub bypass_level: u8,
    pub bypass_transforms: Vec<String>,
    pub start_depth: usize,
    pub max_depth: usize,
    pub traversal_strategy: detector::TraversalStrategy,
    pub sift3_threshold: utils::ResponseChangeThreshold,
}

impl Default for Options {
    fn default() -> Self {
        let mut wordlist_status = HashSet::new();
        wordlist_status.insert(200);
        Self {
            urls: Vec::new(),
            input_file: None,
            payloads: PayloadSource::FilePath("./payloads/traversals.txt".to_string()),
            raw_request: None,
            wordlist: None,
            path: None,
            wordlist_dir: Some("./wordlists/targeted".to_string()),
            wordlist_manipulation: utils::WordlistManipulation::default(),
            extensions: Vec::new(),
            dirsearch_compat: false,
            rate: 1000,
            concurrency: 1000,
            timeout_seconds: 10,
            proxy: None,
            follow_redirects: false,
            header: None,
            methods: vec![reqwest::Method::GET],
            drop_after_fail: "302,301".to_string(),
            validate_status: "404".to_string(),
            fingerprint_status: "400,500".to_string(),
            validate_filters: detector::ResponseFilterConfig {
                status: String::new(),
                size: String::new(),
                words: String::new(),
                lines: String::new(),
                regex: String::new(),
            },
            fingerprint_filters: detector::ResponseFilterConfig {
                status: String::new(),
                size: String::new(),
                words: String::new(),
                lines: String::new(),
                regex: String::new(),
            },
            disable_show_all: true,
            ignore_trailing_slash: false,
            skip_validation: false,
            skip_brute: true,
            auto_collab: false,
            wordlist_status,
            enable_fingerprinting: true,
            waf_test: None,
            tech_override: None,
            disable_waf_bypass: false,
            bypass_level: 1,
            bypass_transforms: Vec::new(),
            start_depth: 0,
            max_depth: 5,
            traversal_strategy: detector::TraversalStrategy::Greedy,
            sift3_threshold: utils::DEFAULT_SIFT3_THRESHOLD,
        }
    }
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("no targets provided (urls and input_file are both empty)")]
    NoTargets,

    #[error("invalid URL: {url}")]
    InvalidUrl { url: String },

    #[error("payloads list is empty")]
    EmptyPayloads,

    #[error("wordlist (or path) is required unless skip_brute is set")]
    MissingWordlist,

    #[error("use either wordlist or path, not both")]
    ConflictingWordlistAndPath,

    #[error("invalid bypass_level {value}, expected 0, 1, or 2")]
    InvalidBypassLevel { value: u8 },

    #[error("invalid max_depth {value}, expected positive integer")]
    InvalidMaxDepth { value: usize },

    #[error("dirsearch compatibility mode requires extensions")]
    DirsearchRequiresExtensions,

    #[error("failed to open file for {kind}: {path}: {source}")]
    FileOpen {
        kind: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read lines for {kind}: {path}: {source}")]
    FileRead {
        kind: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read raw request file: {path}: {source}")]
    RawRequestRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid raw request template: {message}")]
    InvalidRawRequestTemplate { message: String },

    #[error("failed to build HTTP client: {source}")]
    HttpClientBuild {
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to setup proxy: {proxy}: {source}")]
    ProxySetup {
        proxy: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("detector send_url failed: {source}")]
    DetectorSendUrl {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("task join failed: {source}")]
    TaskJoin {
        #[source]
        source: tokio::task::JoinError,
    },
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub started_at: Instant,
    pub elapsed: Duration,
    pub fingerprints: HashMap<String, TargetFingerprint>,
    pub wordlists_loaded: Vec<String>,
    pub matches: Vec<JobResultMeta>,
    pub discovered_routes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Runner {
    options: Options,
}

impl Runner {
    pub fn new(mut options: Options) -> Result<Self, RunnerError> {
        if options.urls.is_empty() && options.input_file.is_none() && options.raw_request.is_none()
        {
            return Err(RunnerError::NoTargets);
        }
        if options.bypass_level > 3 {
            return Err(RunnerError::InvalidBypassLevel {
                value: options.bypass_level,
            });
        }
        if options.max_depth == 0 {
            return Err(RunnerError::InvalidMaxDepth {
                value: options.max_depth,
            });
        }
        if options.skip_validation {
            options.skip_brute = true;
        }
        if options.dirsearch_compat && options.extensions.is_empty() {
            return Err(RunnerError::DirsearchRequiresExtensions);
        }
        if options.wordlist.is_some() && options.path.as_deref().unwrap_or_default().trim() != "" {
            return Err(RunnerError::ConflictingWordlistAndPath);
        }
        let has_path = options.path.as_deref().unwrap_or_default().trim() != "";
        if (!options.skip_brute || options.skip_validation)
            && options.wordlist.is_none()
            && !has_path
        {
            return Err(RunnerError::MissingWordlist);
        }
        Ok(Self { options })
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub async fn run(&self) -> Result<ScanResult, RunnerError> {
        let started_at = Instant::now();

        let payloads = load_payloads(&self.options.payloads).await?;
        if payloads.is_empty() {
            return Err(RunnerError::EmptyPayloads);
        }

        let mut targets = if self.options.urls.is_empty()
            && self.options.input_file.is_none()
            && self.options.raw_request.is_some()
        {
            let path = self.options.raw_request.as_deref().unwrap_or_default();
            let raw =
                tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| RunnerError::RawRequestRead {
                        path: path.to_string(),
                        source: e,
                    })?;
            let inferred =
                detector::infer_target_url_from_raw_request(&raw).map_err(|message| {
                    RunnerError::InvalidRawRequestTemplate {
                        message: format!("failed to infer target URL: {message}"),
                    }
                })?;
            vec![TargetUrl {
                original: inferred.clone(),
                normalized: inferred,
            }]
        } else {
            load_targets(&self.options.urls, self.options.input_file.as_deref()).await?
        };

        for t in targets.iter() {
            if reqwest::Url::parse(&t.original).is_err() {
                return Err(RunnerError::InvalidUrl {
                    url: t.original.clone(),
                });
            }
        }

        if self.options.ignore_trailing_slash {
            for t in targets.iter_mut() {
                let (original, normalized) = normalize_trailing_slash(&t.original);
                t.original = original;
                t.normalized = normalized;
            }
        }

        let fingerprint_client = build_fingerprint_client(
            self.options.proxy.as_deref(),
            self.options.timeout_seconds,
            self.options.follow_redirects,
        )?;

        let fp_options = FingerprintOptions {
            enable_fingerprinting: self.options.enable_fingerprinting,
            waf_test: self.options.waf_test.clone(),
        };

        let mut fingerprints: HashMap<String, TargetFingerprint> = HashMap::new();
        for t in targets.iter() {
            let fp = crate::fingerprint::fingerprint_target(
                &fingerprint_client,
                &t.normalized,
                &fp_options,
            )
            .await;
            fingerprints.insert(t.normalized.clone(), fp);
        }

        let wordlist_config = WordlistLoadConfig {
            path: self.options.path.as_deref(),
            wordlist_dir: self.options.wordlist_dir.as_deref(),
            tech_override: self.options.tech_override.as_deref(),
            manipulation: &self.options.wordlist_manipulation,
            extensions: &self.options.extensions,
            dirsearch_compat: self.options.dirsearch_compat,
            skip_brute: self.options.skip_brute,
            skip_validation: self.options.skip_validation,
        };
        let (wordlist, wordlists_loaded) = load_wordlist(
            self.options.wordlist.as_ref(),
            &fingerprints,
            wordlist_config,
        )
        .await?;

        let (matches, discovered_routes) = run_detector_and_bruteforce(
            &self.options,
            &targets,
            &payloads,
            &wordlist,
            &fingerprints,
        )
        .await?;

        let elapsed = started_at.elapsed();
        Ok(ScanResult {
            started_at,
            elapsed,
            fingerprints,
            wordlists_loaded,
            matches,
            discovered_routes,
        })
    }
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

fn build_fingerprint_client(
    proxy: Option<&str>,
    timeout_seconds: usize,
    follow_redirects: bool,
) -> Result<reqwest::Client, RunnerError> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let timeout = Duration::from_secs(timeout_seconds.try_into().unwrap_or(10));
    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect_policy)
        .timeout(timeout)
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true);

    if let Some(proxy) = proxy.filter(|p| !p.trim().is_empty()) {
        let proxy = reqwest::Proxy::all(proxy).map_err(|e| RunnerError::ProxySetup {
            proxy: proxy.to_string(),
            source: e,
        })?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| RunnerError::HttpClientBuild { source: e })
}

async fn load_targets(
    urls: &[String],
    input_file: Option<&str>,
) -> Result<Vec<TargetUrl>, RunnerError> {
    let mut out: Vec<TargetUrl> = Vec::new();
    for u in urls.iter() {
        let u = u.trim();
        if u.is_empty() {
            continue;
        }
        out.push(TargetUrl {
            original: u.to_string(),
            normalized: u.to_string(),
        });
    }

    if let Some(path) = input_file.filter(|p| !p.trim().is_empty()) {
        let path = crate::config::expand_tilde_string(path);
        let handle = File::open(&path).await.map_err(|e| RunnerError::FileOpen {
            kind: "input_file",
            path: path.clone(),
            source: e,
        })?;
        let mut lines = BufReader::new(handle).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    out.push(TargetUrl {
                        original: line.to_string(),
                        normalized: line.to_string(),
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(RunnerError::FileRead {
                        kind: "input_file",
                        path,
                        source: e,
                    })
                }
            }
        }
    }

    if out.is_empty() {
        return Err(RunnerError::NoTargets);
    }

    Ok(out)
}

async fn load_payloads(source: &PayloadSource) -> Result<Vec<String>, RunnerError> {
    match source {
        PayloadSource::Inline(values) => Ok(values
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()),
        PayloadSource::FilePath(path) => {
            let path = crate::config::expand_tilde_string(path.as_str());
            let handle = File::open(&path).await.map_err(|e| RunnerError::FileOpen {
                kind: "payloads",
                path: path.clone(),
                source: e,
            })?;
            let mut out = Vec::new();
            let mut lines = BufReader::new(handle).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        out.push(line.to_string());
                    }
                    Ok(None) => break,
                    Err(e) => {
                        return Err(RunnerError::FileRead {
                            kind: "payloads",
                            path,
                            source: e,
                        })
                    }
                }
            }
            Ok(out)
        }
    }
}

pub(crate) struct WordlistLoadConfig<'a> {
    pub(crate) path: Option<&'a str>,
    pub(crate) wordlist_dir: Option<&'a str>,
    pub(crate) tech_override: Option<&'a str>,
    pub(crate) manipulation: &'a utils::WordlistManipulation,
    pub(crate) extensions: &'a [String],
    pub(crate) dirsearch_compat: bool,
    pub(crate) skip_brute: bool,
    pub(crate) skip_validation: bool,
}

pub(crate) async fn load_wordlist(
    wordlist: Option<&WordlistSource>,
    fingerprints: &HashMap<String, TargetFingerprint>,
    config: WordlistLoadConfig<'_>,
) -> Result<(Vec<String>, Vec<String>), RunnerError> {
    let WordlistLoadConfig {
        path,
        wordlist_dir,
        tech_override,
        manipulation,
        extensions,
        dirsearch_compat,
        skip_brute,
        skip_validation,
    } = config;
    if skip_brute && !skip_validation {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut out: Vec<String> = Vec::new();
    let mut loaded: Vec<String> = Vec::new();

    if let Some(path) = path {
        let path = path.trim();
        if !path.is_empty() {
            out.push(path.to_string());
        }
    }

    if let Some(wordlist) = wordlist {
        match wordlist {
            WordlistSource::Inline(values) => {
                out.extend(
                    values
                        .iter()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                );
            }
            WordlistSource::FilePath(path) => {
                let path = crate::config::expand_tilde_string(path.as_str());
                let handle = File::open(&path).await.map_err(|e| RunnerError::FileOpen {
                    kind: "wordlist",
                    path: path.clone(),
                    source: e,
                })?;
                loaded.push(path.clone());
                let mut lines = BufReader::new(handle).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            out.push(line.to_string());
                        }
                        Ok(None) => break,
                        Err(e) => {
                            return Err(RunnerError::FileRead {
                                kind: "wordlist",
                                path,
                                source: e,
                            })
                        }
                    }
                }
            }
        }
    }

    let wordlist_dir = wordlist_dir
        .filter(|p| !p.trim().is_empty())
        .map(crate::config::expand_tilde_string);

    let mut tech_keys: Vec<String> = Vec::new();
    if let Some(key) = tech_override.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        tech_keys.push(key.to_lowercase());
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

    if let Some(wordlist_dir) = wordlist_dir.as_deref() {
        for key in tech_keys.iter() {
            let flat_path = format!("{}/{}.txt", wordlist_dir, key);
            if let Ok(handle) = File::open(flat_path.clone()).await {
                loaded.push(flat_path.clone());
                let mut lines = BufReader::new(handle).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            out.push(line.to_string());
                        }
                        Ok(None) => break,
                        Err(e) => {
                            return Err(RunnerError::FileRead {
                                kind: "wordlist_dir",
                                path: flat_path,
                                source: e,
                            })
                        }
                    }
                }
            }

            let dir_path = format!("{}/{}", wordlist_dir, key);
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
                    loaded.push(path_str.clone());
                    let mut lines = BufReader::new(handle).lines();
                    loop {
                        match lines.next_line().await {
                            Ok(Some(line)) => {
                                let line = line.trim();
                                if line.is_empty() {
                                    continue;
                                }
                                out.push(line.to_string());
                            }
                            Ok(None) => break,
                            Err(e) => {
                                return Err(RunnerError::FileRead {
                                    kind: "wordlist_dir",
                                    path: path_str,
                                    source: e,
                                })
                            }
                        }
                    }
                }
            }
        }
    }

    loaded.sort();
    loaded.dedup();

    if !skip_brute || skip_validation {
        out = utils::apply_wordlist_extensions(out, extensions, dirsearch_compat);
        out = utils::apply_wordlist_manipulations(out, manipulation);
    }

    Ok((out, loaded))
}

async fn run_detector_and_bruteforce(
    options: &Options,
    targets: &[TargetUrl],
    payloads: &[String],
    brute_wordlist: &[String],
    fingerprints: &HashMap<String, TargetFingerprint>,
) -> Result<(Vec<JobResultMeta>, Vec<String>), RunnerError> {
    let pb = ProgressBar::hidden();

    let raw_request_template = if let Some(path) = options.raw_request.as_deref() {
        let raw =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|e| RunnerError::RawRequestRead {
                    path: path.to_string(),
                    source: e,
                })?;
        let template = detector::parse_raw_request_template(&raw)
            .map_err(|message| RunnerError::InvalidRawRequestTemplate { message })?;
        Some(Arc::new(template))
    } else {
        None
    };

    let (job_tx, mut job_rx) = mpsc::channel::<Job>(1024);
    let (result_tx, mut result_rx) = mpsc::channel::<JobResultMeta>(1024);
    let (discovery_tx, discovery_rx) = mpsc::channel::<String>(1024);

    let waf_names_by_url: HashMap<String, Vec<String>> = fingerprints
        .iter()
        .map(|(k, v)| (k.clone(), v.wafs.iter().map(|w| w.name.clone()).collect()))
        .collect();

    let mut worker_job_rxs = Vec::new();
    let worker_count = options.concurrency.max(1) as usize;
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
        let urls_for_detector = targets.to_vec();
        let payloads_for_detector = payloads.to_vec();
        let wordlists_for_detector = if options.skip_validation {
            brute_wordlist.to_vec()
        } else {
            Vec::new()
        };
        let bypass_transforms = options.bypass_transforms.clone();
        let header = options.header.clone().unwrap_or_default();
        let raw_request_template = raw_request_template.clone();
        let methods = options.methods.clone();
        let cfg = detector::SendUrlConfig {
            urls: urls_for_detector,
            payloads: payloads_for_detector,
            wordlists: wordlists_for_detector,
            rate: options.rate,
            methods,
            int_status: options.validate_status.clone(),
            pub_status: options.fingerprint_status.clone(),
            drop_after_fail: options.drop_after_fail.clone(),
            skip_validation: options.skip_validation,
            disable_show_all: options.disable_show_all,
            header,
            ignore_trailing_slash: options.ignore_trailing_slash,
            start_depth: options.start_depth,
            max_depth: options.max_depth,
            traversal_strategy: options.traversal_strategy,
            sift3_threshold: options.sift3_threshold,
            validate_filters: options.validate_filters.clone(),
            fingerprint_filters: options.fingerprint_filters.clone(),
            discovery_tx: discovery_tx_for_detector,
            wordlist_status: options.wordlist_status.clone(),
            waf_names_by_url,
            bypass_level: options.bypass_level,
            bypass_transforms,
            disable_waf_bypass: options.disable_waf_bypass,
            raw_request: raw_request_template,
        };
        async move {
            detector::send_url(job_tx, cfg)
                .await
                .map_err(|e| RunnerError::DetectorSendUrl { source: e })
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

    let mut workers = Vec::new();
    for jrx in worker_job_rxs {
        let http_proxy = options.proxy.clone().unwrap_or_default();
        let jtx: mpsc::Sender<JobResultMeta> = result_tx.clone();
        let timeout = options.timeout_seconds;
        let follow_redirects = options.follow_redirects;
        let jpb = pb.clone();
        workers.push(task::spawn(async move {
            detector::run_tester(jpb, jrx, jtx, timeout, http_proxy, follow_redirects).await
        }));
    }

    let collect_handle = task::spawn(async move {
        let mut out: Vec<JobResultMeta> = Vec::new();
        while let Some(result) = result_rx.recv().await {
            if result.result_url.is_empty() {
                continue;
            }
            out.push(result);
        }
        out
    });
    drop(result_tx);

    let mut discovered_routes: Vec<String> = Vec::new();

    match send_urls_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => {
            return Err(RunnerError::TaskJoin { source: e });
        }
    }

    let _ = dispatch_jobs_handle.await;
    for w in workers {
        let _ = w.await;
    }

    let mut matches = collect_handle.await.unwrap_or_default();
    matches.sort_by(|a, b| {
        a.base_url
            .cmp(&b.base_url)
            .then(a.result_url.cmp(&b.result_url))
            .then(a.payload_mutated.cmp(&b.payload_mutated))
            .then(a.depth.cmp(&b.depth))
    });
    matches.dedup_by(|a, b| {
        a.base_url == b.base_url
            && a.result_url == b.result_url
            && a.payload_mutated == b.payload_mutated
            && a.depth == b.depth
    });

    let discovered_for_brute: Vec<String> = discovery_collect_handle.await.unwrap_or_default();

    if !options.skip_brute {
        let validate_status =
            crate::utils::parse_u16_set_csv(&options.validate_status).unwrap_or_default();
        let (brute_discovery_tx, brute_discovery_rx) = mpsc::channel::<String>(1024);
        let discovery_send_handle = task::spawn(async move {
            for url in discovered_for_brute {
                if brute_discovery_tx.send(url).await.is_err() {
                    break;
                }
            }
        });

        discovered_routes = run_bruteforce(
            pb.clone(),
            BruteRunConfig {
                discovery_rx: brute_discovery_rx,
                wordlist: brute_wordlist.to_vec(),
                rate: options.rate,
                concurrency: options.concurrency,
                timeout: options.timeout_seconds,
                http_proxy: options.proxy.clone().unwrap_or_default(),
                sift3_threshold: options.sift3_threshold,
                follow_redirects: options.follow_redirects,
                methods: options.methods.clone(),
                auto_collab: options.auto_collab,
                validate_status,
                wordlist_status: options.wordlist_status.clone(),
            },
        )
        .await;
        let _ = discovery_send_handle.await;
    }

    Ok((matches, discovered_routes))
}

struct BruteRunConfig {
    discovery_rx: mpsc::Receiver<String>,
    wordlist: Vec<String>,
    rate: u32,
    concurrency: u32,
    timeout: usize,
    http_proxy: String,
    sift3_threshold: utils::ResponseChangeThreshold,
    follow_redirects: bool,
    methods: Vec<reqwest::Method>,
    auto_collab: bool,
    validate_status: HashSet<u16>,
    wordlist_status: HashSet<u16>,
}

async fn run_bruteforce(pb: ProgressBar, cfg: BruteRunConfig) -> Vec<String> {
    let BruteRunConfig {
        discovery_rx,
        wordlist,
        rate,
        concurrency,
        timeout,
        http_proxy,
        sift3_threshold,
        follow_redirects,
        methods,
        auto_collab,
        validate_status,
        wordlist_status,
    } = cfg;
    pb.println("starting directory bruteforce");
    let (brute_job_tx, mut brute_job_rx) = mpsc::channel::<BruteJob>(1024);
    let (brute_result_tx, mut brute_result_rx) =
        mpsc::channel::<BruteResult>(concurrency.max(1) as usize);

    let brute_enqueue_handle = tokio::spawn(async move {
        let _ =
            crate::bruteforcer::send_word_to_url_queue(brute_job_tx, discovery_rx, wordlist, rate)
                .await;
    });

    let mut brute_worker_rxs = Vec::new();
    let brute_worker_count = concurrency.max(1) as usize;
    let mut brute_worker_txs = Vec::with_capacity(brute_worker_count);
    for _ in 0..brute_worker_count {
        let (tx, rx) = mpsc::channel::<BruteJob>(1024);
        brute_worker_txs.push(tx);
        brute_worker_rxs.push(rx);
    }

    tokio::spawn(async move {
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

    let mut brute_workers = Vec::new();
    for brx in brute_worker_rxs {
        let http_proxy = http_proxy.clone();
        let btx = brute_result_tx.clone();
        let pb = pb.clone();
        let methods = methods.clone();
        let validate_status = validate_status.clone();
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
            let _ = crate::bruteforcer::run_bruteforcer(pb, brx, btx, config).await;
        }));
    }
    drop(brute_result_tx);

    let collect_handle = task::spawn(async move {
        let mut out: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(result) = brute_result_rx.recv().await {
            if result.data.is_empty() {
                continue;
            }
            if seen.insert(result.data.clone()) {
                out.push(result.data);
            }
        }
        out
    });

    let _ = brute_enqueue_handle.await;
    for w in brute_workers {
        let _ = w.await;
    }

    let results = collect_handle.await.unwrap_or_default();
    pb.println(format!(
        "directory bruteforce completed, {} routes discovered",
        results.len()
    ));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wordlist_manipulation_applies_to_single_path() {
        let fingerprints: HashMap<String, TargetFingerprint> = HashMap::new();
        let manipulation = utils::WordlistManipulation {
            case: Some(utils::WordCase::Lower),
            ..Default::default()
        };
        let cfg = WordlistLoadConfig {
            path: Some("/Admin/Panel"),
            wordlist_dir: None,
            tech_override: None,
            manipulation: &manipulation,
            extensions: &[],
            dirsearch_compat: false,
            skip_brute: false,
            skip_validation: false,
        };

        let (out, loaded) = load_wordlist(None, &fingerprints, cfg).await.unwrap();
        assert_eq!(loaded, Vec::<String>::new());
        assert_eq!(out, vec!["/admin/panel".to_string()]);
    }
}
