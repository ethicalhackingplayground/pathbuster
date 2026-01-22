use colored::Colorize;
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use itertools::iproduct;
use regex::Regex;
use reqwest::{redirect, Proxy};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use std::{error::Error, process::exit, str::FromStr, time::Duration};
use tokio::sync::mpsc;

use crate::transform;
use crate::utils;

mod filters;
mod response;

use filters::{parse_filter_set_u16, parse_filter_set_usize, status_in_list, ResponseFilters};
use response::{
    build_traversal_url, fetch_snapshot, snapshot_diff, snapshot_key, snapshot_summary,
    ResponseSnapshot, ResponseSummary, SnapshotRequest,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraversalStrategy {
    Greedy,
    Quick,
}

fn compute_quick_fingerprint_depth(
    path: &str,
    start_depth: usize,
    max_depth: usize,
) -> Option<usize> {
    let segment_count = path.split('/').filter(|s| !s.is_empty()).count();
    let target_depth = start_depth.saturating_add(segment_count);
    Some(std::cmp::min(max_depth, target_depth))
}

fn compute_quick_validation_depths(start_depth: usize, fingerprint_depth: usize) -> Vec<usize> {
    if fingerprint_depth > start_depth {
        vec![fingerprint_depth.saturating_sub(1)]
    } else {
        Vec::new()
    }
}

fn compute_greedy_validation_depths(start_depth: usize, fingerprint_depth: usize) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    let mut d = fingerprint_depth;
    while d > start_depth {
        d -= 1;
        out.push(d);
    }
    out
}

fn join_payload_and_word(payload: &str, word: &str) -> String {
    let payload = payload.trim();
    let word = word.trim();
    if word.is_empty() {
        return payload.to_string();
    }
    if payload.is_empty() {
        return word.to_string();
    }

    let payload_has_slash =
        payload.ends_with('/') || payload.ends_with("%2f") || payload.ends_with("%2F");
    if payload_has_slash {
        let word = word.trim_start_matches('/');
        format!("{}{}", payload, word)
    } else if word.starts_with('/') {
        format!("{}{}", payload, word)
    } else {
        let mut out = String::with_capacity(payload.len() + 1 + word.len());
        out.push_str(payload);
        out.push('/');
        out.push_str(word);
        out
    }
}

fn status_allowed_by_wordlist(status: u16, allowed: &HashSet<u16>) -> bool {
    allowed.is_empty() || allowed.contains(&status)
}

fn build_baseline_urls(schema: &str, host: &str, port: Option<u16>, path: &str) -> Vec<String> {
    let hostport = if let Some(port) = port {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };
    let base = format!("{schema}://{hostport}");

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let webroot = format!("{base}/");
    if seen.insert(webroot.clone()) {
        out.push(webroot);
    }

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();
    for seg in segments.iter() {
        current.push('/');
        current.push_str(seg);

        let no_slash = format!("{base}{current}");
        if seen.insert(no_slash.clone()) {
            out.push(no_slash);
        }
        let with_slash = format!("{base}{current}/");
        if seen.insert(with_slash.clone()) {
            out.push(with_slash);
        }
    }

    out
}

impl TraversalStrategy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "greedy" => Some(Self::Greedy),
            "quick" => Some(Self::Quick),
            _ => None,
        }
    }
}

// the Job struct which will be used to define our settings for the detection jobs
#[derive(Clone, Debug)]
pub struct JobSettings {
    int_status: String,
    pub_status: String,
    drop_after_fail: String,
    skip_validation: bool,
    disable_show_all: bool,
    ignore_trailing_slash: bool,
    start_depth: usize,
    max_depth: usize,
    traversal_strategy: TraversalStrategy,
    sift3_threshold: utils::ResponseChangeThreshold,
    validate_filters: ResponseFilters,
    fingerprint_filters: ResponseFilters,
    discovery_tx: mpsc::Sender<String>,
    wordlist_status: HashSet<u16>,
}

#[derive(Clone, Debug)]
pub struct TargetUrl {
    pub original: String,
    pub normalized: String,
}

// the Job struct will be used as jobs for the detection phase
#[derive(Clone, Debug)]
pub struct Job {
    settings: Option<JobSettings>,
    url: Option<String>,
    original_url: Option<String>,
    word: Option<String>,
    payload: Option<String>,
    payload_original: Option<String>,
    payload_family: Option<String>,
    header: Option<String>,
    method: Option<reqwest::Method>,
    raw_request: Option<Arc<RawRequestTemplate>>,
    raw_injection_point: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct JobResultMeta {
    pub base_url: String,
    pub result_url: String,
    pub payload_original: String,
    pub payload_mutated: String,
    pub payload_family: String,
    pub depth: usize,
    pub status: u16,
    pub title: String,
    pub size: usize,
    pub words: usize,
    pub lines: usize,
    #[allow(dead_code)]
    pub duration_ms: u128,
    pub server: String,
    pub content_type: String,
}

#[derive(Clone, Debug)]
pub struct ResponseFilterConfig {
    pub status: String,
    pub size: String,
    pub words: String,
    pub lines: String,
    pub regex: String,
}

#[derive(Clone, Debug)]
pub struct SendUrlConfig {
    pub urls: Vec<TargetUrl>,
    pub payloads: Vec<String>,
    pub wordlists: Vec<String>,
    pub rate: u32,
    pub methods: Vec<reqwest::Method>,
    pub int_status: String,
    pub pub_status: String,
    pub drop_after_fail: String,
    pub skip_validation: bool,
    pub disable_show_all: bool,
    pub header: String,
    pub ignore_trailing_slash: bool,
    pub start_depth: usize,
    pub max_depth: usize,
    pub traversal_strategy: TraversalStrategy,
    pub sift3_threshold: utils::ResponseChangeThreshold,
    pub validate_filters: ResponseFilterConfig,
    pub fingerprint_filters: ResponseFilterConfig,
    pub discovery_tx: mpsc::Sender<String>,
    pub wordlist_status: HashSet<u16>,
    pub waf_names_by_url: HashMap<String, Vec<String>>,
    pub bypass_level: u8,
    pub bypass_transforms: Vec<String>,
    pub disable_waf_bypass: bool,
    pub raw_request: Option<Arc<RawRequestTemplate>>,
}

#[derive(Clone, Debug)]
enum RawStarTarget {
    RequestTarget,
    HeaderValue { header_index: usize },
    Body,
}

#[derive(Clone, Debug)]
struct RawStarRef {
    target: RawStarTarget,
    star_index: usize,
}

#[derive(Clone, Debug)]
pub struct RawRequestTemplate {
    method: reqwest::Method,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
    star_refs: Vec<RawStarRef>,
    target_star_positions: Vec<usize>,
    header_value_star_positions: Vec<Vec<usize>>,
    body_star_positions: Vec<usize>,
}

#[derive(Clone, Debug)]
pub(in crate::detector) struct RenderedRawRequest {
    pub(in crate::detector) method: reqwest::Method,
    pub(in crate::detector) url: reqwest::Url,
    pub(in crate::detector) headers: Vec<(String, String)>,
    pub(in crate::detector) body: String,
}

fn star_positions(s: &str) -> Vec<usize> {
    s.as_bytes()
        .iter()
        .enumerate()
        .filter_map(|(idx, b)| if *b == b'*' { Some(idx) } else { None })
        .collect()
}

fn inject_nth_star(
    source: &str,
    positions: &[usize],
    active_star_index: Option<usize>,
    value: &str,
) -> String {
    if positions.is_empty() {
        return source.to_string();
    }
    let mut out = String::with_capacity(source.len().saturating_add(value.len()));
    let bytes = source.as_bytes();
    let mut last = 0usize;
    for (i, pos) in positions.iter().enumerate() {
        if *pos > last {
            out.push_str(std::str::from_utf8(&bytes[last..*pos]).unwrap_or_default());
        }
        if Some(i) == active_star_index {
            out.push_str(value);
        }
        last = pos.saturating_add(1);
    }
    if last < bytes.len() {
        out.push_str(std::str::from_utf8(&bytes[last..]).unwrap_or_default());
    }
    out
}

impl RawRequestTemplate {
    pub fn injection_points_len(&self) -> usize {
        self.star_refs.len()
    }

    pub(in crate::detector) fn render(
        &self,
        base_url: &str,
        injection_point: usize,
        injection: &str,
    ) -> Result<RenderedRawRequest, String> {
        let star_ref = self
            .star_refs
            .get(injection_point)
            .ok_or_else(|| "invalid injection point".to_string())?
            .clone();

        let active_target = match star_ref.target {
            RawStarTarget::RequestTarget => Some(star_ref.star_index),
            _ => None,
        };
        let target = inject_nth_star(
            &self.target,
            &self.target_star_positions,
            active_target,
            injection,
        );

        let mut headers = Vec::with_capacity(self.headers.len());
        for (idx, (k, v)) in self.headers.iter().enumerate() {
            let active = match star_ref.target {
                RawStarTarget::HeaderValue { header_index } if header_index == idx => {
                    Some(star_ref.star_index)
                }
                _ => None,
            };
            let positions = self
                .header_value_star_positions
                .get(idx)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let v = inject_nth_star(v, positions, active, injection);
            headers.push((k.clone(), v));
        }

        let active_body = match star_ref.target {
            RawStarTarget::Body => Some(star_ref.star_index),
            _ => None,
        };
        let body = inject_nth_star(
            &self.body,
            &self.body_star_positions,
            active_body,
            injection,
        );

        let url = if target.starts_with("http://") || target.starts_with("https://") {
            reqwest::Url::parse(&target).map_err(|_| "invalid request target url".to_string())?
        } else {
            let base = reqwest::Url::parse(base_url).map_err(|_| "invalid base url".to_string())?;
            let host = base
                .host_str()
                .ok_or_else(|| "invalid base url".to_string())?;
            let mut origin = format!("{}://{}", base.scheme(), host);
            if let Some(port) = base.port() {
                origin.push_str(&format!(":{port}"));
            }
            origin.push('/');
            let origin =
                reqwest::Url::parse(&origin).map_err(|_| "invalid base url".to_string())?;
            let path = if target.starts_with('/') {
                target
            } else {
                format!("/{}", target)
            };
            origin
                .join(&path)
                .map_err(|_| "invalid request target path".to_string())?
        };

        Ok(RenderedRawRequest {
            method: self.method.clone(),
            url,
            headers,
            body,
        })
    }
}

pub fn parse_raw_request_template(raw: &str) -> Result<RawRequestTemplate, String> {
    let raw = raw.replace("\r\n", "\n");
    let raw = raw.trim_matches('\u{feff}');
    let (head, body) = raw.split_once("\n\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "raw request is empty".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing method in request line".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "missing target in request line".to_string())?;

    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| "invalid method in request line".to_string())?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| "invalid header line in raw request".to_string())?;
        headers.push((k.trim().to_string(), v.trim_start().to_string()));
    }

    let target = target.to_string();
    let target_star_positions = star_positions(&target);
    let header_value_star_positions: Vec<Vec<usize>> =
        headers.iter().map(|(_, v)| star_positions(v)).collect();
    let body = body.to_string();
    let body_star_positions = star_positions(&body);

    let mut star_refs: Vec<RawStarRef> = Vec::new();
    for idx in 0..target_star_positions.len() {
        star_refs.push(RawStarRef {
            target: RawStarTarget::RequestTarget,
            star_index: idx,
        });
    }
    for (header_index, positions) in header_value_star_positions.iter().enumerate() {
        for idx in 0..positions.len() {
            star_refs.push(RawStarRef {
                target: RawStarTarget::HeaderValue { header_index },
                star_index: idx,
            });
        }
    }
    for idx in 0..body_star_positions.len() {
        star_refs.push(RawStarRef {
            target: RawStarTarget::Body,
            star_index: idx,
        });
    }

    if star_refs.is_empty() {
        return Err("raw request template must include at least one '*'".to_string());
    }

    Ok(RawRequestTemplate {
        method,
        target,
        headers,
        body,
        star_refs,
        target_star_positions,
        header_value_star_positions,
        body_star_positions,
    })
}

pub fn infer_target_url_from_raw_request(raw: &str) -> Result<String, String> {
    let raw = raw.replace("\r\n", "\n");
    let raw = raw.trim_matches('\u{feff}');
    let (head, _) = raw.split_once("\n\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "raw request is empty".to_string())?;
    let mut parts = request_line.split_whitespace();
    let _method = parts
        .next()
        .ok_or_else(|| "missing method in request line".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "missing target in request line".to_string())?;

    let mut host: Option<String> = None;
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("host") {
            let v = v.trim();
            if !v.is_empty() {
                host = Some(v.to_string());
                break;
            }
        }
    }

    let sanitized_target = target.replace('*', "");
    if target.starts_with("http://") || target.starts_with("https://") {
        let url = reqwest::Url::parse(&sanitized_target)
            .map_err(|_| "invalid request target url".to_string())?;
        return Ok(url.to_string());
    }

    let host = host.ok_or_else(|| "missing Host header in raw request".to_string())?;
    let base = if host.starts_with("http://") || host.starts_with("https://") {
        reqwest::Url::parse(&host).map_err(|_| "invalid Host url".to_string())?
    } else {
        let base = format!("https://{host}/");
        reqwest::Url::parse(&base).map_err(|_| "invalid Host header".to_string())?
    };

    let path = if sanitized_target.is_empty() {
        "/".to_string()
    } else if sanitized_target.starts_with('/') {
        sanitized_target
    } else {
        format!("/{sanitized_target}")
    };
    base.join(&path)
        .map(|u| u.to_string())
        .map_err(|_| "invalid request target path".to_string())
}

struct PathbusterMatchLine<'a> {
    stage: &'a str,
    url: &'a str,
    status: u16,
    size: usize,
    words: usize,
    lines: usize,
    diff_value: Option<f32>,
    duration_ms: u128,
    server: &'a str,
}

fn format_pathbuster_match_line(args: PathbusterMatchLine<'_>) -> String {
    let status = match args.status {
        200..=299 => args.status.to_string().green(),
        300..=399 => args.status.to_string().blue(),
        400..=499 => args.status.to_string().truecolor(255, 165, 0),
        500..=599 => args.status.to_string().red(),
        _ => args.status.to_string().white(),
    };
    let diff_value = args
        .diff_value
        .map(|d| format!("{d:.1}"))
        .unwrap_or_else(|| "n/a".to_string());
    format!(
        "URL: {} \n\t| [Stage: {}, Status: {}, Size: {}, Words: {}, Lines: {}, DiffThr: {}, Duration: {}ms, Server: {}]",
        args.url,
        args.stage,
        status,
        args.size,
        args.words,
        args.lines,
        diff_value,
        args.duration_ms,
        args.server
    )
}

fn min_body_distance(snapshot: &ResponseSnapshot, baselines: &[ResponseSnapshot]) -> Option<f32> {
    let mut min: Option<f32> = None;
    for baseline in baselines {
        let d = utils::sift3_distance(&snapshot.body_sample, &baseline.body_sample);
        min = Some(match min {
            Some(cur) => cur.min(d),
            None => d,
        });
    }
    min
}

// this asynchronous function will send the url as jobs to all the workers
// each worker will perform tests to detect path normalization misconfigurations.
pub async fn send_url(
    tx: mpsc::Sender<Job>,
    cfg: SendUrlConfig,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let SendUrlConfig {
        urls,
        payloads,
        wordlists,
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
        validate_filters: validate_filter_cfg,
        fingerprint_filters: fingerprint_filter_cfg,
        discovery_tx,
        wordlist_status,
        waf_names_by_url,
        bypass_level,
        bypass_transforms,
        disable_waf_bypass,
        raw_request,
    } = cfg;

    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    let validate_filters = ResponseFilters {
        status: parse_filter_set_u16(&validate_filter_cfg.status),
        size: parse_filter_set_usize(&validate_filter_cfg.size),
        words: parse_filter_set_usize(&validate_filter_cfg.words),
        lines: parse_filter_set_usize(&validate_filter_cfg.lines),
        regex: if validate_filter_cfg.regex.trim().is_empty() {
            None
        } else {
            Regex::new(&validate_filter_cfg.regex).ok().map(Arc::new)
        },
    };
    let fingerprint_filters = ResponseFilters {
        status: parse_filter_set_u16(&fingerprint_filter_cfg.status),
        size: parse_filter_set_usize(&fingerprint_filter_cfg.size),
        words: parse_filter_set_usize(&fingerprint_filter_cfg.words),
        lines: parse_filter_set_usize(&fingerprint_filter_cfg.lines),
        regex: if fingerprint_filter_cfg.regex.trim().is_empty() {
            None
        } else {
            Regex::new(&fingerprint_filter_cfg.regex).ok().map(Arc::new)
        },
    };

    // the job settings
    let job_settings = JobSettings {
        int_status,
        pub_status,
        drop_after_fail,
        skip_validation,
        disable_show_all,
        ignore_trailing_slash,
        start_depth,
        max_depth,
        traversal_strategy,
        sift3_threshold,
        validate_filters,
        fingerprint_filters,
        discovery_tx,
        wordlist_status,
    };

    if skip_validation {
        let effective_wordlists = if wordlists.is_empty() {
            vec![String::new()]
        } else {
            wordlists
        };
        // send the jobs
        for (url, payload, word, method) in iproduct!(urls, payloads, effective_wordlists, methods)
        {
            let waf_names = waf_names_by_url
                .get(&url.normalized)
                .cloned()
                .unwrap_or_default();
            let transformed = transform::generate_payloads(
                &payload,
                &waf_names,
                bypass_level,
                &bypass_transforms,
                disable_waf_bypass,
            );
            for t in transformed {
                let injection_points = raw_request
                    .as_ref()
                    .map(|t| t.injection_points_len())
                    .unwrap_or(1);
                for injection_point in 0..injection_points {
                    let msg = Job {
                        settings: Some(job_settings.clone()),
                        url: Some(url.normalized.clone()),
                        original_url: Some(url.original.clone()),
                        word: Some(word.clone()),
                        payload: Some(t.mutated.clone()),
                        payload_original: Some(t.original.clone()),
                        payload_family: Some(t.family.clone()),
                        header: Some(header.clone()),
                        method: Some(method.clone()),
                        raw_request: raw_request.clone(),
                        raw_injection_point: raw_request.as_ref().map(|_| injection_point),
                    };
                    if tx.send(msg).await.is_err() {
                        continue;
                    }
                    lim.until_ready().await;
                }
            }
        }
    } else {
        let effective_wordlists = if wordlists.is_empty() {
            vec![String::new()]
        } else {
            wordlists
        };
        // send the jobs
        for (url, payload, word, method) in iproduct!(urls, payloads, effective_wordlists, methods)
        {
            let waf_names = waf_names_by_url
                .get(&url.normalized)
                .cloned()
                .unwrap_or_default();
            let transformed = transform::generate_payloads(
                &payload,
                &waf_names,
                bypass_level,
                &bypass_transforms,
                disable_waf_bypass,
            );
            for t in transformed {
                let injection_points = raw_request
                    .as_ref()
                    .map(|t| t.injection_points_len())
                    .unwrap_or(1);
                for injection_point in 0..injection_points {
                    let msg = Job {
                        settings: Some(job_settings.clone()),
                        url: Some(url.normalized.clone()),
                        original_url: Some(url.original.clone()),
                        word: Some(word.clone()),
                        payload: Some(t.mutated.clone()),
                        payload_original: Some(t.original.clone()),
                        payload_family: Some(t.family.clone()),
                        header: Some(header.clone()),
                        method: Some(method.clone()),
                        raw_request: raw_request.clone(),
                        raw_injection_point: raw_request.as_ref().map(|_| injection_point),
                    };
                    if tx.send(msg).await.is_err() {
                        continue;
                    }
                    lim.until_ready().await;
                }
            }
        }
    }
    Ok(())
}

// this function will test for path normalization vulnerabilities
pub async fn run_tester(
    pb: ProgressBar,
    mut rx: mpsc::Receiver<Job>,
    tx: mpsc::Sender<JobResultMeta>,
    timeout: usize,
    http_proxy: String,
    follow_redirects: bool,
) -> JobResultMeta {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    let redirect_policy = if follow_redirects {
        redirect::Policy::limited(10)
    } else {
        redirect::Policy::none()
    };
    let client = if http_proxy.is_empty() {
        reqwest::Client::builder()
            .default_headers(headers)
            .redirect(redirect_policy)
            .timeout(Duration::from_secs(timeout.try_into().unwrap()))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    } else {
        let proxy = match Proxy::all(http_proxy) {
            Ok(proxy) => proxy,
            Err(e) => {
                pb.println(format!("Could not setup proxy, err: {:?}", e));
                exit(1);
            }
        };
        reqwest::Client::builder()
            .default_headers(headers)
            .redirect(redirect_policy)
            .timeout(Duration::from_secs(timeout.try_into().unwrap()))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .proxy(proxy)
            .build()
            .unwrap()
    };

    let title_re = match Regex::new(r"<title>(.*?)</title>") {
        Ok(re) => re,
        Err(e) => {
            pb.println(format!("could not compile title regex: {:?}", e));
            exit(1);
        }
    };

    let mut last_result = JobResultMeta {
        base_url: "".to_string(),
        result_url: "".to_string(),
        payload_original: "".to_string(),
        payload_mutated: "".to_string(),
        payload_family: "".to_string(),
        depth: 0,
        status: 0,
        title: "".to_string(),
        size: 0,
        words: 0,
        lines: 0,
        duration_ms: 0,
        server: "".to_string(),
        content_type: "".to_string(),
    };
    while let Some(job) = rx.recv().await {
        let Job {
            settings,
            url,
            original_url,
            word,
            payload,
            payload_original,
            payload_family,
            header,
            method,
            raw_request,
            raw_injection_point,
        } = job;

        let job_url = url.unwrap();
        let _job_original_url = original_url.unwrap_or_else(|| job_url.clone());
        let job_payload = payload.unwrap();
        let job_payload_original = payload_original.unwrap_or_else(|| job_payload.clone());
        let job_payload_family = payload_family.unwrap_or_else(|| "".to_string());
        let job_settings = settings.unwrap();
        let job_method = method.unwrap_or(reqwest::Method::GET);
        let job_url_new = job_url.clone();
        let job_payload_new = job_payload.clone();

        let job_header = header.unwrap_or_else(|| "".to_owned());
        let job_word = word.unwrap_or_else(|| "".to_string());
        let word_suffix = if job_word.is_empty() {
            ""
        } else {
            job_word.as_str()
        };
        let raw_injection_point = raw_injection_point.unwrap_or(0);

        let url = match reqwest::Url::parse(&job_url_new) {
            Ok(url) => url,
            Err(_) => {
                continue;
            }
        };
        let mut job_url_with_path: String = String::from("");
        let mut job_url_without_path: String = String::from("");
        let schema = url.scheme().to_string();
        let path = url.path().to_string();
        let host = match url.host_str() {
            Some(host) => host,
            None => continue,
        };
        let port = url.port();

        job_url_with_path.push_str(&schema);
        job_url_with_path.push_str("://");
        job_url_with_path.push_str(host);
        if let Some(port) = port {
            job_url_with_path.push_str(&format!(":{port}"));
        }
        job_url_with_path.push_str(&path);
        job_url_without_path.push_str(&schema);
        job_url_without_path.push_str("://");
        job_url_without_path.push_str(host);
        if let Some(port) = port {
            job_url_without_path.push_str(&format!(":{port}"));
        }
        job_url_without_path.push('/');

        let start_depth = job_settings.start_depth;
        let max_depth = std::cmp::max(start_depth, std::cmp::max(1, job_settings.max_depth));
        let traversal_strategy = job_settings.traversal_strategy;
        let path_cnt = path.split("/").count() + 5 + start_depth;
        let mut payload = job_payload_new.repeat(start_depth + 1);
        let new_url = String::from(&job_url);
        let mut track_status_codes = 0;
        let mut depth = start_depth;
        let mut snapshots: Vec<ResponseSnapshot> = Vec::new();
        let mut baseline_snapshots: Vec<ResponseSnapshot> = Vec::new();
        let mut snapshot_keys: HashSet<String> = HashSet::new();
        let mut stop_depth: Option<usize> = None;
        if let Some(raw_request) = raw_request.as_ref() {
            if let Some(snapshot) = fetch_snapshot(
                &client,
                SnapshotRequest::Raw {
                    base_url: &job_url_without_path,
                    template: raw_request.as_ref(),
                    injection_point: raw_injection_point,
                    injection: "",
                    method_override: Some(&job_method),
                },
                &job_header,
                &title_re,
                0,
            )
            .await
            {
                let key = snapshot_key(&snapshot);
                snapshot_keys.insert(key);
                baseline_snapshots.push(snapshot.clone());
                snapshots.push(snapshot);
            }
        } else {
            for baseline_url in build_baseline_urls(&schema, host, port, &path) {
                if let Some(snapshot) = fetch_snapshot(
                    &client,
                    SnapshotRequest::Url {
                        url: &baseline_url,
                        method: &job_method,
                    },
                    &job_header,
                    &title_re,
                    0,
                )
                .await
                {
                    let key = snapshot_key(&snapshot);
                    snapshot_keys.insert(key);
                    baseline_snapshots.push(snapshot.clone());
                    snapshots.push(snapshot);
                }
            }
        }

        if job_settings.skip_validation {
            let word_for_baseline = job_word.trim().trim_start_matches('/');
            if !word_for_baseline.is_empty() {
                let baseline = if let Some(raw_request) = raw_request.as_ref() {
                    fetch_snapshot(
                        &client,
                        SnapshotRequest::Raw {
                            base_url: &job_url_without_path,
                            template: raw_request.as_ref(),
                            injection_point: raw_injection_point,
                            injection: word_for_baseline,
                            method_override: Some(&job_method),
                        },
                        &job_header,
                        &title_re,
                        0,
                    )
                    .await
                } else {
                    let hostport = if let Some(port) = port {
                        format!("{host}:{port}")
                    } else {
                        host.to_string()
                    };
                    let baseline_url = format!("{schema}://{hostport}/{word_for_baseline}");
                    fetch_snapshot(
                        &client,
                        SnapshotRequest::Url {
                            url: &baseline_url,
                            method: &job_method,
                        },
                        &job_header,
                        &title_re,
                        0,
                    )
                    .await
                };
                if let Some(snapshot) = baseline {
                    let key = snapshot_key(&snapshot);
                    snapshot_keys.insert(key);
                    baseline_snapshots.push(snapshot.clone());
                    snapshots.push(snapshot);
                }
            }
        }

        if !job_settings.skip_validation {
            let fingerprint_depth = match traversal_strategy {
                TraversalStrategy::Quick => {
                    compute_quick_fingerprint_depth(&path, start_depth, max_depth)
                }
                TraversalStrategy::Greedy => {
                    let mut out: Option<usize> = None;
                    for d in start_depth..=max_depth {
                        let probe_url = build_traversal_url(
                            &job_url,
                            &job_payload_new,
                            d,
                            word_suffix,
                            !job_settings.ignore_trailing_slash,
                        );
                        let snapshot = if let Some(raw_request) = raw_request.as_ref() {
                            let injection = job_payload_new.repeat(d.saturating_add(1));
                            fetch_snapshot(
                                &client,
                                SnapshotRequest::Raw {
                                    base_url: &job_url_without_path,
                                    template: raw_request.as_ref(),
                                    injection_point: raw_injection_point,
                                    injection: &injection,
                                    method_override: Some(&job_method),
                                },
                                &job_header,
                                &title_re,
                                d,
                            )
                            .await
                        } else {
                            fetch_snapshot(
                                &client,
                                SnapshotRequest::Url {
                                    url: &probe_url,
                                    method: &job_method,
                                },
                                &job_header,
                                &title_re,
                                d,
                            )
                            .await
                        };
                        let snapshot = match snapshot {
                            Some(snapshot) => snapshot,
                            None => continue,
                        };
                        let key = snapshot_key(&snapshot);
                        let _ = snapshot_keys.insert(key);
                        snapshots.push(snapshot.clone());
                        let summary = snapshot_summary(&snapshot);
                        if status_in_list(snapshot.status, &job_settings.pub_status)
                            && !job_settings.fingerprint_filters.matches(&summary)
                        {
                            out = Some(d);
                            break;
                        }
                    }
                    out
                }
            };

            let fingerprint_depth = match fingerprint_depth {
                Some(d) => d,
                None => {
                    pb.inc(1);
                    continue;
                }
            };

            let fingerprint_probe_url = build_traversal_url(
                &job_url,
                &job_payload_new,
                fingerprint_depth,
                word_suffix,
                !job_settings.ignore_trailing_slash,
            );
            let fingerprint_snapshot = if let Some(raw_request) = raw_request.as_ref() {
                let injection = job_payload_new.repeat(fingerprint_depth.saturating_add(1));
                fetch_snapshot(
                    &client,
                    SnapshotRequest::Raw {
                        base_url: &job_url_without_path,
                        template: raw_request.as_ref(),
                        injection_point: raw_injection_point,
                        injection: &injection,
                        method_override: Some(&job_method),
                    },
                    &job_header,
                    &title_re,
                    fingerprint_depth,
                )
                .await
            } else {
                fetch_snapshot(
                    &client,
                    SnapshotRequest::Url {
                        url: &fingerprint_probe_url,
                        method: &job_method,
                    },
                    &job_header,
                    &title_re,
                    fingerprint_depth,
                )
                .await
            };
            let fingerprint_snapshot = match fingerprint_snapshot {
                Some(snapshot) => snapshot,
                None => {
                    pb.inc(1);
                    continue;
                }
            };
            let key = snapshot_key(&fingerprint_snapshot);
            let _ = snapshot_keys.insert(key);
            snapshots.push(fingerprint_snapshot.clone());
            let fingerprint_summary = snapshot_summary(&fingerprint_snapshot);
            if !status_in_list(fingerprint_snapshot.status, &job_settings.pub_status)
                || job_settings
                    .fingerprint_filters
                    .matches(&fingerprint_summary)
            {
                pb.inc(1);
                continue;
            }

            let validation_depths: Vec<usize> = match traversal_strategy {
                TraversalStrategy::Quick => {
                    compute_quick_validation_depths(start_depth, fingerprint_depth)
                }
                TraversalStrategy::Greedy => {
                    compute_greedy_validation_depths(start_depth, fingerprint_depth)
                }
            };

            for d in validation_depths {
                if d < start_depth {
                    continue;
                }
                let validate_url = build_traversal_url(
                    &job_url,
                    &job_payload_new,
                    d,
                    word_suffix,
                    !job_settings.ignore_trailing_slash,
                );
                let validate_snapshot = if let Some(raw_request) = raw_request.as_ref() {
                    let injection = job_payload_new.repeat(d.saturating_add(1));
                    fetch_snapshot(
                        &client,
                        SnapshotRequest::Raw {
                            base_url: &job_url_without_path,
                            template: raw_request.as_ref(),
                            injection_point: raw_injection_point,
                            injection: &injection,
                            method_override: Some(&job_method),
                        },
                        &job_header,
                        &title_re,
                        d,
                    )
                    .await
                } else {
                    fetch_snapshot(
                        &client,
                        SnapshotRequest::Url {
                            url: &validate_url,
                            method: &job_method,
                        },
                        &job_header,
                        &title_re,
                        d,
                    )
                    .await
                };
                let validate_snapshot = match validate_snapshot {
                    Some(snapshot) => snapshot,
                    None => continue,
                };
                let validate_summary = snapshot_summary(&validate_snapshot);
                if !status_in_list(validate_snapshot.status, &job_settings.int_status) {
                    continue;
                }
                if job_settings.validate_filters.matches(&validate_summary) {
                    continue;
                }

                let server = validate_snapshot
                    .headers
                    .get("server")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string());
                let validate_url_for_queue = if let Some(raw_request) = raw_request.as_ref() {
                    let injection = job_payload_new.repeat(d.saturating_add(1));
                    match raw_request.render(&job_url_without_path, raw_injection_point, &injection)
                    {
                        Ok(rendered) => rendered.url.to_string(),
                        Err(_) => validate_url.clone(),
                    }
                } else {
                    validate_url.clone()
                };
                if !job_settings.disable_show_all {
                    let diff_value = min_body_distance(&validate_snapshot, &baseline_snapshots);
                    pb.println(format_pathbuster_match_line(PathbusterMatchLine {
                        stage: "validation",
                        url: &validate_url_for_queue,
                        status: validate_snapshot.status,
                        size: validate_snapshot.body_len,
                        words: validate_summary.words,
                        lines: validate_summary.lines,
                        diff_value,
                        duration_ms: validate_snapshot.duration_ms,
                        server: &server,
                    }));
                }
                let _ = job_settings
                    .discovery_tx
                    .try_send(validate_url_for_queue.to_owned());
                let content_type = validate_snapshot
                    .headers
                    .get("content-type")
                    .cloned()
                    .unwrap_or_default();
                if !job_settings.disable_show_all {
                    let result_msg = JobResultMeta {
                        base_url: job_url.clone(),
                        result_url: validate_url_for_queue.to_owned(),
                        payload_original: job_payload_original.clone(),
                        payload_mutated: job_payload_new.clone(),
                        payload_family: job_payload_family.clone(),
                        depth: d,
                        status: validate_snapshot.status,
                        title: validate_snapshot.title.clone(),
                        size: validate_snapshot.body_len,
                        words: validate_summary.words,
                        lines: validate_summary.lines,
                        duration_ms: validate_snapshot.duration_ms,
                        server,
                        content_type,
                    };
                    let result_job = result_msg.clone();
                    if tx.send(result_msg).await.is_err() {
                        pb.inc(1);
                        continue;
                    }
                    last_result = result_job;
                }
                break;
            }

            pb.inc(1);
            continue;
        }

        for step in 0..path_cnt {
            if step >= max_depth {
                break;
            }
            let mut new_url = new_url.clone();
            if !job_settings.ignore_trailing_slash && !new_url.as_str().ends_with('/') {
                new_url.push('/');
            }
            if job_settings.skip_validation {
                let mut result_url = new_url.clone();
                let injection = join_payload_and_word(&payload, &job_word);
                result_url.push_str(&injection);
                let url_for_display = if let Some(raw_request) = raw_request.as_ref() {
                    match raw_request.render(&job_url_without_path, raw_injection_point, &injection)
                    {
                        Ok(rendered) => rendered.url.to_string(),
                        Err(_) => result_url.clone(),
                    }
                } else {
                    result_url.clone()
                };
                pb.set_message(url_for_display.clone());

                let snapshot = if let Some(raw_request) = raw_request.as_ref() {
                    fetch_snapshot(
                        &client,
                        SnapshotRequest::Raw {
                            base_url: &job_url_without_path,
                            template: raw_request.as_ref(),
                            injection_point: raw_injection_point,
                            injection: &injection,
                            method_override: Some(&job_method),
                        },
                        &job_header,
                        &title_re,
                        depth,
                    )
                    .await
                } else {
                    fetch_snapshot(
                        &client,
                        SnapshotRequest::Url {
                            url: &result_url,
                            method: &job_method,
                        },
                        &job_header,
                        &title_re,
                        depth,
                    )
                    .await
                };
                let snapshot = match snapshot {
                    Some(snapshot) => snapshot,
                    None => continue,
                };

                let key = snapshot_key(&snapshot);
                let _is_new_pattern = snapshot_keys.insert(key);
                snapshots.push(snapshot.clone());

                let summary = snapshot_summary(&snapshot);
                if status_in_list(snapshot.status, &job_settings.pub_status)
                    && !job_settings.fingerprint_filters.matches(&summary)
                {
                    stop_depth = Some(depth);
                    break;
                }

                let status_ok =
                    status_allowed_by_wordlist(snapshot.status, &job_settings.wordlist_status);
                if status_ok && !job_settings.validate_filters.matches(&summary) {
                    let mut all_different = !baseline_snapshots.is_empty();
                    for baseline in baseline_snapshots.iter() {
                        if snapshot_diff(&snapshot, baseline, job_settings.sift3_threshold)
                            .is_none()
                        {
                            all_different = false;
                            break;
                        }
                    }
                    if !all_different {
                        continue;
                    }
                    let server = snapshot.headers.get("server").cloned().unwrap_or_default();
                    let server = if server.is_empty() {
                        "Unknown".to_string()
                    } else {
                        server
                    };
                    if !job_settings.disable_show_all || status_ok {
                        let diff_value = min_body_distance(&snapshot, &baseline_snapshots);
                        pb.println(format_pathbuster_match_line(PathbusterMatchLine {
                            stage: "validation",
                            url: &url_for_display,
                            status: snapshot.status,
                            size: snapshot.body_len,
                            words: summary.words,
                            lines: summary.lines,
                            diff_value,
                            duration_ms: snapshot.duration_ms,
                            server: &server,
                        }));
                    }
                    let _ = job_settings
                        .discovery_tx
                        .try_send(url_for_display.to_owned());
                    let content_type = snapshot
                        .headers
                        .get("content-type")
                        .cloned()
                        .unwrap_or_default();
                    let result_msg = JobResultMeta {
                        base_url: job_url.clone(),
                        result_url: url_for_display.to_owned(),
                        payload_original: job_payload_original.clone(),
                        payload_mutated: job_payload_new.clone(),
                        payload_family: job_payload_family.clone(),
                        depth,
                        status: snapshot.status,
                        title: snapshot.title.clone(),
                        size: snapshot.body_len,
                        words: summary.words,
                        lines: summary.lines,
                        duration_ms: snapshot.duration_ms,
                        server,
                        content_type,
                    };
                    let result_job = result_msg.clone();
                    if tx.send(result_msg).await.is_err() {
                        continue;
                    }
                    last_result = result_job;
                    continue;
                }
            } else if let Some(raw_request) = raw_request.as_ref() {
                let mut result_url = new_url.clone();
                result_url.push_str(&payload);
                let url_for_display = match raw_request.render(
                    &job_url_without_path,
                    raw_injection_point,
                    &payload,
                ) {
                    Ok(rendered) => rendered.url.to_string(),
                    Err(_) => result_url.clone(),
                };
                pb.set_message(url_for_display.clone());

                let snapshot = fetch_snapshot(
                    &client,
                    SnapshotRequest::Raw {
                        base_url: &job_url_without_path,
                        template: raw_request.as_ref(),
                        injection_point: raw_injection_point,
                        injection: &payload,
                        method_override: Some(&job_method),
                    },
                    &job_header,
                    &title_re,
                    depth,
                )
                .await;
                let snapshot = match snapshot {
                    Some(snapshot) => snapshot,
                    None => continue,
                };

                let key = snapshot_key(&snapshot);
                let _is_new_pattern = snapshot_keys.insert(key);
                snapshots.push(snapshot.clone());

                let summary = snapshot_summary(&snapshot);
                if status_in_list(snapshot.status, &job_settings.pub_status)
                    && !job_settings.fingerprint_filters.matches(&summary)
                {
                    stop_depth = Some(depth);
                    break;
                }

                let status_ok =
                    status_allowed_by_wordlist(snapshot.status, &job_settings.wordlist_status);
                if status_ok && !job_settings.validate_filters.matches(&summary) {
                    let mut all_different = !baseline_snapshots.is_empty();
                    for baseline in baseline_snapshots.iter() {
                        if snapshot_diff(&snapshot, baseline, job_settings.sift3_threshold)
                            .is_none()
                        {
                            all_different = false;
                            break;
                        }
                    }
                    if all_different {
                        let server = snapshot.headers.get("server").cloned().unwrap_or_default();
                        let server = if server.is_empty() {
                            "Unknown".to_string()
                        } else {
                            server
                        };
                        if !job_settings.disable_show_all || status_ok {
                            let diff_value = min_body_distance(&snapshot, &baseline_snapshots);
                            pb.println(format_pathbuster_match_line(PathbusterMatchLine {
                                stage: "validation",
                                url: &url_for_display,
                                status: snapshot.status,
                                size: snapshot.body_len,
                                words: summary.words,
                                lines: summary.lines,
                                diff_value,
                                duration_ms: snapshot.duration_ms,
                                server: &server,
                            }));
                        }
                        let _ = job_settings
                            .discovery_tx
                            .try_send(url_for_display.to_owned());
                        let content_type = snapshot
                            .headers
                            .get("content-type")
                            .cloned()
                            .unwrap_or_default();
                        let result_msg = JobResultMeta {
                            base_url: job_url.clone(),
                            result_url: url_for_display.to_owned(),
                            payload_original: job_payload_original.clone(),
                            payload_mutated: job_payload_new.clone(),
                            payload_family: job_payload_family.clone(),
                            depth,
                            status: snapshot.status,
                            title: snapshot.title.clone(),
                            size: snapshot.body_len,
                            words: summary.words,
                            lines: summary.lines,
                            duration_ms: snapshot.duration_ms,
                            server,
                            content_type,
                        };
                        let result_job = result_msg.clone();
                        if tx.send(result_msg).await.is_err() {
                            continue;
                        }
                        last_result = result_job;
                    }
                }
            } else {
                new_url.push_str(&payload);
                let request_url = if word_suffix.is_empty() {
                    new_url.clone()
                } else {
                    let mut out = new_url.clone();
                    out.push_str(word_suffix);
                    out
                };
                pb.set_message(request_url.clone());

                let new_url2 = new_url.clone();
                let mut req = match client.request(job_method.clone(), request_url).build() {
                    Ok(req) => req,
                    Err(_) => {
                        continue;
                    }
                };
                if !job_header.is_empty() {
                    let header_str = job_header.clone();
                    let header_parts: Vec<String> =
                        header_str.split(':').map(String::from).collect();
                    let header_key = header_parts[0].to_string();
                    let header_value = header_parts[1].to_string();

                    let key = match reqwest::header::HeaderName::from_str(header_key.as_str()) {
                        Ok(key) => key,
                        Err(_) => continue,
                    };
                    let value = match reqwest::header::HeaderValue::from_str(header_value.as_str())
                    {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    req.headers_mut().append(key, value);
                }
                let start = Instant::now();
                let resp = match client.execute(req).await {
                    Ok(resp) => resp,
                    Err(_) => {
                        continue;
                    }
                };
                let duration_ms = start.elapsed().as_millis();

                let content_length = resp.content_length().unwrap_or(0);
                let _content_length = content_length;
                let backonemore_url = new_url2.clone();
                let resp_status = resp.status().as_u16();
                let mut resp_headers: HashMap<String, String> = HashMap::new();
                for (k, v) in resp.headers().iter() {
                    if let Ok(v) = v.to_str() {
                        resp_headers.insert(k.as_str().to_lowercase(), v.to_string());
                    }
                }
                let resp_body_bytes = match resp.bytes().await {
                    Ok(body) => body.to_vec(),
                    Err(_) => Vec::new(),
                };
                let resp_body_lossy = String::from_utf8_lossy(&resp_body_bytes);
                let resp_body_sample = resp_body_lossy.chars().take(32768).collect::<String>();
                let mut resp_title = String::new();
                for cap in title_re.captures_iter(&resp_body_sample) {
                    resp_title.push_str(&cap[1]);
                }
                let resp_words = resp_body_sample.split_whitespace().count();
                let resp_lines = resp_body_sample.lines().count();
                let resp_summary = ResponseSummary {
                    status: resp_status,
                    title: resp_title,
                    body_sample: resp_body_sample,
                    body_len: resp_body_bytes.len(),
                    words: resp_words,
                    lines: resp_lines,
                };

                if status_in_list(resp_status, &job_settings.int_status)
                    && !job_settings.validate_filters.matches(&resp_summary)
                {
                    let candidate_snapshot = ResponseSnapshot {
                        depth,
                        status: resp_status,
                        headers: resp_headers.clone(),
                        title: resp_summary.title.clone(),
                        body_sample: resp_summary.body_sample.clone(),
                        body_len: resp_summary.body_len,
                        duration_ms,
                    };
                    let mut all_different = !baseline_snapshots.is_empty();
                    for baseline in baseline_snapshots.iter() {
                        if snapshot_diff(
                            &candidate_snapshot,
                            baseline,
                            job_settings.sift3_threshold,
                        )
                        .is_none()
                        {
                            all_different = false;
                            break;
                        }
                    }
                    if all_different {
                        let server = resp_headers
                            .get("server")
                            .cloned()
                            .unwrap_or_else(|| "Unknown".to_string());
                        let result_url = backonemore_url.clone();
                        let status_ok =
                            status_allowed_by_wordlist(resp_status, &job_settings.wordlist_status);
                        if !job_settings.disable_show_all || status_ok {
                            let diff_value =
                                min_body_distance(&candidate_snapshot, &baseline_snapshots);
                            pb.println(format_pathbuster_match_line(PathbusterMatchLine {
                                stage: "validation",
                                url: &result_url,
                                status: resp_status,
                                size: resp_summary.body_len,
                                words: resp_summary.words,
                                lines: resp_summary.lines,
                                diff_value,
                                duration_ms,
                                server: &server,
                            }));
                        }
                        let normalized_for_queue = if result_url.ends_with('/') {
                            result_url.to_owned()
                        } else {
                            format!("{}/", result_url)
                        };
                        let _ = job_settings.discovery_tx.try_send(normalized_for_queue);
                        let content_type = resp_headers
                            .get("content-type")
                            .cloned()
                            .unwrap_or_default();
                        let result_msg = JobResultMeta {
                            base_url: job_url.clone(),
                            result_url: result_url.to_owned(),
                            payload_original: job_payload_original.clone(),
                            payload_mutated: job_payload_new.clone(),
                            payload_family: job_payload_family.clone(),
                            depth,
                            status: resp_status,
                            title: resp_summary.title.clone(),
                            size: resp_summary.body_len,
                            words: resp_summary.words,
                            lines: resp_summary.lines,
                            duration_ms,
                            server,
                            content_type,
                        };
                        let result_job = result_msg.clone();
                        if tx.send(result_msg).await.is_err() {
                            continue;
                        }
                        last_result = result_job;
                    }
                }

                if status_in_list(resp_status, &job_settings.pub_status)
                    && !job_settings.fingerprint_filters.matches(&resp_summary)
                {
                    // strip the suffix hax and traverse back one more level
                    // to reach the internal doc root.
                    let backonemore: &str = backonemore_url
                        .strip_suffix(job_payload_new.as_str())
                        .unwrap_or_default();
                    let mut request = match client.request(job_method.clone(), backonemore).build()
                    {
                        Ok(request) => request,
                        Err(_) => {
                            continue;
                        }
                    };
                    if !job_header.is_empty() {
                        let header_str = job_header.clone();
                        let header_parts: Vec<String> =
                            header_str.split(':').map(String::from).collect();
                        let header_key = header_parts[0].to_string();
                        let header_value = header_parts[1].to_string();

                        let key = match reqwest::header::HeaderName::from_str(header_key.as_str()) {
                            Ok(key) => key,
                            Err(_) => continue,
                        };
                        let value =
                            match reqwest::header::HeaderValue::from_str(header_value.as_str()) {
                                Ok(value) => value,
                                Err(_) => continue,
                            };
                        request.headers_mut().append(key, value);
                    }
                    let response_title = match client.execute(request).await {
                        Ok(response_title) => response_title,
                        Err(_) => {
                            continue;
                        }
                    };

                    let result_url = backonemore;
                    let mut request = match client.request(job_method.clone(), backonemore).build()
                    {
                        Ok(request) => request,
                        Err(_) => {
                            continue;
                        }
                    };
                    if !job_header.is_empty() {
                        let header_str = job_header.clone();
                        let header_parts: Vec<String> =
                            header_str.split(':').map(String::from).collect();
                        let header_key = header_parts[0].to_string();
                        let header_value = header_parts[1].to_string();

                        let key = match reqwest::header::HeaderName::from_str(header_key.as_str()) {
                            Ok(key) => key,
                            Err(_) => continue,
                        };
                        let value =
                            match reqwest::header::HeaderValue::from_str(header_value.as_str()) {
                                Ok(value) => value,
                                Err(_) => continue,
                            };
                        request.headers_mut().append(key, value);
                    }
                    let start = Instant::now();
                    let response = match client.execute(request).await {
                        Ok(response) => response,
                        Err(_) => {
                            continue;
                        }
                    };
                    let duration_ms = start.elapsed().as_millis();

                    // we hit the internal doc root.
                    if status_in_list(response.status().as_u16(), &job_settings.int_status)
                        && result_url.contains(job_payload_new.as_str())
                    {
                        // track the status codes
                        if job_settings.drop_after_fail == response.status().as_str() {
                            track_status_codes += 1;
                            if track_status_codes >= 5 {
                                break;
                            }
                        }
                        let mut title = String::from("");
                        let content_bytes = match response_title.bytes().await {
                            Ok(body) => body.to_vec(),
                            Err(_) => Vec::new(),
                        };
                        let content = String::from_utf8_lossy(&content_bytes).to_string();
                        let mut baseline_body: String = "".to_string();
                        let baseline_urls =
                            [job_url_with_path.clone(), job_url_without_path.clone()];
                        for baseline_url in baseline_urls {
                            let mut request =
                                match client.request(job_method.clone(), baseline_url).build() {
                                    Ok(request) => request,
                                    Err(_) => {
                                        continue;
                                    }
                                };
                            if !job_header.is_empty() {
                                let header_str = job_header.clone();
                                let header_parts: Vec<String> =
                                    header_str.split(':').map(String::from).collect();
                                let header_key = header_parts[0].to_string();
                                let header_value = header_parts[1].to_string();

                                let key = match reqwest::header::HeaderName::from_str(
                                    header_key.as_str(),
                                ) {
                                    Ok(key) => key,
                                    Err(_) => continue,
                                };
                                let value = match reqwest::header::HeaderValue::from_str(
                                    header_value.as_str(),
                                ) {
                                    Ok(value) => value,
                                    Err(_) => continue,
                                };
                                request.headers_mut().append(key, value);
                            }
                            let baseline_resp = match client.execute(request).await {
                                Ok(baseline_resp) => baseline_resp,
                                Err(_) => continue,
                            };
                            let baseline_body_bytes = match baseline_resp.bytes().await {
                                Ok(body) => body.to_vec(),
                                Err(_) => Vec::new(),
                            };
                            baseline_body =
                                String::from_utf8_lossy(&baseline_body_bytes).to_string();
                            if !baseline_body.is_empty() {
                                break;
                            }
                        }
                        if !baseline_body.is_empty() {
                            let (ok, _) = utils::get_response_change(
                                &content,
                                &baseline_body,
                                job_settings.sift3_threshold,
                            );
                            if !ok {
                                continue;
                            }
                        }
                        for cap in title_re.captures_iter(&content) {
                            title.push_str(&cap[1]);
                        }
                        let words = content.split_whitespace().count();
                        let lines = content.lines().count();
                        let summary = ResponseSummary {
                            status: response.status().as_u16(),
                            title: title.clone(),
                            body_sample: content.chars().take(32768).collect::<String>(),
                            body_len: content.len(),
                            words,
                            lines,
                        };
                        if job_settings.validate_filters.matches(&summary) {
                            continue;
                        }
                        // fetch the server from the headers
                        let server = response
                            .headers()
                            .get("server")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("Unknown");
                        let content_type = response
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let status_ok = status_allowed_by_wordlist(
                            response.status().as_u16(),
                            &job_settings.wordlist_status,
                        );
                        let emit = !job_settings.disable_show_all || status_ok;
                        if emit {
                            let diff_value = if baseline_body.is_empty() {
                                None
                            } else {
                                Some(utils::sift3_distance(&content, &baseline_body))
                            };
                            pb.println(format_pathbuster_match_line(PathbusterMatchLine {
                                stage: "validate",
                                url: result_url,
                                status: response.status().as_u16(),
                                size: content.len(),
                                words,
                                lines,
                                diff_value,
                                duration_ms,
                                server,
                            }));
                        }
                        if job_word.is_empty() {
                            let _ = job_settings.discovery_tx.try_send(result_url.to_owned());
                        }
                        if emit {
                            let result_msg = JobResultMeta {
                                base_url: job_url.clone(),
                                result_url: result_url.to_owned(),
                                title: title.clone(),
                                size: content.len(),
                                words,
                                lines,
                                duration_ms,
                                server: server.to_string(),
                                content_type: content_type.to_string(),
                                payload_family: job_payload_family.clone(),
                                payload_mutated: job_payload_new.clone(),
                                depth: max_depth,
                                payload_original: job_payload.clone(),
                                status: response.status().as_u16(),
                            };
                            let result_job = result_msg.clone();
                            if tx.send(result_msg).await.is_err() {
                                continue;
                            }
                            last_result = result_job;
                        }
                        continue;
                    }
                }
            }
            depth += 1;
            payload.push_str(&job_payload_new);
        }
        if traversal_strategy == TraversalStrategy::Quick {
            if let Some(stop_depth) = stop_depth {
                let suffix = if job_word.is_empty() {
                    ""
                } else {
                    job_word.as_str()
                };
                let mut d = stop_depth;
                while d > start_depth {
                    d -= 1;
                    let probe_url = build_traversal_url(
                        &job_url,
                        &job_payload_new,
                        d,
                        suffix,
                        !job_settings.ignore_trailing_slash,
                    );
                    let snapshot = if let Some(raw_request) = raw_request.as_ref() {
                        let injection =
                            format!("{}{}", job_payload_new.repeat(d.saturating_add(1)), suffix);
                        fetch_snapshot(
                            &client,
                            SnapshotRequest::Raw {
                                base_url: &job_url_without_path,
                                template: raw_request.as_ref(),
                                injection_point: raw_injection_point,
                                injection: &injection,
                                method_override: Some(&job_method),
                            },
                            &job_header,
                            &title_re,
                            d,
                        )
                        .await
                    } else {
                        fetch_snapshot(
                            &client,
                            SnapshotRequest::Url {
                                url: &probe_url,
                                method: &job_method,
                            },
                            &job_header,
                            &title_re,
                            d,
                        )
                        .await
                    };
                    let snapshot = match snapshot {
                        Some(snapshot) => snapshot,
                        None => continue,
                    };

                    let key = snapshot_key(&snapshot);
                    let _is_new_pattern = snapshot_keys.insert(key);
                    snapshots.push(snapshot.clone());
                    let summary = snapshot_summary(&snapshot);
                    if status_in_list(snapshot.status, &job_settings.int_status)
                        && !job_settings.validate_filters.matches(&summary)
                    {
                        break;
                    }
                }
            }
        }
        pb.inc(1);
    }
    last_result
}

#[cfg(test)]
mod tests {
    use super::response::build_traversal_url;
    use std::collections::HashSet;

    #[test]
    fn greedy_strategy_validation_depths_descend() {
        let depths = super::compute_greedy_validation_depths(0, 3);
        assert_eq!(depths, vec![2, 1, 0]);

        let depths2 = super::compute_greedy_validation_depths(1, 4);
        assert_eq!(depths2, vec![3, 2, 1]);
    }

    #[test]
    fn quick_strategy_uses_segments_plus_start_depth() {
        let path = "/a/b/c";
        let d = super::compute_quick_fingerprint_depth(path, 0, 10).unwrap();
        assert_eq!(d, 3);

        let d2 = super::compute_quick_fingerprint_depth(path, 1, 10).unwrap();
        assert_eq!(d2, 4);

        let validation = super::compute_quick_validation_depths(0, d);
        assert_eq!(validation, vec![2]);
    }

    #[test]
    fn skip_validation_join_inserts_slash_when_needed() {
        assert_eq!(super::join_payload_and_word("..", "admin"), "../admin");
        assert_eq!(super::join_payload_and_word("..", "/admin"), "../admin");
        assert_eq!(super::join_payload_and_word("..%2f", "admin"), "..%2fadmin");
        assert_eq!(super::join_payload_and_word("../", "admin"), "../admin");
        assert_eq!(super::join_payload_and_word("", "admin"), "admin");
        assert_eq!(super::join_payload_and_word("..", ""), "..");
    }

    #[test]
    fn quick_strategy_depths_for_static_path() {
        let path = "/static/";
        let start_depth = 0usize;
        let max_depth = 5usize;
        let fingerprint_depth =
            super::compute_quick_fingerprint_depth(path, start_depth, max_depth).unwrap();
        assert_eq!(fingerprint_depth, 1);

        let fingerprint_url = build_traversal_url(
            "http://localhost:8081/static/",
            "../",
            fingerprint_depth,
            "",
            true,
        );
        assert_eq!(fingerprint_url, "http://localhost:8081/static/../../");

        let validation_depths =
            super::compute_quick_validation_depths(start_depth, fingerprint_depth);
        assert_eq!(validation_depths, vec![0]);

        let validation_url = build_traversal_url(
            "http://localhost:8081/static/",
            "../",
            validation_depths[0],
            "",
            true,
        );
        assert_eq!(validation_url, "http://localhost:8081/static/../");
    }

    #[test]
    fn baseline_urls_include_webroot_and_path_levels() {
        let urls = super::build_baseline_urls("http", "example.com", None, "/a/b/");
        assert!(urls.contains(&"http://example.com/".to_string()));
        assert!(urls.contains(&"http://example.com/a".to_string()));
        assert!(urls.contains(&"http://example.com/a/".to_string()));
        assert!(urls.contains(&"http://example.com/a/b".to_string()));
        assert!(urls.contains(&"http://example.com/a/b/".to_string()));
    }

    #[test]
    fn wordlist_status_filter_allows_all_when_empty() {
        let set: HashSet<u16> = HashSet::new();
        assert!(super::status_allowed_by_wordlist(200, &set));
        assert!(super::status_allowed_by_wordlist(404, &set));
    }
}
