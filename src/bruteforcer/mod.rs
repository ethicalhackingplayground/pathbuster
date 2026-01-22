use std::collections::{HashMap, HashSet};
use std::{error::Error, time::Duration};

use colored::Colorize;
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use reqwest::{redirect, Proxy};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::utils;

// the BruteResult struct which will be used as jobs
// to save the data to a file
#[derive(Clone, Debug)]
pub struct BruteResult {
    pub data: String,
    pub rs: String,
}

// the Job struct which will be used as jobs for directory bruteforcing
#[derive(Clone, Debug)]
pub struct BruteJob {
    pub url: Option<String>,
    pub word: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BruteforcerConfig {
    pub timeout: usize,
    pub http_proxy: String,
    pub sift3_threshold: utils::ResponseChangeThreshold,
    pub follow_redirects: bool,
    pub methods: Vec<reqwest::Method>,
    pub auto_collab: bool,
    pub validate_status: HashSet<u16>,
    pub wordlist_status: HashSet<u16>,
}

pub async fn send_word_to_url_queue(
    tx: mpsc::Sender<BruteJob>,
    mut discoveries: mpsc::Receiver<String>,
    wordlists: Vec<String>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let lim = RateLimiter::direct(Quota::per_second(
        std::num::NonZeroU32::new(rate).unwrap_or(std::num::NonZeroU32::MIN),
    ));
    let mut seen: HashSet<String> = HashSet::new();
    while let Some(url) = discoveries.recv().await {
        if !seen.insert(url.clone()) {
            continue;
        }
        for word in wordlists.iter() {
            let msg = BruteJob {
                url: Some(url.clone()),
                word: Some(word.clone()),
            };
            if tx.send(msg).await.is_err() {
                return Ok(());
            }
            lim.until_ready().await;
        }
    }
    Ok(())
}

// runs the directory bruteforcer on the job
pub async fn run_bruteforcer(
    pb: ProgressBar,
    mut rx: mpsc::Receiver<BruteJob>,
    tx: mpsc::Sender<BruteResult>,
    config: BruteforcerConfig,
) -> BruteResult {
    let BruteforcerConfig {
        timeout,
        http_proxy,
        sift3_threshold,
        follow_redirects,
        methods,
        auto_collab,
        validate_status,
        wordlist_status,
    } = config;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    let timeout = Duration::from_secs(timeout as u64);
    let redirect_policy = if follow_redirects {
        redirect::Policy::limited(10)
    } else {
        redirect::Policy::none()
    };
    let mut client_builder = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect_policy)
        .timeout(timeout)
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true);

    if !http_proxy.is_empty() {
        match Proxy::all(&http_proxy) {
            Ok(proxy) => {
                client_builder = client_builder.proxy(proxy);
            }
            Err(e) => {
                let _ = e;
                return BruteResult {
                    data: String::new(),
                    rs: String::new(),
                };
            }
        }
    }

    let client = match client_builder.build() {
        Ok(client) => client,
        Err(e) => {
            let _ = e;
            return BruteResult {
                data: String::new(),
                rs: String::new(),
            };
        }
    };

    struct MatchLine<'a> {
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

    fn format_match_line(args: MatchLine<'_>) -> String {
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
            "URL: {} \n\t| [Stage: {}, Status: {}, Size: {}, Words: {}, Lines: {}, DiffThr: {}, Duration: {}ms, Server: {}]\n",
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

    let mut last_result = BruteResult {
        data: String::new(),
        rs: String::new(),
    };
    let methods = if methods.is_empty() {
        vec![reqwest::Method::GET]
    } else {
        methods
    };

    let mut noise_sizes_by_base: HashMap<String, Vec<usize>> = HashMap::new();
    let mut baseline_validate_by_base_method: HashMap<(String, String), String> = HashMap::new();
    let mut baseline_probe_by_base_method: HashMap<(String, String), String> = HashMap::new();
    let probes = 3usize;
    let internal_probe_word = "pathbuster-diff-probe-8f59c2d6a5e54b0bb8f3";

    fn normalize_word(word: &str) -> Option<String> {
        let w = word.trim().trim_start_matches('/').to_string();
        if w.is_empty() {
            None
        } else {
            Some(w)
        }
    }

    fn build_internal_url(base_url: &str, word: &str) -> String {
        let ends_with_encoded_slash = base_url.ends_with("%2f") || base_url.ends_with("%2F");
        let mut out = if base_url.ends_with('/') || ends_with_encoded_slash {
            base_url.to_string()
        } else {
            format!("{base_url}/")
        };
        out.push_str(word);
        out
    }

    fn build_web_root_url(parsed: &reqwest::Url, word: &str) -> Option<String> {
        let schema = parsed.scheme();
        let host = parsed.host_str()?;
        let host = if let Some(port) = parsed.port() {
            format!("{host}:{port}")
        } else {
            host.to_string()
        };
        Some(format!("{schema}://{host}/{word}"))
    }

    while let Some(job) = rx.recv().await {
        let (Some(job_url), Some(job_word)) = (job.url, job.word) else {
            continue;
        };
        let base_url = job_url.clone();
        let Some(word) = normalize_word(&job_word) else {
            continue;
        };
        if word.is_empty() {
            continue;
        }
        pb.inc(1);
        let url = match reqwest::Url::parse(&base_url) {
            Ok(url) => url,
            Err(_) => continue,
        };
        let Some(web_root_url) = build_web_root_url(&url, &word) else {
            continue;
        };
        let internal_url = build_internal_url(&base_url, &word);
        pb.set_message(internal_url.clone());

        if auto_collab && !noise_sizes_by_base.contains_key(&base_url) {
            let mut sizes: Vec<usize> = Vec::new();
            for i in 0..probes {
                let probe_url = format!("{base_url}pathbuster-ac-{i}");
                let resp = client.get(probe_url).send().await.ok();
                let size = if let Some(resp) = resp {
                    resp.bytes().await.ok().map(|b| b.len())
                } else {
                    None
                };
                if let Some(size) = size {
                    sizes.push(size);
                }
            }
            let mut filtered: HashSet<usize> = HashSet::new();
            for i in 0..sizes.len() {
                for j in (i + 1)..sizes.len() {
                    let (similar, _) = utils::sift3_distance_in_range(
                        &sizes[i].to_string(),
                        &sizes[j].to_string(),
                        sift3_threshold,
                    );
                    if similar {
                        filtered.insert(sizes[i]);
                        filtered.insert(sizes[j]);
                    }
                }
            }
            noise_sizes_by_base.insert(base_url.clone(), filtered.into_iter().collect());
        }

        for method in methods.iter() {
            let req = match client.request(method.clone(), internal_url.clone()).build() {
                Ok(req) => req,
                Err(_) => continue,
            };

            let start = Instant::now();
            let resp = match client.execute(req).await {
                Ok(resp) => resp,
                Err(_) => continue,
            };
            let duration_ms = start.elapsed().as_millis();

            let resp_status = resp.status().as_u16();
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Unknown")
                .to_string();
            let _content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let resp_body_bytes = match resp.bytes().await {
                Ok(body) => body.to_vec(),
                Err(_) => continue,
            };
            let resp_body = String::from_utf8_lossy(&resp_body_bytes);
            let size = resp_body_bytes.len();
            let words = resp_body.split_whitespace().count();
            let lines = resp_body.lines().count();

            if !wordlist_status.is_empty() && !wordlist_status.contains(&resp_status) {
                continue;
            }

            if auto_collab {
                if let Some(noise) = noise_sizes_by_base.get(&base_url) {
                    let is_noise = noise.iter().any(|n| {
                        let (similar, _) = utils::sift3_distance_in_range(
                            &size.to_string(),
                            &n.to_string(),
                            sift3_threshold,
                        );
                        similar
                    });
                    if is_noise {
                        continue;
                    }
                }
            }

            let public_resp = match client
                .request(method.clone(), web_root_url.clone())
                .send()
                .await
            {
                Ok(public_resp) => public_resp,
                Err(_) => continue,
            };
            let public_resp_text = match public_resp.text().await {
                Ok(public_resp_text) => public_resp_text,
                Err(_) => continue,
            };
            let (diff_public_ok, _) =
                utils::get_response_change(resp_body.as_ref(), &public_resp_text, sift3_threshold);
            if !diff_public_ok {
                continue;
            }

            if validate_status.contains(&resp_status) {
                let method_key = method.as_str().to_string();

                let validate_key = (base_url.clone(), method_key.clone());
                if !baseline_validate_by_base_method.contains_key(&validate_key) {
                    let baseline_text = match client
                        .request(method.clone(), base_url.clone())
                        .send()
                        .await
                    {
                        Ok(resp) => resp.text().await.ok(),
                        Err(_) => None,
                    };
                    if let Some(text) = baseline_text {
                        baseline_validate_by_base_method.insert(validate_key.clone(), text);
                    }
                }

                if let Some(validate_body) = baseline_validate_by_base_method.get(&validate_key) {
                    if !validate_body.is_empty() {
                        let (ok, _) = utils::get_response_change(
                            resp_body.as_ref(),
                            validate_body,
                            sift3_threshold,
                        );
                        if !ok {
                            continue;
                        }
                    }
                }

                let probe_key = (base_url.clone(), method_key.clone());
                if !baseline_probe_by_base_method.contains_key(&probe_key) {
                    let probe_url = build_internal_url(&base_url, internal_probe_word);
                    let probe_text = match client.request(method.clone(), probe_url).send().await {
                        Ok(resp) => resp.text().await.ok(),
                        Err(_) => None,
                    };
                    if let Some(text) = probe_text {
                        baseline_probe_by_base_method.insert(probe_key.clone(), text);
                    }
                }

                if let Some(probe_body) = baseline_probe_by_base_method.get(&probe_key) {
                    if !probe_body.is_empty() {
                        let (ok, _) = utils::get_response_change(
                            resp_body.as_ref(),
                            probe_body,
                            sift3_threshold,
                        );
                        if !ok {
                            continue;
                        }
                    }
                }
            }

            {
                let method_key = method.as_str().to_string();
                let lookup_key = (base_url.clone(), method_key);
                let diff_value = if let Some(baseline_body) =
                    baseline_validate_by_base_method.get(&lookup_key)
                {
                    if baseline_body.is_empty() {
                        None
                    } else {
                        Some(utils::sift3_distance(resp_body.as_ref(), baseline_body))
                    }
                } else if let Some(probe_body) = baseline_probe_by_base_method.get(&lookup_key) {
                    if probe_body.is_empty() {
                        None
                    } else {
                        Some(utils::sift3_distance(resp_body.as_ref(), probe_body))
                    }
                } else if !public_resp_text.is_empty() {
                    Some(utils::sift3_distance(resp_body.as_ref(), &public_resp_text))
                } else {
                    None
                };
                pb.println(format_match_line(MatchLine {
                    stage: "bruteforce",
                    url: &internal_url,
                    status: resp_status,
                    size,
                    words,
                    lines,
                    diff_value,
                    duration_ms,
                    server: &server,
                }));

                let result_msg = BruteResult {
                    data: internal_url.to_owned(),
                    rs: size.to_string(),
                };
                let result = result_msg.clone();
                if tx.send(result_msg).await.is_err() {
                    continue;
                }
                pb.inc_length(1);
                last_result = result;
                break;
            }
        }
    }
    last_result
}

#[cfg(test)]
mod tests {
    #[test]
    fn build_internal_url_preserves_encoded_slash_boundary() {
        fn build_internal_url(base_url: &str, word: &str) -> String {
            let ends_with_encoded_slash = base_url.ends_with("%2f") || base_url.ends_with("%2F");
            let mut out = if base_url.ends_with('/') || ends_with_encoded_slash {
                base_url.to_string()
            } else {
                format!("{base_url}/")
            };
            out.push_str(word);
            out
        }

        assert_eq!(
            build_internal_url("http://localhost:8081/static/..%2f", "internal/lab1/flag"),
            "http://localhost:8081/static/..%2finternal/lab1/flag"
        );
        assert_eq!(
            build_internal_url("http://localhost:8081/static/../", "internal/lab1/flag"),
            "http://localhost:8081/static/../internal/lab1/flag"
        );
        assert_eq!(
            build_internal_url("http://localhost:8081/static", "internal/lab1/flag"),
            "http://localhost:8081/static/internal/lab1/flag"
        );
    }
}
