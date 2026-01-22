use std::collections::HashMap;
use std::str::FromStr;

use distance::sift3;
use regex::Regex;
use tokio::time::Instant;

use crate::utils;

#[derive(Clone, Debug)]
pub(in crate::detector) struct ResponseSummary {
    pub(in crate::detector) status: u16,
    pub(in crate::detector) title: String,
    pub(in crate::detector) body_sample: String,
    pub(in crate::detector) body_len: usize,
    pub(in crate::detector) words: usize,
    pub(in crate::detector) lines: usize,
}

#[derive(Clone, Debug)]
pub(in crate::detector) struct ResponseSnapshot {
    #[allow(dead_code)]
    pub(in crate::detector) depth: usize,
    pub(in crate::detector) status: u16,
    pub(in crate::detector) headers: HashMap<String, String>,
    pub(in crate::detector) title: String,
    pub(in crate::detector) body_sample: String,
    pub(in crate::detector) body_len: usize,
    pub(in crate::detector) duration_ms: u128,
}

pub(in crate::detector) fn header_map_to_hashmap(
    headers: &reqwest::header::HeaderMap,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(v) = v.to_str() {
            out.insert(k.as_str().to_lowercase(), v.to_string());
        }
    }
    out
}

pub(in crate::detector) fn snapshot_key(snapshot: &ResponseSnapshot) -> String {
    let server = snapshot
        .headers
        .get("server")
        .map(|s| s.as_str())
        .unwrap_or("");
    let content_type = snapshot
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    format!(
        "{}|{}|{}|{}|{}",
        snapshot.status, server, content_type, snapshot.title, snapshot.body_len
    )
}

pub(in crate::detector) fn snapshot_summary(snapshot: &ResponseSnapshot) -> ResponseSummary {
    let words = snapshot.body_sample.split_whitespace().count();
    let lines = snapshot.body_sample.lines().count();
    ResponseSummary {
        status: snapshot.status,
        title: snapshot.title.clone(),
        body_sample: snapshot.body_sample.clone(),
        body_len: snapshot.body_len,
        words,
        lines,
    }
}

pub(in crate::detector) fn snapshot_diff(
    current: &ResponseSnapshot,
    previous: &ResponseSnapshot,
    threshold: utils::ResponseChangeThreshold,
) -> Option<String> {
    let mut diffs: Vec<String> = vec![];
    if current.status != previous.status {
        diffs.push(format!("status {}->{}", previous.status, current.status));
    }

    let keys_to_compare = ["server", "content-type", "location", "www-authenticate"];
    for key in keys_to_compare {
        let a = previous.headers.get(key).map(|s| s.as_str()).unwrap_or("");
        let b = current.headers.get(key).map(|s| s.as_str()).unwrap_or("");
        if a != b {
            diffs.push(format!("header:{} {}->{}", key, a, b));
        }
    }

    if previous.body_len != current.body_len {
        diffs.push(format!("len {}->{}", previous.body_len, current.body_len));
    }

    let body_distance = sift3(&previous.body_sample, &current.body_sample);
    let (within_threshold, _) =
        utils::get_response_change(&previous.body_sample, &current.body_sample, threshold);
    if within_threshold {
        diffs.push(format!("sift3 {}", body_distance));
    }

    let timing_delta = previous.duration_ms.abs_diff(current.duration_ms);
    if timing_delta >= 250 {
        diffs.push(format!(
            "timing {}ms->{}ms",
            previous.duration_ms, current.duration_ms
        ));
    }

    if diffs.is_empty() {
        None
    } else {
        Some(diffs.join(", "))
    }
}

pub(in crate::detector) fn build_traversal_url(
    base_url: &str,
    payload: &str,
    depth: usize,
    suffix: &str,
    pad_slash: bool,
) -> String {
    let mut out = base_url.to_string();
    if pad_slash && !out.ends_with('/') {
        out.push('/');
    }
    let repeats = depth.saturating_add(1);
    out.push_str(&payload.repeat(repeats));
    out.push_str(suffix);
    out
}

pub(in crate::detector) enum SnapshotRequest<'a> {
    Url {
        url: &'a str,
        method: &'a reqwest::Method,
    },
    Raw {
        base_url: &'a str,
        template: &'a super::RawRequestTemplate,
        injection_point: usize,
        injection: &'a str,
        method_override: Option<&'a reqwest::Method>,
    },
}

pub(in crate::detector) async fn fetch_snapshot(
    client: &reqwest::Client,
    req: SnapshotRequest<'_>,
    job_header: &str,
    title_re: &Regex,
    depth: usize,
) -> Option<ResponseSnapshot> {
    let mut req = match req {
        SnapshotRequest::Url { url, method } => client.request(method.clone(), url).build().ok()?,
        SnapshotRequest::Raw {
            base_url,
            template,
            injection_point,
            injection,
            method_override,
        } => {
            let rendered = template.render(base_url, injection_point, injection).ok()?;
            let method = method_override.unwrap_or(&rendered.method).clone();
            let mut builder = client.request(method, rendered.url);
            for (k, v) in rendered.headers {
                if k.eq_ignore_ascii_case("content-length") {
                    continue;
                }
                let key = reqwest::header::HeaderName::from_str(k.trim()).ok()?;
                let value = reqwest::header::HeaderValue::from_str(v.trim()).ok()?;
                builder = builder.header(key, value);
            }
            if !rendered.body.is_empty() {
                builder = builder.body(rendered.body);
            }
            builder.build().ok()?
        }
    };
    if !job_header.is_empty() {
        if let Some((header_key, header_value)) = job_header.split_once(':') {
            let key = match reqwest::header::HeaderName::from_str(header_key.trim()) {
                Ok(key) => key,
                Err(_) => return None,
            };
            let value = match reqwest::header::HeaderValue::from_str(header_value.trim()) {
                Ok(value) => value,
                Err(_) => return None,
            };
            req.headers_mut().append(key, value);
        } else {
            return None;
        }
    }

    let start = Instant::now();
    let resp = match client.execute(req).await {
        Ok(resp) => resp,
        Err(_) => return None,
    };
    let duration_ms = start.elapsed().as_millis();
    let status = resp.status().as_u16();
    let headers = header_map_to_hashmap(resp.headers());
    let body_bytes = match resp.bytes().await {
        Ok(body) => body.to_vec(),
        Err(_) => Vec::new(),
    };
    let body_len = body_bytes.len();
    let body_sample = String::from_utf8_lossy(&body_bytes)
        .chars()
        .take(32768)
        .collect::<String>();
    let mut title = String::new();
    for cap in title_re.captures_iter(&body_sample) {
        title.push_str(&cap[1]);
    }
    Some(ResponseSnapshot {
        depth,
        status,
        headers,
        title,
        body_sample,
        body_len,
        duration_ms,
    })
}
