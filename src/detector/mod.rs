use std::{error::Error, process::exit, time::Duration};

use colored::Colorize;
use differ::{Differ, Tag};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use itertools::iproduct;
use regex::Regex;
use reqwest::{redirect, Proxy};
use tokio::{fs::File, io::AsyncWriteExt, sync::mpsc};

use crate::utils;

// the Job struct which will be used to define our settings for the detection jobs
#[derive(Clone, Debug)]
pub struct JobSettings {
    match_status: String,
    drop_after_fail: String,
}

// the Job struct will be used as jobs for the detection phase
#[derive(Clone, Debug)]
pub struct Job {
    settings: Option<JobSettings>,
    url: Option<String>,
    payload: Option<String>,
}

// the JobResult struct which will be used as jobs
// to save the data to a file
#[derive(Clone, Debug)]
pub struct JobResult {
    pub data: String,
}

// this asynchronous function will send the url as jobs to all the workers
// each worker will perform tests to detect path normalization misconfigurations.
pub async fn send_url(
    mut tx: spmc::Sender<Job>,
    urls: Vec<String>,
    payloads: Vec<String>,
    rate: u32,
    match_status: String,
    drop_after_fail: String,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // the job settings
    let job_settings = JobSettings {
        match_status: match_status.to_string(),
        drop_after_fail: drop_after_fail,
    };

    // send the jobs
    for (url, payload) in iproduct!(urls, payloads) {
        let msg = Job {
            settings: Some(job_settings.clone()),
            url: Some(url.clone()),
            payload: Some(payload.clone()),
        };
        if let Err(_) = tx.send(msg) {
            continue;
        }
        lim.until_ready().await;
    }
    Ok(())
}

// this function will test for path normalization vulnerabilities
pub async fn run_tester(
    pb: ProgressBar,
    rx: spmc::Receiver<Job>,
    tx: mpsc::Sender<JobResult>,
    timeout: usize,
    http_proxy: String,
) -> JobResult {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    let client;
    if http_proxy.is_empty() {
        //no certs
        client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(redirect::Policy::limited(10))
            .timeout(Duration::from_secs(timeout.try_into().unwrap()))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
    } else {
        let proxy = match Proxy::all(http_proxy) {
            Ok(proxy) => proxy,
            Err(e) => {
                pb.println(format!("Could not setup proxy, err: {:?}", e));
                exit(1);
            }
        };
        //no certs
        client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(redirect::Policy::limited(10))
            .timeout(Duration::from_secs(timeout.try_into().unwrap()))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .proxy(proxy)
            .build()
            .unwrap();
    }

    while let Ok(job) = rx.recv() {
        let job_url = job.url.unwrap();
        let job_payload = job.payload.unwrap();
        let job_settings = job.settings.unwrap();
        let job_url_new = job_url.clone();
        let job_payload_new = job_payload.clone();
        pb.inc(1);
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

        job_url_with_path.push_str(&schema);
        job_url_with_path.push_str("://");
        job_url_with_path.push_str(&host);
        job_url_with_path.push_str(&path);
        job_url_without_path.push_str(&schema);
        job_url_without_path.push_str("://");
        job_url_without_path.push_str(&host);
        job_url_without_path.push_str("/");

        let path_cnt = path.split("/").count() + 5;
        let mut payload = String::from(job_payload);
        let new_url = String::from(&job_url);
        let mut track_status_codes = 0;
        for _ in 0..path_cnt {
            let job_url_without_path = job_url_without_path.clone();
            let mut new_url = new_url.clone();
            if !new_url.as_str().ends_with("/") {
                new_url.push_str("/");
            }
            new_url.push_str(&payload);

            if pb.eta().as_secs_f32() >= 60.0 {
                if (pb.eta().as_secs_f32() / 60.0) >= 60.0 {
                    pb.set_message(format!(
                        "eta: {}h {} {}",
                        ((pb.eta().as_secs_f32() / 60.0) / 60.0).round().to_string(),
                        "scanning ::".bold().white(),
                        new_url.bold().blue(),
                    ));
                } else {
                    pb.set_message(format!(
                        "eta: {}m {} {}",
                        (pb.eta().as_secs_f32() / 60.0).round().to_string(),
                        "scanning ::".bold().white(),
                        new_url.bold().blue(),
                    ));
                }
            } else {
                pb.set_message(format!(
                    " eta: {}s {} {}",
                    (pb.eta().as_secs_f32()).round().to_string(),
                    "scanning ::".bold().white(),
                    new_url.bold().blue(),
                ));
            }

            let new_url2 = new_url.clone();
            let get = client.get(new_url);
            let req = match get.build() {
                Ok(req) => req,
                Err(_) => {
                    continue;
                }
            };
            let resp = match client.execute(req).await {
                Ok(resp) => resp,
                Err(_) => {
                    continue;
                }
            };
            let pub_get = client.get(job_url_without_path);
            let pub_req = match pub_get.build() {
                Ok(pub_req) => pub_req,
                Err(_) => {
                    continue;
                }
            };
            let pub_resp = match client.execute(pub_req).await {
                Ok(pub_resp) => pub_resp,
                Err(_) => {
                    continue;
                }
            };

            let content_length = match resp.content_length() {
                Some(content_length) => content_length.to_string(),
                None => { "" }.to_owned(),
            };
            let backonemore_url = new_url2.clone();

            if job_settings.match_status.contains(resp.status().as_str()) {
                // strip the suffix hax and traverse back one more level
                // to reach the internal doc root.
                let backonemore = match backonemore_url.strip_suffix(job_payload_new.as_str()) {
                    Some(backonemore) => backonemore,
                    None => "",
                };
                let get = client.get(backonemore);
                let request = match get.build() {
                    Ok(request) => request,
                    Err(_) => {
                        continue;
                    }
                };
                let response_title = match client.execute(request).await {
                    Ok(response_title) => response_title,
                    Err(_) => {
                        continue;
                    }
                };

                let result_url = backonemore.clone();
                let get = client.get(backonemore);
                let request = match get.build() {
                    Ok(request) => request,
                    Err(_) => {
                        continue;
                    }
                };
                let response = match client.execute(request).await {
                    Ok(response) => response,
                    Err(_) => {
                        continue;
                    }
                };

                let internal_get = client.get(backonemore);

                let internal_req = match internal_get.build() {
                    Ok(internal_req) => internal_req,
                    Err(_) => {
                        continue;
                    }
                };
                let internal_resp = match client.execute(internal_req).await {
                    Ok(internal_resp) => internal_resp,
                    Err(_) => {
                        continue;
                    }
                };

                let internal_cl = match internal_resp.text().await {
                    Ok(internal_cl) => internal_cl,
                    Err(_) => continue,
                };

                let public_cl = match pub_resp.text().await {
                    Ok(public_cl) => public_cl,
                    Err(_) => continue,
                };

                // we hit the internal doc root.
                let (ok, distance_between_responses) =
                    utils::get_response_change(&internal_cl, &public_cl);
                if response.status().as_str() != "400"
                    && ok
                    && result_url.contains(&job_payload_new)
                {
                    // track the status codes
                    if job_settings.drop_after_fail == response.status().as_str() {
                        track_status_codes += 1;
                        if track_status_codes >= 5 {
                            return JobResult {
                                data: "".to_string(),
                            };
                        }
                    }
                    pb.println(format!(
                        "{} {}",
                        "found internal doc root :: ".bold().green(),
                        result_url.bold().blue(),
                    ));
                    let mut title = String::from("");
                    let content = match response_title.text().await {
                        Ok(content) => content,
                        Err(_) => "".to_string(),
                    };
                    let re = Regex::new(r"<title>(.*?)</title>").unwrap();
                    for cap in re.captures_iter(&content) {
                        title.push_str(&cap[1]);
                    }
                    // fetch the server from the headers
                    let server = match response.headers().get("Server") {
                        Some(server) => match server.to_str() {
                            Ok(server) => server,
                            Err(_) => "Unknown",
                        },
                        None => "Unknown",
                    };

                    let internal_resp_text_lines = internal_cl.lines().collect::<Vec<_>>();
                    let public_resp_text_lines = public_cl.lines().collect::<Vec<_>>();
                    let character_differences =
                        Differ::new(&public_resp_text_lines, &internal_resp_text_lines);
                    pb.println(format!(
                        "\n{}{}{} {}",
                        "(".bold().white(),
                        "*".bold().blue(),
                        ")".bold().white(),
                        "found some response changes:".bold().green(),
                    ));
                    for span in character_differences.spans() {
                        match span.tag {
                            Tag::Equal => (),  // ignore
                            Tag::Insert => (), // ignore
                            Tag::Delete => (), // ignore
                            Tag::Replace => {
                                for line in &internal_resp_text_lines[span.b_start..span.b_end] {
                                    if line.to_string() == "" {
                                        pb.println(format!("\n{}", line.bold().white(),));
                                    } else {
                                        pb.println(format!("{}", line.bold().white(),));
                                    }
                                }
                            }
                        }
                    }
                    pb.println(format!("\n"));
                    if response.status().is_client_error() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                            "[".bold().white(),
                            "OK".bold().green(),
                            "]".bold().white(),
                            "[".bold().white(),
                            result_url.bold().cyan(),
                            "]".bold().white(),
                            "[".bold().white(),
                            "*".bold().green(),
                            "]".bold().white(),
                            "Response:".bold().white(),
                            "payload:".bold().white(),
                            "[".bold().white(),
                            job_payload_new.bold().blue(),
                            "]".bold().white(),
                            "status:".bold().white(),
                            "[".bold().white(),
                            response.status().as_str().bold().blue(),
                            "]".bold().white(),
                            "content_length:".bold().white(),
                            "[".bold().white(),
                            content_length.yellow(),
                            "]".bold().white(),
                            "server:".bold().white(),
                            "[".bold().white(),
                            server.bold().purple(),
                            "]".bold().white(),
                            "title:".bold().white(),
                            "[".bold().white(),
                            title.bold().purple(),
                            "]".bold().white(),
                            "deviation:".bold().white(),
                            "[".bold().white(),
                            distance_between_responses.to_string().bold().purple(),
                            "]".bold().white(),
                        ));
                    }
                    if response.status().is_success() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                            "[".bold().white(),
                            "OK".bold().green(),
                            "]".bold().white(),
                            "[".bold().white(),
                            result_url.bold().cyan(),
                            "]".bold().white(),
                            "[".bold().white(),
                            "*".bold().green(),
                            "]".bold().white(),
                            "Response:".bold().white(),
                            "payload:".bold().white(),
                            "[".bold().white(),
                            job_payload_new.bold().blue(),
                            "]".bold().white(),
                            "status:".bold().white(),
                            "[".bold().white(),
                            response.status().as_str().bold().green(),
                            "]".bold().white(),
                            "content_length:".bold().white(),
                            "[".bold().white(),
                            content_length.yellow(),
                            "]".bold().white(),
                            "server:".bold().white(),
                            "[".bold().white(),
                            server.bold().purple(),
                            "]".bold().white(),
                            "title:".bold().white(),
                            "[".bold().white(),
                            title.bold().purple(),
                            "]".bold().white(),
                            "deviation:".bold().white(),
                            "[".bold().white(),
                            distance_between_responses.to_string().bold().purple(),
                            "]".bold().white(),
                        ));
                    }
                    if response.status().is_redirection() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                            "[".bold().white(),
                            "OK".bold().green(),
                            "]".bold().white(),
                            "[".bold().white(),
                            result_url.bold().cyan(),
                            "]".bold().white(),
                            "[".bold().white(),
                            "*".bold().green(),
                            "]".bold().white(),
                            "Response:".bold().white(),
                            "payload:".bold().white(),
                            "[".bold().white(),
                            job_payload_new.bold().blue(),
                            "]".bold().white(),
                            "status:".bold().white(),
                            "[".bold().white(),
                            response.status().as_str().bold().blue(),
                            "]".bold().white(),
                            "content_length:".bold().white(),
                            "[".bold().white(),
                            content_length.yellow(),
                            "]".bold().white(),
                            "server:".bold().white(),
                            "[".bold().white(),
                            server.bold().purple(),
                            "]".bold().white(),
                            "title:".bold().white(),
                            "[".bold().white(),
                            title.bold().purple(),
                            "]".bold().white(),
                            "deviation:".bold().white(),
                            "[".bold().white(),
                            distance_between_responses.to_string().bold().purple(),
                            "]".bold().white(),
                        ));
                    }
                    if response.status().is_server_error() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                            "[".bold().white(),
                            "OK".bold().green(),
                            "]".bold().white(),
                            "[".bold().white(),
                            result_url.bold().cyan(),
                            "]".bold().white(),
                            "[".bold().white(),
                            "*".bold().green(),
                            "]".bold().white(),
                            "Response:".bold().white(),
                            "payload:".bold().white(),
                            "[".bold().white(),
                            job_payload_new.bold().blue(),
                            "]".bold().white(),
                            "status:".bold().white(),
                            "[".bold().white(),
                            response.status().as_str().bold().red(),
                            "]".bold().white(),
                            "content_length:".bold().white(),
                            "[".bold().white(),
                            content_length.yellow(),
                            "]".bold().white(),
                            "server:".bold().white(),
                            "[".bold().white(),
                            server.bold().purple(),
                            "]".bold().white(),
                            "title:".bold().white(),
                            "[".bold().white(),
                            title.bold().purple(),
                            "]".bold().white(),
                            "deviation:".bold().white(),
                            "[".bold().white(),
                            distance_between_responses.to_string().bold().purple(),
                            "]".bold().white(),
                        ));
                    }
                    if response.status().is_informational() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                            "[".bold().white(),
                            "OK".bold().green(),
                            "]".bold().white(),
                            "[".bold().white(),
                            result_url.bold().cyan(),
                            "]".bold().white(),
                            "[".bold().white(),
                            "*".bold().green(),
                            "]".bold().white(),
                            "Response:".bold().white(),
                            "payload:".bold().white(),
                            "[".bold().white(),
                            job_payload_new.bold().blue(),
                            "]".bold().white(),
                            "status:".bold().white(),
                            "[".bold().white(),
                            response.status().as_str().bold().purple(),
                            "]".bold().white(),
                            "content_length:".bold().white(),
                            "[".bold().white(),
                            content_length.yellow(),
                            "]".bold().white(),
                            "server:".bold().white(),
                            "[".bold().white(),
                            server.bold().purple(),
                            "]".bold().white(),
                            "title:".bold().white(),
                            "[".bold().white(),
                            title.bold().purple(),
                            "]".bold().white(),
                            "deviation:".bold().white(),
                            "[".bold().white(),
                            distance_between_responses.to_string().bold().purple(),
                            "]".bold().white(),
                        ));
                    }
                    // send the result message through the channel to the workers.
                    let result_msg = JobResult {
                        data: result_url.to_owned(),
                    };
                    let result_job = result_msg.clone();
                    if let Err(_) = tx.send(result_msg).await {
                        continue;
                    }
                    pb.inc_length(1);
                    return result_job;
                }
            }
            payload.push_str(&job_payload_new);
        }
    }
    return JobResult {
        data: "".to_string(),
    };
}

pub async fn save_traversals(_: ProgressBar, mut outfile: File, traversal: String) {
    let mut outbuf = traversal.as_bytes().to_owned();
    outbuf.extend_from_slice(b"\n");
    if let Err(_) = outfile.write(&outbuf).await {
        // pb.println(format!("failed to write output '{:?}': {:?}", outbuf, e));
        return;
    }
}
