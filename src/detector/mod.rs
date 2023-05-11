use std::{error::Error, process::exit, str::FromStr, time::Duration};

use colored::Colorize;
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use itertools::iproduct;
use regex::Regex;
use reqwest::{redirect, Proxy};
use tokio::{fs::File, io::AsyncWriteExt, sync::mpsc};

// the Job struct which will be used to define our settings for the detection jobs
#[derive(Clone, Debug)]
pub struct JobSettings {
    int_status: String,
    pub_status: String,
    drop_after_fail: String,
    skip_validation: bool,
}

// the Job struct will be used as jobs for the detection phase
#[derive(Clone, Debug)]
pub struct Job {
    settings: Option<JobSettings>,
    url: Option<String>,
    word: Option<String>,
    payload: Option<String>,
    header: Option<String>,
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
    wordlists: Vec<String>,
    rate: u32,
    int_status: String,
    pub_status: String,
    drop_after_fail: String,
    skip_validation: bool,
    header: String,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // the job settings
    let job_settings = JobSettings {
        int_status: int_status.to_string(),
        pub_status: pub_status.to_string(),
        drop_after_fail: drop_after_fail,
        skip_validation: skip_validation,
    };

    println!("{}", header);

    if skip_validation {
        // send the jobs
        for (url, payload, word) in iproduct!(urls, payloads, wordlists) {
            let msg = Job {
                settings: Some(job_settings.clone()),
                url: Some(url.clone()),
                word: Some(word.clone()),
                payload: Some(payload.clone()),
                header: Some(header.clone()),
            };
            if let Err(_) = tx.send(msg) {
                continue;
            }
            lim.until_ready().await;
        }
    } else {
        // send the jobs
        for (url, payload) in iproduct!(urls, payloads) {
            let msg = Job {
                settings: Some(job_settings.clone()),
                url: Some(url.clone()),
                word: Some("".to_string()),
                payload: Some(payload.clone()),
                header: Some(header.clone()),
            };
            if let Err(_) = tx.send(msg) {
                continue;
            }
            lim.until_ready().await;
        }
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

        let job_header = match job.header {
            Some(job_header) => job_header,
            None => "".to_owned(),
        };
        let job_word = match job.word {
            Some(job_word) => job_word,
            None => "".to_string(),
        };

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
            let mut new_url = new_url.clone();
            if !new_url.as_str().ends_with("/") {
                new_url.push_str("/");
            }

            if job_settings.skip_validation {
                new_url.push_str(&payload);
                new_url.push_str(&job_word);
                let result_url = new_url.clone();
                let title_url = result_url.clone();
                pb.set_message(format!(
                    "{} {}",
                    "scanning ::".bold().white(),
                    new_url.bold().blue(),
                ));

                let get = client.get(new_url);
                let mut req = match get.build() {
                    Ok(req) => req,
                    Err(_) => {
                        continue;
                    }
                };
                if job_header != "" {
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
                let response = match client.execute(req).await {
                    Ok(resp) => resp,
                    Err(_) => {
                        continue;
                    }
                };

                // fetch the server from the headers
                let server = match response.headers().get("Server") {
                    Some(server) => match server.to_str() {
                        Ok(server) => server,
                        Err(_) => "Unknown",
                    },
                    None => "Unknown",
                };

                let content_length = match response.content_length() {
                    Some(content_length) => content_length.to_string(),
                    None => { "" }.to_owned(),
                };

                let get = client.get(title_url);
                let mut request = match get.build() {
                    Ok(request) => request,
                    Err(_) => {
                        continue;
                    }
                };
                if job_header != "" {
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
                    request.headers_mut().append(key, value);
                }
                let response_title = match client.execute(request).await {
                    Ok(response_title) => response_title,
                    Err(_) => {
                        continue;
                    }
                };

                let mut title = String::from("");
                let content = match response_title.text().await {
                    Ok(content) => content,
                    Err(_) => "".to_string(),
                };
                let re = Regex::new(r"<title>(.*?)</title>").unwrap();
                for cap in re.captures_iter(&content) {
                    title.push_str(&cap[1]);
                }

                if job_settings.int_status.contains(response.status().as_str()) {
                    if response.status().is_client_error() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                        ));
                    }
                    if response.status().is_success() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                        ));
                    }
                    if response.status().is_redirection() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                        ));
                    }
                    if response.status().is_server_error() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                        ));
                    }
                    if response.status().is_informational() {
                        pb.println(format!(
                            "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                    return result_job;
                }
            } else {
                new_url.push_str(&payload);

                pb.set_message(format!(
                    "{} {}",
                    "scanning ::".bold().white(),
                    new_url.bold().blue(),
                ));

                let new_url2 = new_url.clone();
                let get = client.get(new_url);
                let mut req = match get.build() {
                    Ok(req) => req,
                    Err(_) => {
                        continue;
                    }
                };
                if job_header != "" {
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
                let resp = match client.execute(req).await {
                    Ok(resp) => resp,
                    Err(_) => {
                        continue;
                    }
                };

                let content_length = match resp.content_length() {
                    Some(content_length) => content_length.to_string(),
                    None => { "" }.to_owned(),
                };
                let backonemore_url = new_url2.clone();

                if job_settings.pub_status.contains(resp.status().as_str()) {
                    // strip the suffix hax and traverse back one more level
                    // to reach the internal doc root.
                    let backonemore = match backonemore_url.strip_suffix(job_payload_new.as_str()) {
                        Some(backonemore) => backonemore,
                        None => "",
                    };
                    let get = client.get(backonemore);
                    let mut request = match get.build() {
                        Ok(request) => request,
                        Err(_) => {
                            continue;
                        }
                    };
                    if job_header != "" {
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

                    let result_url = backonemore.clone();
                    let get = client.get(backonemore);
                    let mut request = match get.build() {
                        Ok(request) => request,
                        Err(_) => {
                            continue;
                        }
                    };
                    if job_header != "" {
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
                    let response = match client.execute(request).await {
                        Ok(response) => response,
                        Err(_) => {
                            continue;
                        }
                    };

                    // we hit the internal doc root.
                    if job_settings
                        .int_status
                        .contains(&response.status().as_str())
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
                        if response.status().is_client_error() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                            ));
                        }
                        if response.status().is_success() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                            ));
                        }
                        if response.status().is_redirection() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                            ));
                        }
                        if response.status().is_server_error() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                            ));
                        }
                        if response.status().is_informational() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n{}{}{} {}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
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
                        return result_job;
                    }
                }
            }

            payload.push_str(&job_payload_new);
        }
        pb.inc(1);
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
