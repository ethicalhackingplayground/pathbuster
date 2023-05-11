use std::{error::Error, process::exit, time::Duration};

use colored::Colorize;
use differ::{Differ, Tag};
use governor::{Quota, RateLimiter};
use indicatif::ProgressBar;
use itertools::iproduct;
use reqwest::{redirect, Proxy};
use tokio::{fs::File, io::AsyncWriteExt, sync::mpsc};

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

// this asynchronous function will send the results to another set of workers
// for each worker to perform a directory brute force operation on each url.
pub async fn send_word_to_url(
    mut tx: spmc::Sender<BruteJob>,
    urls: Vec<String>,
    wordlists: Vec<String>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // start the scan
    for (word, url) in iproduct!(wordlists, urls) {
        let url_cp = url.clone();
        let msg = BruteJob {
            url: Some(url_cp),
            word: Some(word.clone()),
        };
        if let Err(_) = tx.send(msg) {
            continue;
        }
        lim.until_ready().await;
    }
    Ok(())
}

// runs the directory bruteforcer on the job
pub async fn run_bruteforcer(
    pb: ProgressBar,
    rx: spmc::Receiver<BruteJob>,
    tx: mpsc::Sender<BruteResult>,
    timeout: usize,
    http_proxy: String,
) -> BruteResult {
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
            .redirect(redirect::Policy::none())
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
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_secs(timeout.try_into().unwrap()))
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .proxy(proxy)
            .build()
            .unwrap();
    }

    while let Ok(job) = rx.recv() {
        let job_url = job.url.unwrap();
        let job_word = job.word.unwrap();
        let job_url_new = job_url.clone();
        pb.inc(1);
        let mut web_root_url: String = String::from("");
        let mut internal_web_root_url: String = String::from(job_url);
        let url = match reqwest::Url::parse(&job_url_new) {
            Ok(url) => url,
            Err(_) => {
                continue;
            }
        };

        let schema = url.scheme().to_string();
        let host = match url.host_str() {
            Some(host) => host,
            None => continue,
        };

        web_root_url.push_str(&schema);
        web_root_url.push_str("://");
        web_root_url.push_str(&host);
        web_root_url.push_str("/");
        web_root_url.push_str(&job_word);

        internal_web_root_url.push_str(&job_word);
        let internal_url = internal_web_root_url.clone();
        let internal_web_url = internal_url.clone();

        pb.set_message(format!(
            "{} {}",
            "directory bruteforcing ::".bold().white(),
            internal_url.bold().blue(),
        ));

        let internal_url = internal_web_url.clone();
        let get = client.get(internal_web_url);
        let internal_get = client.get(internal_web_root_url);
        let public_get = client.get(web_root_url);

        let public_req = match public_get.build() {
            Ok(req) => req,
            Err(_) => {
                continue;
            }
        };

        let internal_req = match internal_get.build() {
            Ok(req) => req,
            Err(_) => {
                continue;
            }
        };

        let public_resp = match client.execute(public_req).await {
            Ok(public_resp) => public_resp,
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

        let public_resp_text = match public_resp.text().await {
            Ok(public_resp_text) => public_resp_text,
            Err(_) => continue,
        };

        let internal_resp_text = match internal_resp.text().await {
            Ok(internal_resp_text) => internal_resp_text,
            Err(_) => continue,
        };

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

        let content_length = match resp.content_length() {
            Some(content_length) => content_length.to_string(),
            None => "".to_string(),
        };

        let (ok, distance_between_responses) =
            utils::get_response_change(&internal_resp_text, &public_resp_text);
        if ok && resp.status().as_str() == "200" {
            let internal_resp_text_lines = internal_resp_text.lines().collect::<Vec<_>>();
            let public_resp_text_lines = public_resp_text.lines().collect::<Vec<_>>();
            let character_differences =
                Differ::new(&internal_resp_text_lines, &public_resp_text_lines);

            if character_differences.spans().len() > 0 {
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
                            if span.b_end < internal_resp_text_lines.len() {
                                for line in &internal_resp_text_lines[span.b_start..span.b_end] {
                                    if line.to_string() == "" {
                                        pb.println(format!("\n{}", line.bold().white(),));
                                    } else {
                                        pb.println(format!("{}", line.bold().white(),));
                                    }
                                }
                            } else {
                                for line in &internal_resp_text_lines[span.a_start..span.a_end] {
                                    if line.to_string() == "" {
                                        pb.println(format!("\n{}", line.bold().white(),));
                                    } else {
                                        pb.println(format!("{}", line.bold().white(),));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            pb.println(format!("\n"));
            pb.println(format!(
                "{} {}{}{} {} {}",
                "found something interesting".bold().green(),
                "(".bold().white(),
                distance_between_responses.to_string().bold().white(),
                ")".bold().white(),
                "deviations from webroot ::".bold().white(),
                internal_url.bold().blue(),
            ));

            // send the result message through the channel to the workers.
            let result_msg = BruteResult {
                data: internal_url.to_owned(),
                rs: content_length,
            };
            let result = result_msg.clone();
            if let Err(_) = tx.send(result_msg).await {
                continue;
            }
            pb.inc_length(1);
            return result;
        }
    }
    return BruteResult {
        data: "".to_string(),
        rs: "".to_string(),
    };
}

// Saves the output to a file
pub async fn save_discoveries(
    _: ProgressBar,
    mut outfile: File,
    mut brx: mpsc::Receiver<BruteResult>,
) {
    while let Some(result) = brx.recv().await {
        let mut outbuf = result.data.as_bytes().to_owned();
        outbuf.extend_from_slice(b"\n");
        if let Err(_) = outfile.write(&outbuf).await {
            continue;
        }
    }
}
