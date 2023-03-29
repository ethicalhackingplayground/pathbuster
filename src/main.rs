use std::error::Error;
use std::io::Write;
use std::process::exit;
use std::time::Duration;

use regex::Regex;

use levenshtein::levenshtein;

use clap::App;
use clap::Arg;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use governor::Quota;
use governor::RateLimiter;

use reqwest::redirect;

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::runtime::Builder;
use tokio::time::Instant;
use tokio::{fs::File, task};

use colored::Colorize;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

// the Job struct which will be used to define our settings for the job
#[derive(Clone, Debug)]
struct JobSettings {
    match_status: String,
    drop_after_fail: String,
}

// the Job struct which will be used to send to the workers
#[derive(Clone, Debug)]
struct Job {
    settings: Option<JobSettings>,
    url: Option<String>,
    payload: Option<String>,
}

// the JobResult struct which contains the data to be saved to a file
#[derive(Clone, Debug)]
pub struct JobResult {
    data: String,
}

// the BruteResult struct which contains the data to be saved to a file
#[derive(Clone, Debug)]
pub struct BruteResult {
    data: String,
}

// the Job struct which will be used for directory bruteforcing
#[derive(Clone, Debug)]
struct BruteJob {
    url: Option<String>,
    word: Option<String>,
}

fn print_banner() {
    const BANNER: &str = r#"                             
                 __  __    __               __           
    ____  ____ _/ /_/ /_  / /_  __  _______/ /____  _____
   / __ \/ __ `/ __/ __ \/ __ \/ / / / ___/ __/ _ \/ ___/
  / /_/ / /_/ / /_/ / / / /_/ / /_/ (__  ) /_/  __/ /    
 / .___/\__,_/\__/_/ /_/_.___/\__,_/____/\__/\___/_/     
/_/                                                          
                     v0.3.9
                     ------
        path normalization pentesting tool                       
    "#;
    write!(&mut rainbowcoat::stdout(), "{}", BANNER).unwrap();
    println!(
        "{}{}{} {}",
        "[".bold().white(),
        "WRN".bold().yellow(),
        "]".bold().white(),
        "Use with caution. You are responsible for your actions"
            .bold()
            .white()
    );
    println!(
        "{}{}{} {}",
        "[".bold().white(),
        "WRN".bold().yellow(),
        "]".bold().white(),
        "Developers assume no liability and are not responsible for any misuse or damage."
            .bold()
            .white()
    );
    println!(
        "{}{}{} {}\n",
        "[".bold().white(),
        "WRN".bold().yellow(),
        "]".bold().white(),
        "By using pathbuster, you also agree to the terms of the APIs used."
            .bold()
            .white()
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // print the banner
    print_banner();

    // parse the cli arguments
    let matches = App::new("pathbuster")
        .version("0.3.9")
        .author("Blake Jacobs <krypt0mux@gmail.com>")
        .about("path-normalization pentesting tool")
        .arg(
            Arg::with_name("urls")
                .short('u')
                .long("urls")
                .takes_value(true)
                .required(true)
                .help("the url you would like to test"),
        )
        .arg(
            Arg::with_name("rate")
                .short('r')
                .long("rate")
                .takes_value(true)
                .default_value("1000")
                .help("Maximum in-flight requests per second"),
        )
        .arg(
            Arg::with_name("drop-after-fail")
                .long("drop-after-fail")
                .takes_value(true)
                .default_value("302,301")
                .required(false)
                .help("ignore requests with the same response code multiple times in a row"),
        )
        .arg(
            Arg::with_name("match-status")
                .long("match-status")
                .takes_value(true)
                .required(false)
                .default_value("400"),
        )
        .arg(
            Arg::with_name("payloads")
                .long("payloads")
                .required(true)
                .takes_value(true)
                .default_value("./payloads/traversals.txt")
                .help("the file containing the traversal payloads"),
        )
        .arg(
            Arg::with_name("wordlist")
                .long("wordlist")
                .required(true)
                .takes_value(true)
                .default_value("./wordlists/wordlist.txt")
                .help("the file containing the wordlist used for directory bruteforcing"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short('c')
                .long("concurrency")
                .default_value("1000")
                .takes_value(true)
                .help("The amount of concurrent requests"),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .default_value("10")
                .takes_value(true)
                .help("The delay between each request"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("workers")
                .default_value("10")
                .takes_value(true)
                .help("The amount of workers"),
        )
        .arg(
            Arg::with_name("out")
                .short('o')
                .long("out")
                .takes_value(true)
                .help("The output file"),
        )
        .get_matches();

    let rate = match matches.value_of("rate").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            println!("{}", "could not parse rate, using default of 1000");
            1000
        }
    };

    let concurrency = match matches.value_of("concurrency").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            println!("{}", "could not parse concurrency, using default of 1000");
            1000
        }
    };

    let drop_after_fail = match matches
        .get_one::<String>("drop-after-fail")
        .map(|s| s.to_string())
    {
        Some(drop_after_fail) => drop_after_fail,
        None => {
            println!(
                "{}",
                "could not parse drop-after-fail, using default of 302,301"
            );
            "".to_string()
        }
    };

    let payloads_path = match matches.value_of("payloads") {
        Some(payloads_path) => payloads_path,
        None => {
            println!("{}", "invalid payloads file");
            exit(1);
        }
    };

    let wordlist_path = match matches.value_of("wordlist") {
        Some(wordlist_path) => wordlist_path,
        None => {
            println!("{}", "invalid wordlist file");
            exit(1);
        }
    };
    let urls_path = match matches.get_one::<String>("urls").map(|s| s.to_string()) {
        Some(urls_path) => urls_path,
        None => "".to_string(),
    };
    // copy some variables
    let _urls_path = urls_path.clone();

    let match_status = match matches
        .get_one::<String>("match-status")
        .map(|s| s.to_string())
    {
        Some(match_status) => match_status,
        None => "".to_string(),
    };

    let timeout = match matches.get_one::<String>("timeout").map(|s| s.to_string()) {
        Some(timeout) => timeout.parse::<usize>().unwrap(),
        None => 10,
    };

    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            println!("{}", "could not parse workers, using default of 10");
            10
        }
    };

    // Set up a worker pool with 4 threads
    let rt = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(w)
        .build()
        .unwrap();

    let now = Instant::now();

    // define the file handle for the wordlists.
    let payloads_handle = match File::open(payloads_path).await {
        Ok(payloads_handle) => payloads_handle,
        Err(e) => {
            println!("failed to open input file: {:?}", e);
            exit(1);
        }
    };

    // define the file handle for the wordlists.
    let wordlist_handle = match File::open(wordlist_path).await {
        Ok(wordlist_handle) => wordlist_handle,
        Err(e) => {
            println!("failed to open input file: {:?}", e);
            exit(1);
        }
    };

    // build our wordlists by constructing the arrays and storing
    // the words in the array.
    let (job_tx, job_rx) = spmc::channel::<Job>();
    let (result_tx, _result_rx) = mpsc::channel::<JobResult>(w);

    let mut urls = vec![];
    let mut payloads = vec![];
    let mut wordlist = vec![];

    let payload_buf = BufReader::new(payloads_handle);
    let mut payload_lines = payload_buf.lines();

    // read the payloads file and append each line to an array.
    while let Ok(Some(payload)) = payload_lines.next_line().await {
        payloads.push(payload);
    }

    let wordlist_buf = BufReader::new(wordlist_handle);
    let mut wordlist_lines = wordlist_buf.lines();

    // read the payloads file and append each line to an array.
    while let Ok(Some(word)) = wordlist_lines.next_line().await {
        wordlist.push(word);
    }

    // read the hosts file if specified and append each line to an array.
    let urls_handle = match File::open(urls_path).await {
        Ok(urls_handle) => urls_handle,
        Err(e) => {
            println!("failed to open input file: {:?}", e);
            exit(1);
        }
    };
    let urls_buf = BufReader::new(urls_handle);
    let mut urls_lines = urls_buf.lines();
    while let Ok(Some(url)) = urls_lines.next_line().await {
        urls.push(url);
    }

    // set the message
    println!(
        "{}",
        "----------------------------------------------------------"
            .bold()
            .white()
    );
    println!(
        "{}  {}    {} {}\n{}  {}        {} {}\n{}  {}    {} {}\n{}  {} {} {}\n{}  {}     {} {}",
        ">".bold().green(),
        "Payloads".bold().white(),
        ":".bold().white(),
        payloads.len().to_string().bold().cyan(),
        ">".bold().green(),
        "Urls".bold().white(),
        ":".bold().white(),
        urls.len().to_string().bold().cyan(),
        ">".bold().green(),
        "Matchers".bold().white(),
        ":".bold().white(),
        match_status.to_string().bold().cyan(),
        ">".bold().green(),
        "Concurrency".bold().white(),
        ":".bold().white(),
        concurrency.to_string().bold().cyan(),
        ">".bold().green(),
        "Workers".bold().white(),
        ":".bold().white(),
        w.to_string().bold().cyan(),
    );
    println!(
        "{}",
        "----------------------------------------------------------"
            .bold()
            .white()
    );
    println!("");

    let pb = ProgressBar::new(0);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.enable_steady_tick(Duration::from_millis(500));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.blue} {elapsed} ({len}) {pos} {msg}")
            .unwrap()
            .progress_chars(r#"#>-"#),
    );

    // spawn our workers
    let out_pb = pb.clone();
    let job_pb = pb.clone();
    rt.spawn(
        async move { send_url(job_tx, urls, payloads, rate, match_status, drop_after_fail).await },
    );

    // process the jobs
    let workers = FuturesUnordered::new();

    // process the jobs for scanning.
    for _ in 0..concurrency {
        let jrx = job_rx.clone();
        let jtx: mpsc::Sender<JobResult> = result_tx.clone();
        let jpb = job_pb.clone();
        workers.push(task::spawn(async move {
            run_tester(jpb, jrx, jtx, timeout).await
        }));
    }

    let outfile_path = match matches.value_of("out") {
        Some(outfile_path) => outfile_path,
        None => {
            println!("{}", "invalid output file path");
            exit(1);
        }
    };

    let mut outfile_path_brute = String::from("discovered-routes");
    outfile_path_brute.push_str(".txt");

    // print the results
    let out_pb = out_pb.clone();
    let brute_wordlist = wordlist.clone();
    let worker_results: Vec<_> = workers.collect().await;
    let mut results: Vec<String> = vec![];
    for result in worker_results {
        let result = match result {
            Ok(result) => result,
            Err(_) => continue,
        };
        let result_data = result.data.clone();
        let out_data = result.data.clone();
        if result.data.is_empty() == false {
            let out_pb = out_pb.clone();
            results.push(result_data);
            let outfile_handle_traversal = match OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(outfile_path)
                .await
            {
                Ok(outfile_handle_traversal) => outfile_handle_traversal,
                Err(e) => {
                    println!("failed to open output file: {:?}", e);
                    exit(1);
                }
            };
            save_traversals(out_pb, outfile_handle_traversal, out_data).await;
        }
    }
    for result in results {
        let outfile_path_brute = outfile_path_brute.clone();
        let outfile_handle_brute = match OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(outfile_path_brute)
            .await
        {
            Ok(outfile_handle_brute) => outfile_handle_brute,
            Err(e) => {
                println!("failed to open output file: {:?}", e);
                exit(1);
            }
        };
        let out_pb = out_pb.clone();
        out_pb.set_length(0);
        let brute_wordlist = brute_wordlist.clone();
        let (brute_job_tx, brute_job_rx) = spmc::channel::<BruteJob>();
        let (brute_result_tx, brute_result_rx) = mpsc::channel::<BruteResult>(w);
        // start orchestrator tasks
        rt.spawn(async move { send_word_to_url(brute_job_tx, result, brute_wordlist, rate).await });
        rt.spawn(
            async move { save_discoveries(out_pb, outfile_handle_brute, brute_result_rx).await },
        );
        // process the jobs for directory bruteforcing.
        let workers = FuturesUnordered::new();
        for _ in 0..concurrency {
            let brx = brute_job_rx.clone();
            let btx: mpsc::Sender<BruteResult> = brute_result_tx.clone();
            let bpb = job_pb.clone();
            workers.push(task::spawn(async move {
                run_bruteforcer(bpb, brx, btx, timeout).await
            }));
        }
        let worker_results: Vec<_> = workers.collect().await;
        for result in worker_results {
            let result = match result {
                Ok(result) => result,
                Err(_) => continue,
            };
            if result.data.is_empty() == false {
                println!(
                    "{} {}",
                    "discovered ::".bold().green(),
                    result.data.bold().white()
                );
            }
        }
    }

    rt.shutdown_background();

    let elapsed_time = now.elapsed();

    println!(
        "{}, {} {}{}",
        "Completed!".bold().green(),
        "scan took".bold().white(),
        elapsed_time.as_secs().to_string().bold().white(),
        "s".bold().white()
    );
    println!(
        "{} {}",
        "results are saved in".bold().white(),
        outfile_path.bold().cyan(),
    );

    Ok(())
}

// this function will send the jobs to the workers
async fn send_url(
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

    // start the scan
    for url in urls.iter() {
        for payload in payloads.iter() {
            let msg = Job {
                settings: Some(job_settings.clone()),
                url: Some(url.clone()),
                payload: Some(payload.clone()),
            };
            if let Err(_) = tx.send(msg) {
                continue;
            }
        }
        lim.until_ready().await;
    }
    Ok(())
}

// this function will send the jobs to the workers
async fn send_word_to_url(
    mut tx: spmc::Sender<BruteJob>,
    url: String,
    wordlists: Vec<String>,
    rate: u32,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // start the scan
    for word in wordlists.iter() {
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
async fn run_bruteforcer(
    pb: ProgressBar,
    rx: spmc::Receiver<BruteJob>,
    tx: mpsc::Sender<BruteResult>,
    timeout: usize,
) -> BruteResult {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    //no certs
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(timeout.try_into().unwrap()))
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    while let Ok(job) = rx.recv() {
        let job_url = job.url.unwrap();
        let job_word = job.word.unwrap();
        let job_url_new = job_url.clone();

        let mut web_root_url: String = String::from("");
        let mut internal_web_root_url: String = String::from(job_url);
        let url = match reqwest::Url::parse(&job_url_new) {
            Ok(url) => url,
            Err(_) => {
                continue;
            }
        };

        pb.inc(1);

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

        let public_cl = match public_resp.content_length() {
            Some(public_cl) => public_cl.to_string(),
            None => continue,
        };

        let internal_cl = match internal_resp.content_length() {
            Some(internal_cl) => internal_cl.to_string(),
            None => continue,
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

        let distance_between_responses = levenshtein(&internal_cl, &public_cl);
        if distance_between_responses > 2
            && resp.status().as_str() != "404"
            && resp.status().as_str() != "400"
        {
            pb.println(format!(
                "{} {}{}{} {} {}",
                "found something interesting".bold().green(),
                "(".bold().white(),
                distance_between_responses.to_string().bold().white(),
                ")".bold().white(),
                "deviations from webroot ::".bold().white(),
                internal_url.bold().blue(),
            ));
            pb.inc_length(1);

            // send the result message through the channel to the workers.
            let result_msg = BruteResult {
                data: internal_url.to_owned(),
            };
            let result = result_msg.clone();
            if let Err(_) = tx.send(result_msg).await {
                continue;
            }

            return result;
        }
    }
    return BruteResult {
        data: "".to_string(),
    };
}

// this function will test for path normalization vulnerabilities
async fn run_tester(
    pb: ProgressBar,
    rx: spmc::Receiver<Job>,
    tx: mpsc::Sender<JobResult>,
    timeout: usize,
) -> JobResult {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0",
        ),
    );

    //no certs
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(timeout.try_into().unwrap()))
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

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
            pb.set_message(format!(
                "{} {}",
                "scanning ::".bold().white(),
                new_url.bold().blue(),
            ));
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

            // let content_length = match resp.content_length() {
            //     Some(content_length) => content_length.to_string(),
            //     None => "".to_string(),
            // };
            // if job_settings.filter_body_size.contains(&content_length)
            //     || job_settings.filter_status.contains(resp.status().as_str())
            // {
            //     continue;
            // }
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
                let distance_between_responses = levenshtein(&internal_cl, &public_cl);
                if response.status().as_str() != "400"
                    && distance_between_responses > 2
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

async fn save_traversals(_: ProgressBar, mut outfile: File, traversal: String) {
    let mut outbuf = traversal.as_bytes().to_owned();
    outbuf.extend_from_slice(b"\n");
    if let Err(_) = outfile.write(&outbuf).await {
        // pb.println(format!("failed to write output '{:?}': {:?}", outbuf, e));
        return;
    }
}

// Saves the output to a file
async fn save_discoveries(_: ProgressBar, mut outfile: File, mut brx: mpsc::Receiver<BruteResult>) {
    while let Some(result) = brx.recv().await {
        let mut outbuf = result.data.as_bytes().to_owned();
        outbuf.extend_from_slice(b"\n");
        if let Err(_) = outfile.write(&outbuf).await {
            // pb.println(format!("failed to write output '{:?}': {:?}", outbuf, e));
            continue;
        }
    }
}
