use std::error::Error;
use std::io::Write;
use std::process::exit;
use std::time::Duration;

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

use urlencoding::encode;

// the Job struct which will be used to define our settings for the job
#[derive(Clone, Debug)]
struct JobSettings {
    deviation: String,
    match_status: String,
    filter_body_size: String,
    filter_status: String,
    drop_after_fail: String,
}

// the Job struct which will be used to send to the workers
#[derive(Clone, Debug)]
struct Job {
    settings: Option<JobSettings>,
    host: Option<String>,
    url: Option<String>,
    path: Option<String>,
    payload: Option<String>,
    word: Option<String>,
}

// the JobResult struct which contains the data to be saved to a file
#[derive(Clone, Debug)]
pub struct JobResult {
    data: String,
}

fn print_banner() {
    const BANNER: &str = r#"                             
                 __  __    __               __           
    ____  ____ _/ /_/ /_  / /_  __  _______/ /____  _____
   / __ \/ __ `/ __/ __ \/ __ \/ / / / ___/ __/ _ \/ ___/
  / /_/ / /_/ / /_/ / / / /_/ / /_/ (__  ) /_/  __/ /    
 / .___/\__,_/\__/_/ /_/_.___/\__,_/____/\__/\___/_/     
/_/                                                          
                                v0.2.0                              
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
        .version("0.2.0")
        .author("Blake Jacobs <blake@cyberlix.io")
        .about("path-normalization pentesting tool")
        .arg(
            Arg::with_name("url")
                .short('u')
                .long("url")
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
                .default_value("200"),
        )
        .arg(
            Arg::with_name("filter-body-size")
                .long("filter-body-size")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::with_name("filter-status")
                .long("filter-status")
                .takes_value(true)
                .default_value("302,301")
                .required(false),
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
                .required(false)
                .takes_value(true)
                .default_value("")
                .help("the file containing the technology paths"),
        )
        .arg(
            Arg::with_name("hosts")
                .long("hosts")
                .required(false)
                .takes_value(true)
                .default_value("")
                .help("the file containing the list of root domains"),
        )
        .arg(
            Arg::with_name("paths")
                .long("paths")
                .required(false)
                .takes_value(true)
                .default_value("")
                .help("the file containing the list of routes (crawl the host to collect routes)"),
        )
        .arg(
            Arg::with_name("deviation")
                .long("deviation")
                .required(true)
                .takes_value(true)
                .default_value("3")
                .help("The distance between the responses"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short('c')
                .long("concurrency")
                .default_value("100")
                .takes_value(true)
                .help("The amount of concurrent requests"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("workers")
                .default_value("1")
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

    // find out what argument we are using
    let pb = ProgressBar::new(0);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {elapsed} ({len}) {pos} {per_sec}")
            .unwrap()
            .progress_chars(r#"#>-"#),
    );

    let rate = match matches.value_of("rate").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            pb.println("could not parse rate, using default of 1000");
            1000
        }
    };

    let concurrency = match matches.value_of("concurrency").unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            pb.println("could not parse concurrency, using default of 100");
            100
        }
    };

    let url_arg = match matches.get_one::<String>("url").map(|s| s.to_string()) {
        Some(url_arg) => url_arg,
        None => "".to_string(),
    };

    let deviation = match matches
        .get_one::<String>("deviation")
        .map(|s| s.to_string())
    {
        Some(deviation) => deviation,
        None => "".to_string(),
    };

    let drop_after_fail = match matches
        .get_one::<String>("drop-after-fail")
        .map(|s| s.to_string())
    {
        Some(drop_after_fail) => drop_after_fail,
        None => {
            pb.println("could not parse drop-after-fail, using default of 302,301");
            "".to_string()
        }
    };

    let wordlist_path = match matches.value_of("wordlist") {
        Some(wordlist_path) => wordlist_path,
        None => {
            pb.println("invalid wordlist file");
            exit(1);
        }
    };
    // copy some variables
    let _wordlist_path = wordlist_path.clone();

    let payloads_path = match matches.value_of("payloads") {
        Some(payloads_path) => payloads_path,
        None => {
            pb.println("invalid payloads file");
            exit(1);
        }
    };

    let paths_path = match matches.get_one::<String>("paths").map(|s| s.to_string()) {
        Some(paths_path) => paths_path,
        None => "".to_string(),
    };
    // copy some variables
    let _paths_path = paths_path.clone();

    let hosts_path = match matches.get_one::<String>("hosts").map(|s| s.to_string()) {
        Some(hosts_path) => hosts_path,
        None => "".to_string(),
    };
    // copy some variables
    let _hosts_path = hosts_path.clone();

    let match_status = match matches
        .get_one::<String>("match-status")
        .map(|s| s.to_string())
    {
        Some(match_status) => match_status,
        None => "".to_string(),
    };
    let filter_body_size = match matches
        .get_one::<String>("filter-body-size")
        .map(|s| s.to_string())
    {
        Some(filter_body_size) => filter_body_size,
        None => "".to_string(),
    };
    let filter_status = match matches
        .get_one::<String>("filter-status")
        .map(|s| s.to_string())
    {
        Some(filter_status) => filter_status,
        None => "".to_string(),
    };
    let outfile_path = match matches.value_of("out") {
        Some(outfile_path) => outfile_path,
        None => {
            pb.println("invalid output file path");
            exit(1);
        }
    };

    let outfile_handle = match OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(outfile_path)
        .await
    {
        Ok(outfile_handle) => outfile_handle,
        Err(e) => {
            pb.println(format!("failed to open output file: {:?}", e));
            exit(1);
        }
    };

    let w: usize = match matches.value_of("workers").unwrap().parse::<usize>() {
        Ok(w) => w,
        Err(_) => {
            pb.println("could not parse workers, using default of 1");
            1
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
            pb.println(format!("failed to open input file: {:?}", e));
            exit(1);
        }
    };

    // build our wordlists by constructing the arrays and storing
    // the words in the array.
    let (job_tx, job_rx) = spmc::channel::<Job>();
    let (result_tx, result_rx) = mpsc::channel::<JobResult>(w);

    let mut hosts = vec![];
    let mut wordlists = vec![];
    let mut payloads = vec![];
    let mut paths = vec![];

    let payload_buf = BufReader::new(payloads_handle);
    let mut payload_lines = payload_buf.lines();

    // set the message
    println!(
        "{}{}{} {}",
        "[".bold().white(),
        "+".bold().green(),
        "]".bold().white(),
        "Generating Payloads".bold().white()
    );

    // read the payloads file and append each line to an array.
    while let Ok(Some(payload)) = payload_lines.next_line().await {
        let _payload = encode(&payload.to_string()).to_string();
        payloads.push(_payload);
        payloads.push(payload);
    }

    // read the wordlist file if specified and append each line to an array.
    if !_wordlist_path.is_empty() {
        let wordlists_handle = match File::open(wordlist_path).await {
            Ok(wordlists_handle) => wordlists_handle,
            Err(e) => {
                pb.println(format!("failed to open input file: {:?}", e));
                exit(1);
            }
        };
        let wordlist_buf = BufReader::new(wordlists_handle);
        let mut wordlist_lines = wordlist_buf.lines();
        while let Ok(Some(words)) = wordlist_lines.next_line().await {
            wordlists.push(words);
        }
    }

    // read the paths file if specified and append each line to an array.
    if !_paths_path.is_empty() {
        // define the file handle for the wordlists.
        let paths_handle = match File::open(paths_path).await {
            Ok(paths_handle) => paths_handle,
            Err(e) => {
                pb.println(format!("failed to open input file: {:?}", e));
                exit(1);
            }
        };
        let paths_buf = BufReader::new(paths_handle);
        let mut path_lines = paths_buf.lines();
        while let Ok(Some(path)) = path_lines.next_line().await {
            paths.push(path);
        }
    }

    // read the hosts file if specified and append each line to an array.
    if !_hosts_path.is_empty() {
        let hosts_handle = match File::open(hosts_path).await {
            Ok(hosts_handle) => hosts_handle,
            Err(e) => {
                pb.println(format!("failed to open input file: {:?}", e));
                exit(1);
            }
        };
        let hosts_buf = BufReader::new(hosts_handle);
        let mut host_lines = hosts_buf.lines();
        while let Ok(Some(host)) = host_lines.next_line().await {
            hosts.push(host);
        }
    }

    // append some more payloads
    for i in 0..=47 {
        let i = char::from_u32(i).unwrap();
        let _payload = encode(&i.to_string()).to_string();
        // single url encoding bypass
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
        // double url encoding bypass
        let _payload = encode(&_payload.to_string()).to_string();
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
    }
    for i in 58..=63 {
        let i = char::from_u32(i).unwrap();
        let _payload = encode(&i.to_string()).to_string();
        // single url encoding bypass
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
        // double url encoding bypass
        let _payload = encode(&_payload.to_string()).to_string();
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
    }
    for i in 91..=96 {
        let i = char::from_u32(i).unwrap();
        let _payload = encode(&i.to_string()).to_string();
        // single url encoding bypass
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
        // double url encoding bypass
        let _payload = encode(&_payload.to_string()).to_string();
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
    }
    for i in 160..=844 {
        let i = char::from_u32(i).unwrap();
        let _payload = encode(&i.to_string()).to_string();
        // single url encoding bypass
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
        // double url encoding bypass
        let _payload = encode(&_payload.to_string()).to_string();
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
    }
    for i in 8194..=8332 {
        let i = char::from_u32(i).unwrap();
        let _payload = encode(&i.to_string()).to_string();
        // single url encoding bypass
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
        // double url encoding bypass
        let _payload = encode(&_payload.to_string()).to_string();
        if _payload.contains("%") {
            payloads.push(_payload.to_string());
        }
    }

    // print the number of generated payloads.
    // set the message
    println!(
        "{}{}{} {} {} {}\n",
        "[".bold().white(),
        "+".bold().green(),
        "]".bold().white(),
        "Generated".bold().white(),
        payloads.len().to_string().bold().white(),
        "payloads".bold().white()
    );

    // spawn our workers
    rt.spawn(async move {
        send_url(
            job_tx,
            url_arg.to_string(),
            hosts,
            paths,
            wordlists,
            payloads,
            rate,
            match_status,
            deviation,
            filter_body_size,
            filter_status,
            drop_after_fail,
        )
        .await
    });
    let out_pb = pb.clone();
    rt.spawn(async move {
        // start orchestrator task
        output(out_pb, outfile_handle, result_rx).await;
    });

    // process the jobs.
    let workers = FuturesUnordered::new();
    for _ in 0..concurrency {
        let rx = job_rx.clone();
        let tx: mpsc::Sender<JobResult> = result_tx.clone();
        let pb = pb.clone();
        workers.push(task::spawn(async move { run_tester(pb, rx, tx).await }));
    }

    // print the results
    let _results: Vec<_> = workers.collect().await;
    let elapsed_time = now.elapsed();
    rt.shutdown_background();
    println!(
        "\n{}, {} {}{}",
        "Completed!".bold().green(),
        "scan took".bold().white(),
        elapsed_time.as_secs().to_string().bold().white(),
        "s".bold().white()
    );

    Ok(())
}

// this function will send the jobs to the workers
async fn send_url(
    mut tx: spmc::Sender<Job>,
    url: String,
    hosts: Vec<String>,
    paths: Vec<String>,
    wordlists: Vec<String>,
    payloads: Vec<String>,
    rate: u32,
    match_status: String,
    deviation: String,
    filter_body_size: String,
    filter_status: String,
    drop_after_fail: String,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // the job settings
    let job_settings = JobSettings {
        filter_status: filter_status,
        filter_body_size: filter_body_size,
        deviation: deviation.to_string(),
        match_status: match_status.to_string(),
        drop_after_fail: drop_after_fail,
    };

    // only fuzz with hosts, paths and payloads, if the wordlist is not defined
    if !hosts.is_empty() && !paths.is_empty() {
        for host in hosts.iter() {
            for path in paths.iter() {
                for payload in payloads.iter() {
                    let msg = Job {
                        host: Some(host.clone()),
                        path: Some(path.clone()),
                        settings: Some(job_settings.clone()),
                        url: Some(url.clone()),
                        payload: Some(payload.clone()),
                        word: Some("".to_string()),
                    };
                    if let Err(_) = tx.send(msg) {
                        continue;
                    }
                }
            }
        }

    // fuzz using payloads in paths
    } else if !paths.is_empty() {
        for path in paths.iter() {
            for payload in payloads.iter() {
                let msg = Job {
                    host: Some("".to_string()),
                    path: Some(path.clone()),
                    settings: Some(job_settings.clone()),
                    url: Some(url.clone()),
                    payload: Some(payload.clone()),
                    word: Some("".to_string()),
                };
                if let Err(_) = tx.send(msg) {
                    continue;
                }
            }
        }

    // fuzz using both payloads, paths and wordlists, if they are both defined
    } else if !wordlists.is_empty() && !paths.is_empty() {
        for path in paths.iter() {
            for payload in payloads.iter() {
                for word in wordlists.iter() {
                    let msg = Job {
                        host: Some("".to_string()),
                        path: Some(path.clone()),
                        settings: Some(job_settings.clone()),
                        url: Some(url.clone()),
                        payload: Some(payload.clone()),
                        word: Some(word.clone()),
                    };
                    if let Err(_) = tx.send(msg) {
                        continue;
                    }
                }
            }
        }

    // fuzz using both payloads, hosts, paths and wordlists, if they are both defined
    } else if !hosts.is_empty() && !paths.is_empty() && !wordlists.is_empty() {
        for host in hosts.iter() {
            for path in paths.iter() {
                for payload in payloads.iter() {
                    for word in wordlists.iter() {
                        let msg = Job {
                            host: Some(host.clone()),
                            path: Some(path.clone()),
                            settings: Some(job_settings.clone()),
                            url: Some(url.clone()),
                            payload: Some(payload.clone()),
                            word: Some(word.clone()),
                        };
                        if let Err(_) = tx.send(msg) {
                            continue;
                        }
                    }
                }
            }
        }

    // require args are not specified
    } else {
        for payload in payloads.iter() {
            for word in wordlists.iter() {
                let msg = Job {
                    host: Some("".to_string()),
                    path: Some("".to_string()),
                    settings: Some(job_settings.clone()),
                    url: Some(url.clone()),
                    payload: Some(payload.clone()),
                    word: Some(word.clone()),
                };
                if let Err(_) = tx.send(msg) {
                    continue;
                }
            }
        }
    }
    lim.until_ready().await;
    Ok(())
}

// this function will test for path normalization vulnerabilities
async fn run_tester(pb: ProgressBar, rx: spmc::Receiver<Job>, tx: mpsc::Sender<JobResult>) {
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
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    while let Ok(job) = rx.recv() {
        let job_url = job.url.unwrap();
        let job_word = job.word.unwrap();
        let job_payload = job.payload.unwrap();
        let job_path = job.path.unwrap();
        let job_host = job.host.unwrap();
        let job_settings = job.settings.unwrap();
        let job_path_new = job_path.clone();
        let job_payload_new = job_payload.clone();
        let job_url_new = job_url.clone();
        let job_host_new = job_host.clone();

        pb.inc(1);

        let mut _path = String::from(job_path);
        let mut _payload = String::from(job_payload);
        let path_cnt = job_path_new.split("/").count() + 5;
        let mut track_status_codes = 0;
        for _ in 0..path_cnt {
            let mut _new_url = String::from(&job_url_new);
            if job_payload_new.is_empty() == false {
                _new_url = _new_url.replace("{payloads}", &_payload);
            }
            if job_word.is_empty() == false {
                _new_url = _new_url.replace("{words}", &job_word);
            }
            if job_path_new.is_empty() == false {
                _new_url = _new_url.replace("{paths}", &job_path_new);
            }
            if job_host_new.is_empty() == false {
                _new_url = _new_url.replace("{hosts}", &job_host);
            }

            let mut url = String::from("");
            url.push_str(&_new_url);
            let print_url = url.clone();

            let get = client.get(url);
            let req = match get.build() {
                Ok(req) => req,
                Err(_) => continue,
            };

            let resp = match client.execute(req).await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let content_length = match resp.content_length() {
                Some(content_length) => content_length.to_string(),
                None => { "" }.to_owned(),
            };
            let out_url = print_url.clone();
            if resp
                .status()
                .to_string()
                .contains(&job_settings.match_status)
                && content_length.is_empty() == false
            {
                if job_settings.filter_body_size.contains(&content_length) {
                    return;
                }

                if resp
                    .status()
                    .to_string()
                    .contains(&job_settings.filter_status)
                {
                    return;
                }
                // track the status codes
                if job_settings.drop_after_fail == resp.status().as_str() {
                    track_status_codes += 1;
                    if track_status_codes >= 5 {
                        // set the message
                        println!(
                            "{}{}{} {} {} {}",
                            "[".bold().white(),
                            "+".bold().red(),
                            "]".bold().white(),
                            "skipping".bold().white(),
                            print_url.bold().white(),
                            "recurring status codes ".bold().white()
                        );
                        return;
                    }
                }

                let parsed_url = match reqwest::Url::parse(&print_url) {
                    Ok(parsed_url) => parsed_url,
                    Err(e) => {
                        pb.println(format!("There is an error parsing the URL: {:?}", e));
                        continue;
                    }
                };

                let mut new_url = String::from("");
                new_url.push_str(parsed_url.scheme());
                new_url.push_str("://");
                new_url.push_str(parsed_url.host_str().unwrap());
                new_url.push_str("/");
                new_url.push_str(&job_word);

                let get = client.get(new_url);
                let req = match get.build() {
                    Ok(req) => req,
                    Err(_) => continue,
                };

                let web_root_resp = match client.execute(req).await {
                    Ok(web_root_resp) => web_root_resp,
                    Err(_) => continue,
                };

                let web_root_content_length = match web_root_resp.content_length() {
                    Some(web_root_content_length) => web_root_content_length.to_string(),
                    None => "".to_string(),
                };

                let response_deviation = levenshtein(&web_root_content_length, &content_length);
                let deviation = match job_settings.deviation.parse::<usize>() {
                    Ok(deviation) => deviation,
                    Err(_) => continue,
                };

                if response_deviation >= deviation {
                    if resp.status().is_client_error() {
                        pb.println(format!(
                            "{}{}{} {}{}{} {}{}{}",
                            "[".bold().white(),
                            resp.status().as_str().bold().blue(),
                            "]".bold().white(),
                            "[".bold().white(),
                            content_length.dimmed().white(),
                            "]".bold().white(),
                            "[".bold().white(),
                            print_url.bold().cyan(),
                            "]".bold().white()
                        ));
                    }

                    if resp.status().is_success() {
                        pb.println(format!(
                            "{}{}{} {}{}{} {}{}{}",
                            "[".bold().white(),
                            resp.status().as_str().bold().green(),
                            "]".bold().white(),
                            "[".bold().white(),
                            content_length.dimmed().white(),
                            "]".bold().white(),
                            "[".bold().white(),
                            print_url.bold().cyan(),
                            "]".bold().white()
                        ));
                    }

                    if resp.status().is_redirection() {
                        pb.println(format!(
                            "{}{}{} {}{}{} {}{}{}",
                            "[".bold().white(),
                            resp.status().as_str().bold().cyan(),
                            "]".bold().white(),
                            "[".bold().white(),
                            content_length.dimmed().white(),
                            "]".bold().white(),
                            "[".bold().white(),
                            print_url.bold().cyan(),
                            "]".bold().white()
                        ));
                    }

                    if resp.status().is_server_error() {
                        pb.println(format!(
                            "{}{}{} {}{}{} {}{}{}",
                            "[".bold().white(),
                            resp.status().as_str().bold().red(),
                            "]".bold().white(),
                            "[".bold().white(),
                            content_length.dimmed().white(),
                            "]".bold().white(),
                            "[".bold().white(),
                            print_url.bold().cyan(),
                            "]".bold().white()
                        ));
                    }

                    if resp.status().is_informational() {
                        pb.println(format!(
                            "{}{}{} {}{}{} {}{}{}",
                            "[".bold().white(),
                            resp.status().as_str().bold().purple(),
                            "]".bold().white(),
                            "[".bold().white(),
                            content_length.dimmed().white(),
                            "]".bold().white(),
                            "[".bold().white(),
                            print_url.bold().cyan(),
                            "]".bold().white()
                        ));
                    }

                    // send the result message through the channel to the workers.
                    let result_msg = JobResult { data: out_url };
                    if let Err(_) = tx.send(result_msg).await {
                        continue;
                    }
                    pb.inc_length(1);
                }
            }
            _payload.push_str(&job_payload_new);
        }
    }
}

// Saves the output to a file
async fn output(_: ProgressBar, mut outfile: File, mut rx: mpsc::Receiver<JobResult>) {
    while let Some(result) = rx.recv().await {
        let mut outbuf = result.data.as_bytes().to_owned();
        outbuf.extend_from_slice(b"\n");
        if let Err(_) = outfile.write(&outbuf).await {
            // pb.println(format!("failed to write output '{:?}': {:?}", outbuf, e));
            continue;
        }
    }
}
