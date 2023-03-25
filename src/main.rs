use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
use std::process::Stdio;
use std::process::exit;
use std::process::Command;
use std::time::Duration;

use uuid::Uuid;

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
    verbose: bool,
}

// the Job struct which will be used to send to the workers
#[derive(Clone, Debug)]
struct Job {
    settings: Option<JobSettings>,
    url: Option<String>,
    payload: Option<String>,
}

// the PayloadFilter will be used to filter out the payloads
#[derive(Clone, Debug)]
struct PayloadFilter {
    payload: String,
}

impl PayloadFilter {
    fn is_valid_payload(self: &Self, server: String) -> (String, String, bool) {
        /* perform basic payload filtering */
        let mut server_map = HashMap::new();
        server_map.insert(1, "Apache");
        server_map.insert(2, "Nginx");
        server_map.insert(3, "Stackpath");
        let mut proxy = String::from("");
        let mut invalid = false;
        let mut reason = String::from("");
        if server_map.get(&1).unwrap().contains(&server) {
            // Apache filtering
            invalid = self.payload.contains("%2f") || self.payload.contains("%");
            proxy.push_str(server_map.get(&1).unwrap());
            reason.push_str("doesn't allow #, %, %00 in path, %2f is treated as a 404");
        }
        if server_map.get(&2).unwrap().contains(&server) {
            // Nginx filtering
            invalid = self.payload.contains("%00") || self.payload.contains("%");
            proxy.push_str(server_map.get(&2).unwrap());
            reason.push_str("doesn't allow %00, 0x00, % in path");
        }
        if server_map.get(&3).unwrap().contains(&server) {
            // Stackpath filtering
            invalid =
                self.payload == "%2f%2e%2e%2f" || self.payload == "../" || self.payload == "%";
            proxy.push_str(server_map.get(&3).unwrap());
            reason.push_str("doesn't allow %00, 0x00, % and space in the path ");
            reason.push_str("doesn't allow /../ or %2f%2e%2e%2f (403, WAF)")
        }
        if server.is_empty() {
            // Proxy Unknown filtering
            invalid = false;
        }
        return (proxy, reason, invalid);
    }
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
                                v0.3.0                            
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
        .version("0.2.8")
        .author("Blake Jacobs <blake@cyberlix.io")
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
                .default_value("404,403,401,302,301,500,303,501,502")
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
                .required(true)
                .takes_value(true)
                .default_value("./wordlists/wordlist.txt")
                .help("the file containing the wordlist for discovery"),
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
                .default_value("1")
                .takes_value(true)
                .help("The amount of workers"),
        )
        .arg(
            Arg::with_name("verbose")
                .short('v')
                .long("verbose")
                .default_value("false")
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
            .template("{spinner:.green} Scanning  {elapsed} ({len}) {pos} {per_sec}")
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
            pb.println("could not parse concurrency, using default of 1000");
            1000
        }
    };

    let wordlist_path = match matches.get_one::<String>("wordlist").map(|s| s.to_string()) {
        Some(wordlist_path) => wordlist_path,
        None => "".to_string(),
    };
    let _wordlist_path = wordlist_path.clone();

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

    let payloads_path = match matches.value_of("payloads") {
        Some(payloads_path) => payloads_path,
        None => {
            pb.println("invalid payloads file");
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
    let filter_body_size = match matches
        .get_one::<String>("filter-body-size")
        .map(|s| s.to_string())
    {
        Some(filter_body_size) => filter_body_size,
        None => "".to_string(),
    };
    let _filter_body_size = filter_body_size.clone();
    let filter_status = match matches
        .get_one::<String>("filter-status")
        .map(|s| s.to_string())
    {
        Some(filter_status) => filter_status,
        None => "".to_string(),
    };
    let _filter_status = filter_status.clone();

    let timeout = match matches
        .get_one::<String>("timeout")
        .map(|s| s.to_string())
    {
        Some(timeout) => timeout.parse::<usize>().unwrap(),
        None => 10,
    };


    let verbose = match matches.value_of("verbose").unwrap().parse::<bool>() {
        Ok(verbose) => verbose,
        Err(_) => false,
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

    let mut urls = vec![];
    let mut payloads = vec![];
    let mut wordlist = vec![];

    let payload_buf = BufReader::new(payloads_handle);
    let mut payload_lines = payload_buf.lines();

    // read the payloads file and append each line to an array.
    while let Ok(Some(payload)) = payload_lines.next_line().await {
        payloads.push(payload);
    }

    // read the hosts file if specified and append each line to an array.
    let wordlist_handle = match File::open(wordlist_path).await {
        Ok(wordlist_handle) => wordlist_handle,
        Err(e) => {
            pb.println(format!("failed to open input file: {:?}", e));
            exit(1);
        }
    };
    let wordlist_buf = BufReader::new(wordlist_handle);
    let mut wordlist_lines = wordlist_buf.lines();
    while let Ok(Some(word)) = wordlist_lines.next_line().await {
        wordlist.push(word);
    }

    // read the hosts file if specified and append each line to an array.
    let urls_handle = match File::open(urls_path).await {
        Ok(urls_handle) => urls_handle,
        Err(e) => {
            pb.println(format!("failed to open input file: {:?}", e));
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
        "{} {} {}\t{} {} {}  {} {} {}  {} {}",
        "Payloads:".bold().white(),
        payloads.len().to_string().bold().cyan(),
        ":".bold().green(),
        "Urls:".bold().white(),
        urls.len().to_string().bold().cyan(),
        ":".bold().green(),
        "Matchers:".bold().white(),
        match_status.to_string().bold().cyan(),
        ":".bold().green(),
        "Concurrency:".bold().white(),
        concurrency.to_string().bold().cyan(),
    );
    println!("");

    // spawn our workers
    rt.spawn(async move {
        send_url(
            job_tx,
            urls,
            payloads,
            rate,
            match_status,
            drop_after_fail,
            verbose,
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
        workers.push(task::spawn(async move { run_tester(pb, rx, tx, timeout).await }));
    }

    // print the results
    let _results: Vec<_> = workers.collect().await;
    rt.shutdown_background();

    println!("");
    println!("");
    println!(
        "{}{}{} {}\n",
        "[".bold().white(),
        "RUN".bold().green(),
        "]".bold().white(),
        "Directory bruteforcing Using FFuf".bold().white(),
    );

    let mut _w1 = String::from(outfile_path);
    _w1.push_str(":W1");
    let mut _w2 = String::from(_wordlist_path);
    _w2.push_str(":W2");

    // result output name for ffuf
    let id = Uuid::new_v4();
    let mut _output_results = String::from("pathbuster-");
    _output_results.push_str(&id.to_string());
    _output_results.push_str(".json");
    let child  = Command::new("ffuf")
        .arg("-u")
        .arg("W1W2")
        .arg("-w")
        .arg(_w1)
        .arg("-w")
        .arg(_w2)
        .arg("-v")
        .arg("-c")
        .arg("-t")
        .arg("100")
        .arg("-fs")
        .arg(_filter_body_size)
        .arg("-fc")
        .arg(_filter_status)
        .arg("-o")
        .arg(_output_results)
        .stdout(Stdio::inherit())
        .spawn()
        .expect("failed to execute process");
    
    let output = child
    .wait_with_output()
    .expect("failed to wait on child");


    
    if String::from_utf8_lossy(&output.stderr).is_empty() {
        println!(
            "{} {}",
            ">".bold().blue(),
            String::from_utf8_lossy(&output.stdout).bold().white()
        );
    } else {
        println!("{}", String::from_utf8_lossy(&output.stderr).bold().red());
    }

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
    verbose: bool,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));

    // the job settings
    let job_settings = JobSettings {
        match_status: match_status.to_string(),
        drop_after_fail: drop_after_fail,
        verbose: verbose,
    };

    // start the scan
    for url in urls.iter() {
        for payload in payloads.iter() {
            let msg = Job {
                url: Some(url.clone()),
                settings: Some(job_settings.clone()),
                payload: Some(payload.clone()),
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
async fn run_tester(pb: ProgressBar, rx: spmc::Receiver<Job>, tx: mpsc::Sender<JobResult>, timeout:usize) {
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
        let job_payload_new = job_payload.clone();
        let job_url_new = job_url.clone();
        pb.inc(1);

        let mut job_url: String = String::from("");
        let url = match reqwest::Url::parse(&job_url_new) {
            Ok(url) => url,
            Err(_) => {
                continue;
            },
        };

        let schema = url.scheme().to_string();
        let path = url.path().to_string();
        let host = match url.host_str() {
            Some(host) => host,
            None => continue,
        };

        job_url.push_str(&schema);
        job_url.push_str("://");
        job_url.push_str(&host);
        job_url.push_str(&path);

        let path_cnt = path.split("/").count() + 3;
        let mut payload = String::from(job_payload);
        let new_url = String::from(&job_url);
        let mut track_status_codes = 0;
        for _ in 0..path_cnt {
            let mut new_url = new_url.clone();
            if !new_url.as_str().ends_with("/") {
                new_url.push_str("/");
            }
            new_url.push_str(&payload);
            new_url.push_str("hax");

            let payload_to_filter = payload.clone();

            if job_settings.verbose == true {
                pb.println(format!(
                    "{}{}{} {} {}",
                    "[".bold().white(),
                    "*".bold().cyan(),
                    "]".bold().white(),
                    "Scanning Url ".bold().white(),
                    new_url.dimmed().blue(),
                ));
            }

            let new_url2 = new_url.clone();
            let get = client.get(new_url);
            let req = match get.build() {
                Ok(req) => req,
                Err(_) => {
                    continue;
                },
            };

            let resp = match client.execute(req).await {
                Ok(resp) => resp,
                Err(_) => {
                    continue;
                },
            };

            // fetch the server from the headers
            let server = match resp.headers().get("Server") {
                Some(server) => match server.to_str() {
                    Ok(server) => server,
                    Err(_) => "Unknown",
                },
                None => "Unknown",
            };

            let payload_filter = PayloadFilter {
                payload: payload_to_filter,
            };
            let (proxy, reason, invalid) = payload_filter.is_valid_payload(server.to_string());
            if !invalid {
                let content_length = match resp.content_length() {
                    Some(content_length) => content_length.to_string(),
                    None => { "" }.to_owned(),
                };

                let backonemore_url = new_url2.clone();
                if job_settings.match_status.contains(resp.status().as_str())
                    && content_length.is_empty() == false
                {
                    // strip the suffix hax and traverse back one more level
                    // to reach the internal doc root.
                    let strip_suffix = match backonemore_url.strip_suffix("hax") {
                        Some(backonemore) => backonemore,
                        None => "",
                    };
                    let backonemore = match strip_suffix.strip_suffix(job_payload_new.as_str()) {
                        Some(backonemore) => backonemore,
                        None => "",
                    };

                    let result_url = backonemore.clone();
                    let get = client.get(backonemore);
                    let request = match get.build() {
                        Ok(request) => request,
                        Err(_) => {
                            continue;
                        },
                    };
                    let response = match client.execute(request).await {
                        Ok(response) => response,
                        Err(_) => {
                            continue;
                        },
                    };

                    // we git the internal doc root.
                    if (response.status().as_str() == "404" || response.status().as_str() == "500")
                        && result_url.contains(&job_payload_new)
                    {
                        // track the status codes
                        if job_settings.drop_after_fail == response.status().as_str() {
                            track_status_codes += 1;
                            if track_status_codes >= 5 {
                                if job_settings.verbose == true {
                                    // set the message
                                    println!(
                                        "{}{}{} {} {} {}",
                                        "[".bold().white(),
                                        "+".bold().red(),
                                        "]".bold().white(),
                                        "skipping".bold().white(),
                                        result_url.bold().white(),
                                        "recurring status codes ".bold().white()
                                    );
                                }
                                return;
                            }
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
                                "{}{}{} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                                "[".bold().white(),
                                "OK".bold().green(),
                                "]".bold().white(),
                                "[".bold().white(),
                                result_url.bold().cyan(),
                                "]".bold().white(),
                                "status:".bold().white(),
                                "[".bold().white(),
                                response.status().as_str().bold().blue(),
                                "]".bold().white(),
                                "response_size:".bold().white(),
                                "[".bold().white(),
                                content_length.yellow(),
                                "]".bold().white(),
                                "server:".bold().white(),
                                "[".bold().white(),
                                server.bold().purple(),
                                "]".bold().white(),
                            ));
                        }

                        if response.status().is_success() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                                "[".bold().white(),
                                "OK".bold().green(),
                                "]".bold().white(),
                                "[".bold().white(),
                                result_url.bold().cyan(),
                                "]".bold().white(),
                                "status:".bold().green(),
                                "[".bold().white(),
                                response.status().as_str().bold().blue(),
                                "]".bold().white(),
                                "response_size:".bold().white(),
                                "[".bold().white(),
                                content_length.yellow(),
                                "]".bold().white(),
                                "server:".bold().white(),
                                "[".bold().white(),
                                server.bold().purple(),
                                "]".bold().white(),
                            ));
                        }

                        if response.status().is_redirection() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                                "[".bold().white(),
                                "OK".bold().green(),
                                "]".bold().white(),
                                "[".bold().white(),
                                result_url.bold().cyan(),
                                "]".bold().white(),
                                "status:".bold().cyan(),
                                "[".bold().white(),
                                response.status().as_str().bold().blue(),
                                "]".bold().white(),
                                "response_size:".bold().white(),
                                "[".bold().white(),
                                content_length.yellow(),
                                "]".bold().white(),
                                "server:".bold().white(),
                                "[".bold().white(),
                                server.bold().purple(),
                                "]".bold().white(),
                            ));
                        }

                        if response.status().is_server_error() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                                "[".bold().white(),
                                "OK".bold().green(),
                                "]".bold().white(),
                                "[".bold().white(),
                                result_url.bold().cyan(),
                                "]".bold().white(),
                                "status:".bold().white(),
                                "[".bold().white(),
                                response.status().as_str().bold().red(),
                                "]".bold().white(),
                                "response_size:".bold().white(),
                                "[".bold().white(),
                                content_length.yellow(),
                                "]".bold().white(),
                                "server:".bold().white(),
                                "[".bold().white(),
                                server.bold().purple(),
                                "]".bold().white(),
                            ));
                        }

                        if response.status().is_informational() {
                            pb.println(format!(
                                "{}{}{} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t {} {}{}{}\n\t",
                                "[".bold().white(),
                                "OK".bold().green(),
                                "]".bold().white(),
                                "[".bold().white(),
                                result_url.bold().cyan(),
                                "]".bold().white(),
                                "status:".bold().white(),
                                "[".bold().white(),
                                response.status().as_str().bold().purple(),
                                "]".bold().white(),
                                "response_size:".bold().white(),
                                "[".bold().white(),
                                content_length.yellow(),
                                "]".bold().white(),
                                "server:".bold().white(),
                                "[".bold().white(),
                                server.bold().purple(),
                                "]".bold().white(),
                            ));
                        }

                        // send the result message through the channel to the workers.
                        let result_msg = JobResult {
                            data: result_url.to_owned(),
                        };
                        if let Err(_) = tx.send(result_msg).await {
                            continue;
                        }
                        pb.inc_length(1);
                    }
                }
            } else {
                if proxy.is_empty() {
                    return;
                } else {
                    if job_settings.verbose == true {
                        // set the message
                        pb.println(format!(
                            "{}{}{} {} {} {} {}\n\t {}: {}",
                            "[".bold().white(),
                            "*".bold().red(),
                            "]".bold().white(),
                            "skipping payload".bold().white(),
                            job_payload_new.bold().white(),
                            "for url".bold().white(),
                            new_url2.bold().white(),
                            proxy.bold().white(),
                            reason.bold().white()
                        ));
                    }
                }
                continue;
            }
            payload.push_str(&job_payload_new);
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
