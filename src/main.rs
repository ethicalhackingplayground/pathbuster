use std::error::Error;
use std::process::exit;
use std::time::Duration;

use levenshtein::levenshtein;

use clap::App;
use clap::Arg;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use governor::Quota;
use governor::RateLimiter;

use reqwest::redirect;

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use tokio::time::Instant;
use tokio::runtime::Builder;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::{fs::File, task};

use colored::Colorize;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use urlencoding::encode;



// the Job struct which will be used to define our settings for the job
#[derive(Clone, Debug)]
struct JobSettings {
    stop_at_match: bool,
    deviation: String,
    match_status: String,
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
                                v0.1.6                                   
    "#;
    println!("{}", BANNER.white().bold());
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
        "By using cyberlix, you also agree to the terms of the APIs used."
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
        .version("0.1.3")
        .author("Blake Jacobs <blake@cyberlix.io")
        .about("path-normalization pentesting tool")
        .arg(
            Arg::with_name("url")
            .short('u')
            .long("url")
            .takes_value(true)
            .required(true)
            .help("the url you would like to test")
        )
        .arg(
            Arg::with_name("rate")
            .short('r')
            .long("rate")
            .takes_value(true)
            .default_value("1000")
            .help("Maximum in-flight requests per second")
        )
        .arg(
            Arg::with_name("stop-at-first-match")
            .long("stop-at-first-match")
            .takes_value(true)
            .default_value("false")
            .required(false)
            .help("stops execution flow on the first match")
        )
        .arg(
            Arg::with_name("match-status")
            .long("match-status")
            .takes_value(true)
            .required(false)
            .default_value("200")
        )
        .arg(
            Arg::with_name("payloads")
            .long("payloads")
            .required(true)
            .takes_value(true)
            .default_value("")
            .help("the file containing the traversal payloads")
        )
        .arg(
            Arg::with_name("wordlist")
            .long("wordlist")
            .required(false)
            .takes_value(true)
            .default_value(".wordlist.tmp")
            .help("the file containing the technology paths")
        )
        .arg(
            Arg::with_name("hosts")
            .long("hosts")
            .required(false)
            .takes_value(true)
            .default_value(".hosts.tmp")
            .help("the file containing the list of root domains")
        )
        .arg(
            Arg::with_name("paths")
            .long("paths")
            .required(true)
            .takes_value(true)
            .default_value(".paths.tmp")
            .help("the file containing the list of routes (crawl the host to collect routes)")
        )
        .arg(
            Arg::with_name("deviation")
            .long("deviation")
            .required(true)
            .takes_value(true)
            .default_value("3")
            .help("The distance between the responses")
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
    
    let wordlist_path = match matches.value_of("wordlist") {
        Some(wordlist_path) => wordlist_path,
        None => {
            pb.println("invalid wordlist file");
            exit(1);
        }
    };

    let payloads_path = match matches.value_of("payloads") {
        Some(payloads_path) => payloads_path,
        None => {
            pb.println("invalid payloads file");
            exit(1);
        }
    };

    let url_arg = match matches.get_one::<String>("url").map(|s| s.to_string()) {
         Some(url_arg) => url_arg,
         None => {
            "".to_string()
         },
    };

    let stop_at_match = match matches.get_one::<String>("stop-at-first-match").map(|s| s.to_string()) {
        Some(stop_at_match) => match stop_at_match.parse::<bool>() {
            Ok(stop_at_match) => stop_at_match,
            Err(_) => {
                pb.println("invalid format");
                false
            },
        },
        None => {
            pb.println("invalid format");
            false
        },
    };

    let deviation = match matches.get_one::<String>("deviation").map(|s| s.to_string()) {
        Some(deviation) => deviation,
        None => {
           "".to_string()
        },
    };

    let paths_path = match matches.get_one::<String>("paths").map(|s| s.to_string()) {
        Some(paths_path) => paths_path,
        None => {
            "".to_string()
        }
    };
    let hosts_path = match matches.get_one::<String>("hosts").map(|s| s.to_string()) {
        Some(hosts_path) => hosts_path,
        None => {
            "".to_string()
        }
    };
    let match_status = match matches.get_one::<String>("match-status").map(|s| s.to_string()) {
        Some(match_status) => match_status,
        None => {
            "".to_string()
        }
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
    let wordlists_handle = match File::open(wordlist_path).await {
        Ok(wordlists_handle) => wordlists_handle,
        Err(e) => {
            pb.println(format!("failed to open input file: {:?}", e));
            exit(1);
        }
    };
    let hosts_handle = match File::open(hosts_path).await {
        Ok(hosts_handle) => hosts_handle,
        Err(e) => {
            pb.println(format!("failed to open input file: {:?}", e));
            exit(1);
        }
    };
    // define the file handle for the wordlists.
    let paths_handle = match File::open(paths_path).await {
        Ok(paths_handle) => paths_handle,
        Err(e) => {
            pb.println(format!("failed to open input file: {:?}", e));
            exit(1);
        }
    };



    // build our wordlists by constructing the arrays and storing 
    // the words in the array.
    let (job_tx, job_rx) = spmc::channel::<Job>();
    let (result_tx, result_rx) = mpsc::channel::<JobResult>(w);

    let payload_buf = BufReader::new(payloads_handle);
    let mut payload_lines = payload_buf.lines();
    let mut payloads = vec![];

    let wordlist_buf = BufReader::new(wordlists_handle);
    let mut wordlist_lines = wordlist_buf.lines();
    let mut wordlists = vec![];

    let paths_buf = BufReader::new(paths_handle);
    let mut path_lines = paths_buf.lines();
    let mut paths = vec![];

    
    let hosts_buf = BufReader::new(hosts_handle);
    let mut host_lines = hosts_buf.lines();
    let mut hosts = vec![];

    while let Ok(Some(words)) = wordlist_lines.next_line().await {
        wordlists.push(words);
    }
    while let Ok(Some(payload)) = payload_lines.next_line().await {
        let _payload = encode(&payload.to_string()).to_string();
        payloads.push(_payload);
        payloads.push(payload);
    }
    while let Ok(Some(path)) = path_lines.next_line().await {
        paths.push(path);
    }
    while let Ok(Some(host)) = host_lines.next_line().await {
        hosts.push(host);
    }

    // append some more payloads
    for i in 0u8..=255 {
        let _char = i as char;
        let _payload = encode(&_char.to_string()).to_string();
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
    println!("{}{}{} Generated {} payloads", "[".bold().white(), "+".bold().green(), "]".bold().white(), payloads.len().to_string().bold().white());


    // spawn our workers 
    rt.spawn(async move {
        send_url(job_tx, url_arg.to_string(), hosts, paths, wordlists, payloads, rate, match_status, deviation, stop_at_match).await
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
        workers.push(task::spawn(
            async move { run_tester(pb, rx, tx).await },
        ));
    }


    // print the results
    let _results: Vec<_> = workers.collect().await;
    let elapsed_time = now.elapsed();
    rt.shutdown_background();
    println!(
        "\n\n{}, {} {}s",
        "Completed!".bold().green(),
        "scan took".bold().white(),
        elapsed_time.as_secs().to_string().bold().white()
    );

    Ok(())
} 



// this function will send the jobs to the workers
async fn send_url(mut tx:spmc::Sender<Job>, url:String, hosts:Vec<String>, paths:Vec<String>, wordlists:Vec<String>, payloads:Vec<String>, rate:u32, match_status:String, deviation:String, stop_at_match:bool) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {

    //set rate limit
    let lim = RateLimiter::direct(Quota::per_second(std::num::NonZeroU32::new(rate).unwrap()));


    // the job settings
    let job_settings = JobSettings {
        stop_at_match: stop_at_match,
        deviation: deviation.to_string(),
        match_status: match_status.to_string(),
    };

    // only fuzz with wordlists, if the payloads are not defined
    if paths.is_empty() {
        for host in hosts.iter() {
            for payload in payloads.iter() {
                let msg = Job {
                    host: Some(host.clone()),
                    path: Some("".to_string()),
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

    // only fuzz with payloads, if the wordlists are not defined
    }else if wordlists.is_empty() {
        for path in paths.iter() {
            for host in hosts.iter() {
                for payload in payloads.iter() {
                    let msg = Job {
                        host: Some(host.clone()),
                        path: Some(path.clone()),
                        settings: Some(job_settings.clone()),
                        url: Some(url.clone()),
                        payload: Some(payload.to_string()),
                        word: Some("".to_string()),
                    };
                
                    if let Err(_) = tx.send(msg) {
                        continue;
                    }
                }
            }
        }

    // only fuzz with payloads, if the hosts are not defined
    }else if hosts.is_empty() {
        for path in paths.iter() {
            for payload in payloads.iter() {
                let msg = Job {
                    host: Some("".to_string()),
                    path: Some(path.clone()),
                    settings: Some(job_settings.clone()),
                    url: Some(url.clone()),
                    payload: Some(payload.to_string()),
                    word: Some("".to_string()),
                };
                if let Err(_) = tx.send(msg) {
                    continue;
                }
            }
        }

    // only fuzz with hosts, paths and payloads, if the wordlist is not defined
    }else if  !hosts.is_empty() && !paths.is_empty() {
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
    
    
    // fuzz using both payloads, hosts, paths and wordlists, if they are both defined
    }else if  !hosts.is_empty() && !paths.is_empty() && !wordlists.is_empty() {
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
    }else{
        println!("{}{}{} {}", "[".bold().white(), "!".bold().red(), "]".bold().white(), "Please specify the correct wordlists".bold().white());
        exit(1);
    }
    lim.until_ready().await;
    Ok(())
}



// this function will test for path normalization vulnerabilities
async fn run_tester(pb: ProgressBar, rx: spmc::Receiver<Job>, tx: mpsc::Sender<JobResult>)  {

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
                None => {
                    ""
                }.to_owned(),
            };
            let out_url = print_url.clone();
            if resp.status().to_string().contains(&job_settings.match_status) && content_length.is_empty() == false {

                let parsed_url = match reqwest::Url::parse(&print_url) {
                    Ok(parsed_url) => parsed_url,
                    Err(e) => {
                        pb.println(format!("There is an error parsing the URL: {:?}", e));
                        continue;
                    },
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
                        pb.println(format!("{}{}{} {}{}{} {}{}{}",  "[".bold().white(), resp.status().as_str().bold().blue(), "]".bold().white(), 
                                                                        "[".bold().white(), content_length.dimmed().white(), "]".bold().white(), 
                                                                        "[".bold().white(), print_url.bold().cyan(), "]".bold().white()));

                        if job_settings.stop_at_match == true {
                            break;
                        }
                    }
            
                    if resp.status().is_success() {
                        pb.println(format!("{}{}{} {}{}{} {}{}{}",  "[".bold().white(), resp.status().as_str().bold().green(), "]".bold().white(), 
                                                                        "[".bold().white(), content_length.dimmed().white(), "]".bold().white(), 
                                                                        "[".bold().white(), print_url.bold().cyan(), "]".bold().white()));
                        if job_settings.stop_at_match == true {
                            break;
                        }
                    }
            
                    if resp.status().is_redirection() {
                        pb.println(format!("{}{}{} {}{}{} {}{}{}",  "[".bold().white(), resp.status().as_str().bold().cyan(), "]".bold().white(), 
                                                                        "[".bold().white(), content_length.dimmed().white(), "]".bold().white(), 
                                                                        "[".bold().white(), print_url.bold().cyan(), "]".bold().white()));

                        if job_settings.stop_at_match == true {
                            break;
                        }
                    }
            
                    if resp.status().is_server_error() {
                        pb.println(format!("{}{}{} {}{}{} {}{}{}",  "[".bold().white(), resp.status().as_str().bold().red(), "]".bold().white(), 
                                                                        "[".bold().white(), content_length.dimmed().white(), "]".bold().white(), 
                                                                        "[".bold().white(), print_url.bold().cyan(), "]".bold().white()));

                        if job_settings.stop_at_match == true {
                            break;
                        }
                    }
        
                            
                    if resp.status().is_informational() {
                        pb.println(format!("{}{}{} {}{}{} {}{}{}",  "[".bold().white(), resp.status().as_str().bold().purple(), "]".bold().white(), 
                                                                        "[".bold().white(), content_length.dimmed().white(), "]".bold().white(), 
                                                                        "[".bold().white(), print_url.bold().cyan(), "]".bold().white()));

                        if job_settings.stop_at_match == true {
                            break;
                        }
                    }
        
                    // send the result message through the channel to the workers.
                    let result_msg = JobResult {
                        data: out_url,
                    };
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