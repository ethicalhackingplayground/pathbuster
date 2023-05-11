use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
use std::process::exit;
use std::time::Duration;

use clap::App;
use clap::Arg;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::fs::OpenOptions;
use tokio::sync::mpsc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::runtime::Builder;
use tokio::time::Instant;
use tokio::{fs::File, task};

use colored::Colorize;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::bruteforcer::BruteJob;
use crate::bruteforcer::BruteResult;
use crate::detector::Job;
use crate::detector::JobResult;

mod bruteforcer;
mod detector;
mod utils;

// our fancy ascii banner to make it look hackery :D
fn print_banner() {
    const BANNER: &str = r#"                             
                 __  __    __               __           
    ____  ____ _/ /_/ /_  / /_  __  _______/ /____  _____
   / __ \/ __ `/ __/ __ \/ __ \/ / / / ___/ __/ _ \/ ___/
  / /_/ / /_/ / /_/ / / / /_/ / /_/ (__  ) /_/  __/ /    
 / .___/\__,_/\__/_/ /_/_.___/\__,_/____/\__/\___/_/     
/_/                                                          
                     v0.5.5
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

// asynchronous entry point main where the magic happens.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    // print the banner
    print_banner();

    // parse the cli arguments
    let matches = App::new("pathbuster")
        .version("0.5.5")
        .author("Blake Jacobs <krypt0mux@gmail.com>")
        .about("path-normalization pentesting tool")
        .arg(
            Arg::with_name("urls")
                .short('u')
                .long("urls")
                .takes_value(true)
                .required(true)
                .display_order(1)
                .help("the url you would like to test"),
        )
        .arg(
            Arg::with_name("rate")
                .short('r')
                .long("rate")
                .takes_value(true)
                .default_value("1000")
                .display_order(2)
                .help("Maximum in-flight requests per second"),
        )
        .arg(
            Arg::with_name("skip-brute")
                .long("skip-brute")
                .takes_value(false)
                .required(false)
                .display_order(3)
                .help("skip the directory bruteforcing stage"),
        )
        .arg(
            Arg::with_name("drop-after-fail")
                .long("drop-after-fail")
                .takes_value(true)
                .default_value("302,301")
                .required(false)
                .display_order(4)
                .help("ignore requests with the same response code multiple times in a row"),
        )
        .arg(
            Arg::with_name("int-status")
                .long("int-status")
                .takes_value(true)
                .required(false)
                .default_value("404,500")
                .display_order(5)
                .help("the internal web root status"),
        )
        .arg(
            Arg::with_name("pub-status")
                .long("pub-status")
                .takes_value(true)
                .required(false)
                .default_value("400")
                .display_order(6)
                .help("the public web root status"),
        )
        .arg(
            Arg::with_name("proxy")
                .short('p')
                .long("proxy")
                .required(false)
                .takes_value(true)
                .display_order(7)
                .help("http proxy to use (eg http://127.0.0.1:8080)"),
        )
        .arg(
            Arg::with_name("skip-validation")
                .short('s')
                .long("skip-validation")
                .required(false)
                .takes_value(false)
                .display_order(8)
                .long_help("this is used to bypass known protected endpoints using traversals")
                .help("skips the validation process"),
        )
        .arg(
            Arg::with_name("concurrency")
                .short('c')
                .long("concurrency")
                .default_value("1000")
                .takes_value(true)
                .display_order(9)
                .help("The amount of concurrent requests"),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .default_value("10")
                .takes_value(true)
                .display_order(10)
                .help("The delay between each request"),
        )
        .arg(
            Arg::with_name("header")
                .long("header")
                .default_value("")
                .takes_value(true)
                .display_order(11)
                .help("The header to insert into each request"),
        )
        .arg(
            Arg::with_name("workers")
                .short('w')
                .long("workers")
                .default_value("10")
                .takes_value(true)
                .display_order(12)
                .help("The amount of workers"),
        )
        .arg(
            Arg::with_name("payloads")
                .long("payloads")
                .required(true)
                .takes_value(true)
                .display_order(13)
                .default_value("./payloads/traversals.txt")
                .help("the file containing the traversal payloads"),
        )
        .arg(
            Arg::with_name("wordlist")
                .long("wordlist")
                .required(true)
                .takes_value(true)
                .display_order(14)
                .default_value("./wordlists/wordlist.txt")
                .help("the file containing the wordlist used for directory bruteforcing"),
        )
        .arg(
            Arg::with_name("out")
                .short('o')
                .long("out")
                .display_order(15)
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

    let http_proxy = match matches.get_one::<String>("proxy").map(|p| p.to_string()) {
        Some(http_proxy) => http_proxy,
        None => "".to_string(),
    };

    let payloads_path = match matches.value_of("payloads") {
        Some(payloads_path) => payloads_path,
        None => {
            println!("{}", "invalid payloads file");
            exit(1);
        }
    };

    let header = match matches.value_of("header").unwrap().parse::<String>() {
        Ok(header) => header,
        Err(_) => "".to_string(),
    };

    let mut skip_dir = matches.is_present("skip-brute");
    let skip_validation = matches.is_present("skip-validation");
    if skip_validation {
        skip_dir = true;
    }

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

    let int_status = match matches
        .get_one::<String>("int-status")
        .map(|s| s.to_string())
    {
        Some(int_status) => int_status,
        None => "".to_string(),
    };

    let pub_status = match matches
        .get_one::<String>("pub-status")
        .map(|s| s.to_string())
    {
        Some(pub_status) => pub_status,
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
        "{}  {}      {} {}\n{}  {}          {} {}\n{}  {}  {} {}\n{}  {}  {} {}\n{}  {}   {} {}\n{}  {}       {} {}",
        ">".bold().green(),
        "Payloads".bold().white(),
        ":".bold().white(),
        payloads.len().to_string().bold().cyan(),
        ">".bold().green(),
        "Urls".bold().white(),
        ":".bold().white(),
        urls.len().to_string().bold().cyan(),
        ">".bold().green(),
        "Int Matchers".bold().white(),
        ":".bold().white(),
        int_status.to_string().bold().cyan(),
        ">".bold().green(),
        "Pub Matchers".bold().white(),
        ":".bold().white(),
        pub_status.to_string().bold().cyan(),
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

    let bar_length = (urls.len() * payloads.len()) as u64;

    let pb = ProgressBar::new(bar_length);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.enable_steady_tick(Duration::from_millis(200));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.blue} ({eta}) {elapsed} ({len}) {pos} {msg}")
            .unwrap()
            .progress_chars(r#"#>-"#),
    );

    // spawn our workers
    let out_pb = pb.clone();
    let job_pb: ProgressBar = pb.clone();
    let job_wordlist = wordlist.clone();
    rt.spawn(async move {
        detector::send_url(
            job_tx,
            urls,
            payloads,
            job_wordlist,
            rate,
            int_status,
            pub_status,
            drop_after_fail,
            skip_validation,
            header,
        )
        .await
    });

    // process the jobs
    let workers = FuturesUnordered::new();

    // process the jobs for scanning.
    for _ in 0..concurrency {
        let http_proxy = http_proxy.clone();
        let jrx = job_rx.clone();
        let jtx: mpsc::Sender<JobResult> = result_tx.clone();
        let jpb = job_pb.clone();
        workers.push(task::spawn(async move {
            //  run the detector
            detector::run_tester(jpb, jrx, jtx, timeout, http_proxy).await
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
    let mut brute_results: HashMap<String, String> = HashMap::new();
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
            detector::save_traversals(out_pb, outfile_handle_traversal, out_data).await;
        }
    }

    if !skip_dir {
        let pb_results = results.clone();
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
        let bar_length = (pb_results.len() * wordlist.len()) as u64;
        out_pb.set_length(bar_length);
        out_pb.set_position(0);
        let brute_pb = out_pb.clone();
        let brute_wordlist = brute_wordlist.clone();
        let (brute_job_tx, brute_job_rx) = spmc::channel::<BruteJob>();
        let (brute_result_tx, brute_result_rx) = mpsc::channel::<BruteResult>(w);
        // start orchestrator tasks
        rt.spawn(async move {
            bruteforcer::send_word_to_url(brute_job_tx, results, brute_wordlist, rate).await
        });
        rt.spawn(async move {
            bruteforcer::save_discoveries(out_pb, outfile_handle_brute, brute_result_rx).await
        });

        // process the jobs for directory bruteforcing.
        let workers = FuturesUnordered::new();
        for _ in 0..concurrency {
            let http_proxy = http_proxy.clone();
            let brx = brute_job_rx.clone();
            let btx: mpsc::Sender<BruteResult> = brute_result_tx.clone();
            let bpb = brute_pb.clone();
            workers.push(task::spawn(async move {
                bruteforcer::run_bruteforcer(bpb, brx, btx, timeout, http_proxy).await
            }));
        }
        let worker_results: Vec<_> = workers.collect().await;
        for result in worker_results {
            let result = match result {
                Ok(result) => result,
                Err(_) => continue,
            };
            let content_length = result.rs.clone();
            let result_data = result.data.clone();
            if result.data.is_empty() == false {
                brute_results.insert(result_data, content_length);
            }
        }
    }
    rt.shutdown_background();

    // print out the discoveries.
    println!("\n\n");
    println!("{}", "Discovered:".bold().green());
    println!("{}", "===========".bold().green());
    for result in brute_results {
        println!(
            "{} {} {} {}",
            "::".bold().green(),
            result.0.bold().white(),
            "::".bold().green(),
            result.1.bold().white()
        );
    }

    let elapsed_time = now.elapsed();

    println!("\n\n");
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
