use clap::{ArgAction, Parser};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "pathbuster",
    version,
    about = "path-normalization pentesting tool",
    long_about = "Pathbuster is a path-normalization pentesting tool for detecting URL normalization quirks and traversal weaknesses.\n\nExamples:\n  pathbuster -u https://target.tld/\n  pathbuster -u https://target.tld/ -r 500 -t 200 --timeout 10\n  pathbuster -u https://target.tld/ --config ~/.pathbuster/config.yml\n\nTip: Use --config to persist scan settings and keep CLI invocations short."
)]
pub struct CliArgs {
    #[arg(
        short = 'v',
        long = "vb",
        visible_alias = "verbose",
        action = ArgAction::Count,
        help_heading = "Output",
        help = "Increase verbosity (-v, -vv)."
    )]
    pub verbose: u8,

    #[arg(
        short = 'c',
        long = "clr",
        visible_alias = "color",
        help_heading = "Output",
        help = "Enable colored output (overrides --no-color)."
    )]
    pub color: bool,

    #[arg(
        long = "dsa",
        visible_alias = "disable-show-all",
        num_args = 0..=1,
        default_missing_value = "true",
        help_heading = "Output",
        help = "Only show findings matching --wordlist-status."
    )]
    pub disable_show_all: Option<bool>,

    #[arg(
        short = 'u',
        long = "u",
        visible_alias = "url",
        value_name = "URL",
        action = ArgAction::Append,
        help_heading = "Input",
        help = "Target URL (repeatable)."
    )]
    pub url: Vec<String>,

    #[arg(
        short = 'i',
        long = "if",
        visible_alias = "input-file",
        value_name = "FILE",
        help_heading = "Input",
        help = "Load target URLs from a file (one per line)."
    )]
    pub input_file: Option<String>,

    #[arg(
        short = 'C',
        long = "cfg",
        visible_alias = "config",
        value_name = "FILE",
        help_heading = "Input",
        help = "Path to config file (defaults to ~/.pathbuster/config.yml)."
    )]
    pub config: Option<String>,

    #[arg(
        short = 'r',
        long = "rt",
        visible_alias = "rate",
        value_name = "RPS",
        help_heading = "Performance",
        help = "Request rate limit (requests per second)."
    )]
    pub rate: Option<u32>,

    #[arg(
        short = 'B',
        long = "sb",
        visible_alias = "skip-brute",
        help_heading = "Scan",
        help = "Skip bruteforce/discovery phase."
    )]
    pub skip_brute: bool,

    #[arg(
        long = "ac",
        visible_alias = "auto-collab",
        help_heading = "Bruteforce",
        help = "Enable automatic collaboration filtering during bruteforce."
    )]
    pub auto_collab: bool,

    #[arg(
        long = "ws",
        visible_alias = "wordlist-status",
        value_name = "CODES",
        help_heading = "Bruteforce",
        help = "Allowed status codes for bruteforce findings (comma-separated)."
    )]
    pub wordlist_status: Option<String>,

    #[arg(
        long = "bqc",
        visible_aliases = ["brute-queue-concurrency", "bfc"],
        value_name = "N",
        help_heading = "Bruteforce",
        help = "Max base URLs per bruteforce batch (0 = no batching)."
    )]
    pub brute_queue_concurrency: Option<u32>,

    #[arg(
        short = 'f',
        long = "daf",
        visible_alias = "drop-after-fail",
        value_name = "CODES",
        help_heading = "Scan",
        help = "Stop scanning a target after receiving these status codes (comma-separated)."
    )]
    pub drop_after_fail: Option<String>,

    #[arg(
        long = "vs",
        visible_alias = "validate-status",
        value_name = "CODES",
        help_heading = "Scan",
        help = "HTTP status matcher for validation phase (comma-separated)."
    )]
    pub validate_status: Option<String>,

    #[arg(
        short = 'P',
        long = "fps",
        visible_alias = "fingerprint-status",
        value_name = "CODES",
        help_heading = "Scan",
        help = "HTTP status matcher for fingerprinting phase (comma-separated)."
    )]
    pub fingerprint_status: Option<String>,

    #[arg(
        short = 'S',
        long = "fst",
        visible_alias = "filter-status",
        value_name = "SET",
        help_heading = "Filters",
        help = "Exclude responses by HTTP status using stage prefixes (comma-separated, e.g. V:404,F:500)."
    )]
    pub filter_status: Option<String>,

    #[arg(
        short = 'Z',
        long = "fsi",
        visible_alias = "filter-size",
        value_name = "SET",
        help_heading = "Filters",
        help = "Exclude responses by body size in bytes using stage prefixes (comma-separated, e.g. V:1234,F:5678)."
    )]
    pub filter_size: Option<String>,

    #[arg(
        short = 'W',
        long = "fw",
        visible_alias = "filter-words",
        value_name = "SET",
        help_heading = "Filters",
        help = "Exclude responses by word count using stage prefixes (comma-separated, e.g. V:10,F:25)."
    )]
    pub filter_words: Option<String>,

    #[arg(
        short = 'L',
        long = "fl",
        visible_alias = "filter-lines",
        value_name = "SET",
        help_heading = "Filters",
        help = "Exclude responses by line count using stage prefixes (comma-separated, e.g. V:5,F:20)."
    )]
    pub filter_lines: Option<String>,

    #[arg(
        short = 'R',
        long = "frx",
        visible_alias = "filter-regex",
        value_name = "STAGE:REGEX",
        help_heading = "Filters",
        action = clap::ArgAction::Append,
        help = "Exclude responses matching regex in title or body using stage prefixes (e.g. --filter-regex V:<regex> --filter-regex F:<regex>)."
    )]
    pub filter_regex: Vec<String>,

    #[arg(
        short = 'd',
        long = "rdt",
        visible_alias = "response-diff-threshold",
        value_name = "MIN-MAX",
        help_heading = "Scan",
        help = "Response difference threshold range used by validation/bruteforce comparisons."
    )]
    pub response_diff_threshold: Option<String>,

    #[arg(
        short = 'p',
        long = "px",
        visible_alias = "proxy",
        value_name = "URL",
        help_heading = "HTTP",
        help = "HTTP proxy URL (e.g. http://127.0.0.1:8080)."
    )]
    pub proxy: Option<String>,

    #[arg(
        short = 'F',
        long = "frd",
        visible_alias = "follow-redirects",
        help_heading = "HTTP",
        help = "Follow HTTP redirects."
    )]
    pub follow_redirects: bool,

    #[arg(
        short = 's',
        long = "sv",
        visible_alias = "skip-validation",
        help_heading = "Scan",
        help = "Skip validation phase and go straight to bruteforce/discovery."
    )]
    pub skip_validation: bool,

    #[arg(
        short = 't',
        long = "cnc",
        visible_alias = "concurrency",
        value_name = "N",
        help_heading = "Performance",
        help = "Max in-flight requests during scanning."
    )]
    pub concurrency: Option<u32>,

    #[arg(
        short = 'T',
        long = "to",
        visible_alias = "timeout",
        value_name = "SECONDS",
        help_heading = "HTTP",
        help = "Per-request timeout in seconds."
    )]
    pub timeout: Option<usize>,

    #[arg(
        short = 'H',
        long = "hdr",
        visible_alias = "header",
        value_name = "HEADER",
        help_heading = "HTTP",
        help = "Add a header to all requests (format: 'Key: Value')."
    )]
    pub header: Option<String>,

    #[arg(
        short = 'm',
        long = "mth",
        visible_alias = "methods",
        value_name = "METHODS",
        help_heading = "HTTP",
        help = "Comma-separated HTTP methods to use (e.g. GET,POST)."
    )]
    pub methods: Option<String>,

    #[arg(
        short = 'w',
        long = "wrk",
        visible_alias = "workers",
        value_name = "N",
        help_heading = "Performance",
        help = "Number of runtime worker threads."
    )]
    pub workers: Option<usize>,

    #[arg(
        short = 'Y',
        long = "pl",
        visible_alias = "payloads",
        value_name = "FILE",
        help_heading = "Input",
        help = "Payload file path (one payload per line)."
    )]
    pub payloads: Option<String>,

    #[arg(
        short = 'Q',
        long = "rr",
        visible_alias = "raw-request",
        value_name = "FILE",
        help_heading = "Input",
        help = "Load a raw HTTP request template from a file; use '*' to mark the injection point."
    )]
    pub raw_request: Option<String>,

    #[arg(
        short = 'K',
        long = "wl",
        visible_alias = "wordlist",
        value_name = "FILE",
        help_heading = "Input",
        help = "Wordlist file path (one word per line)."
    )]
    pub wordlist: Option<String>,

    #[arg(
        short = 'e',
        long = "extensions",
        visible_alias = "ext",
        value_name = "EXTENSIONS",
        help_heading = "Bruteforce",
        help = "Extension list separated by commas (e.g. php,asp)."
    )]
    pub extensions: Option<String>,

    #[arg(
        short = 'D',
        long = "dirsearch",
        visible_alias = "dirsearch-compat",
        help_heading = "Bruteforce",
        help = "DirSearch wordlist compatibility mode (replace %EXT% with extensions)."
    )]
    pub dirsearch_compat: bool,

    #[arg(
        long = "pth",
        visible_alias = "path",
        value_name = "PATH",
        help_heading = "Input",
        help = "Scan a single path instead of using a wordlist (e.g. admin, admin/login.php)."
    )]
    pub path: Option<String>,

    #[arg(
        short = 'J',
        long = "wd",
        visible_alias = "wordlist-dir",
        value_name = "DIR",
        help_heading = "Input",
        help = "Targeted wordlist directory (auto-selected by tech fingerprint)."
    )]
    pub wordlist_dir: Option<String>,

    #[arg(
        short = 'M',
        long = "wm",
        visible_alias = "wordlist-manipulation",
        value_name = "LIST",
        help_heading = "Wordlist Manipulation",
        help = "Comma-separated wordlist transforms (e.g. sort,unique,lower,smart,smartjoin=c:_)."
    )]
    pub wordlist_manipulation: Option<String>,

    #[arg(
        short = 'o',
        long = "out",
        visible_alias = "output",
        value_name = "FILE",
        help_heading = "Output",
        help = "Write results to a file."
    )]
    pub output: Option<String>,

    #[arg(
        short = 'A',
        long = "of",
        visible_alias = "output-format",
        value_name = "FORMAT",
        help_heading = "Output",
        help = "Output format (e.g. text, json)."
    )]
    pub output_format: Option<String>,

    #[arg(
        short = 'I',
        long = "its",
        visible_alias = "ignore-trailing-slash",
        help_heading = "Scan",
        help = "Treat URLs with/without trailing slash as equivalent."
    )]
    pub ignore_trailing_slash: bool,

    #[arg(
        long = "sd",
        visible_alias = "start-depth",
        value_name = "N",
        help_heading = "Traversal",
        help = "Initial traversal depth (0-based)."
    )]
    pub start_depth: Option<usize>,

    #[arg(
        long = "md",
        visible_alias = "max-depth",
        value_name = "N",
        help_heading = "Traversal",
        help = "Maximum traversal depth."
    )]
    pub max_depth: Option<usize>,

    #[arg(
        short = 'X',
        long = "ts",
        visible_alias = "traversal-strategy",
        value_name = "STRATEGY",
        help_heading = "Traversal",
        help = "Traversal strategy (greedy or quick)."
    )]
    pub traversal_strategy: Option<String>,

    #[arg(
        short = 'n',
        long = "nc",
        visible_alias = "no-color",
        help_heading = "Output",
        help = "Disable colored output."
    )]
    pub no_color: bool,

    #[arg(
        short = 'g',
        long = "df",
        visible_alias = "disable-fingerprinting",
        help_heading = "Fingerprinting",
        help = "Disable fingerprinting (WAF/tech)."
    )]
    pub disable_fingerprinting: bool,

    #[arg(
        short = 'a',
        long = "wt",
        visible_alias = "waf-test",
        value_name = "NAME",
        help_heading = "Fingerprinting",
        help = "Only test for a specific WAF signature by name."
    )]
    pub waf_test: Option<String>,

    #[arg(
        long = "tch",
        visible_alias = "tech",
        value_name = "NAME",
        help_heading = "Fingerprinting",
        help = "Override detected tech name for targeted wordlist selection."
    )]
    pub tech: Option<String>,

    #[arg(
        short = 'b',
        long = "dwb",
        visible_alias = "disable-waf-bypass",
        help_heading = "Bypass",
        help = "Disable WAF-aware payload transformations."
    )]
    pub disable_waf_bypass: bool,

    #[arg(
        short = 'x',
        long = "bt",
        visible_alias = "bypass-transform",
        value_name = "NAME",
        action = ArgAction::Append,
        help_heading = "Bypass",
        help = "Force specific payload transform families (repeatable)."
    )]
    pub bypass_transform: Vec<String>,

    #[arg(
        short = 'l',
        long = "bl",
        visible_alias = "bypass-level",
        value_name = "N",
        help_heading = "Bypass",
        help = "Bypass aggressiveness level (0-3)."
    )]
    pub bypass_level: Option<u8>,
}
