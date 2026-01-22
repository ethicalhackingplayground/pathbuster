
<h1 align="center">pathbuster
  <br>
</h1>

<h4 align="center">A path-normalization pentesting tool (inspired by <a href="https://github.com/ffuf/ffuf">FFUF</a>)</h4>

<p align="center">
  <a href="/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"/></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Made%20with-Rust-1f425f.svg"/></a>
  <a href="https://github.com/ethicalhackingplayground/pathmbuster/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
  <a href="https://twitter.com/z0idsec"><img src="https://img.shields.io/twitter/follow/z0idsec.svg?logo=twitter"></a>
  <br>
</p>

---

<p align="center">
  <a href="#whats-new">Whats New</a> •
  <a href="#bug-fixes">Bug Fixes</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#example-scan">Example Scan</a> •
  <a href="#examples">Examples</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a> •
</p>

---

## What's New?

- [x] Unified response filtering under **--filter-\*** flags with stage prefixes (V/F).
- [x] Implemented **--drop-after-fail** which will ignore requests with the same response code multiple times in a row.
- [x] Added in a **--proxy** argument, so you can now perform proxy-related tasks such as sending everything to burp.
- [x] Pathbuster will now give you an eta on when the tool will finish processing all jobs.
- [x] Added in a **--skip-brute** argument, so you have the choice to perform a directory brute force or not.
- [x] Split scan matching into **--validate-status** and **--fingerprint-status** for scan-stage control.
- [x] Added in a **--skip-validation** argument which is used to bypass known protected endpoints using traversals.
- [x] Added in a **--header** argument which is used to add in additonal headers into each request.
- [x] Added **--methods** for scanning with one or more HTTP methods (comma-separated).
- [x] Added **--path** for scanning a single path without a wordlist.
- [x] Added wordlist transforms via **--wordlist-manipulation** (alias: **--wm**).
- [x] Added traversal strategy selection via **--traversal-strategy** (`greedy` / `quick`).
- [x] Added bruteforce gating via **--wordlist-status** and output filtering via **--disable-show-all**.
- [x] Added bruteforce batching via **--brute-queue-concurrency** and optional noise filtering via **--ac**.
---


## Installation

Install rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install pathbuster

```bash
cargo install pathbuster
```


## Usage

```bash
pathbuster -h
```

This command will show the tool's help information and present a list of all the switches that are available.

### Default config

On first run, Pathbuster will create a default config file at:

- Linux/macOS: `~/.pathbuster/config.yml`
- Windows: `%USERPROFILE%\\.pathbuster\\config.yml`

The generated config contains the default settings, with optional keys commented out.

You can also explicitly point to a config file:

```bash
pathbuster --config ./config.yml
```

### Common options (high level)

- Targets: `--url <URL>` (repeatable) or `--input-file <FILE>`
- Payloads: `--payloads <FILE>`
- Raw request: `--raw-request <FILE>` (optional, uses `*` as injection points)
- Bruteforce target: `--wordlist <FILE>` (recommended) or `--path <PATH>` and optional `--wordlist-dir <DIR>`
- Wordlist manipulation (optional): `--wordlist-manipulation <LIST>` (alias: `--wm`)
- Output: `--output <FILE>` and optional `--output-format <text|json|xml|html>`
- Output filtering: `--disable-show-all` (only show matches allowed by `--wordlist-status`)
- Networking: `--proxy <URL>`, `--follow-redirects`, `--timeout <SECONDS>`, `--methods <METHODS>`
- Validation tuning: `--response-diff-threshold <MIN-MAX>`
- Bruteforce tuning: `--wordlist-status <CODES>`, `--brute-queue-concurrency <N>`, `--ac`
- Filters:
  - `--filter-status <SET>` (e.g. `V:404,F:500` or `404,500` for both stages)
  - `--filter-size <SET>` (e.g. `V:1234,F:5678`)
  - `--filter-words <SET>` (e.g. `V:10,F:25`)
  - `--filter-lines <SET>` (e.g. `V:5,F:20`)
  - `--filter-regex <STAGE:REGEX>` (repeatable, e.g. `--filter-regex V:<re> --filter-regex F:<re>`)
  - Stage-scoped filters and status matchers work with both traversal strategies (`greedy` and `quick`)

## Traversal strategies (quick vs greedy)

Pathbuster has two traversal strategies you can select via `--traversal-strategy`:

### Greedy (default)

- Probes depths from `--start-depth` up to `--max-depth` to find a depth where `--fingerprint-status` matches.
- Once a “fingerprint depth” is found, it validates every depth back down toward `--start-depth`.
- Higher request count, but more consistent when you don’t know how the target normalizes paths.

### Quick

- Computes the “fingerprint depth” directly from the target URL path segment count plus `--start-depth` (clamped to `--max-depth`).
- Validates a minimal set of depths (favoring speed over coverage) and moves on.
- Lower request count, best when your base URL has meaningful path segments (e.g. `https://example.com/app/`).

## Arguments

| Flag | Value | Description |
| --- | --- | --- |
| `-u, --url` | `URL` (repeatable) | Target URL(s) to scan. |
| `-i, --input-file` | `FILE` | Load target URLs from a file (one per line). |
| `-C, --config` | `FILE` | Config file path (defaults to `~/.pathbuster/config.yml`). |
| `--payloads` | `FILE` | Payload file path (one payload per line). |
| `--raw-request` | `FILE` | Raw HTTP request template with `*` injection points. |
| `--wordlist` | `FILE` | Wordlist file path (one word per line). |
| `--path` | `PATH` | Scan a single path instead of using a wordlist. |
| `--wordlist-dir` | `DIR` | Targeted wordlist directory (auto-selected by tech fingerprint). |
| `--wordlist-manipulation, --wm` | `LIST` | Comma-separated wordlist transforms (see Wordlist manipulation). |
| `--skip-brute` | (flag) | Skip bruteforce/discovery phase. |
| `-s, --skip-validation` | (flag) | Skip validation phase and go straight to bruteforce/discovery. |
| `-r, --rate` | `RPS` | Request rate limit (requests per second). |
| `-t, --concurrency` | `N` | Max in-flight requests during scanning. |
| `-w, --workers` | `N` | Number of runtime worker threads. |
| `--timeout` | `SECONDS` | Per-request timeout. |
| `-p, --proxy` | `URL` | HTTP proxy URL (e.g. `http://127.0.0.1:8080`). |
| `--follow-redirects` | (flag) | Follow HTTP redirects. |
| `--header` | `HEADER` | Add a header to all requests (`Key: Value`). |
| `-m, --methods` | `METHODS` | Comma-separated HTTP methods to use (e.g. `GET,POST`). |
| `--wordlist-status, --ws` | `CODES` | Allowed status codes for bruteforce findings (comma-separated). |
| `--brute-queue-concurrency, --bqc, --bfc` | `N` | Max base URLs per bruteforce batch (0 = no batching). |
| `--ac` | (flag) | Enable automatic collaboration filtering during bruteforce. |
| `--drop-after-fail` | `CODES` | Stop scanning a target after these status codes (comma-separated). |
| `--validate-status, --vs` | `CODES` | HTTP status matcher for validation phase. |
| `--fingerprint-status` | `CODES` | HTTP status matcher for fingerprinting phase. |
| `--filter-status` | `SET` | Exclude responses by HTTP status using stage prefixes (e.g. `V:404,F:500`). |
| `--filter-size` | `SET` | Exclude responses by body size using stage prefixes (e.g. `V:1234,F:5678`). |
| `--filter-words` | `SET` | Exclude responses by word count using stage prefixes (e.g. `V:10,F:25`). |
| `--filter-lines` | `SET` | Exclude responses by line count using stage prefixes (e.g. `V:5,F:20`). |
| `--filter-regex` | `STAGE:REGEX` | Exclude responses matching regex using stage prefixes (repeatable). |
| `-d, --response-diff-threshold, --rdt` | `MIN-MAX` | Response diff threshold range for comparisons. |
| `-I, --ignore-trailing-slash, --its` | (flag) | Treat URLs with/without trailing slash as equivalent. |
| `--start-depth` | `N` | Initial traversal depth (0-based). |
| `--max-depth` | `N` | Maximum traversal depth. |
| `-X, --traversal-strategy, --ts` | `STRATEGY` | Traversal strategy (`greedy` or `quick`). |
| `--disable-fingerprinting` | (flag) | Disable fingerprinting (WAF/tech). |
| `--waf-test` | `NAME` | Only test for a specific WAF signature by name. |
| `--tech` | `NAME` | Override detected tech name for targeted wordlist selection. |
| `--disable-waf-bypass` | (flag) | Disable WAF-aware payload transformations. |
| `--bypass-level` | `N` | Bypass aggressiveness level (0-3). |
| `--bypass-transform` | `NAME` (repeatable) | Force specific payload transform families. |
| `-o, --output` | `FILE` | Write results to a file. |
| `--output-format` | `FORMAT` | Output format (e.g. `text`, `json`). |
| `-v, --verbose` | (count) | Increase verbosity (`-v`, `-vv`). |
| `-c, --color` | (flag) | Enable colored output (overrides `--no-color`). |
| `--disable-show-all, --dsa` | (flag) | Only show findings matching `--wordlist-status`. |
| `--no-color` | (flag) | Disable colored output. |
| `-h, --help` | (flag) | Print help. |
| `-V, --version` | (flag) | Print version. |

## Wordlist manipulation

`--wordlist-manipulation <LIST>` (alias: `--wm`) applies one or more transforms to the bruteforce wordlist before scanning.

`LIST` is a comma-separated list of transforms:

- `sort`: Sort words (also enables `unique` via `dedup` when both are set)
- `unique` / `uniq`: Deduplicate words (preserves first-seen order unless `sort` is also set)
- `reverse` / `rev`: Reverse each word
- `lower`: Lowercase each word
- `upper`: Uppercase each word
- `title`: Title-case each word (ASCII)
- `prefix=<STR>`: Prefix each word with `<STR>`
- `suffix=<STR>`: Suffix each word with `<STR>`
- `replace=<FROM:TO>`: Replace substring `<FROM>` with `<TO>` (repeatable by adding multiple `replace=...` entries)
- `smart`: Split naming conventions into separate words (`AdminPanel` -> `Admin`, `Panel`; `admin_panel` -> `admin`, `panel`; `admin-panel` -> `admin`, `panel`)
- `smartjoin=<CASE:SEP>`: Split then join with `SEP` (CASE is one of `c,l,u,t` or empty). Example: `smartjoin=l:_` turns `AdminPanel` into `admin_panel`.

Examples:

```bash
pathbuster \
  --url https://example.com/app/ \
  --payloads ./payloads/traversals.txt \
  --wordlist ./wordlists/wordlist.txt \
  --wordlist-manipulation sort,unique,lower,replace=..%2f:../
```

```bash
pathbuster \
  --url https://example.com/app/ \
  --payloads ./payloads/traversals.txt \
  --wordlist ./wordlists/wordlist.txt \
  --wm smartjoin=l:_
```

## Examples

Basic usage (single target):

```bash
pathbuster --url https://example.com/app/ \
  --payloads ./payloads/traversals.txt \
  --wordlist ./wordlists/wordlist.txt \
  --output ./output.html --output-format html
```

### Scan with multiple HTTP methods

```bash
pathbuster --url https://example.com/app/ \
  --methods GET,POST \
  --payloads ./payloads/traversals.txt \
  --wordlist ./wordlists/wordlist.txt \
  --skip-brute
```

### Scan a single path (no wordlist)

```bash
pathbuster --url https://example.com/app/ \
  --payloads ./payloads/traversals.txt \
  --path admin \
  --skip-brute
```

### Run a scan with explicit scan settings

```bash
pathbuster \
  --url https://example.com/app/ \
  --payloads ./payloads/traversals.txt \
  --wordlist ./wordlists/wordlist.txt \
  --wordlist-dir ./wordlists/targeted \
  --rate 500 \
  --concurrency 200 \
  --timeout 10 \
  --response-diff-threshold 5-1000 \
  --validate-status 404 \
  --fingerprint-status 400,500 \
  --filter-status V:301,302,F:404 \
  --bypass-level 2 \
  --follow-redirects
```

### Use a raw HTTP request template with injection points

Create a request file containing one or more `*` markers:

```http
GET /app/* HTTP/1.1
Host: example.com
User-Agent: pathbuster
Accept: */*

```

Then run:

```bash
pathbuster \
  --url https://example.com/app/ \
  --raw-request ./request.txt \
  --payloads ./payloads/traversals.txt \
  --wordlist ./wordlists/wordlist.txt
```

### Specify scan settings via config file

Create or edit `~/.pathbuster/config.yml`:

```yaml
rate: 500
concurrency: 200
timeout: 10

payloads: ./payloads/traversals.txt
wordlist: ./wordlists/wordlist.txt
# Or scan a single path without a wordlist:
# path: admin
wordlist_dir: ./wordlists/targeted
wordlist_manipulation: "sort,unique,lower"
wordlist_status: "200"
disable_show_all: false

validate_status: "404"
fingerprint_status: "400,500"
response_diff_threshold: "5-1000"
filter_status: ""
filter_size: ""
filter_words: ""
filter_lines: ""
filter_regex: []

follow_redirects: true
disable_fingerprinting: false
disable_waf_bypass: false
bypass_level: 3
bypass_transform: []
```

Run using that config:

```bash
pathbuster --url https://example.com/app/ --config ~/.pathbuster/config.yml
```

---

## Example scan:
```bash
pathbuster --url https://example.com/app/ \
  --path internal/admin \
  --validate-status 404 \
  --fingerprint-status 404 \
  --traversal-strategy quick \
  --max-depth 5 \
  --rate 50 \
  --concurrency 20 \
  --timeout 5 \
  --wordlist-status 200 \
  --brute-queue-concurrency 3 \
  --disable-show-all
```

![Demo](static/demo.gif)

---

### Using as a Rust library

Library usage examples are in the [examples](./examples) folder.

- Basic runner example: [library_scan.rs](./examples/library_scan.rs)
- Inline payloads + raw request example: [library_scan_inline.rs](./examples/library_scan_inline.rs)
- Filters example: [library_scan_filters.rs](./examples/library_scan_filters.rs)
- Skip-validation + wordlist manipulation example: [library_scan_skip_validation.rs](./examples/library_scan_skip_validation.rs)

Run the example binary:

```bash
cargo run --example library_scan
```

You can also run scans by constructing a `Runner` with `Options` and calling `run()`.

Basic example (same as [library_scan.rs](./examples/library_scan.rs)):

```rust
use std::error::Error;

use pathbuster::runner::{Options, PayloadSource, Runner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let runner = Runner::new(Options {
        urls: vec!["https://example.com/app/".to_string()],
        payloads: PayloadSource::FilePath("./payloads/traversals.txt".to_string()),
        skip_brute: true,
        rate: 10,
        concurrency: 10,
        timeout_seconds: 5,
        max_depth: 2,
        ..Options::default()
    })?;

    let result = runner.run().await?;

    println!("Targets: {}", result.fingerprints.len());
    println!("Matches: {}", result.matches.len());
    for m in result.matches.iter() {
        println!("{} {} {}", m.base_url, m.status, m.result_url);
    }

    Ok(())
}
```

---

### Warning

Do not run automated scans, brute forcing, or high-rate tooling (including Pathbuster) against PentesterLab infrastructure or any training platform you do not own or explicitly have permission to test.

## Support Development

If this project helps you uncover any interesting or impactful bugs, I'd really appreciate a bit of support or recognition. A shout-out on Twitter/X ([@z0idsec](https://x.com/z0idsec)) or buying me a coffee goes a long way in supporting continued development and research.

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge\&logo=buy-me-a-coffee\&logoColor=black)](https://buymeacoffee.com/z0idsec)

Thanks for checking it out - hope you enjoy using it.


## Contributing

Contributions are welcome and appreciated. If you're planning a significant change, please open an issue first to discuss the proposed approach and ensure alignment before submitting a pull request.

When submitting changes, please ensure that any relevant tests are updated or added as appropriate.

## Contributors

Thanks to everyone who has contributed to this project.

<a href="https://github.com/ethicalhackingplayground/pathbuster/graphs/contributors"> <img src="https://contrib.rocks/image?repo=ethicalhackingplayground/pathbuster" /> </a>


## License

Pathbuster is distributed under [MIT License](https://github.com/ethicalhackingplayground/pathbuster/blob/main/LICENSE)
