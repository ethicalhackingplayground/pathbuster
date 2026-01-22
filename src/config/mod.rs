use std::env;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ConfigFile {
    pub urls: Option<Vec<String>>,
    pub input_file: Option<String>,
    pub rate: Option<u32>,
    pub concurrency: Option<u32>,
    pub timeout: Option<usize>,
    pub workers: Option<usize>,
    pub output: Option<String>,
    pub output_format: Option<String>,
    pub proxy: Option<String>,
    pub header: Option<String>,
    pub methods: Option<String>,
    pub drop_after_fail: Option<String>,
    #[serde(alias = "int_status")]
    pub validate_status: Option<String>,
    #[serde(alias = "pub_status")]
    pub fingerprint_status: Option<String>,
    pub filter_status: Option<String>,
    pub filter_size: Option<String>,
    pub filter_words: Option<String>,
    pub filter_lines: Option<String>,
    pub filter_regex: Option<Vec<String>>,
    pub payloads: Option<String>,
    pub wordlist: Option<String>,
    pub extensions: Option<String>,
    pub dirsearch_compat: Option<bool>,
    pub path: Option<String>,
    pub wordlist_dir: Option<String>,
    pub wordlist_manipulation: Option<String>,
    pub tech: Option<String>,
    pub waf_test: Option<String>,
    pub no_color: Option<bool>,
    pub disable_show_all: Option<bool>,
    pub ignore_trailing_slash: Option<bool>,
    pub skip_validation: Option<bool>,
    pub skip_brute: Option<bool>,
    pub auto_collab: Option<bool>,
    pub wordlist_status: Option<String>,
    pub brute_queue_concurrency: Option<u32>,
    pub disable_fingerprinting: Option<bool>,
    pub disable_waf_bypass: Option<bool>,
    pub bypass_level: Option<u8>,
    pub bypass_transform: Option<Vec<String>>,
    pub start_depth: Option<usize>,
    #[serde(alias = "sift3_threshold")]
    pub response_diff_threshold: Option<String>,
    pub traversal_strategy: Option<String>,
    pub max_depth: Option<usize>,
    pub follow_redirects: Option<bool>,
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| {
            let drive = env::var_os("HOMEDRIVE")?;
            let path = env::var_os("HOMEPATH")?;
            Some(PathBuf::from(drive).join(path))
        })
}

pub fn default_config_path() -> Option<PathBuf> {
    Some(home_dir()?.join(".pathbuster").join("config.yml"))
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

pub fn expand_tilde_string(path: &str) -> String {
    expand_tilde(path).to_string_lossy().to_string()
}

pub fn load_config(path: &PathBuf, allow_missing: bool) -> Result<ConfigFile, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_yaml::from_str::<ConfigFile>(&contents)
            .map_err(|e| format!("failed to parse config '{}': {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && allow_missing => {
            Ok(ConfigFile::default())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("config file not found '{}'", path.display()))
        }
        Err(e) => Err(format!("failed to read config '{}': {e}", path.display())),
    }
}

fn default_config_yaml() -> String {
    r#"# Pathbuster config
#
# Location (default):
#   ~/.pathbuster/config.yml

# Targets (choose at least one)
# urls:
#   - https://example.com/app/
# input_file: ./targets.txt

# Output (optional)
# output: ./output.html
# output_format: html

# Performance
rate: 1000
concurrency: 1000
timeout: 10
workers: 10

# Input
payloads: ./payloads/traversals.txt
wordlist: ./wordlists/wordlist.txt
# extensions: php,asp
# dirsearch_compat: false
# Alternatively, target a single path instead of using a wordlist:
# path: admin
wordlist_dir: ./wordlists/targeted

# HTTP (optional)
# proxy: http://127.0.0.1:8080
# header: "Key: Value"
# methods: GET,POST
follow_redirects: false

# Matching
drop_after_fail: "302,301"
validate_status: "404"
fingerprint_status: "400,500"

# Response difference threshold range used by validation/bruteforce comparisons.
# CLI equivalent: --response-diff-threshold MIN-MAX
response_diff_threshold: "5-1000"

# Filters (stage prefixes: V:<set> and/or F:<set>, or unprefixed applies to both)
filter_status: ""
filter_size: ""
filter_words: ""
filter_lines: ""
filter_regex: []

# Traversal
start_depth: 0
max_depth: 5
traversal_strategy: greedy

ignore_trailing_slash: false
skip_validation: false
skip_brute: false

# Bruteforce
auto_collab: false
wordlist_status: "200"
brute_queue_concurrency: 0

# Fingerprinting
disable_fingerprinting: false
# waf_test: cloudflare
# tech: php

# Output styling
no_color: false

# Bypass
disable_waf_bypass: false
bypass_level: 1
bypass_transform: []
"#
    .to_string()
}

pub fn ensure_default_config_file(path: &PathBuf) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid config path '{}'", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "failed to create config directory '{}': {e}",
            parent.display()
        )
    })?;
    let contents = default_config_yaml();
    std::fs::write(path, contents)
        .map_err(|e| format!("failed to write config file '{}': {e}", path.display()))?;
    Ok(())
}
