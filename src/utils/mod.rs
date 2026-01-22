use std::collections::HashSet;

use distance::sift3;

#[derive(Clone, Copy, Debug)]
pub struct ResponseChangeThreshold {
    pub start: f32,
    pub end: f32,
}

pub const DEFAULT_SIFT3_THRESHOLD: ResponseChangeThreshold = ResponseChangeThreshold {
    start: 0.0,
    end: 1000.0,
};

pub fn parse_sift3_threshold_range(value: &str) -> Result<ResponseChangeThreshold, String> {
    let trimmed = value.trim();
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() != 2 {
        return Err("expected format MIN-MAX".to_string());
    }
    let start: f32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| "invalid MIN value".to_string())?;
    let end: f32 = parts[1]
        .trim()
        .parse()
        .map_err(|_| "invalid MAX value".to_string())?;
    if start < 0.0 || end < 0.0 {
        return Err("threshold values must be non-negative".to_string());
    }
    if start >= end {
        return Err("MIN must be less than MAX".to_string());
    }
    Ok(ResponseChangeThreshold { start, end })
}

pub fn parse_http_methods_csv(value: &str) -> Result<Vec<reqwest::Method>, String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err("methods list is empty".to_string());
    }

    let mut out: Vec<reqwest::Method> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for part in raw.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        let canonical = item.to_ascii_uppercase();
        let method = reqwest::Method::from_bytes(canonical.as_bytes())
            .map_err(|_| format!("invalid method '{item}'"))?;
        if seen.insert(method.as_str().to_string()) {
            out.push(method);
        }
    }

    if out.is_empty() {
        return Err("methods list is empty".to_string());
    }
    Ok(out)
}

pub fn parse_extensions_csv(value: &str) -> Result<Vec<String>, String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err("extensions list is empty".to_string());
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for part in raw.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        let cleaned = item.trim_start_matches('.');
        if cleaned.is_empty() {
            continue;
        }
        let key = cleaned.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(cleaned.to_string());
        }
    }
    if out.is_empty() {
        return Err("extensions list is empty".to_string());
    }
    Ok(out)
}

pub fn get_response_change(a: &str, b: &str, threshold: ResponseChangeThreshold) -> (bool, f32) {
    let s = sift3(a, b);
    if s > threshold.start && s < threshold.end {
        (true, s)
    } else {
        (false, 0.0)
    }
}

pub fn sift3_distance(a: &str, b: &str) -> f32 {
    sift3(a, b)
}

pub fn sift3_distance_in_range(
    a: &str,
    b: &str,
    threshold: ResponseChangeThreshold,
) -> (bool, f32) {
    let d = sift3_distance(a, b);
    if d >= threshold.start && d <= threshold.end {
        (true, d)
    } else {
        (false, d)
    }
}

pub fn parse_u16_set_csv(value: &str) -> Result<HashSet<u16>, String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err("list is empty".to_string());
    }
    let mut out = HashSet::new();
    for part in raw.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        let code: u16 = item
            .parse()
            .map_err(|_| format!("invalid status code '{item}'"))?;
        out.insert(code);
    }
    if out.is_empty() {
        return Err("list is empty".to_string());
    }
    Ok(out)
}

pub fn apply_wordlist_extensions(
    words: Vec<String>,
    extensions: &[String],
    dirsearch_compat: bool,
) -> Vec<String> {
    if extensions.is_empty() {
        return words;
    }
    let mut out: Vec<String> = Vec::new();
    if dirsearch_compat {
        for word in words {
            let trimmed = word.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("%EXT%") {
                for ext in extensions {
                    out.push(trimmed.replace("%EXT%", ext));
                }
            } else {
                out.push(trimmed.to_string());
            }
        }
    } else {
        for word in words {
            let trimmed = word.trim();
            if trimmed.is_empty() {
                continue;
            }
            out.push(trimmed.to_string());
            if trimmed.contains("%EXT%") {
                continue;
            }
            if trimmed.ends_with('/') {
                continue;
            }
            for ext in extensions {
                if ext.is_empty() {
                    continue;
                }
                out.push(format!("{trimmed}.{ext}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u16_set_csv_parses_and_dedupes() {
        let set = parse_u16_set_csv("200, 404,200").unwrap();
        assert!(set.contains(&200));
        assert!(set.contains(&404));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_extensions_csv_strips_dots_and_dedupes() {
        let out = parse_extensions_csv("php,.asp,PHP").unwrap();
        assert_eq!(out, vec!["php".to_string(), "asp".to_string()]);
    }

    #[test]
    fn apply_wordlist_extensions_appends_when_not_dirsearch() {
        let out = apply_wordlist_extensions(
            vec!["admin".to_string(), "api/".to_string()],
            &vec!["php".to_string(), "asp".to_string()],
            false,
        );
        assert_eq!(
            out,
            vec![
                "admin".to_string(),
                "admin.php".to_string(),
                "admin.asp".to_string(),
                "api/".to_string(),
            ]
        );
    }

    #[test]
    fn apply_wordlist_extensions_replaces_ext_placeholder_in_dirsearch_mode() {
        let out = apply_wordlist_extensions(
            vec!["index.%EXT%".to_string(), "admin".to_string()],
            &vec!["php".to_string(), "asp".to_string()],
            true,
        );
        assert_eq!(
            out,
            vec![
                "index.php".to_string(),
                "index.asp".to_string(),
                "admin".to_string(),
            ]
        );
    }

    #[test]
    fn sift3_distance_in_range_is_inclusive() {
        let threshold = ResponseChangeThreshold {
            start: 0.0,
            end: 0.0,
        };
        let (ok, d) = sift3_distance_in_range("1234", "1234", threshold);
        assert!(ok);
        assert_eq!(d, 0.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCase {
    Lower,
    Upper,
    Title,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartJoinCase {
    Preserve,
    Lower,
    Upper,
    Title,
    Camel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmartJoinSpec {
    pub case: SmartJoinCase,
    pub separator: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WordlistManipulation {
    pub sort: bool,
    pub unique: bool,
    pub reverse: bool,
    pub case: Option<WordCase>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub replace: Vec<(String, String)>,
    pub smart: bool,
    pub smart_join: Option<SmartJoinSpec>,
}

pub fn parse_wordlist_manipulation_list(value: &str) -> Result<WordlistManipulation, String> {
    let mut cfg = WordlistManipulation::default();
    let raw = value.trim();
    if raw.is_empty() {
        return Ok(cfg);
    }

    for part in raw.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }

        let (key, val) = if let Some((k, v)) = item.split_once('=') {
            (k.trim().to_ascii_lowercase(), Some(v.trim()))
        } else {
            (item.to_ascii_lowercase(), None)
        };

        match key.as_str() {
            "sort" => cfg.sort = true,
            "unique" | "uniq" => cfg.unique = true,
            "reverse" | "rev" => cfg.reverse = true,
            "lower" => {
                if matches!(cfg.case, Some(WordCase::Upper | WordCase::Title)) {
                    return Err("cannot combine lower with upper/title".to_string());
                }
                cfg.case = Some(WordCase::Lower);
            }
            "upper" => {
                if matches!(cfg.case, Some(WordCase::Lower | WordCase::Title)) {
                    return Err("cannot combine upper with lower/title".to_string());
                }
                cfg.case = Some(WordCase::Upper);
            }
            "title" => {
                if matches!(cfg.case, Some(WordCase::Lower | WordCase::Upper)) {
                    return Err("cannot combine title with lower/upper".to_string());
                }
                cfg.case = Some(WordCase::Title);
            }
            "prefix" => {
                let v = val.ok_or_else(|| "prefix requires prefix=<STR>".to_string())?;
                cfg.prefix = Some(v.to_string());
            }
            "suffix" => {
                let v = val.ok_or_else(|| "suffix requires suffix=<STR>".to_string())?;
                cfg.suffix = Some(v.to_string());
            }
            "replace" => {
                let v = val.ok_or_else(|| "replace requires replace=<FROM:TO>".to_string())?;
                let (from, to) = parse_replace_spec(v)?;
                cfg.replace.push((from, to));
            }
            "smart" => cfg.smart = true,
            "smartjoin" | "smart-join" => {
                let v = val.ok_or_else(|| "smartjoin requires smartjoin=<CASE:SEP>".to_string())?;
                cfg.smart_join = Some(parse_smart_join_spec(v)?);
            }
            other => return Err(format!("unknown manipulation '{other}'")),
        }
    }

    Ok(cfg)
}

pub fn parse_smart_join_spec(value: &str) -> Result<SmartJoinSpec, String> {
    let (case_raw, sep_raw) = value
        .split_once(':')
        .ok_or_else(|| "expected CASE:SEP".to_string())?;
    let sep = sep_raw.to_string();
    if sep.is_empty() {
        return Err("separator cannot be empty".to_string());
    }
    let case = match case_raw.trim().to_ascii_lowercase().as_str() {
        "" => SmartJoinCase::Preserve,
        "c" => SmartJoinCase::Camel,
        "l" => SmartJoinCase::Lower,
        "u" => SmartJoinCase::Upper,
        "t" => SmartJoinCase::Title,
        other => return Err(format!("invalid CASE '{other}', expected c,l,u,t or empty")),
    };
    Ok(SmartJoinSpec {
        case,
        separator: sep,
    })
}

pub fn parse_replace_spec(value: &str) -> Result<(String, String), String> {
    let (from_raw, to_raw) = value
        .split_once(':')
        .ok_or_else(|| "expected FROM:TO".to_string())?;
    let from = from_raw.to_string();
    if from.is_empty() {
        return Err("FROM cannot be empty".to_string());
    }
    Ok((from, to_raw.to_string()))
}

pub fn apply_wordlist_manipulations(
    mut words: Vec<String>,
    cfg: &WordlistManipulation,
) -> Vec<String> {
    for w in words.iter_mut() {
        *w = w.trim().to_string();
    }
    words.retain(|w| !w.is_empty());

    if cfg.smart {
        let mut out: Vec<String> = Vec::new();
        for w in words.iter() {
            out.extend(smart_break(w));
        }
        words = out;
    }

    if let Some(spec) = cfg.smart_join.as_ref() {
        let mut out: Vec<String> = Vec::with_capacity(words.len());
        for w in words.iter() {
            if let Some(v) = smart_join(w, spec) {
                if !v.is_empty() {
                    out.push(v);
                }
            }
        }
        words = out;
    }

    if !cfg.replace.is_empty() {
        for w in words.iter_mut() {
            for (from, to) in cfg.replace.iter() {
                if from.is_empty() {
                    continue;
                }
                *w = w.replace(from, to);
            }
        }
    }

    if let Some(prefix) = cfg.prefix.as_deref() {
        if !prefix.is_empty() {
            for w in words.iter_mut() {
                let mut s = String::with_capacity(prefix.len() + w.len());
                s.push_str(prefix);
                s.push_str(w);
                *w = s;
            }
        }
    }

    if let Some(suffix) = cfg.suffix.as_deref() {
        if !suffix.is_empty() {
            for w in words.iter_mut() {
                let mut s = String::with_capacity(suffix.len() + w.len());
                s.push_str(w);
                s.push_str(suffix);
                *w = s;
            }
        }
    }

    if let Some(case) = cfg.case {
        match case {
            WordCase::Lower => {
                for w in words.iter_mut() {
                    w.make_ascii_lowercase();
                }
            }
            WordCase::Upper => {
                for w in words.iter_mut() {
                    w.make_ascii_uppercase();
                }
            }
            WordCase::Title => {
                for w in words.iter_mut() {
                    *w = title_ascii(w);
                }
            }
        }
    }

    if cfg.reverse {
        for w in words.iter_mut() {
            *w = w.chars().rev().collect::<String>();
        }
    }

    for w in words.iter_mut() {
        *w = w.trim().to_string();
    }
    words.retain(|w| !w.is_empty());

    if cfg.sort {
        words.sort();
        if cfg.unique {
            words.dedup();
        }
        return words;
    }

    if cfg.unique {
        let mut seen: HashSet<String> = HashSet::new();
        words.retain(|w| seen.insert(w.clone()));
    }

    words
}

pub fn smart_break(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut buf = String::new();

    let flush = |buf: &mut String, out: &mut Vec<String>| {
        if !buf.is_empty() {
            out.push(std::mem::take(buf));
        }
    };

    for i in 0..chars.len() {
        let ch = chars[i];
        if is_smart_separator(ch) {
            flush(&mut buf, &mut out);
            continue;
        }
        if !buf.is_empty() {
            let prev = buf.chars().last().unwrap_or(ch);
            let next = chars.get(i + 1).copied();
            if is_boundary(prev, ch, next) {
                flush(&mut buf, &mut out);
            }
        }
        buf.push(ch);
    }
    flush(&mut buf, &mut out);

    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_smart_separator(ch: char) -> bool {
    ch.is_whitespace() || ch == '_' || ch == '-' || ch == '.'
}

fn is_boundary(prev: char, curr: char, next: Option<char>) -> bool {
    if prev.is_ascii_lowercase() && curr.is_ascii_uppercase() {
        return true;
    }
    if prev.is_ascii_uppercase() && curr.is_ascii_uppercase() {
        if let Some(next) = next {
            if next.is_ascii_lowercase() {
                return true;
            }
        }
    }
    if prev.is_ascii_alphabetic() && curr.is_ascii_digit() {
        return true;
    }
    if prev.is_ascii_digit() && curr.is_ascii_alphabetic() {
        return true;
    }
    false
}

fn smart_join(input: &str, spec: &SmartJoinSpec) -> Option<String> {
    let tokens = smart_break(input);
    if tokens.is_empty() {
        return None;
    }
    let mut out_tokens: Vec<String> = Vec::with_capacity(tokens.len());
    for (idx, t) in tokens.iter().enumerate() {
        let mapped = match spec.case {
            SmartJoinCase::Preserve => t.clone(),
            SmartJoinCase::Lower => t.to_ascii_lowercase(),
            SmartJoinCase::Upper => t.to_ascii_uppercase(),
            SmartJoinCase::Title => title_ascii(t),
            SmartJoinCase::Camel => {
                if idx == 0 {
                    t.to_ascii_lowercase()
                } else {
                    title_ascii(t)
                }
            }
        };
        if !mapped.is_empty() {
            out_tokens.push(mapped);
        }
    }
    Some(out_tokens.join(&spec.separator))
}

fn title_ascii(input: &str) -> String {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = String::with_capacity(input.len());
    out.push(first.to_ascii_uppercase());
    for ch in chars {
        out.push(ch.to_ascii_lowercase());
    }
    out
}
