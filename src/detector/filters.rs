use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;

use super::response::ResponseSummary;

#[derive(Clone, Debug, Default)]
pub(in crate::detector) struct ResponseFilters {
    pub(in crate::detector) status: HashSet<u16>,
    pub(in crate::detector) size: HashSet<usize>,
    pub(in crate::detector) words: HashSet<usize>,
    pub(in crate::detector) lines: HashSet<usize>,
    pub(in crate::detector) regex: Option<Arc<Regex>>,
}

impl ResponseFilters {
    pub(in crate::detector) fn matches(&self, summary: &ResponseSummary) -> bool {
        if !self.status.is_empty() && self.status.contains(&summary.status) {
            return true;
        }
        if !self.size.is_empty() && self.size.contains(&summary.body_len) {
            return true;
        }
        if !self.words.is_empty() && self.words.contains(&summary.words) {
            return true;
        }
        if !self.lines.is_empty() && self.lines.contains(&summary.lines) {
            return true;
        }
        if let Some(re) = self.regex.as_ref() {
            if re.is_match(&summary.title) || re.is_match(&summary.body_sample) {
                return true;
            }
        }
        false
    }
}

pub(in crate::detector) fn status_in_list(status: u16, list: &str) -> bool {
    let status_str = status.to_string();
    list.split(',')
        .map(|s| s.trim())
        .any(|s| !s.is_empty() && s == status_str)
}

pub(in crate::detector) fn parse_filter_set_u16(input: &str) -> HashSet<u16> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u16>().ok())
        .collect()
}

pub(in crate::detector) fn parse_filter_set_usize(input: &str) -> HashSet<usize> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<usize>().ok())
        .collect()
}
