pub mod report;

use std::collections::HashMap;

use serde::Serialize;

use crate::detector::JobResultMeta;
use crate::fingerprint::TargetFingerprint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Xml,
    Html,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "text" | "txt" => Some(Self::Text),
            "json" => Some(Self::Json),
            "xml" => Some(Self::Xml),
            "html" | "htm" => Some(Self::Html),
            _ => None,
        }
    }
}

pub fn infer_format_from_path(path: &str) -> Option<OutputFormat> {
    let lower = path.trim().to_lowercase();
    if lower.ends_with(".json") {
        return Some(OutputFormat::Json);
    }
    if lower.ends_with(".xml") {
        return Some(OutputFormat::Xml);
    }
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        return Some(OutputFormat::Html);
    }
    if lower.ends_with(".txt") {
        return Some(OutputFormat::Text);
    }
    None
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputRecord {
    pub base_url: String,
    pub url: String,
    pub payload_original: String,
    pub payload_mutated: String,
    pub payload_family: String,
    pub depth: usize,
    pub status: u16,
    pub title: String,
    pub size: usize,
    pub words: usize,
    pub lines: usize,
    pub server: String,
    pub content_type: String,
    pub tech: Vec<String>,
    pub waf: Vec<String>,
}

pub fn build_records(
    results: &[JobResultMeta],
    fingerprints_by_url: &HashMap<String, TargetFingerprint>,
) -> Vec<OutputRecord> {
    results
        .iter()
        .map(|r| {
            let fp = fingerprints_by_url
                .get(&r.base_url)
                .cloned()
                .unwrap_or_default();
            let waf = fp.wafs.into_iter().map(|w| w.name).collect::<Vec<_>>();
            OutputRecord {
                base_url: r.base_url.clone(),
                url: r.result_url.clone(),
                payload_original: r.payload_original.clone(),
                payload_mutated: r.payload_mutated.clone(),
                payload_family: r.payload_family.clone(),
                depth: r.depth,
                status: r.status,
                title: r.title.clone(),
                size: r.size,
                words: r.words,
                lines: r.lines,
                server: r.server.clone(),
                content_type: r.content_type.clone(),
                tech: fp.tech.products,
                waf,
            }
        })
        .collect()
}

pub fn render_text(records: &[OutputRecord]) -> Vec<u8> {
    let mut out = String::new();
    for r in records {
        out.push_str(&r.url);
        out.push('\n');
    }
    out.into_bytes()
}

pub fn render_json(records: &[OutputRecord]) -> Vec<u8> {
    serde_json::to_vec_pretty(records).unwrap_or_else(|_| b"[]\n".to_vec())
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn render_xml(records: &[OutputRecord]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push('\n');
    out.push_str("<results>\n");
    for r in records {
        out.push_str("  <result>\n");
        out.push_str(&format!(
            "    <base_url>{}</base_url>\n",
            escape_xml(&r.base_url)
        ));
        out.push_str(&format!("    <url>{}</url>\n", escape_xml(&r.url)));
        out.push_str(&format!(
            "    <payload_original>{}</payload_original>\n",
            escape_xml(&r.payload_original)
        ));
        out.push_str(&format!(
            "    <payload_mutated>{}</payload_mutated>\n",
            escape_xml(&r.payload_mutated)
        ));
        out.push_str(&format!(
            "    <payload_family>{}</payload_family>\n",
            escape_xml(&r.payload_family)
        ));
        out.push_str(&format!("    <depth>{}</depth>\n", r.depth));
        out.push_str(&format!("    <status>{}</status>\n", r.status));
        out.push_str(&format!("    <title>{}</title>\n", escape_xml(&r.title)));
        out.push_str(&format!("    <size>{}</size>\n", r.size));
        out.push_str(&format!("    <words>{}</words>\n", r.words));
        out.push_str(&format!("    <lines>{}</lines>\n", r.lines));
        out.push_str(&format!("    <server>{}</server>\n", escape_xml(&r.server)));
        out.push_str(&format!(
            "    <content_type>{}</content_type>\n",
            escape_xml(&r.content_type)
        ));
        out.push_str("    <tech>\n");
        for t in &r.tech {
            out.push_str(&format!("      <product>{}</product>\n", escape_xml(t)));
        }
        out.push_str("    </tech>\n");
        out.push_str("    <waf>\n");
        for w in &r.waf {
            out.push_str(&format!("      <name>{}</name>\n", escape_xml(w)));
        }
        out.push_str("    </waf>\n");
        out.push_str("  </result>\n");
    }
    out.push_str("</results>\n");
    out.into_bytes()
}

pub fn render_html(records: &[OutputRecord]) -> Vec<u8> {
    report::render_html(records)
}
