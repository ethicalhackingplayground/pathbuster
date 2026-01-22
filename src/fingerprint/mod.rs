use std::collections::HashMap;

use reqwest::header::HeaderMap;

#[derive(Clone, Debug, Default)]
pub struct TechFingerprint {
    pub products: Vec<String>,
    #[allow(dead_code)]
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct WafMatch {
    pub name: String,
    pub confidence: f32,
    #[allow(dead_code)]
    pub evidence: Vec<String>,
    #[allow(dead_code)]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TargetFingerprint {
    pub tech: TechFingerprint,
    pub wafs: Vec<WafMatch>,
}

#[derive(Clone, Debug)]
pub struct FingerprintOptions {
    pub enable_fingerprinting: bool,
    pub waf_test: Option<String>,
}

#[derive(Clone, Debug)]
struct ResponseView {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Clone, Debug)]
struct WafSignature {
    name: &'static str,
    checks: Vec<WafCheck>,
}

#[derive(Clone, Debug)]
enum WafCheck {
    HeaderContains {
        header: &'static str,
        needle: &'static str,
        weight: u8,
    },
    CookieContains {
        needle: &'static str,
        weight: u8,
    },
    BodyContains {
        needle: &'static str,
        weight: u8,
    },
    StatusIs {
        status: u16,
        weight: u8,
    },
}

fn header_map_to_hashmap(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(v) = v.to_str() {
            out.insert(k.as_str().to_lowercase(), v.to_string());
        }
    }
    out
}

fn get_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(&name.to_lowercase()).map(|s| s.as_str())
}

fn detect_tech_simple(view: &ResponseView) -> TechFingerprint {
    let mut products: Vec<String> = Vec::new();
    let mut evidence: Vec<String> = Vec::new();

    if let Some(server) = get_header(&view.headers, "server") {
        let s = server.to_lowercase();
        if s.contains("nginx") {
            products.push("nginx".to_string());
            evidence.push(format!("header:server:{server}"));
        } else if s.contains("apache") {
            products.push("apache".to_string());
            evidence.push(format!("header:server:{server}"));
        } else if s.contains("cloudfront") {
            products.push("cloudfront".to_string());
            evidence.push(format!("header:server:{server}"));
        } else if s.contains("microsoft-iis") || s == "iis" {
            products.push("iis".to_string());
            evidence.push(format!("header:server:{server}"));
        }
    }

    if let Some(x_powered_by) = get_header(&view.headers, "x-powered-by") {
        let x = x_powered_by.to_lowercase();
        if x.contains("php") {
            products.push("php".to_string());
            evidence.push(format!("header:x-powered-by:{x_powered_by}"));
        }
        if x.contains("asp.net") {
            products.push("asp.net".to_string());
            evidence.push(format!("header:x-powered-by:{x_powered_by}"));
        }
        if x.contains("express") {
            products.push("express".to_string());
            evidence.push(format!("header:x-powered-by:{x_powered_by}"));
        }
    }

    if let Some(aspnet) = get_header(&view.headers, "x-aspnet-version") {
        products.push("asp.net".to_string());
        evidence.push(format!("header:x-aspnet-version:{aspnet}"));
    }

    if let Some(set_cookie) = get_header(&view.headers, "set-cookie") {
        let c = set_cookie.to_lowercase();
        if c.contains("phpsessid=") {
            products.push("php".to_string());
            evidence.push(format!("cookie:set-cookie:{set_cookie}"));
        }
        if c.contains("jsessionid=") {
            products.push("java".to_string());
            evidence.push(format!("cookie:set-cookie:{set_cookie}"));
        }
    }

    let body_lc = view.body.to_lowercase();
    if body_lc.contains("wp-content/") || body_lc.contains("wp-includes/") {
        products.push("wordpress".to_string());
        evidence.push("body:wordpress".to_string());
    }
    if body_lc.contains("drupal-settings-json") || body_lc.contains("drupal") {
        products.push("drupal".to_string());
        evidence.push("body:drupal".to_string());
    }
    if body_lc.contains("joomla!") || body_lc.contains("joomla") {
        products.push("joomla".to_string());
        evidence.push("body:joomla".to_string());
    }

    products.sort();
    products.dedup();
    evidence.sort();
    evidence.dedup();

    TechFingerprint { products, evidence }
}

#[cfg(not(windows))]
async fn detect_tech_wappalyzer(url: &str) -> TechFingerprint {
    let url = url.to_string();
    let handle = tokio::task::spawn_blocking(move || {
        let parsed = match reqwest::Url::parse(&url) {
            Ok(parsed) => parsed,
            Err(_) => return TechFingerprint::default(),
        };

        let mut rt = match tokio02::runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return TechFingerprint::default(),
        };

        let analysis = rt.block_on(async move { wappalyzer::scan(parsed).await });
        let techs = match analysis.result {
            Ok(techs) => techs,
            Err(_) => return TechFingerprint::default(),
        };

        let mut products: Vec<String> = techs.iter().map(|t| t.name.clone()).collect();
        products.sort();
        products.dedup();

        let evidence: Vec<String> = techs
            .into_iter()
            .map(|t| format!("wappalyzer:{}:{}", t.category, t.name))
            .collect();

        TechFingerprint { products, evidence }
    });

    match handle.await {
        Ok(fp) => fp,
        Err(_) => TechFingerprint::default(),
    }
}

fn waf_signatures() -> Vec<WafSignature> {
    vec![
        WafSignature {
            name: "Cloudflare",
            checks: vec![
                WafCheck::HeaderContains {
                    header: "server",
                    needle: "cloudflare",
                    weight: 5,
                },
                WafCheck::HeaderContains {
                    header: "cf-ray",
                    needle: "",
                    weight: 6,
                },
                WafCheck::CookieContains {
                    needle: "cf_clearance=",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "attention required! | cloudflare",
                    weight: 6,
                },
            ],
        },
        WafSignature {
            name: "AWS WAF",
            checks: vec![
                WafCheck::BodyContains {
                    needle: "the request could not be satisfied",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "generated by cloudfront",
                    weight: 5,
                },
                WafCheck::HeaderContains {
                    header: "via",
                    needle: "cloudfront",
                    weight: 4,
                },
            ],
        },
        WafSignature {
            name: "Akamai",
            checks: vec![
                WafCheck::HeaderContains {
                    header: "server",
                    needle: "akamai",
                    weight: 4,
                },
                WafCheck::HeaderContains {
                    header: "x-akamai-transformed",
                    needle: "",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "reference #",
                    weight: 3,
                },
            ],
        },
        WafSignature {
            name: "F5 BIG-IP ASM",
            checks: vec![
                WafCheck::CookieContains {
                    needle: "bigipserver",
                    weight: 5,
                },
                WafCheck::BodyContains {
                    needle: "the requested url was rejected",
                    weight: 6,
                },
            ],
        },
        WafSignature {
            name: "FortiWeb",
            checks: vec![
                WafCheck::HeaderContains {
                    header: "server",
                    needle: "fortiweb",
                    weight: 5,
                },
                WafCheck::BodyContains {
                    needle: "fortiweb",
                    weight: 3,
                },
            ],
        },
        WafSignature {
            name: "Imperva",
            checks: vec![
                WafCheck::HeaderContains {
                    header: "x-cdn",
                    needle: "imperva",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "incapsula",
                    weight: 5,
                },
                WafCheck::CookieContains {
                    needle: "incap_ses_",
                    weight: 5,
                },
            ],
        },
        WafSignature {
            name: "Sucuri",
            checks: vec![
                WafCheck::HeaderContains {
                    header: "server",
                    needle: "sucuri",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "access denied - sucuri website firewall",
                    weight: 6,
                },
            ],
        },
        WafSignature {
            name: "ModSecurity",
            checks: vec![
                WafCheck::BodyContains {
                    needle: "mod_security",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "this error was generated by mod_security",
                    weight: 6,
                },
                WafCheck::StatusIs {
                    status: 406,
                    weight: 2,
                },
            ],
        },
        WafSignature {
            name: "Azure Front Door",
            checks: vec![
                WafCheck::HeaderContains {
                    header: "x-azure-ref",
                    needle: "",
                    weight: 6,
                },
                WafCheck::BodyContains {
                    needle: "azure front door",
                    weight: 4,
                },
            ],
        },
    ]
}

fn check_matches(check: &WafCheck, view: &ResponseView) -> Option<String> {
    match check {
        WafCheck::HeaderContains { header, needle, .. } => {
            let value = get_header(&view.headers, header)?;
            if needle.is_empty() {
                return Some(format!("header:{} present", header));
            }
            if value.to_lowercase().contains(&needle.to_lowercase()) {
                return Some(format!("header:{} contains {}", header, needle));
            }
            None
        }
        WafCheck::CookieContains { needle, .. } => {
            let set_cookie = get_header(&view.headers, "set-cookie").unwrap_or("");
            if set_cookie.to_lowercase().contains(&needle.to_lowercase()) {
                Some(format!("cookie contains {}", needle))
            } else {
                None
            }
        }
        WafCheck::BodyContains { needle, .. } => {
            if view.body.to_lowercase().contains(&needle.to_lowercase()) {
                Some(format!("body contains {}", needle))
            } else {
                None
            }
        }
        WafCheck::StatusIs { status, .. } => {
            if view.status == *status {
                Some(format!("status {}", status))
            } else {
                None
            }
        }
    }
}

fn check_weight(check: &WafCheck) -> u8 {
    match check {
        WafCheck::HeaderContains { weight, .. } => *weight,
        WafCheck::CookieContains { weight, .. } => *weight,
        WafCheck::BodyContains { weight, .. } => *weight,
        WafCheck::StatusIs { weight, .. } => *weight,
    }
}

fn detect_waf(view: &ResponseView, waf_test: Option<&str>) -> Vec<WafMatch> {
    let mut matches: Vec<WafMatch> = vec![];
    for sig in waf_signatures() {
        if let Some(waf_test) = waf_test {
            if sig.name.to_lowercase() != waf_test.to_lowercase() {
                continue;
            }
        }
        let total_weight: u32 = sig.checks.iter().map(|c| check_weight(c) as u32).sum();
        let mut hit_weight: u32 = 0;
        let mut evidence: Vec<String> = vec![];
        for check in sig.checks.iter() {
            if let Some(ev) = check_matches(check, view) {
                hit_weight += check_weight(check) as u32;
                evidence.push(ev);
            }
        }
        if hit_weight == 0 {
            continue;
        }
        let confidence = if total_weight == 0 {
            0.0
        } else {
            (hit_weight as f32) / (total_weight as f32)
        };
        matches.push(WafMatch {
            name: sig.name.to_string(),
            confidence,
            evidence,
            version: None,
        });
    }
    matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    matches
}

pub async fn fingerprint_target(
    client: &reqwest::Client,
    url: &str,
    options: &FingerprintOptions,
) -> TargetFingerprint {
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return TargetFingerprint::default(),
    };

    let mut urls_to_probe = vec![url.to_string()];
    let root = format!(
        "{}://{}/",
        parsed.scheme(),
        parsed.host_str().unwrap_or_default()
    );
    if root != url {
        urls_to_probe.push(root);
    }

    let mut best_view: Option<ResponseView> = None;
    #[cfg(not(windows))]
    let mut best_probe_url: Option<String> = None;
    for probe in urls_to_probe {
        let resp = match client.get(probe.as_str()).send().await {
            Ok(resp) => resp,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        let headers = header_map_to_hashmap(resp.headers());
        let body = match resp.text().await {
            Ok(body) => body.chars().take(32768).collect::<String>(),
            Err(_) => "".to_string(),
        };
        best_view = Some(ResponseView {
            status,
            headers,
            body,
        });
        #[cfg(not(windows))]
        {
            best_probe_url = Some(probe.clone());
        }
        break;
    }

    let view = match best_view {
        Some(view) => view,
        None => return TargetFingerprint::default(),
    };

    let wafs = if options.enable_fingerprinting {
        detect_waf(&view, options.waf_test.as_deref())
    } else {
        vec![]
    };

    let tech = if options.enable_fingerprinting {
        #[cfg(windows)]
        {
            detect_tech_simple(&view)
        }

        #[cfg(not(windows))]
        {
            let probe_url = best_probe_url.as_deref().unwrap_or(url);
            let fp = detect_tech_wappalyzer(probe_url).await;
            if fp.products.is_empty() {
                detect_tech_simple(&view)
            } else {
                fp
            }
        }
    } else {
        TechFingerprint::default()
    };

    TargetFingerprint { tech, wafs }
}

#[cfg(test)]
pub(crate) fn detect_waf_for_tests(
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    waf_test: Option<&str>,
) -> Vec<WafMatch> {
    let view = ResponseView {
        status,
        headers,
        body,
    };
    detect_waf(&view, waf_test)
}
