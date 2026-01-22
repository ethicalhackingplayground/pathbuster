use crate::cli::args::CliArgs;

pub fn validate(args: &CliArgs) -> Result<(), String> {
    if let Some(level) = args.bypass_level {
        if level > 3 {
            return Err("invalid bypass-level, expected 0, 1, 2, or 3".to_string());
        }
    }
    if let Some(raw) = args.response_diff_threshold.as_deref() {
        crate::utils::parse_sift3_threshold_range(raw)
            .map_err(|e| format!("invalid --response-diff-threshold '{raw}': {e}"))?;
    }
    if let Some(raw) = args.wordlist_status.as_deref() {
        crate::utils::parse_u16_set_csv(raw)
            .map_err(|e| format!("invalid --wordlist-status '{raw}': {e}"))?;
    }
    if let Some(raw) = args.validate_status.as_deref() {
        crate::utils::parse_u16_set_csv(raw)
            .map_err(|e| format!("invalid --validate-status '{raw}': {e}"))?;
    }
    if let Some(raw) = args.fingerprint_status.as_deref() {
        crate::utils::parse_u16_set_csv(raw)
            .map_err(|e| format!("invalid --fingerprint-status '{raw}': {e}"))?;
    }
    if let Some(raw) = args.drop_after_fail.as_deref() {
        crate::utils::parse_u16_set_csv(raw)
            .map_err(|e| format!("invalid --drop-after-fail '{raw}': {e}"))?;
    }
    if let Some(raw) = args.extensions.as_deref() {
        crate::utils::parse_extensions_csv(raw)
            .map_err(|e| format!("invalid --extensions '{raw}': {e}"))?;
    }
    if let Some(max_depth) = args.max_depth {
        if max_depth == 0 {
            return Err("invalid max-depth, expected positive integer".to_string());
        }
    }
    if let Some(start_depth) = args.start_depth {
        if start_depth > 1_000_000 {
            return Err("invalid start-depth".to_string());
        }
    }
    Ok(())
}
