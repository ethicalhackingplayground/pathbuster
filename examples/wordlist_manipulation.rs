use std::error::Error;

use pathbuster::utils::{apply_wordlist_manipulations, parse_wordlist_manipulation_list};

fn print_list(label: &str, items: &[String]) {
    println!("{label} ({}):", items.len());
    for s in items {
        println!("  {s}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let input = vec![
        "AdminPanel".to_string(),
        "admin-panel".to_string(),
        "admin_panel".to_string(),
        "LOGIN".to_string(),
        "login".to_string(),
        "..%2f".to_string(),
    ];

    let cfg = parse_wordlist_manipulation_list(
        "smart,smartjoin=l:_,lower,replace=..%2f:../,prefix=/,suffix=/,unique,sort",
    )
    .map_err(|e| format!("invalid wordlist manipulation list: {e}"))?;

    let output = apply_wordlist_manipulations(input.clone(), &cfg);

    print_list("Input", &input);
    print_list("Output", &output);

    Ok(())
}
