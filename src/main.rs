fn main() {
    if let Err(err) = pathbuster::app::run_cli() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
