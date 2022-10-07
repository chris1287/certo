mod machinery;

use clap::Parser;
use machinery::cert_utils::dump;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    cert: std::path::PathBuf,
}

fn main() {
    let args = Args::parse();
    match std::fs::read(args.cert) {
        Ok(data) => dump(&data),
        Err(e) => println!("error: {}", e)
    };
}
