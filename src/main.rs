mod machinery;

use clap::Parser;
use machinery::cert_utils::summarize;
use anyhow::{Result, Context};

#[derive(Parser)]
#[command(about = "Pretty-print x509 certificate (or certificate bundle) most relevant information", long_about = None)]
struct Args {
    #[arg(value_name="x509 certificate")]
    cert: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let data = std::fs::read(args.cert).context("cannot read given file")?;
    summarize(&data).context("cannot summarize given file")?;
    Ok(())
}
