mod machinery;

use clap::Parser;
use machinery::cert_utils::summarize;
use anyhow::{Result, Context};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    cert: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let data = std::fs::read(args.cert).context("cannot read given file")?;
    summarize(&data).context("cannot summarize given file")?;
    Ok(())
}
