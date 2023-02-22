mod machinery;

use clap::Parser;
use machinery::cert_utils::summarize;
use anyhow::{Result, Context};

#[derive(Parser)]
#[command(about = "Pretty-print x509 certificate (or certificate bundle) most relevant information", long_about = None)]
struct Args {
    #[arg(value_name="x509 certificate")]
    cert: Vec<std::path::PathBuf>,
    #[arg(short, long, help = "Output in a machine-readable format", default_value = "false")]
    porcelain: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    for cert in args.cert {
        let data = std::fs::read(cert).context("cannot read given file")?;
        summarize(&data, args.porcelain).context("cannot summarize given file")?;
    }
    Ok(())
}
