use anyhow::{bail, Result};
use std::path::PathBuf;
use structopt::StructOpt;

mod set1;
mod set2;

#[derive(StructOpt, Debug)]
pub struct CryptopalArgs {
    /// Specify the challenge number. Default solves all of them.
    #[structopt(short = "c", long = "challenge")]
    pub challenge: usize,

    /// Input file for the challenge specified.
    #[structopt(short = "i", long = "inputfile")]
    pub inputfile: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = CryptopalArgs::from_args();

    match args.challenge {
        n if (1..=8).contains(&n) => set1::run(&args)?,
        n if (9..=16).contains(&n) => set2::run(&args)?,
        n => bail!("Challenge {n} doesn't exist"),
    };

    Ok(())
}
