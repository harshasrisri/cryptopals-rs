use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

mod set1;
mod set2;

#[derive(StructOpt, Debug)]
pub struct CryptopalArgs {
    /// Specify the set number. Default solves all of them.
    #[structopt(short = "s", long = "set")]
    pub set: usize,

    /// Specify the challenge number. Default solves all of them.
    #[structopt(short = "c", long = "challenge")]
    pub challenge: usize,

    /// Input file for the challenge specified.
    #[structopt(short = "i", long = "inputfile")]
    pub inputfile: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = CryptopalArgs::from_args();

    match args.set {
        1 => set1::run(&args)?,
        2 => set2::run(&args)?,
        _ => anyhow::bail!("Set {} doesn't exist", args.set),
    };

    Ok(())
}
