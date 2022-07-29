use anyhow::{bail, Result};
use std::path::PathBuf;

mod set1;
mod set2;

pub struct CryptopalArgs {
    pub challenge: usize,
    pub inputfile: Option<PathBuf>,
}

impl CryptopalArgs {
    fn from_args() -> Self {
        let mut args = std::env::args();
        let command = args.next().expect("Couldn't get command");
        let challenge = args.next().map(|n| n.parse().ok()).flatten();
        let inputfile = args.next().map(PathBuf::from);

        if let Some(challenge) = challenge {
            CryptopalArgs { challenge, inputfile }
        } else {
            eprintln!("Usage: {command} <challenge_number> [inputfile]");
            std::process::exit(1);
        }
    }
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
