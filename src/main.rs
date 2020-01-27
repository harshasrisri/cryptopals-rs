use std::path::PathBuf;
use structopt::StructOpt;
mod set1;

#[derive(StructOpt, Debug)]
pub struct CryptopalArgs {
    /// Specify the set number. Default solves all of them.
    #[structopt(short = "s", long = "set", default_value = "0")]
    pub set: usize,

    /// Specify the challenge number. Default solves all of them.
    #[structopt(short = "c", long = "challenge", default_value = "0")]
    pub challenge: usize,

    /// Input file for the challenge specified.
    #[structopt(short = "i", long = "inputfile")]
    pub inputfile: Option<PathBuf>,
}

fn main() {
    let args = CryptopalArgs::from_args();
    let mut executed = 0;

    if args.set == 0 || args.set == 1 {
        set1::run(&args);
        executed += 1;
    }

    if executed == 0 {
        println!("Set {} doesn't exist", args.set);
    }
}
