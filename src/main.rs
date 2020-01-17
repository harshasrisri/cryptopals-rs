use structopt::StructOpt;
mod set1;

#[derive(StructOpt, Debug)]
struct CryptopalArgs {
    /// Specify the set number. Default solves all of them.
    #[structopt(short = "s", long = "set", default_value = "0")]
    set: usize,

    /// Specify the challenge number. Default solves all of them.
    #[structopt(short = "c", long = "challenge", default_value = "0")]
    challenge: usize,
}

fn main() {
    let args = CryptopalArgs::from_args();
    let mut executed = 0;

    if args.set == 0 || args.set == 1 {
        set1::run(args.challenge);
        executed += 1;
    }

    if executed == 0 {
        println!("Set {} doesn't exist", args.set);
    }
}
