use crate::CryptopalArgs;
use anyhow::Result;
use cryptopals::encodecode::{PKCS7, Padding};

fn pkcs7padding() -> Result<()> {
    let input = "YELLOW SUBMARINE".to_owned().into_bytes();
    println!("input - {:?}", input);

    let mut padded = input.clone();
    PKCS7::pad(&mut padded, 20);
    println!("Padded - {:?}", padded);

    let mut stripped = padded.clone();
    PKCS7::strip(&mut stripped);
    println!("Stripped - {:?}", stripped);

    assert_eq!(input, stripped);
    println!("PKCS7 Padding(input) == Stripped");
    Ok(())
}

pub fn run(args: &CryptopalArgs) -> Result<()> {
    match args.challenge {
        1 => pkcs7padding()?,
        _ => anyhow::bail!(
            "Challenge {} doesn't exist in set {}",
            args.challenge,
            args.set
        ),
    };

    Ok(())
}
