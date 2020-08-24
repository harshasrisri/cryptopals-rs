use crate::CryptopalArgs;
use anyhow::Result;
use cryptopals::constants::CARGO_HOME;
use cryptopals::encodecode::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn pkcs7padding() -> Result<()> {
    let input = "YELLOW SUBMARINE".to_owned().into_bytes();
    println!(
        "input    - \"{}\" : {:?}",
        String::from_utf8(input.clone())?,
        input
    );

    let mut padded = input.clone();
    PKCS7::pad(&mut padded, 20);
    println!(
        "Padded   - \"{}\" : {:?}",
        String::from_utf8(padded.clone())?,
        padded
    );

    let mut stripped = padded;
    PKCS7::strip(&mut stripped);
    println!(
        "Stripped - \"{}\" : {:?}",
        String::from_utf8(stripped.clone())?,
        stripped
    );

    assert_eq!(input, stripped);
    println!("PKCS7 Padding(input) == Stripped");
    Ok(())
}

fn cbc_encrypt() -> Result<()> {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c7.txt");
    let input = File::open(input)?;
    let _input = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect::<Vec<String>>()
        .join("")
        .as_str()
        .b64_decode()?;

    unimplemented!()
}

pub fn run(args: &CryptopalArgs) -> Result<()> {
    match args.challenge {
        1 => pkcs7padding()?,
        2 => cbc_encrypt()?,
        _ => anyhow::bail!(
            "Challenge {} doesn't exist in set {}",
            args.challenge,
            args.set
        ),
    };

    Ok(())
}
