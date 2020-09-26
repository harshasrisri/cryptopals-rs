use crate::CryptopalArgs;
use anyhow::Result;
use cryptopals::aes::{AesCbc128, Cipher};
// use cryptopals::aes::O_AesCbc128;
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

    let padded = input.clone().pad(20);
    println!(
        "Padded   - \"{}\" : {:?}",
        String::from_utf8(padded.clone())?,
        padded
    );

    let stripped = padded.strip();
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
    input.push_str("/inputs/s2c2.txt");
    let input = File::open(input)?;
    let input = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .flat_map(|line| line.b64_decode())
        .flatten()
        .collect::<Vec<u8>>();

    let key = b"YELLOW SUBMARINE";
    let output = AesCbc128::decrypt(key, input.as_slice())?;

    // This verification was explicitly discouraged by cryptopals. However, it
    // exists for reassurance that our decryption works like actual CBC
    // let mut output2 = O_AesCbc128::decrypt(key, input.as_slice())?;
    // assert_eq!(output1, output2);

    println!("CBC decrypted output:");
    println!("{}", String::from_utf8(output)?);
    Ok(())
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
