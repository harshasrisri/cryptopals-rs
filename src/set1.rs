use crate::CryptopalArgs;
use anyhow::Result;
use cryptopals::constants::CARGO_HOME;
use cryptopals::cryptobuf::*;
use cryptopals::encodecode::*;
use cryptopals::xorcrypt::*;
use openssl::symm::{decrypt, Cipher};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn hex2b64() -> Result<()> {
    let input =  "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = input.hex_decode()?;
    println!(
        "hex2b64({}) = {} ({})",
        input,
        output.b64_encode(),
        String::from_utf8(output)?
    );
    Ok(())
}

fn fixed_xor() -> Result<()> {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    print!("fixed_xor({}, {}) = ", input1, input2);

    let input1 = input1.hex_decode()?;
    let input2 = input2.hex_decode()?;
    println!("{}", input1.xor(&input2)?.hex_encode());
    Ok(())
}

fn single_byte_xor() -> Result<()> {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    print!("single_byte_xor({}) = ", input);

    let input = input.hex_decode()?;
    let (guess, freq_rank) = input.guess_xor_key()?;
    println!(
        "{} ({}) ({})",
        guess,
        String::from_utf8(input.single_key_xor(guess))?,
        freq_rank
    );
    Ok(())
}

fn detect_single_char_xor() -> Result<()> {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c4.txt");
    println!("input file: {}", input);
    let input = File::open(input)?;
    let mut max_rank = 0.0;
    let mut output = None;
    for line in BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
    {
        let line = line.hex_decode()?;
        let (guess, freq) = line.guess_xor_key()?;
        if freq > max_rank {
            max_rank = freq;
            if let Ok(s) = String::from_utf8(line.single_key_xor(guess)) {
                output = Some(s);
            }
        }
    }

    print!(
        "Encrypted string in inputs/s1c4.txt with freq rank {} = {}",
        max_rank,
        output.unwrap()
    );
    Ok(())
}

fn repeat_key_xor() {
    let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";

    println!(
        "-\n{}\n-\nAbove text repeatedly XOR'ed with the key {} is:\n{}",
        input,
        key,
        input
            .bytes()
            .collect::<Vec<u8>>()
            .repeat_key_xor("ICE")
            .hex_encode()
    );
}

fn break_repeat_key_xor() -> Result<()> {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c6.txt");
    println!("{}", input);
    let input = File::open(input)?;
    let input = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect::<Vec<String>>()
        .join("")
        .as_str()
        .b64_decode()?;
    let guessed_key = String::from_utf8(input.guess_vigenere()?)?;
    println!("Vigenere Key: {}", guessed_key);
    println!(
        "Plain text: {}",
        String::from_utf8(input.repeat_key_xor(guessed_key.as_str()))?
    );
    Ok(())
}

fn aes_decrypt() -> Result<()> {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c7.txt");
    let input = File::open(input)?;
    let input = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect::<Vec<String>>()
        .join("")
        .as_str()
        .b64_decode()?;
    let ciphertext = input.as_slice();
    let key = b"YELLOW SUBMARINE";
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, ciphertext)?;
    println!("Plain text: {}", String::from_utf8(plaintext)?);
    Ok(())
}

fn detect_aes_ecb() -> Result<()> {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c8.txt");
    println!("input file: {}", input);
    let input = File::open(input)?;
    for (i, line) in BufReader::new(input)
        .lines()
        .filter_map(|line| line.ok())
        .enumerate()
    {
        let line = line.hex_decode()?;
        let chunks = line.chunks(16);
        if line.len() / 16 != chunks.collect::<HashSet<_>>().len() {
            println!("ECB detected on line number {}", i);
        }
    }
    Ok(())
}

pub fn run(args: &CryptopalArgs) -> Result<()> {
    match args.challenge {
        1 => hex2b64()?,
        2 => fixed_xor()?,
        3 => single_byte_xor()?,
        4 => detect_single_char_xor()?,
        5 => repeat_key_xor(),
        6 => break_repeat_key_xor()?,
        7 => aes_decrypt()?,
        8 => detect_aes_ecb()?,
        _ => anyhow::bail!(
            "Challenge {} doesn't exist in set {}",
            args.challenge,
            args.set
        ),
    };

    Ok(())
}
