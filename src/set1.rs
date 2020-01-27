use cryptopals::cryptobuf::*;
use cryptopals::encodecode::*;
use cryptopals::xorcrypt::*;
use cryptopals::constants::CARGO_HOME;
use crate::CryptopalArgs;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn hex2b64() {
    let input =  "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = input.hex_decode().unwrap();
    println!(
        "hex2b64({}) = {} ({})",
        input,
        output.b64_encode(),
        String::from_utf8(output).unwrap_or_else(|_| "** Not a valid UTF8 buffer **".to_string())
    );
}

pub fn fixed_xor() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    print!("fixed_xor({}, {}) = ", input1, input2);

    let input1 = input1.hex_decode().unwrap();
    let input2 = input2.hex_decode().unwrap();
    println!("{}", input1.xor(&input2).unwrap().hex_encode());
}

pub fn single_byte_xor() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    print!("single_byte_xor({}) = ", input);

    let input = input.hex_decode().unwrap();
    let (guess, freq_rank) = input.guess_xor_key().unwrap();
    println!(
        "{} ({}) ({})",
        guess,
        String::from_utf8(input.single_key_xor(guess)).unwrap(),
        freq_rank
    );
}

pub fn detect_single_char_xor() {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c4.txt");
    println!("{}", input);
    let input = File::open(input).unwrap();
    let mut max_rank = 0.0;
    let mut output = None;
    for line in BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
    {
        let line = line.hex_decode().unwrap();
        let (guess, freq) = line.guess_xor_key().unwrap();
        if freq > max_rank {
            max_rank = freq;
            output = Some(
                String::from_utf8(line.single_key_xor(guess)).unwrap_or_else(|_| "".to_string()),
            );
        }
    }
    print!(
        "Encrypted string in inputs/s1c4.txt with freq rank {} = {}",
        max_rank,
        output.unwrap()
    );
}

pub fn repeat_key_xor() {
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

pub fn break_repeat_key_xor() {
    let mut input = CARGO_HOME.to_owned();
    input.push_str("/inputs/s1c6.txt");
    println!("{}", input);
    let input = File::open(input).unwrap();
    let input = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect::<Vec<String>>()
        .join("")
        .as_str()
        .b64_decode()
        .unwrap();
    let guessed_key = String::from_utf8(input.guess_vigenere().unwrap()).unwrap();
    println!("Vigenere Key: {}", guessed_key);
    println!(
        "Plain text: {}",
        String::from_utf8(input.repeat_key_xor(guessed_key.as_str())).unwrap()
    );
}

pub fn run(args: &CryptopalArgs) {
    let mut executed = 0;
    let challenge = args.challenge;

    if challenge == 0 || challenge == 1 {
        println!("----");
        hex2b64();
        executed += 1;
    }
    if challenge == 0 || challenge == 2 {
        println!("----");
        fixed_xor();
        executed += 1;
    }
    if challenge == 0 || challenge == 3 {
        println!("----");
        single_byte_xor();
        executed += 1;
    }
    if challenge == 0 || challenge == 4 {
        println!("----");
        detect_single_char_xor();
        executed += 1;
    }
    if challenge == 0 || challenge == 5 {
        println!("----");
        repeat_key_xor();
        executed += 1;
    }
    if challenge == 0 || challenge == 6 {
        println!("----");
        break_repeat_key_xor();
        executed += 1;
    }
    if executed == 0 {
        println!("Challenge {} doesn't exist in this set", challenge);
    } else {
        println!("----");
    }
}
