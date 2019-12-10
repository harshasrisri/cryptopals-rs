use cryptopals::encodecode::*;
use cryptopals::xorcrypt::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn hex2b64() {
    let input =  "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let output = input.hex_decode().unwrap();
    println!(
        "hex2b64({}) = {} ({})",
        input,
        output.b64_encode(),
        String::from_utf8(output).unwrap_or_else(|_| "** Not a valid UTF8 buffer **".to_string())
    );
}

fn fixed_xor() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    print!("fixed_xor({}, {}) = ", input1, input2);

    let input1 = input1.hex_decode().unwrap();
    let input2 = input2.hex_decode().unwrap();
    println!("{}", input1.fixed_xor(&input2).unwrap().hex_encode());
}

fn single_byte_xor() {
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

fn detect_single_char_xor() {
    let input = File::open("inputs/s1c4.txt").unwrap();
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

fn break_repeat_key_xor() {
    let input = File::open("inputs/s1c6.txt").unwrap();
    let vigenere_key = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect::<Vec<String>>()
        .join("")
        .as_str()
        .b64_decode()
        .unwrap()
        .guess_vigenere()
        .unwrap();
    println!("Vigenere Key: {}", String::from_utf8(vigenere_key).unwrap());
}

fn main() {
    println!("----");
    hex2b64();
    println!("----");
    fixed_xor();
    println!("----");
    single_byte_xor();
    println!("----");
    detect_single_char_xor();
    println!("----");
    repeat_key_xor();
    println!("----");
    break_repeat_key_xor();
    println!("----");
}
