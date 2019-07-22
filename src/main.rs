use cryptopals;
use cryptopals::*;

fn main() {
    println!("Set 1 Challenge 1 - {}", "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".hex_decode().unwrap().b64_encode());

    println!(
        "Set 1 Challenge 2 - {}",
        "1c0111001f010100061a024b53535009181c"
            .hex_decode()
            .unwrap()
            .fixed_xor("686974207468652062756c6c277320657965".hex_decode().unwrap())
            .unwrap()
            .hex_encode()
    );

    let s1c3_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let s1c3_guess = s1c3_input.hex_decode().unwrap().guess_xor_key().unwrap();
    println!(
        "Set 1 Challenge 3 - {} - {}",
        s1c3_guess,
        String::from_utf8(s1c3_input.hex_decode().unwrap().single_key_xor(s1c3_guess)).unwrap()
    );
}
