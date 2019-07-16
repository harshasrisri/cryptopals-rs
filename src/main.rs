use cryptopals;

fn main() {
    println!("Set 1 Challenge 1 - {}", cryptopals::hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap());
    println!("Set 1 Challenge 2 - {}", cryptopals::fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") .unwrap());
}
