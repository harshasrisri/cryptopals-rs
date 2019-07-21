use cryptopals;
use cryptopals::XORCrypto;

#[test]
pub fn test_hex2base64() {
    assert_eq!(
        cryptopals::hex2base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
            )
        .unwrap(),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

#[test]
pub fn test_fixed_xor() {
    assert_eq!(
        "1c0111001f010100061a024b53535009181c"
            .fixed_xor("686974207468652062756c6c277320657965")
            .unwrap(),
        "746865206b696420646f6e277420706c6179"
    );
}

#[test]
pub fn test_single_key_xor() {
    assert_eq!(
        hex::encode("Cooking MC's like a pound of bacon")
            .single_key_xor('X')
            .unwrap(),
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    );
}

#[test]
pub fn test_freq_rank() {
    assert_eq!("2e2e2e2e2e2e2e2e2e2e".freq_rank().unwrap().ceil() as u32, 0);
    assert_eq!(
        "65656565656565656565".freq_rank().unwrap().ceil() as u32,
        127
    );
}
