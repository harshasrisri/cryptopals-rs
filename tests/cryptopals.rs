use cryptopals;

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
        cryptopals::fixed_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965"
        )
        .unwrap(),
        "746865206b696420646f6e277420706c6179"
    );
}
