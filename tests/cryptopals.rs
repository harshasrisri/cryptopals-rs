use cryptopals;
use cryptopals::*;

type Result = std::result::Result<(), hex::FromHexError>;

#[test]
pub fn test_hex2base64() -> Result {
    assert_eq!(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".hex_decode()?.b64_encode(),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
    Ok(())
}

#[test]
pub fn test_fixed_xor() -> Result {
    assert_eq!(
        "1c0111001f010100061a024b53535009181c"
            .hex_decode()?
            .fixed_xor("686974207468652062756c6c277320657965".hex_decode()?)?
            .hex_encode(),
        "746865206b696420646f6e277420706c6179"
    );
    Ok(())
}

#[test]
pub fn test_single_key_xor() -> Result {
    assert_eq!(
        "Cooking MC's like a pound of bacon"
            .bytes()
            .collect::<Vec<u8>>()
            .single_key_xor('X')
            .hex_encode(),
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    );
    Ok(())
}

#[test]
pub fn test_freq_rank() -> Result {
    assert_eq!(
        "2e2e2e2e2e2e2e2e2e2e".hex_decode()?.freq_rank().ceil() as u32,
        0
    );
    assert_eq!(
        "65656565656565656565".hex_decode()?.freq_rank().ceil() as u32,
        127
    );
    Ok(())
}
