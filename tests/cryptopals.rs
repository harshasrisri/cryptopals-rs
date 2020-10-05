use anyhow::Result;
use cryptopals::buffer::*;
use cryptopals::decode_b64_file;
use cryptopals::xorcrypt::*;

#[test]
pub fn test_hex2base64() -> Result<()> {
    assert_eq!(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".hex_decode()?.b64_encode(),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
    Ok(())
}

#[test]
pub fn test_fixed_xor() -> Result<()> {
    assert_eq!(
        "1c0111001f010100061a024b53535009181c"
            .hex_decode()?
            .xor(&"686974207468652062756c6c277320657965".hex_decode()?)?
            .hex_encode(),
        "746865206b696420646f6e277420706c6179"
    );
    Ok(())
}

#[test]
pub fn test_single_key_xor() -> Result<()> {
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
pub fn test_freq_rank() -> Result<()> {
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

#[test]
pub fn test_repeat_key_xor() -> Result<()> {
    assert_eq!(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".bytes().collect::<Vec<u8>>().repeat_key_xor("ICE").hex_encode(),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    Ok(())
}

#[test]
pub fn test_hamming_distance() -> Result<()> {
    let str1 = "this is a test".as_bytes().to_vec();
    let str2 = "wokka wokka!!!".as_bytes().to_vec();
    assert_eq!(str1.hamming_distance(&str2).unwrap(), 37);
    Ok(())
}

#[test]
pub fn test_vigenere() -> Result<()> {
    let cipherblob = decode_b64_file("inputs/s1c6.txt")?;
    let guessed_key = String::from_utf8(cipherblob.guess_vigenere()?).unwrap();
    let plainblob = cipherblob.repeat_key_xor(guessed_key.as_str());
    let reconstructed = plainblob.repeat_key_xor(guessed_key.as_str());
    assert_eq!(cipherblob, reconstructed);
    Ok(())
}

#[test]
fn test_pkcs7() {
    const SIZE: u8 = 16;
    for i in 0..SIZE + 1 {
        let input = vec![i; i as usize];
        println!("{:?}", input);
        let padded = input.clone().pad(SIZE);
        println!("{:?}", padded);
        let stripped = padded.strip();
        println!("{:?}", stripped);
        assert_eq!(input, stripped);
    }
}
