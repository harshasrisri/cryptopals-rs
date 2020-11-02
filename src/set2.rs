use crate::CryptopalArgs;
use anyhow::Result;
use cryptopals::aes::{AesCbc128, AesEcb128, Cipher};
use cryptopals::buffer::*;
use cryptopals::decode_b64_file;

fn pkcs7_padding() -> Result<()> {
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

fn decrypt_cbc() -> Result<()> {
    let iv = vec![0; AesCbc128::BLOCK_SIZE];
    let key = b"YELLOW SUBMARINE";
    let input = decode_b64_file("inputs/s2c2.txt")?;
    let output = AesCbc128::decrypt(key, Some(iv.as_slice()), input.as_slice())?;

    println!("CBC decrypted output:");
    println!("{}", String::from_utf8(output)?);
    Ok(())
}

fn ecb_cbc_oracle() -> Result<()> {
    let input = {
        let iv = [0; AesCbc128::BLOCK_SIZE];
        let ciphertext = decode_b64_file("inputs/s2c2.txt")?;
        AesCbc128::decrypt(b"YELLOW SUBMARINE", Some(&iv), &ciphertext)?
    }
    .pad_with_random();

    let ecb = rand::random();
    let _enc_data = {
        let key = cryptopals::gen_rand_key(AesCbc128::BLOCK_SIZE);
        if ecb {
            println!("Encrypting in AesEcb128 using {}", key.hex_encode());
            AesEcb128::encrypt(&key, None, &input)
        } else {
            println!("Encrypting in AesCbc128 using {}", key.hex_encode());
            let iv = std::iter::repeat_with(rand::random)
                .take(AesCbc128::BLOCK_SIZE)
                .collect::<Vec<u8>>();
            AesCbc128::encrypt(&key, Some(&iv), &input)
        }
    };
    unimplemented!()
}

pub fn run(args: &CryptopalArgs) -> Result<()> {
    match args.challenge {
        1 => pkcs7_padding()?,
        2 => decrypt_cbc()?,
        3 => ecb_cbc_oracle()?,
        _ => anyhow::bail!(
            "Challenge {} doesn't exist in set {}",
            args.challenge,
            args.set
        ),
    };

    Ok(())
}
