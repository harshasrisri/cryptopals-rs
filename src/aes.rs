use crate::xorcrypt::XORCrypto;
use anyhow::Result;
use openssl::symm::{Cipher as oCipher, Crypter, Mode};

pub trait Cipher {
    const BLOCK_SIZE: usize;
    fn encrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>>;
}

pub struct AesEcb128;

impl Cipher for AesEcb128 {
    const BLOCK_SIZE: usize = 16;

    fn encrypt(key: &[u8], _iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Encrypt, key, None)?;
        let res = data
            .chunks(Self::BLOCK_SIZE)
            .map(|plaintext| {
                let mut plaintext = plaintext.to_vec();
                plaintext.resize_with(Self::BLOCK_SIZE, Default::default);
                let mut ciphertext = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let _size = crypter.update(&plaintext, &mut ciphertext)?;
                ciphertext.truncate(Self::BLOCK_SIZE);
                Ok(ciphertext)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(res)
    }

    fn decrypt(key: &[u8], _iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
        let res = data
            .chunks(Self::BLOCK_SIZE)
            .map(|ciphertext| {
                let mut ciphertext = ciphertext.to_vec();
                ciphertext.resize_with(Self::BLOCK_SIZE, Default::default);
                let mut plaintext = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(&ciphertext, &mut plaintext)?;
                Ok(plaintext[size..size + Self::BLOCK_SIZE].to_vec())
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(res)
    }
}

pub struct AesCbc128;

impl Cipher for AesCbc128 {
    const BLOCK_SIZE: usize = 16;

    fn encrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(iv.is_some(), "IV is required for this cipher");
        let mut iv = iv.unwrap().to_vec();
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Encrypt, key, None)?;
        let res = data
            .chunks(Self::BLOCK_SIZE)
            .map(|chunk| {
                let mut plaintext = chunk.to_vec();
                plaintext.resize_with(Self::BLOCK_SIZE, Default::default);
                let interim = iv.xor(&plaintext)?;
                let mut ciphertext = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let _size = crypter.update(&interim, &mut ciphertext)?;
                ciphertext.truncate(Self::BLOCK_SIZE);
                // println!("{} --XOR--> {} --encrypt--> {}({}) = {}",
                //          plaintext.hex_encode(), iv.hex_encode(),
                //          interim.hex_encode(), size, ciphertext.hex_encode());
                iv.copy_from_slice(&ciphertext);
                Ok(ciphertext)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(res)
    }

    fn decrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(iv.is_some(), "IV is required for this cipher");
        let iv = iv.unwrap();
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
        let res = iv
            .chunks(Self::BLOCK_SIZE)
            .take(1)
            .chain(data.chunks(Self::BLOCK_SIZE))
            .collect::<Vec<_>>()
            .windows(2)
            .map(|window| {
                let iv = window[0].to_vec();
                let mut ciphertext = window[1].to_vec();
                ciphertext.resize_with(Self::BLOCK_SIZE, Default::default);
                let mut interim = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(&ciphertext, &mut interim)?;
                let plaintext = iv.as_slice().xor(&interim[size..size + Self::BLOCK_SIZE])?;
                // println!("{} --decrypt--> {}({}) --XOR--> {} = {}",
                //          ciphertext.hex_encode(), interim.hex_encode(),
                //          size, iv.hex_encode(), plaintext.hex_encode());
                Ok(plaintext)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(res)
    }
}
