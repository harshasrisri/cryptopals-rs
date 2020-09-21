use crate::xorcrypt::BufferOps;
use anyhow::Result;
use openssl::symm::{decrypt as oDecrypt, encrypt as oEncrypt, Cipher as oCipher, Crypter, Mode};

pub trait Cipher {
    const BLOCK_SIZE: usize;
    fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

pub struct AesEcb128;

impl Cipher for AesEcb128 {
    const BLOCK_SIZE: usize = 16;

    fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        oEncrypt(oCipher::aes_128_ecb(), key, None, data).map_err(|e| anyhow::Error::new(e))
    }

    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        oDecrypt(oCipher::aes_128_ecb(), key, None, data).map_err(|e| anyhow::Error::new(e))
    }
}

pub struct AesCbc128;

impl Cipher for AesCbc128 {
    const BLOCK_SIZE: usize = 16;

    fn encrypt(_key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
        let res = vec![0; Self::BLOCK_SIZE]
            .chunks(Self::BLOCK_SIZE)
            .chain(data.chunks(Self::BLOCK_SIZE))
            .collect::<Vec<_>>()
            .windows(2)
            .flat_map(|window| {
                let iv = window[0];
                let ciphertext = window[1];
                let mut interim = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(ciphertext, interim.as_mut_slice()).unwrap();
                let plaintext = iv.xor(&interim[size..size + Self::BLOCK_SIZE]).unwrap();
                // println!("{} --decrypt--> {}({}) --XOR--> {} = {}", ciphertext.hex_encode(), interim.hex_encode(), size, iv.hex_encode(), plaintext.hex_encode());
                plaintext
            })
            .collect::<Vec<u8>>();
        // res.extend_from_slice(vec![0 as u8; Self::BLOCK_SIZE * 2].as_slice());
        // crypter.finalize(&mut res[data.len()..])?;
        Ok(res)
    }
}

// pub struct O_AesCbc128;
//
// impl Cipher for O_AesCbc128 {
//     const BLOCK_SIZE: usize = 16;

//     fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
//         let iv = vec![0 as u8; Self::BLOCK_SIZE];
//         oEncrypt(oCipher::aes_128_cbc(), key, Some(iv.as_slice()), data).map_err(|e| anyhow::Error::new(e))
//     }

//     fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
//         let iv = vec![0 as u8; Self::BLOCK_SIZE];
//         oDecrypt(oCipher::aes_128_cbc(), key, Some(iv.as_slice()), data).map_err(|e| anyhow::Error::new(e))
//     }
// }
