use crate::xorcrypt::BufferOps;
use anyhow::Result;
use openssl::symm::{Cipher as oCipher, Crypter, Mode};

pub trait Cipher {
    const BLOCK_SIZE: usize;
    fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

pub struct AesEcb128;

impl Cipher for AesEcb128 {
    const BLOCK_SIZE: usize = 16;

    fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Encrypt, key, None)?;
        let res = data.chunks(Self::BLOCK_SIZE)
            .map(|plaintext| {
                let mut ciphertext = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(plaintext, ciphertext.as_mut_slice())?;
                Ok(ciphertext[size .. size + Self::BLOCK_SIZE].to_vec())
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(res)
    }

    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(oCipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
        let res = data.chunks(Self::BLOCK_SIZE)
            .map(|ciphertext| {
                let mut plaintext = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(ciphertext, plaintext .as_mut_slice())?;
                Ok(plaintext[size .. size + Self::BLOCK_SIZE].to_vec())
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
            .map(|window| {
                let iv = window[0];
                let ciphertext = window[1];
                let mut interim = vec![0 as u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(ciphertext, interim.as_mut_slice())?;
                let plaintext = iv.xor(&interim[size..size + Self::BLOCK_SIZE])?;
                // println!("{} --decrypt--> {}({}) --XOR--> {} = {}", 
                //          ciphertext.hex_encode(), interim.hex_encode(), 
                //          size, iv.hex_encode(), plaintext.hex_encode());
                Ok(plaintext)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
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
