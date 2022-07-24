use crate::xorcrypt::XORCrypto;
use anyhow::{bail, ensure, Result};
use openssl::symm::{Cipher as oCipher, Crypter, Mode};

pub trait Cipher {
    const BLOCK_SIZE: usize = 16;
    fn encrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>>;
}

pub struct AesEcb<const N: usize>;
pub struct AesCbc<const N: usize>;

pub type AesEcb128 = AesEcb<128>;
pub type AesEcb256 = AesEcb<256>;

pub type AesCbc128 = AesCbc<128>;
pub type AesCbc256 = AesCbc<256>;

impl<const N: usize> Cipher for AesEcb<N> {
    fn encrypt(key: &[u8], _iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            key.len() * 8 == N,
            "Unexpected key length {} for AES-{}",
            key.len() * 8,
            N
        );

        let cipher_engine = match N {
            128 => oCipher::aes_128_ecb(),
            256 => oCipher::aes_256_ecb(),
            _ => bail!("Unhandled key length"),
        };

        let mut crypter = Crypter::new(cipher_engine, Mode::Encrypt, key, None)?;

        let res = data
            .chunks(Self::BLOCK_SIZE)
            .map(|plaintext| {
                let mut plaintext = plaintext.to_vec();
                plaintext.resize_with(Self::BLOCK_SIZE, Default::default);
                let mut ciphertext = vec![0_u8; Self::BLOCK_SIZE * 2];
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
        ensure!(
            key.len() * 8 == N,
            "Unexpected key length {} for AES-{}",
            key.len() * 8,
            N
        );

        let cipher_engine = match N {
            128 => oCipher::aes_128_ecb(),
            256 => oCipher::aes_256_ecb(),
            _ => bail!("Unhandled Block Size"),
        };

        let mut crypter = Crypter::new(cipher_engine, Mode::Decrypt, key, None)?;

        let res = data
            .chunks(Self::BLOCK_SIZE)
            .map(|ciphertext| {
                let mut ciphertext = ciphertext.to_vec();
                ciphertext.resize_with(Self::BLOCK_SIZE, Default::default);
                let mut plaintext = vec![0_u8; Self::BLOCK_SIZE * 2];
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

impl<const N: usize> Cipher for AesCbc<N> {
    fn encrypt(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            key.len() * 8 == N,
            "Unexpected key length {} for AES-{}",
            key.len() * 8,
            N
        );
        ensure!(iv.is_some(), "IV is required for this cipher");

        let cipher_engine = match N {
            128 => oCipher::aes_128_ecb(),
            256 => oCipher::aes_256_ecb(),
            _ => bail!("Unhandled Block Size"),
        };

        let mut crypter = Crypter::new(cipher_engine, Mode::Encrypt, key, iv)?;
        let mut iv = iv.unwrap().to_vec();

        let res = data
            .chunks(Self::BLOCK_SIZE)
            .map(|chunk| {
                let mut plaintext = chunk.to_vec();
                plaintext.resize_with(Self::BLOCK_SIZE, Default::default);
                let interim = iv.xor(&plaintext)?;
                let mut ciphertext = vec![0_u8; Self::BLOCK_SIZE * 2];
                let _size = crypter.update(&interim, &mut ciphertext)?;
                ciphertext.truncate(Self::BLOCK_SIZE);
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
        ensure!(
            key.len() * 8 == N,
            "Unexpected key length {} for AES-{}",
            key.len() * 8,
            N
        );
        ensure!(iv.is_some(), "IV is required for this cipher");

        let cipher_engine = match N {
            128 => oCipher::aes_128_ecb(),
            256 => oCipher::aes_256_ecb(),
            _ => bail!("Unhandled Block Size"),
        };

        let mut crypter = Crypter::new(cipher_engine, Mode::Decrypt, key, iv)?;
        let iv = iv.unwrap();

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
                let mut interim = vec![0_u8; Self::BLOCK_SIZE * 2];
                let size = crypter.update(&ciphertext, &mut interim)?;
                let plaintext = iv.as_slice().xor(&interim[size..size + Self::BLOCK_SIZE])?;
                Ok(plaintext)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(res)
    }
}
