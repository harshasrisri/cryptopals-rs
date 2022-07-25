use crate::{gen_rand_key, xorcrypt::XORCrypto};
use anyhow::{bail, ensure, Result};
use openssl::symm::{Cipher as oCipher, Crypter, Mode};
use rand::{distributions::Standard, prelude::Distribution};

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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    ECB,
    CBC,
}

impl Distribution<AesMode> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AesMode {
        match rng.gen() {
            true => AesMode::ECB,
            false => AesMode::CBC,
        }
    }
}

pub struct OracleBuilder<'a> {
    mode: Option<AesMode>,
    key: Option<&'a [u8]>,
    key_len: Option<usize>,
    iv: Option<&'a [u8]>,
}

impl<'a> OracleBuilder<'a> {
    pub fn with_mode(mut self, mode: AesMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn with_key(mut self, key: &'a [u8]) -> Self {
        self.key = Some(key);
        self
    }

    pub fn with_iv(mut self, iv: &'a [u8]) -> Self {
        self.iv = Some(iv);
        self
    }

    pub fn with_key_len(mut self, key_len: usize) -> Self {
        self.key_len = Some(key_len);
        self
    }

    pub fn build(self) -> Oracle {
        let mode = self.mode.unwrap_or_else(rand::random);
        let key_len = self.key_len.unwrap_or(16);
        let key = self
            .key
            .map(|slice| slice.to_vec())
            .unwrap_or_else(|| gen_rand_key(key_len));
        let iv = match (&mode, self.iv) {
            (AesMode::ECB, _) => None,
            (AesMode::CBC, None) => Some(gen_rand_key(AesCbc128::BLOCK_SIZE)),
            (AesMode::CBC, Some(iv)) => Some(iv.to_vec()),
        };
        Oracle { mode, key, iv }
    }
}

pub struct Oracle {
    mode: AesMode,
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl Oracle {
    pub fn builder<'a>() -> OracleBuilder<'a> {
        OracleBuilder {
            mode: None,
            key: None,
            key_len: None,
            iv: None,
        }
    }

    pub fn get_mode(&self) -> AesMode {
        self.mode
    }

    pub fn get_key(&self) -> &[u8] {
        self.key.as_slice()
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let iv = self.iv.as_deref();
        match self.mode {
            AesMode::ECB => AesEcb128::encrypt(&self.key, iv, data),
            AesMode::CBC => AesCbc128::encrypt(&self.key, iv, data),
        }
    }
}
