use anyhow::Result;
use openssl::symm::{decrypt as oDecrypt, encrypt as oEncrypt, Cipher as oCipher};

pub trait Cipher {
    fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

pub struct AesEcb128;
pub struct AesCbc128;

impl Cipher for AesEcb128 {
    fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        oEncrypt(oCipher::aes_128_ecb(), key, None, data).map_err(|e| anyhow::Error::new(e))
    }

    fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        oDecrypt(oCipher::aes_128_ecb(), key, None, data).map_err(|e| anyhow::Error::new(e))
    }
}

impl Cipher for AesCbc128 {
    fn encrypt(_key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn decrypt(_key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
