use base64;
use hex;
use std::collections::HashMap;

mod constants;
use constants::*;

type Result<T> = std::result::Result<T, hex::FromHexError>;

pub trait Encoding {
    fn b64_encode(&self) -> String;
    fn hex_encode(&self) -> String;
}

impl Encoding for Vec<u8> {
    fn b64_encode(&self) -> String {
        base64::encode(&self)
    }

    fn hex_encode(&self) -> String {
        hex::encode(&self)
    }
}

pub trait Decoding {
    fn b64_decode(self) -> std::result::Result<Vec<u8>, base64::DecodeError>;
    fn hex_decode(self) -> Result<Vec<u8>>;
}

impl Decoding for &str {
    fn b64_decode(self) -> std::result::Result<Vec<u8>, base64::DecodeError> {
        base64::decode(self)
    }

    fn hex_decode(self) -> Result<Vec<u8>> {
        hex::decode(self)
    }
}

pub trait XORCrypto {
    fn fixed_xor(self: &Self, rhs: &Self) -> Result<Vec<u8>>;
    fn single_key_xor(self: &Self, key: char) -> Vec<u8>;
    fn guess_xor_key(self: &Self) -> Result<(char, f32)>;
    fn freq_rank(self: &Self) -> f32;
}

impl XORCrypto for Vec<u8> {
    fn fixed_xor(&self, rhs: &Self) -> Result<Vec<u8>> {
        if self.len() != rhs.len() {
            return Err(hex::FromHexError::InvalidStringLength);
        }

        Ok(self
            .iter()
            .zip(rhs.iter())
            .map(|(l, r)| l ^ r)
            .collect::<Vec<u8>>())
    }

    fn single_key_xor(&self, key: char) -> Vec<u8> {
        self.iter().map(|&x| (x ^ key as u8)).collect::<Vec<u8>>()
    }

    fn guess_xor_key(&self) -> Result<(char, f32)> {
        let mut guess = None;
        let mut max_freq = 0.0;
        for (i, freq) in PRINTABLE_ASCII
            .iter()
            .map(|&key| self.single_key_xor(key))
            .map(|buf| buf.freq_rank())
            .enumerate()
        {
            if freq > max_freq {
                max_freq = freq;
                guess = Some(i);
            }
        }
        match guess {
            Some(i) => Ok((PRINTABLE_ASCII[i], max_freq)),
            None => Err(hex::FromHexError::InvalidStringLength),
        }
    }

    fn freq_rank(&self) -> f32 {
        let freq_map: HashMap<u8, f32> = ETAOIN_SHRDLU.iter().cloned().collect();
        self.iter().map(|x| freq_map.get(&x).unwrap_or(&0.0)).sum()
    }
}
