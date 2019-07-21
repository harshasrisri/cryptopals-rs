use base64;
use hex;
use std::collections::HashMap;

mod constants;
use constants::*;

pub trait XORCrypto {
    fn is_hex_encoded(self: Self) -> bool;
    fn fixed_xor(self: Self, rhs: Self) -> Result<String, hex::FromHexError>;
    fn single_key_xor(self: Self, key: char) -> Result<String, hex::FromHexError>;
    fn guess_xor_key(self: Self) -> Result<char, hex::FromHexError>;
    fn freq_rank(self: Self) -> Result<f32, hex::FromHexError>;
}

impl XORCrypto for &str {
    fn is_hex_encoded(self: Self) -> bool {
        hex::decode(self).is_ok()
    }

    fn fixed_xor(self, rhs: Self) -> Result<String, hex::FromHexError> {
        if self.len() != rhs.len() {
            return Err(hex::FromHexError::InvalidStringLength);
        }

        Ok(hex::encode(
            hex::decode(self)?
                .iter()
                .zip(hex::decode(rhs)?.iter())
                .map(|(l, r)| l ^ r)
                .collect::<Vec<u8>>(),
        ))
    }

    fn single_key_xor(self, key: char) -> Result<String, hex::FromHexError> {
        Ok(hex::encode(
            hex::decode(self)?
                .iter()
                .map(|&x| (x ^ key as u8))
                .collect::<Vec<u8>>(),
        ))
    }

    fn guess_xor_key(self) -> Result<char, hex::FromHexError> {
        let mut guess = None;
        let mut max_freq = 0.0;
        for (i, freq) in PRINTABLE_ASCII
            .iter()
            .map(|&key| self.single_key_xor(key).unwrap())
            .map(|payload| payload.freq_rank().unwrap())
            .enumerate()
        {
            if freq > max_freq {
                max_freq = freq;
                guess = Some(i);
            }
        }
        match guess {
            Some(i) => Ok(PRINTABLE_ASCII[i]),
            None => Err(hex::FromHexError::InvalidStringLength),
        }
    }

    fn freq_rank(self) -> Result<f32, hex::FromHexError> {
        let freq_map: HashMap<u8, f32> = ETAOIN_SHRDLU.iter().cloned().collect();
        Ok(hex::decode(self)?
            .iter()
            .map(|x| freq_map.get(&x).unwrap_or(&0.0))
            .sum())
    }
}

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    Ok(base64::encode(&hex::decode(input)?))
}
