use base64;
use hex;
use std::collections::HashMap;

const PRINTABLE_ASCII: [char; 94] = [
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
];

const ETAOIN_SHRDLU: [(u8, f32); 27] = [
    (b' ', 13.00),
    (b'e', 12.70),
    (b't', 9.056),
    (b'a', 8.167),
    (b'o', 7.507),
    (b'i', 6.966),
    (b'n', 6.749),
    (b's', 6.327),
    (b'h', 6.094),
    (b'r', 5.987),
    (b'd', 4.253),
    (b'l', 4.025),
    (b'u', 2.758),
    (b'b', 1.492),
    (b'c', 2.782),
    (b'f', 2.228),
    (b'g', 2.015),
    (b'j', 0.153),
    (b'k', 0.772),
    (b'm', 2.406),
    (b'p', 1.929),
    (b'q', 0.095),
    (b'v', 0.978),
    (b'w', 2.360),
    (b'x', 0.150),
    (b'y', 1.974),
    (b'z', 0.074),
];

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
