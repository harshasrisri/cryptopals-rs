use base64;
use hex;
use std::collections::HashMap;

const ETAOIN_SHRDLU: [(u8, f32); 27] = [
    (' ' as u8, 13.00),
    ('e' as u8, 12.70),
    ('t' as u8, 9.056),
    ('a' as u8, 8.167),
    ('o' as u8, 7.507),
    ('i' as u8, 6.966),
    ('n' as u8, 6.749),
    ('s' as u8, 6.327),
    ('h' as u8, 6.094),
    ('r' as u8, 5.987),
    ('d' as u8, 4.253),
    ('l' as u8, 4.025),
    ('u' as u8, 2.758),
    ('b' as u8, 1.492),
    ('c' as u8, 2.782),
    ('f' as u8, 2.228),
    ('g' as u8, 2.015),
    ('j' as u8, 0.153),
    ('k' as u8, 0.772),
    ('m' as u8, 2.406),
    ('p' as u8, 1.929),
    ('q' as u8, 0.095),
    ('v' as u8, 0.978),
    ('w' as u8, 2.360),
    ('x' as u8, 0.150),
    ('y' as u8, 1.974),
    ('z' as u8, 0.074),
];

pub trait XORCrypto {
    fn is_hex_encoded(self: Self) -> bool;
    fn fixed_xor(self: Self, rhs: Self) -> Result<String, hex::FromHexError>;
    fn single_key_xor(self: Self, key: char) -> Result<String, hex::FromHexError>;
    fn freq_rank(self: Self) -> Result<f32, hex::FromHexError>;
}

impl XORCrypto for &str {
    fn is_hex_encoded(self: Self) -> bool {
        match hex::decode(self) {
            Ok(_) => true,
            Err(_) => false,
        }
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
