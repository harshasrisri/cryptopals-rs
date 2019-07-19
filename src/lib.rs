use base64;
use hex;

pub trait XORCrypto {
    fn is_hex_encoded(self: Self) -> bool;
    fn fixed_xor(self: Self, rhs: Self) -> Result<String, hex::FromHexError>;
    fn single_key_xor(self: Self, key: char) -> Result<String, hex::FromHexError>;
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
}

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    Ok(base64::encode(&hex::decode(input)?))
}
