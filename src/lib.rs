use base64;
use hex;

pub trait XORCrypto {
    fn fixed_xor(self: Self, rhs: Self) -> Result<String, hex::FromHexError>;
}

impl XORCrypto for &str {
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
}

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    Ok(base64::encode(&hex::decode(input)?))
}
