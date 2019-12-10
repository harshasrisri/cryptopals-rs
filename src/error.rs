use base64;
use hex;

#[derive(Debug, Clone, PartialEq)]
pub enum CryptopalError {
    Hex(hex::FromHexError),
    B64(base64::DecodeError),
    UnequalBufLength,
    CantGuessXorKey,
}

pub type CryptopalResult<T> = std::result::Result<T, CryptopalError>;

impl From<hex::FromHexError> for CryptopalError {
    fn from(error: hex::FromHexError) -> Self {
        CryptopalError::Hex(error)
    }
}

impl From<base64::DecodeError> for CryptopalError {
    fn from(error: base64::DecodeError) -> Self {
        CryptopalError::B64(error)
    }
}
