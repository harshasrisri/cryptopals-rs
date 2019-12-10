use crate::error::{CryptopalError, CryptopalResult};
use base64;
use hex;

pub trait Encoding {
    fn b64_encode(&self) -> String;
    fn hex_encode(&self) -> String;
}

impl<T: ?Sized + AsRef<[u8]>> Encoding for T {
    fn b64_encode(&self) -> String {
        base64::encode(&self)
    }

    fn hex_encode(&self) -> String {
        hex::encode(&self)
    }
}

pub trait Decoding {
    fn b64_decode(&self) -> CryptopalResult<Vec<u8>>;
    fn hex_decode(&self) -> CryptopalResult<Vec<u8>>;
}

impl<T: ?Sized + AsRef<[u8]>> Decoding for T {
    fn b64_decode(&self) -> CryptopalResult<Vec<u8>> {
        base64::decode(self).map_err(CryptopalError::from)
    }

    fn hex_decode(&self) -> CryptopalResult<Vec<u8>> {
        hex::decode(self).map_err(CryptopalError::from)
    }
}
