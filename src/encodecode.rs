use base64;
use hex;

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
