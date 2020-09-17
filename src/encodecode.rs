use anyhow::Result;

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
    fn b64_decode(&self) -> Result<Vec<u8>>;
    fn hex_decode(&self) -> Result<Vec<u8>>;
}

impl<T: ?Sized + AsRef<[u8]>> Decoding for T {
    fn b64_decode(&self) -> Result<Vec<u8>> {
        Ok(base64::decode(self)?)
    }

    fn hex_decode(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(self)?)
    }
}

pub trait Padding {
    fn pad(input: &mut Vec<u8>, block_size: u8);
    fn strip(input: &mut Vec<u8>);
}

pub struct PKCS7;

impl Padding for PKCS7 {
    fn pad(input: &mut Vec<u8>, block_size: u8) {
        let excess = block_size as usize - input.len() % block_size as usize;
        let excess = if excess == 0 {
            block_size
        } else {
            excess as u8
        };
        input.extend(std::iter::repeat(excess).take(excess.into()));
    }

    fn strip(input: &mut Vec<u8>) {
        let padding = if let Some(last) = input.last() {
            *last as usize
        } else {
            return;
        };
        if input[input.len() - padding..]
            .iter()
            .all(|byte| *byte == padding as u8)
        {
            input.truncate(input.len() - padding as usize);
        }
    }
}
