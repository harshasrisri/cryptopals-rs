use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

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

pub trait PKCS7 {
    fn pad(self, block_size: u8) -> Self;
    fn strip(self) -> Self;
}

impl PKCS7 for Vec<u8> {
    fn pad(mut self, block_size: u8) -> Vec<u8> {
        let excess = block_size as usize - self.len() % block_size as usize;
        let excess = if excess == 0 {
            block_size
        } else {
            excess as u8
        };
        self.extend(std::iter::repeat(excess).take(excess.into()));
        self
    }

    fn strip(mut self) -> Vec<u8> {
        let padding = if let Some(last) = self.last() {
            *last as usize
        } else {
            return self;
        };
        if self[self.len() - padding..]
            .iter()
            .all(|byte| *byte == padding as u8)
        {
            self.truncate(self.len() - padding as usize);
        }
        self
    }
}

pub fn decode_b64_file<P>(path: P) -> Result<Vec<u8>>
where
    P: AsRef<Path>,
{
    let input = File::open(path)?;
    let res = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .flat_map(|line| line.b64_decode())
        .flatten()
        .collect();
    Ok(res)
}
