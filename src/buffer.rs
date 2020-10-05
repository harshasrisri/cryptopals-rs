use crate::xorcrypt::XORCrypto;
use anyhow::Result;
use std::collections::HashMap;

#[rustfmt::skip]
lazy_static! {
    static ref ETAOIN_SHRDLU: HashMap<u8, f32> = [
        (b' ', 13.00), (b'e', 12.70), (b't', 9.056), (b'a', 8.167), (b'o', 7.507),
        (b'i', 6.966), (b'n', 6.749), (b's', 6.327), (b'h', 6.094), (b'r', 5.987),
        (b'd', 4.253), (b'l', 4.025), (b'u', 2.758), (b'b', 1.492), (b'c', 2.782),
        (b'f', 2.228), (b'g', 2.015), (b'j', 0.153), (b'k', 0.772), (b'm', 2.406),
        (b'p', 1.929), (b'q', 0.095), (b'v', 0.978), (b'w', 2.360), (b'x', 0.150),
        (b'y', 1.974), (b'z', 0.074),
    ].iter().cloned().collect();
}

pub trait BufferOps {
    fn count_ones(&self) -> u32;
    fn freq_rank(&self) -> f32;
    fn hamming_distance(&self, rhs: &Self) -> Result<u32>;
    fn matrixify(&self, cols: usize) -> Vec<&[u8]>;
}

impl<T: ?Sized + AsRef<[u8]>> BufferOps for T {
    fn count_ones(&self) -> u32 {
        self.as_ref().iter().map(|b| b.count_ones()).sum()
    }

    fn freq_rank(&self) -> f32 {
        self.as_ref()
            .iter()
            .map(|x| ETAOIN_SHRDLU.get(&x).unwrap_or(&0.0))
            .sum()
    }

    fn hamming_distance(&self, rhs: &Self) -> Result<u32> {
        Ok(self.as_ref().xor(rhs.as_ref())?.count_ones())
    }

    fn matrixify(&self, cols: usize) -> Vec<&[u8]> {
        self.as_ref().chunks_exact(cols).collect()
    }
}

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
