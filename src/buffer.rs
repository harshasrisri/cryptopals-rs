use crate::constants::ETAOIN_SHRDLU;
use crate::xorcrypt::XORCrypto;
use anyhow::Result;

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
