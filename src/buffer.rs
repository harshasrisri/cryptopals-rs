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
        self.as_ref().iter()
            .map(|x| ETAOIN_SHRDLU.get(&x).unwrap_or(&0.0))
            .sum()
    }

    fn hamming_distance(&self, rhs: &Self) -> Result<u32> {
        Ok(self.as_ref().xor(rhs.as_ref())?.count_ones())
    }

    fn matrixify(&self, cols: usize) -> Vec<&[u8]> {
        self.as_ref().chunks_exact(cols)
            .map(|slice| slice)
            .collect::<Vec<_>>()
    }
}

