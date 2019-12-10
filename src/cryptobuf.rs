use crate::constants::ETAOIN_SHRDLU;
use crate::error::*;
use std::collections::HashMap;

pub trait XORBuf {
    fn count_ones(&self) -> u32;
    fn freq_rank(&self) -> f32;
    fn xor(&self, rhs: &Self) -> CryptopalResult<Vec<u8>>;
    fn hamming_distance(&self, rhs: &Self) -> CryptopalResult<u32>;
    fn matrixify(&self, cols: usize) -> Vec<Vec<u8>>;
    fn matrixify_padded(&self, cols: usize) -> Vec<Vec<u8>>;
}

impl XORBuf for Vec<u8> {
    fn count_ones(&self) -> u32 {
        self.iter().map(|b| b.count_ones()).sum()
    }

    fn freq_rank(&self) -> f32 {
        let freq_map: HashMap<u8, f32> = ETAOIN_SHRDLU.iter().cloned().collect();
        self.iter().map(|x| freq_map.get(&x).unwrap_or(&0.0)).sum()
    }

    fn xor(&self, rhs: &Self) -> CryptopalResult<Self> {
        if self.len() != rhs.len() {
            return Err(CryptopalError::UnequalBufLength);
        }

        Ok(self.iter().zip(rhs.iter()).map(|(l, r)| l ^ r).collect())
    }

    fn hamming_distance(&self, rhs: &Self) -> CryptopalResult<u32> {
        let hamming_vector = self.xor(rhs)?;
        Ok(hamming_vector.count_ones())
    }

    fn matrixify(&self, cols: usize) -> Vec<Vec<u8>> {
        self.chunks_exact(cols)
            .map(|slice| slice.to_vec())
            .collect::<Vec<_>>()
    }

    fn matrixify_padded(&self, cols: usize) -> Vec<Vec<u8>> {
        let mut result = self.matrixify(cols);
        let excess = self.len() % cols;

        if excess == 0 {
            return result;
        }

        let padding = ((self.len() / cols) + 1) * cols - self.len();
        let mut last_chunk = Vec::new();

        for i in self.iter().skip(self.len() - excess) {
            last_chunk.push(*i);
        }

        for _ in 0..padding {
            last_chunk.push(b' ');
        }

        result.push(last_chunk);
        result
    }
}
