use crate::constants::ETAOIN_SHRDLU;
use anyhow::Result;

pub trait XORCrypto {
    fn count_ones(&self) -> u32;
    fn freq_rank(&self) -> f32;
    fn xor(&self, rhs: &Self) -> Result<Vec<u8>>;
    fn hamming_distance(&self, rhs: &Self) -> Result<u32>;
    fn matrixify(&self, cols: usize) -> Vec<Vec<u8>>;
    fn matrixify_padded(&self, cols: usize) -> Vec<Vec<u8>>;
}

impl XORCrypto for Vec<u8> {
    fn count_ones(&self) -> u32 {
        self.iter().map(|b| b.count_ones()).sum()
    }

    fn freq_rank(&self) -> f32 {
        self.iter()
            .map(|x| ETAOIN_SHRDLU.get(&x).unwrap_or(&0.0))
            .sum()
    }

    fn xor(&self, rhs: &Self) -> Result<Self> {
        anyhow::ensure!(self.len() == rhs.len(), "Input buffers differ in lengths");
        Ok(self.iter().zip(rhs.iter()).map(|(l, r)| l ^ r).collect())
    }

    fn hamming_distance(&self, rhs: &Self) -> Result<u32> {
        Ok(self.xor(rhs)?.count_ones())
    }

    fn matrixify(&self, cols: usize) -> Vec<Vec<u8>> {
        self.chunks_exact(cols)
            .map(|slice| slice.to_vec())
            .collect::<Vec<_>>()
    }

    fn matrixify_padded(&self, cols: usize) -> Vec<Vec<u8>> {
        let mut result = self.matrixify(cols);

        if self.len() % cols == 0 {
            return result;
        }

        let last_padded_chunk = self
            .iter()
            .skip(result.len() * cols)
            .copied()
            .chain(std::iter::repeat(b' '))
            .take(cols)
            .collect();

        result.push(last_padded_chunk);
        result
    }
}
