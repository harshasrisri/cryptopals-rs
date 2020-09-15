use crate::constants::*;
use crate::transpose;
use anyhow::Result;

pub trait XORCrypto {
    fn single_key_xor(&self, key: char) -> Vec<u8>;
    fn repeat_key_xor(&self, key: &str) -> Vec<u8>;
    fn guess_xor_key(&self) -> Result<(char, f32)>;
    fn guess_vigenere(&self) -> Result<Vec<u8>>;
}

impl XORCrypto for Vec<u8> {
    fn single_key_xor(&self, key: char) -> Vec<u8> {
        self.iter().map(|&x| (x ^ key as u8)).collect::<Vec<u8>>()
    }

    fn repeat_key_xor(&self, key: &str) -> Vec<u8> {
        key.bytes()
            .cycle()
            .zip(self.iter())
            .map(|(k, d)| k ^ d)
            .collect()
    }

    fn guess_xor_key(&self) -> Result<(char, f32)> {
        let mut guess = None;
        let mut max_freq = 0.0;
        for (i, freq) in PRINTABLE_ASCII
            .iter()
            .map(|&key| self.single_key_xor(key))
            .map(|buf| buf.freq_rank())
            .enumerate()
        {
            if freq > max_freq {
                max_freq = freq;
                guess = Some(i);
            }
        }
        guess
            .map(|i| (PRINTABLE_ASCII[i], max_freq))
            .ok_or_else(|| anyhow::anyhow!("Can't guess XOR key for message"))
    }

    fn guess_vigenere(&self) -> Result<Vec<u8>> {
        let chunk_combinations = NUM_CHUNKS_VIGENERE * (NUM_CHUNKS_VIGENERE - 1) / 2;
        let mut normalized_keysizes = (2..std::cmp::min(40, self.len() / NUM_CHUNKS_VIGENERE))
            .map(|n| {
                let mut hamming_distance = 0;
                let chunks = self
                    .chunks_exact(n)
                    .take(NUM_CHUNKS_VIGENERE)
                    .collect::<Vec<_>>();
                for i in 0..NUM_CHUNKS_VIGENERE {
                    for j in i..NUM_CHUNKS_VIGENERE {
                        hamming_distance += chunks[i].hamming_distance(&chunks[j]).unwrap();
                    }
                }
                (
                    n,
                    (hamming_distance as f32 / chunk_combinations as f32 / n as f32) as usize,
                )
            })
            .collect::<Vec<_>>();

        normalized_keysizes.sort_by(|a, b| (a.1).cmp(&b.1));

        let mut guessed_keys = normalized_keysizes
            .iter()
            .take(4)
            .map(|keysize| self.matrixify(keysize.0))
            .map(|matrix| {
                transpose(&matrix)
                    .iter()
                    .map(|row| row.guess_xor_key().unwrap().0 as u8)
                    .collect::<Vec<u8>>()
            })
            .map(|key| (key.freq_rank(), key))
            .collect::<Vec<_>>();

        guessed_keys.sort_by(|a, b| (b.0).partial_cmp(&a.0).unwrap());
        Ok(guessed_keys[0].1.to_vec())
    }
}

pub trait BufferOps {
    fn count_ones(&self) -> u32;
    fn freq_rank(&self) -> f32;
    fn xor(&self, rhs: &Self) -> Result<Vec<u8>>;
    fn hamming_distance(&self, rhs: &Self) -> Result<u32>;
    fn matrixify(&self, cols: usize) -> Vec<&[u8]>;
}

impl<T> BufferOps for T
where
    T: AsRef<[u8]>,
{
    fn count_ones(&self) -> u32 {
        self.as_ref().iter().map(|b| b.count_ones()).sum()
    }

    fn freq_rank(&self) -> f32 {
        self.as_ref()
            .iter()
            .map(|x| ETAOIN_SHRDLU.get(&x).unwrap_or(&0.0))
            .sum()
    }

    fn xor(&self, rhs: &Self) -> Result<Vec<u8>> {
        anyhow::ensure!(
            self.as_ref().len() == rhs.as_ref().len(),
            "Input buffers differ in lengths"
        );
        Ok(self
            .as_ref()
            .iter()
            .zip(rhs.as_ref().iter())
            .map(|(l, r)| l ^ r)
            .collect())
    }

    fn hamming_distance(&self, rhs: &Self) -> Result<u32> {
        Ok(self.xor(rhs)?.count_ones())
    }

    fn matrixify(&self, cols: usize) -> Vec<&[u8]> {
        self.as_ref()
            .chunks_exact(cols)
            .map(|slice| slice)
            .collect::<Vec<_>>()
    }
}
