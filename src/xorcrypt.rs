use crate::constants::*;
use crate::cryptobuf::*;
use anyhow::Result;

pub trait XORCrypt {
    fn single_key_xor(&self, key: char) -> Vec<u8>;
    fn repeat_key_xor(&self, key: &str) -> Vec<u8>;
    fn guess_xor_key(&self) -> Result<(char, f32)>;
    fn guess_vigenere(&self) -> Result<Vec<u8>>;
}

impl XORCrypt for Vec<u8> {
    fn single_key_xor(&self, key: char) -> Vec<u8> {
        self.iter().map(|&x| (x ^ key as u8)).collect::<Vec<u8>>()
    }

    fn repeat_key_xor(&self, key: &str) -> Vec<u8> {
        self.iter()
            .enumerate()
            .map(|(i, c)| c ^ (key.as_bytes()[i % key.len()] as u8))
            .collect::<Vec<u8>>()
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
            .ok_or(anyhow::anyhow!("Can't guess XOR key for message"))
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
                        hamming_distance += chunks[i]
                            .to_vec()
                            .hamming_distance(&chunks[j].to_vec())
                            .unwrap();
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
            .map(|matrix| crate::transpose(&matrix))
            .map(|matrix| {
                matrix
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
