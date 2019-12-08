use base64;
use hex;
use std::collections::HashMap;

mod constants;
use constants::*;

pub type Result<T> = std::result::Result<T, hex::FromHexError>;
const NUM_CHUNKS: usize = 4;
const CHUNK_COMBOS: usize = 6;

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

pub trait XORCrypto {
    fn fixed_xor(&self, rhs: &Self) -> Result<Vec<u8>>;
    fn count_ones(&self) -> u32;
    fn hamming_distance(&self, rhs: &Self) -> Result<u32>;
    fn single_key_xor(&self, key: char) -> Vec<u8>;
    fn repeat_key_xor(&self, key: &str) -> Vec<u8>;
    fn guess_xor_key(&self) -> Result<(char, f32)>;
    fn matrixify(&self, cols: usize) -> Vec<Vec<u8>>;
    fn guess_vigenere(&self) -> Result<Vec<u8>>;
    fn freq_rank(&self) -> f32;
}

fn transpose(input: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut trans = Vec::new();

    for i in 0..input[0].len() {
        let mut col = Vec::new();
        for row in input {
            col.push(row[i]);
        }
        trans.push(col);
    }

    trans
}

impl XORCrypto for Vec<u8> {
    fn fixed_xor(&self, rhs: &Self) -> Result<Vec<u8>> {
        if self.len() != rhs.len() {
            return Err(hex::FromHexError::InvalidStringLength);
        }

        Ok(self
            .iter()
            .zip(rhs.iter())
            .map(|(l, r)| l ^ r)
            .collect::<Vec<u8>>())
    }

    fn count_ones(&self) -> u32 {
        self.iter().map(|b| b.count_ones()).sum()
    }

    fn hamming_distance(&self, rhs: &Self) -> Result<u32> {
        let hamming_vector = self.fixed_xor(rhs)?;
        Ok(hamming_vector.count_ones())
    }

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
        match guess {
            Some(i) => Ok((PRINTABLE_ASCII[i], max_freq)),
            None => Err(hex::FromHexError::InvalidStringLength),
        }
    }

    fn matrixify(&self, cols: usize) -> Vec<Vec<u8>> {
        let mut result = self.chunks_exact(cols)
            .map(|slice| slice.to_vec())
            .collect::<Vec<_>>();
        let last_align = result.len() * cols;
        let pad_align = (result.len() + 1) * cols;
        let mut last_chunk = Vec::new();

        for i in last_align..self.len() {
            last_chunk.push(self[i]);
        }
        for _ in self.len()..pad_align {
            last_chunk.push(' ' as u8);
        }

        if last_chunk.len() == cols {
            result.push(last_chunk);
        }

        result
    }

    fn guess_vigenere(&self) -> Result<Vec<u8>> {
        let mut normalized_keysizes = (2..std::cmp::min(40, self.len() / NUM_CHUNKS))
            .map(|n| {
                let mut hamming_distance = 0;
                let chunks = self.chunks_exact(n).take(NUM_CHUNKS).collect::<Vec<_>>();
                for i in 0..NUM_CHUNKS {
                    for j in i..NUM_CHUNKS {
                        hamming_distance += chunks[i]
                            .to_vec()
                            .hamming_distance(&chunks[j].to_vec())
                            .unwrap();
                    }
                }
                (n, (hamming_distance as f32 / CHUNK_COMBOS as f32 / n as f32) as usize)
            })
        .collect::<Vec<_>>();

        normalized_keysizes.sort_by(|a,b|(a.1).cmp(&b.1));

        let mut guessed_keys = normalized_keysizes
            .iter()
            .take(4)
            .map(|keysize| self.matrixify(keysize.0))
            .map(|matrix| transpose(&matrix))
            .map(|matrix| {
                matrix
                    .iter()
                    .map(|row| row.guess_xor_key().unwrap().0 as u8)
                    .collect::<Vec<u8>>()
            })
        .map(|key| (key.freq_rank(), key))
            .collect::<Vec<_>>();

        guessed_keys.sort_by(|a,b| (b.0).partial_cmp(&a.0).unwrap());
        Ok(guessed_keys[0].1.iter().cloned().collect())
    }

    fn freq_rank(&self) -> f32 {
        let freq_map: HashMap<u8, f32> = ETAOIN_SHRDLU.iter().cloned().collect();
        self.iter().map(|x| freq_map.get(&x).unwrap_or(&0.0)).sum()
    }
}
