pub mod aes;
pub mod buffer;
pub mod xorcrypt;

use crate::buffer::*;
use anyhow::Result;
use buffer::Base64;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[macro_use]
extern crate lazy_static;

fn transpose<T>(input: &[&[T]]) -> Vec<Vec<T>>
where
    T: Clone,
{
    let mut trans = Vec::new();

    for i in 0..input[0].as_ref().len() {
        let mut col = Vec::new();
        for row in input {
            col.push(row[i].clone());
        }
        trans.push(col);
    }

    trans
}

pub fn decode_b64_file<P>(path: P) -> Result<Vec<u8>>
where
    P: AsRef<Path>,
{
    let input = File::open(path)?;
    let res = BufReader::new(input)
        .lines()
        .filter_map(std::result::Result::ok)
        .flat_map(|line| line.decode::<Base64>())
        .flatten()
        .collect();
    Ok(res)
}

pub fn gen_rand_key(key_len: usize) -> Vec<u8> {
    std::iter::repeat_with(rand::random).take(key_len).collect()
}
