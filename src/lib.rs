pub mod aes;
pub mod buffer;
pub mod constants;
pub mod xorcrypt;

use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use crate::buffer::Decoding;

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
            col.push(row.as_ref()[i].clone());
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
        .flat_map(|line| line.b64_decode())
        .flatten()
        .collect();
    Ok(res)
}
