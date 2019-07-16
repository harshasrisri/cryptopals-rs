use base64;
use hex;

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    Ok(base64::encode(&hex::decode(input)?))
}

pub fn fixed_xor(lhs: &str, rhs: &str) -> Result<String, hex::FromHexError> {
    Ok(hex::encode(
        hex::decode(lhs)?
            .iter()
            .zip(hex::decode(rhs)?.iter())
            .map(|(l, r)| l ^ r)
            .collect::<Vec<u8>>(),
    ))
}
