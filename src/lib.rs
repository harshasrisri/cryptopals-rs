pub mod constants;
pub mod encodecode;
pub mod xorcrypt;

pub type Result<T> = std::result::Result<T, hex::FromHexError>;

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
