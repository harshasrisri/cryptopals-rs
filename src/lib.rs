pub mod constants;
pub mod cryptobuf;
pub mod encodecode;
pub mod xorcrypt;

#[macro_use]
extern crate lazy_static;

fn transpose<T>(input: &[Vec<T>]) -> Vec<Vec<T>>
where
    T: Clone,
{
    let mut trans = Vec::new();

    for i in 0..input[0].len() {
        let mut col = Vec::new();
        for row in input {
            col.push(row[i].clone());
        }
        trans.push(col);
    }

    trans
}
