pub mod aes;
pub mod buffer;
pub mod constants;
pub mod encodecode;
pub mod xorcrypt;

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
