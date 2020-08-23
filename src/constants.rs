use std::collections::HashMap;

pub const PRINTABLE_ASCII: [char; 95] = [
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', ' ',
];

lazy_static! {
    pub static ref ETAOIN_SHRDLU: HashMap<u8, f32> = [
        (b' ', 13.00),
        (b'e', 12.70),
        (b't', 9.056),
        (b'a', 8.167),
        (b'o', 7.507),
        (b'i', 6.966),
        (b'n', 6.749),
        (b's', 6.327),
        (b'h', 6.094),
        (b'r', 5.987),
        (b'd', 4.253),
        (b'l', 4.025),
        (b'u', 2.758),
        (b'b', 1.492),
        (b'c', 2.782),
        (b'f', 2.228),
        (b'g', 2.015),
        (b'j', 0.153),
        (b'k', 0.772),
        (b'm', 2.406),
        (b'p', 1.929),
        (b'q', 0.095),
        (b'v', 0.978),
        (b'w', 2.360),
        (b'x', 0.150),
        (b'y', 1.974),
        (b'z', 0.074),
    ]
    .iter()
    .cloned()
    .collect();
}

pub const NUM_CHUNKS_VIGENERE: usize = 4;
pub const CHUNK_COMBOS: usize = 6;
pub const CARGO_HOME: &str = env!("CARGO_MANIFEST_DIR");
