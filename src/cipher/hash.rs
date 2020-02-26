use sha3::{Sha3_512, Digest};
use std::convert::TryInto;

pub struct Hash {
    pub mac: [u8; 32],
    pub encrypt: [u8; 32]
}

impl Hash {
    pub fn make(key: &str) -> Self
    {
        let slice = Sha3_512::digest(key.as_bytes());

        Hash {
            mac: slice[..32].try_into().unwrap(),
            encrypt: slice[32..].try_into().unwrap()
        }
    }
}