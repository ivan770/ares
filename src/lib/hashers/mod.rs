pub mod sha3_512;

pub struct Hash {
    pub mac: [u8; 32],
    pub encrypt: [u8; 32],
}

pub trait Hasher {
    fn make(key: &str) -> Hash;
}
