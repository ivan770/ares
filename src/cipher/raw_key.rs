use crate::cipher::hash::Hash;

pub struct RawKey {
    pub key: Hash,
    pub iv: [u8; 16]
}
