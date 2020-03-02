use crate::hashers::{Hash, Hasher};
use sha3::Digest;
use std::convert::TryInto;

pub struct Sha3_512 {}

impl Hasher for Sha3_512 {
    fn make(key: &str) -> Hash {
        let slice = sha3::Sha3_512::digest(key.as_bytes());

        Hash {
            mac: slice[..32].try_into().unwrap(),
            encrypt: slice[32..].try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashers::sha3_512::Sha3_512;
    use crate::hashers::Hasher;
    use hex_literal::hex;

    #[test]
    fn is_hashing_correctly() {
        let hash = Sha3_512::make("test");

        assert_eq!(
            hash.encrypt,
            hex!("8288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14")
        );
        assert_eq!(
            hash.mac,
            hex!("9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a67")
        );
    }
}
