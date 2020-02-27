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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::Hash;

    #[test]
    fn is_hashing_correctly()
    {
        let hash = Hash::make("test");

        assert_eq!(hash.encrypt, hex!("8288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"));
        assert_eq!(hash.mac, hex!("9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a67"));
    }
}