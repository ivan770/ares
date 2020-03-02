use crate::ciphers::Cipher;
use crate::hashers::{Hash, Hasher};
use crate::iv::Iv;
use crate::signers::Signer;

pub struct RawKey {
    pub key: Hash,
    pub iv: Iv,
}

impl RawKey {
    pub fn make(key: Hash, iv: Iv) -> Self {
        RawKey { key, iv }
    }

    pub fn from_string<T: Hasher>(key: &str) -> Self {
        RawKey::make(T::make(key), Iv::random())
    }

    pub fn to_cipher<'a, T: From<&'a RawKey> + Cipher>(&'a self) -> T {
        T::from(self)
    }

    pub fn to_mac<'a, T: From<&'a RawKey> + Signer>(&'a self) -> T {
        T::from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{Hasher, Iv, RawKey};
    use crate::ciphers::aes_256::Aes256Cbc;
    use crate::hashers::sha3_512::Sha3_512;
    use crate::signers::hmac::Hmac;

    #[test]
    fn generates_raw_key_correctly() {
        let hash = Sha3_512::make("Qwerty");
        let iv = Iv::random();
        let raw_key = RawKey::make(hash, iv);
        raw_key.to_cipher::<Aes256Cbc>();
        raw_key.to_mac::<Hmac>();
    }

    #[test]
    fn generates_raw_key_from_string_correctly() {
        let raw_key = RawKey::from_string::<Sha3_512>("Qwerty");
        raw_key.to_cipher::<Aes256Cbc>();
        raw_key.to_mac::<Hmac>();
    }
}
