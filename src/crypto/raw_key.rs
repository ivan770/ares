use crate::crypto::hashers::{Hash, Hasher};
use crate::crypto::iv::Iv;
use crate::crypto::Aes;
use crate::crypto::Hasher as HasherImpl;
use crate::crypto::Hmac;
use hmac::crypto_mac::Mac;

pub struct RawKey {
    pub key: Hash,
    pub iv: Iv,
}

impl RawKey {
    pub fn make(key: Hash, iv: Iv) -> Self {
        RawKey { key, iv }
    }

    pub fn from_string(key: &str) -> Self {
        RawKey::make(HasherImpl::make(key), Iv::random())
    }

    pub fn to_cipher(&self) -> Aes {
        Aes::make(self)
    }

    pub fn to_mac(&self) -> Hmac {
        Hmac::new_varkey(&self.key.mac).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{Hasher, HasherImpl, Iv, RawKey};

    #[test]
    fn generates_raw_key_correctly() {
        let hash = HasherImpl::make("Qwerty");
        let iv = Iv::random();
        let raw_key = RawKey::make(hash, iv);
        raw_key.to_cipher();
        raw_key.to_mac();
    }

    #[test]
    fn generates_raw_key_from_string_correctly() {
        let raw_key = RawKey::from_string("Qwerty");
        raw_key.to_cipher();
        raw_key.to_mac();
    }
}
