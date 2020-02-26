use crate::cipher::hash::Hash;
use crate::cipher::iv::Iv;
use crate::cipher::Aes256Cbc;
use crate::cipher::HmacSha256;
use crate::block_modes::BlockMode;
use hmac::crypto_mac::Mac;

pub struct RawKey {
    key: Hash,
    pub iv: Iv
}

impl RawKey {
    pub fn make(key: Hash, iv: Iv) -> Self
    {
        RawKey {
            key,
            iv 
        }
    }

    pub fn from_string(key: &str) -> Self
    {
        RawKey::make(Hash::make(key), Iv::random())
    }

    pub fn to_cipher(&self) -> Aes256Cbc
    {
        Aes256Cbc::new_var(&self.key.encrypt, &self.iv.iv).unwrap()
    }

    pub fn to_mac(&self) -> HmacSha256
    {
        HmacSha256::new_varkey(&self.key.mac).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash, RawKey, Iv};

    #[test]
    fn generates_raw_key_correctly()
    {
        let hash = Hash::make("Qwerty");
        let iv = Iv::random();
        let raw_key = RawKey::make(hash, iv);
        raw_key.to_cipher();
        raw_key.to_mac();
    }

    #[test]
    fn generates_raw_key_from_string_correctly()
    {
        let raw_key = RawKey::from_string("Qwerty");
        raw_key.to_cipher();
        raw_key.to_mac();
    }
}