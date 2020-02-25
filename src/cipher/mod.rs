pub mod hash;
pub mod raw_key;
pub mod input;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes256;
use rand::random;
use raw_key::RawKey;

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn generate_iv() -> [u8; 16]
{
    random()
}

pub fn cipher_from_raw_key(raw_key: &RawKey) -> Aes256Cbc
{
    Aes256Cbc::new_var(&raw_key.key.encrypt, &raw_key.iv).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::block_modes::BlockMode;
    use super::{RawKey, cipher_from_raw_key, hash::Hash};
    use std::convert::TryInto;
    use hex_literal::hex;

    #[test]
    fn is_encrypting_correctly() {
        let iv = hex!("746f74616c6c7972616e646f6d766563");
        let key = Hash::make(String::from("testkey"));
        let rawkey = RawKey {
            iv, key
        };

        let msg = String::from("123");

        let encrypted_msg = cipher_from_raw_key(&rawkey).encrypt_vec(msg.as_bytes());
        assert_eq!(encrypted_msg.as_ref(), hex!("11491BF281032E30F85299870CD62B0B"));
    }

    #[test]
    fn is_encrypting_correctly_with_empty_key() {
        let iv = hex!("746f74616c6c7972616e646f6d766563");
        let key = Hash::make(String::from(""));
        let rawkey = RawKey {
            iv, key
        };

        let msg = String::from("123");

        let encrypted_msg = cipher_from_raw_key(&rawkey).encrypt_vec(msg.as_bytes());
        assert_eq!(encrypted_msg.as_ref(), hex!("5AF16C47A34F07D4C3F569344B1D6673"));
    }

    #[test]
    #[should_panic]
    fn iv_too_small()
    {
        let iv: [u8; 16] = String::from("qwerty").as_bytes().try_into().unwrap();
        let key = Hash::make(String::from("testkey"));
        let rawkey = RawKey {
            iv, key
        };

        cipher_from_raw_key(&rawkey);
    }

    #[test]
    #[should_panic]
    fn iv_too_big()
    {
        let iv: [u8; 16] = String::from("qwertyqwertyqwertyqwerty1").as_bytes().try_into().unwrap();
        let key = Hash::make(String::from("testkey"));
        let rawkey = RawKey {
            iv, key
        };

        cipher_from_raw_key(&rawkey);
    }
}