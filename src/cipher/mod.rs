pub mod raw_key;
pub mod input;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes128;
use rand::random;
use raw_key::RawKey;

pub type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub fn generate_iv() -> [u8; 16]
{
    random()
}

pub fn cipher_from_raw_key(raw_key: &RawKey) -> Aes128Cbc
{
    Aes128Cbc::new_var(&raw_key.key, &raw_key.iv).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::block_modes::BlockMode;
    use super::{RawKey, cipher_from_raw_key};
    use std::convert::TryInto;
    use hex_literal::hex;

    #[test]
    fn is_encrypting_correctly() {
        let iv = hex!("746f74616c6c7972616e646f6d766563");
        let key = hex!("73757065727365637265746b65793132");
        let rawkey = RawKey {
            iv, key
        };

        let msg = String::from("123");

        let encrypted_msg = cipher_from_raw_key(&rawkey).encrypt_vec(msg.as_bytes());
        assert_eq!(encrypted_msg.as_ref(), hex!("B11CA0692E1F89015766F4B668E6A5ED"));
    }

    #[test]
    #[should_panic]
    fn key_too_small()
    {
        let iv = hex!("746f74616c6c7972616e646f6d766563");
        let key: [u8; 16] = String::from("qwerty").as_bytes().try_into().unwrap();
        let rawkey = RawKey {
            iv, key
        };

        cipher_from_raw_key(&rawkey);
    }

    #[test]
    #[should_panic]
    fn key_too_big()
    {
        let iv = hex!("746f74616c6c7972616e646f6d766563");
        let key: [u8; 16] = String::from("qwertyqwertyqwertyqwerty1").as_bytes().try_into().unwrap();
        let rawkey = RawKey {
            iv, key
        };

        cipher_from_raw_key(&rawkey);
    }

    #[test]
    #[should_panic]
    fn iv_too_small()
    {
        let iv: [u8; 16] = String::from("qwerty").as_bytes().try_into().unwrap();
        let key = hex!("73757065727365637265746b65793132");
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
        let key = hex!("73757065727365637265746b65793132");
        let rawkey = RawKey {
            iv, key
        };

        cipher_from_raw_key(&rawkey);
    }
}