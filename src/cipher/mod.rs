pub mod hash;
pub mod raw_key;
pub mod iv;

use block_modes::Cbc;
use block_modes::block_padding::Pkcs7;
use sha3::Sha3_256;
use hmac::Hmac;
use aes_soft::Aes256;

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;
pub type HmacSha256 = Hmac<Sha3_256>;

#[cfg(test)]
mod tests {
    use crate::block_modes::BlockMode;
    use crate::cipher::raw_key::RawKey;
    use crate::cipher::hash::Hash;
    use crate::cipher::iv::Iv;
    use std::convert::TryInto;
    use hex_literal::hex;

    #[test]
    fn is_encrypting_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563")
        };
        let key = Hash::make("testkey");
        let rawkey = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = rawkey.to_cipher().encrypt_vec(msg.as_bytes());
        assert_eq!(encrypted_msg.as_ref(), hex!("11491BF281032E30F85299870CD62B0B"));
    }

    #[test]
    fn is_encrypting_correctly_with_empty_key() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563")
        };
        let key = Hash::make("");
        let rawkey = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = rawkey.to_cipher().encrypt_vec(msg.as_bytes());
        assert_eq!(encrypted_msg.as_ref(), hex!("5AF16C47A34F07D4C3F569344B1D6673"));
    }

    #[test]
    #[should_panic]
    fn iv_too_small()
    {
        let iv = Iv {
            iv: String::from("qwerty").as_bytes().try_into().unwrap()
        };
        let key = Hash::make("testkey");
        let rawkey = RawKey::make(key, iv);

        rawkey.to_cipher();
    }

    #[test]
    #[should_panic]
    fn iv_too_big()
    {
        let iv = Iv {
            iv: String::from("qwertyqwertyqwertyqwerty1").as_bytes().try_into().unwrap()
        };
        let key = Hash::make("testkey");
        let rawkey = RawKey::make(key, iv);

        rawkey.to_cipher();
    }
}