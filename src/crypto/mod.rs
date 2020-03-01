pub mod ciphers;
pub mod hashers;
pub mod iv;
pub mod raw_key;

use crate::crypto::ciphers::aes_256::Aes256Cbc;
use crate::crypto::hashers::sha3_512::Sha3_512;
use hmac::Hmac as BaseHmac;
use sha3::Sha3_256;

pub type Aes<'a> = Aes256Cbc<'a>;
pub type Hmac = BaseHmac<Sha3_256>;
pub type Hasher = Sha3_512;

#[cfg(test)]
mod tests {
    use super::Hasher as HasherImpl;
    use crate::crypto::ciphers::Cipher;
    use crate::crypto::hashers::Hasher;
    use crate::crypto::iv::Iv;
    use crate::crypto::raw_key::RawKey;
    use hex_literal::hex;
    use hmac::crypto_mac::Mac;
    use std::convert::TryInto;

    #[test]
    fn is_encrypting_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = HasherImpl::make("testkey");
        let rawkey = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = rawkey.to_cipher().encrypt(msg.as_bytes());
        assert_eq!(
            encrypted_msg.as_ref(),
            hex!("11491BF281032E30F85299870CD62B0B")
        );
    }

    #[test]
    fn is_encrypting_correctly_with_empty_key() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = HasherImpl::make("");
        let rawkey = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = rawkey.to_cipher().encrypt(msg.as_bytes());
        assert_eq!(
            encrypted_msg.as_ref(),
            hex!("5AF16C47A34F07D4C3F569344B1D6673")
        );
    }

    #[test]
    #[should_panic]
    fn iv_too_small() {
        let iv = Iv {
            iv: String::from("qwerty").as_bytes().try_into().unwrap(),
        };
        let key = HasherImpl::make("testkey");
        let rawkey = RawKey::make(key, iv);

        rawkey.to_cipher();
    }

    #[test]
    #[should_panic]
    fn iv_too_big() {
        let iv = Iv {
            iv: String::from("qwertyqwertyqwertyqwerty1")
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        let key = HasherImpl::make("testkey");
        let rawkey = RawKey::make(key, iv);

        rawkey.to_cipher();
    }

    #[test]
    fn is_signing_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = HasherImpl::make("testkey");
        let rawkey = RawKey::make(key, iv);

        let msg = String::from("123");

        let mut sign = rawkey.to_mac();
        sign.input(msg.as_bytes());
        assert_eq!(
            sign.result().code().as_slice(),
            hex!("4606943e0582b639e375a78628358d12783e45c74635a8fd3d26812633b34d14")
        );
    }
}
