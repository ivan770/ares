use crate::ciphers::Cipher;
use crate::ciphers::Error;
use crate::raw_key::RawKey;
use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;
use block_modes::Cbc;

type Conjuncted = Cbc<Aes256, Pkcs7>;

pub struct Aes256Cbc<'a> {
    raw_key: &'a RawKey,
}

impl<'a> Aes256Cbc<'a> {
    fn make_cipher(&self) -> Conjuncted {
        Conjuncted::new_var(&self.raw_key.key.encrypt, &self.raw_key.iv.iv).unwrap()
    }
}

impl<'a> Cipher for Aes256Cbc<'a> {
    fn encrypt(&self, buffer: &[u8]) -> Vec<u8> {
        self.make_cipher().encrypt_vec(buffer)
    }

    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .make_cipher()
            .decrypt_vec(buffer)
            .map_err(|_| Error::DecryptionError)?)
    }
}

impl<'a> From<&'a RawKey> for Aes256Cbc<'a> {
    fn from(raw_key: &'a RawKey) -> Self {
        Aes256Cbc { raw_key }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphers::aes_256::Aes256Cbc;
    use crate::ciphers::Cipher;
    use crate::hashers::sha3_512::Sha3_512;
    use crate::hashers::Hasher;
    use crate::iv::Iv;
    use crate::raw_key::RawKey;
    use hex_literal::hex;
    use std::convert::TryInto;

    #[test]
    fn is_encrypting_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = Sha3_512::make("testkey");
        let raw_key = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = Aes256Cbc::from(&raw_key).encrypt(msg.as_bytes());
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
        let key = Sha3_512::make("");
        let raw_key = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = Aes256Cbc::from(&raw_key).encrypt(msg.as_bytes());
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
        let key = Sha3_512::make("testkey");
        let rawkey = RawKey::make(key, iv);

        rawkey.to_cipher::<Aes256Cbc>();
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
        let key = Sha3_512::make("testkey");
        let rawkey = RawKey::make(key, iv);

        rawkey.to_cipher::<Aes256Cbc>();
    }
}
