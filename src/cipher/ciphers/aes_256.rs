use crate::block_modes::BlockMode;
use crate::block_modes::BlockModeError;
use crate::cipher::ciphers::Cipher;
use crate::cipher::raw_key::RawKey;
use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::Cbc;

type Conjuncted = Cbc<Aes256, Pkcs7>;

pub struct Aes256Cbc<'a> {
    raw_key: &'a RawKey,
}

impl<'a> Aes256Cbc<'a> {
    pub fn make(raw_key: &'a RawKey) -> Self {
        Aes256Cbc { raw_key }
    }

    fn make_cipher(&self) -> Conjuncted {
        Conjuncted::new_var(&self.raw_key.key.encrypt, &self.raw_key.iv.iv).unwrap()
    }
}

impl<'a> Cipher<BlockModeError> for Aes256Cbc<'a> {
    fn encrypt(&self, buffer: &[u8]) -> Vec<u8> {
        self.make_cipher().encrypt_vec(buffer)
    }

    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, BlockModeError> {
        Ok(self.make_cipher().decrypt_vec(buffer)?)
    }
}

#[cfg(test)]
mod tests {
    use super::Aes256Cbc;
    use crate::cipher::ciphers::Cipher;
    use crate::cipher::hashers::Hasher;
    use crate::cipher::iv::Iv;
    use crate::cipher::raw_key::RawKey;
    use crate::cipher::Hasher as HasherImpl;
    use hex_literal::hex;

    #[test]
    fn is_encrypting_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = HasherImpl::make("testkey");
        let raw_key = RawKey::make(key, iv);

        let msg = String::from("123");

        let encrypted_msg = Aes256Cbc::make(&raw_key).encrypt(msg.as_bytes());
        assert_eq!(
            encrypted_msg.as_ref(),
            hex!("11491BF281032E30F85299870CD62B0B")
        );
    }
}
