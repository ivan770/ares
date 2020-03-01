use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::Cbc;
use crate::block_modes::BlockMode;
use crate::block_modes::BlockModeError;
use crate::cipher::ciphers::Cipher;
use crate::cipher::raw_key::RawKey;

type Conjuncted = Cbc<Aes256, Pkcs7>;

pub struct Aes256Cbc<'a> {
    raw_key: &'a RawKey
}

impl<'a> Aes256Cbc<'a> {
    pub fn make(raw_key: &'a RawKey) -> Self
    {
        Aes256Cbc {
            raw_key
        }
    }

    fn make_cipher(&self) -> Conjuncted
    {
        Conjuncted::new_var(&self.raw_key.key.encrypt, &self.raw_key.iv.iv).unwrap()
    }
}

impl<'a> Cipher<BlockModeError> for Aes256Cbc<'a> {
    fn encrypt(&self, buffer: &[u8]) -> Vec<u8>
    {
        self.make_cipher().encrypt_vec(buffer)
    }

    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, BlockModeError>
    {
        Ok(self.make_cipher().decrypt_vec(buffer)?)
    }
}