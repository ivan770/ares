pub mod aes_256;

#[derive(Debug)]
pub enum Error {
    DecryptionError,
}

pub trait Cipher {
    fn encrypt(&self, buffer: &[u8]) -> Vec<u8>;
    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, Error>;
}
