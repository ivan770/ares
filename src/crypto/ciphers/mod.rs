pub mod aes_256;

use std::error::Error;

pub trait Cipher<T: Error> {
    fn encrypt(&self, buffer: &[u8]) -> Vec<u8>;
    fn decrypt(&self, buffer: &[u8]) -> Result<Vec<u8>, T>;
}
