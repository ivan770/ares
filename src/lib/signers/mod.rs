pub mod hmac;

#[derive(Debug)]
pub enum Error {
    InvalidSignature,
}

pub trait Signer {
    fn make(key: &[u8]) -> Self;
    fn sign(&self, buffer: &[u8]) -> [u8; 32];
    fn verify(&self, buffer: &[u8], mac: &[u8]) -> Result<(), Error>;
}
