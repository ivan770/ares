pub mod decrypt;
pub mod encrypt;
mod errors;
mod progress;

use ares::ciphers::aes_256::Aes256Cbc;
use ares::hashers::sha3_512::Sha3_512;
use ares::signers::hmac::Hmac;

pub type Aes<'a> = Aes256Cbc<'a>;
pub type Hasher = Sha3_512;
pub type Signer = Hmac;
