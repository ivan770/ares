pub mod raw;
pub mod input;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes128;
use rand::random;
use raw::RawKey;

pub type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub fn generate_iv() -> [u8; 16]
{
    random()
}

pub fn cipher_from_raw_key(raw_key: &RawKey) -> Aes128Cbc
{
    Aes128Cbc::new_var(&raw_key.key, &raw_key.iv).unwrap()
}
