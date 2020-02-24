use crate::cipher::cipher_from_raw_key;
use crate::cipher::raw_key::RawKey;
use crate::cipher::Aes128Cbc;
use std::convert::TryInto;
use std::array::TryFromSliceError;

#[cfg(not(test))]
fn request_raw_key(iv: [u8; 16]) -> Result<RawKey, TryFromSliceError>
{
    let key = dialoguer::PasswordInput::new().with_prompt("Encryption key").interact().unwrap();
    Ok(RawKey {
        key: key.as_bytes().try_into()?,
        iv: iv
    })
}

#[cfg(test)]
fn request_raw_key(iv: [u8; 16]) -> Result<RawKey, TryFromSliceError>
{
    let key = std::fs::read("key.txt").unwrap();
    Ok(RawKey {
        key: key.as_slice().try_into()?,
        iv: iv
    })
}

pub fn cipher_from_user_input(iv: [u8; 16]) -> Result<Aes128Cbc, TryFromSliceError>
{
    let request = request_raw_key(iv)?;
    Ok(cipher_from_raw_key(&request))
}
