use crate::cipher::cipher_from_raw_key;
use crate::cipher::raw_key::RawKey;
use crate::cipher::hash::Hash;
use crate::cipher::Aes256Cbc;
use std::io::Error;

#[cfg(not(test))]
fn request_raw_key(iv: [u8; 16]) -> Result<RawKey, Error>
{
    let key = dialoguer::PasswordInput::new()
        .with_prompt("Encryption key")
        .with_confirmation("Confirm encryption key", "Inputs do not match")
        .interact()?;

    Ok(RawKey {
        key: Hash::make(key),
        iv: iv
    })
}

#[cfg(test)]
fn request_raw_key(iv: [u8; 16]) -> Result<RawKey, Error>
{
    let key = String::from_utf8(std::fs::read("key.txt").unwrap()).unwrap();
    Ok(RawKey {
        key: Hash::make(key),
        iv: iv
    })
}

pub fn cipher_from_user_input(iv: [u8; 16]) -> Result<Aes256Cbc, Error>
{
    let request = request_raw_key(iv)?;
    Ok(cipher_from_raw_key(&request))
}
