use crate::key::generate_iv;
use crate::encrypted_file::EncryptedFile;
use crate::key::input::cipher_from_user_input;
use crate::block_modes::BlockMode;
use crate::file::{open_file, write_file};
use std::array::TryFromSliceError;

fn process(file: &[u8]) -> Result<Vec<u8>, TryFromSliceError>
{
    let iv = generate_iv();
    let encrypted_file = EncryptedFile {
        iv: iv,
        buffer: cipher_from_user_input(iv)?.encrypt_vec(file)
    };

    Ok(bincode::serialize(&encrypted_file).unwrap())
}

pub fn encrypt(from: &str, to: &str)
{
    match open_file(from) {
        Ok(file) => {
            match process(&file) {
                Ok(buffer) => write_file(to, &buffer),
                Err(_) => println!("Invalid encryption key")
            }
        },
        Err(_) => println!("Unable to open file")
    }
}
