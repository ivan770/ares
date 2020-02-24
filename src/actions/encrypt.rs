use crate::cipher::generate_iv;
use crate::encrypted_file::EncryptedFile;
use crate::cipher::input::cipher_from_user_input;
use crate::block_modes::BlockMode;
use crate::file::{open_file, write_file};
use crate::help::HELP_MSG;
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

fn write_buffer(to: &str, buffer: &[u8])
{
    match write_file(to, buffer) {
        Ok(_) => (),
        Err(_) => println!("Error writing encrypted data to {}.{}", to, HELP_MSG)
    }
}

pub fn encrypt(from: &str, to: &str)
{
    match open_file(from) {
        Ok(file) => {
            match process(&file) {
                Ok(buffer) => write_buffer(to, &buffer),
                Err(_) => println!("Invalid encryption key.{}", HELP_MSG)
            }
        },
        Err(_) => println!("Unable to open file.{}", HELP_MSG)
    }
}
