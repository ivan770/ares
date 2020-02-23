use crate::encrypted_file::EncryptedFile;
use crate::key::input::cipher_from_user_input;
use crate::file::{open_file, write_file};
use crate::block_modes::BlockMode;
use bincode::deserialize;
use std::error::Error;
use bincode::ErrorKind;

fn process(file: EncryptedFile) -> Result<Vec<u8>, Box<dyn Error>>
{
    Ok(cipher_from_user_input(file.iv)?.decrypt_vec(&file.buffer)?)
}

fn deserialize_file(file: &[u8]) -> Result<EncryptedFile, Box<ErrorKind>>
{
    Ok(deserialize(file)?)
}

fn write_buffer(file: EncryptedFile, to: &str)
{
    match process(file) {
        Ok(buffer) => write_file(to, &buffer),
        Err(_) => println!("Invalid encryption key")
    }
}

pub fn decrypt(from: &str, to: &str)
{
    match open_file(from) {
        Ok(file) => {
            match deserialize_file(&file) {
                Ok(encrypted_file) => write_buffer(encrypted_file, to),
                Err(_) => println!("Invalid file format")
            }
        },
        Err(_) => println!("Unable to open file")
    }
}
