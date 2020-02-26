use crate::encrypted_file::EncryptedFile;
use crate::input::Input;
use crate::block_modes::BlockMode;
use crate::file::{open_file, write_file};
use crate::help::HELP_MSG;
use std::io::Error;

fn process(file: &[u8]) -> Result<Vec<u8>, Error>
{
    let raw_key = Input::make_from_cfg()?.to_raw_key();
    let encrypted_file = EncryptedFile {
        iv: raw_key.iv,
        buffer: raw_key.to_cipher().encrypt_vec(file)
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
