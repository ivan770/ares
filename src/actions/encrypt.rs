use crate::actions::errors::Error;
use crate::cipher::raw_key::RawKey;
use crate::encrypted_file::EncryptedFile;
use crate::input::Input;
use crate::block_modes::BlockMode;
use crate::file::{open_file, write_file};
use crate::help::HELP_MSG;

fn make_raw_key() -> Result<RawKey, Error>
{
    let raw_key = Input::make_from_cfg()
        .map_err(|_| Error::InvalidInput)?
        .to_raw_key();

    Ok(raw_key)
}

fn process(from: &str, to: &str) -> Result<(), Error>
{
    let file = open_file(from).map_err(|_| Error::FileOpen)?;
    let raw_key = make_raw_key()?;
    let encrypted_file = EncryptedFile {
        iv: raw_key.iv,
        buffer: raw_key.to_cipher().encrypt_vec(&file)
    };

    let encrypted_buffer = bincode::serialize(&encrypted_file).unwrap();
    write_file(to, &encrypted_buffer).map_err(|_| Error::WritingEncryptedToFile)?;
    Ok(())
}

pub fn encrypt(from: &str, to: &str)
{
    match process(from, to) {
        Ok(_) => println!("Encrypted successfully!"),
        Err(e) => println!("{}.{}", e, HELP_MSG)
    }
}
