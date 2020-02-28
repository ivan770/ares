use crate::actions::errors::Error;
use crate::actions::progress::Progress;
use crate::input::Input;
use crate::cipher::iv::Iv;
use crate::cipher::raw_key::RawKey;
use crate::encrypted_file::EncryptedFile;
use crate::file::{open_file, write_file};
use crate::block_modes::BlockMode;
use crate::help::HELP_MSG;
use bincode::deserialize;

fn make_raw_key(iv: Iv) -> Result<RawKey, Error>
{
    let raw_key = Input::make_from_cfg()
        .map_err(|_| Error::InvalidInput)?
        .to_raw_key_iv(iv);

    Ok(raw_key)
}

fn decrypt_file(file: EncryptedFile, raw_key: RawKey) -> Result<Vec<u8>, Error>
{
    let buffer = raw_key
        .to_cipher()
        .decrypt_vec(&file.buffer)
        .map_err(|_| Error::InvalidEncryptionKey)?;

    Ok(buffer)
}

fn deserialize_file(file: &[u8]) -> Result<EncryptedFile, Error>
{
    let encrypted_file = deserialize(file)
        .map_err(|_| Error::InvalidFileFormat)?;

    Ok(encrypted_file)
}

fn write_buffer(buffer: &[u8], to: &str) -> Result<(), Error>
{
    Ok(write_file(to, buffer).map_err(|_| Error::WritingDecryptedToFile)?)
}

fn process_file(pb: &Progress, from: &str, to: &str) -> Result<(), Error>
{
    let buffer = open_file(from).map_err(|_| Error::FileOpen)?;
    let encrypted_file = deserialize_file(&buffer)?;
    let raw_key = make_raw_key(encrypted_file.iv)?;
    pb.spawn_thread()
        .apply_styles()
        .start("Decrypting...");
    let decrypted_file = decrypt_file(encrypted_file, raw_key)?;
    write_buffer(&decrypted_file, to)?;
    Ok(())
}

pub fn decrypt(from: &str, to: &str)
{
    let pb = Progress::make();
    match process_file(&pb, from, to) {
        Ok(_) => {
            pb.end();
            println!("Decrypted successfully!")
        },
        Err(e) => {
            pb.end();
            println!("{}.{}", e, HELP_MSG)
        }
    }
}
