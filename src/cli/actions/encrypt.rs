use crate::actions::errors::Error;
use crate::actions::progress::Progress;
use crate::Aes;
use ares::ciphers::Cipher;
use ares::raw_key::RawKey;
use ares::encrypted_file::EncryptedFile;
use crate::file::{open_file, write_file};
use crate::help::HELP_MSG;
use crate::input::Input;
use hmac::crypto_mac::Mac;
use std::convert::TryInto;

fn make_raw_key() -> Result<RawKey, Error> {
    let raw_key = Input::make_from_cfg()
        .map_err(|_| Error::InvalidInput)?
        .to_raw_key();

    Ok(raw_key)
}

fn make_mac_result(raw_key: &RawKey, input: &[u8]) -> [u8; 32] {
    let mut mac = raw_key.to_mac();
    mac.input(input);
    mac.result().code().as_slice().try_into().unwrap()
}

fn process(pb: &Progress, from: &str, to: &str) -> Result<(), Error> {
    let file = open_file(from).map_err(|_| Error::FileOpen)?;
    let raw_key = make_raw_key()?;
    pb.spawn_thread().apply_styles().start("Encrypting...");

    let buffer = raw_key.to_cipher::<Aes>().encrypt(&file);
    let mac = make_mac_result(&raw_key, &buffer);

    let encrypted_file = EncryptedFile {
        iv: raw_key.iv,
        buffer,
        mac,
    };

    pb.start("Saving to file...");
    let encrypted_buffer = bincode::serialize(&encrypted_file).unwrap();
    write_file(to, &encrypted_buffer).map_err(|_| Error::WritingEncryptedToFile)?;
    Ok(())
}

pub fn encrypt(from: &str, to: &str) {
    let pb = Progress::make();
    match process(&pb, from, to) {
        Ok(_) => {
            pb.end();
            println!("Encrypted successfully!")
        }
        Err(e) => {
            pb.end();
            println!("{}.{}", e, HELP_MSG)
        }
    }
}
