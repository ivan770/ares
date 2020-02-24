extern crate block_modes;

mod cipher;
mod file;
mod help;
mod actions;
mod encrypted_file;

use actions::*;
use clap::{App, Arg};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("ares")
        .version(VERSION)
        .about("AES file encryption made easy")
        .author("https://github.com/ivan770")
        .subcommand(
            App::new("encrypt")
                .about("Encrypt file")
                .arg(
                    Arg::with_name("from")
                        .help("file to encrypt")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("to")
                        .help("output file")
                        .index(2)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("decrypt")
                .about("Decrypt file")
                .arg(
                    Arg::with_name("from")
                        .help("file to decrypt")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("to")
                        .help("output file")
                        .index(2)
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand_name() {
        Some("encrypt") => {
            let submatches = matches.subcommand_matches("encrypt").unwrap();
            encrypt::encrypt(submatches.value_of("from").unwrap(), submatches.value_of("to").unwrap());
        },
        Some("decrypt") => {
            let submatches = matches.subcommand_matches("decrypt").unwrap();
            decrypt::decrypt(submatches.value_of("from").unwrap(), submatches.value_of("to").unwrap());
        },
        _ => println!("Command not found. Use --help flag to open help"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, read, remove_file};
    use std::path::Path;
    use std::io::Write;
    use super::{encrypt, decrypt};

    const KEY: &'static str = "key.txt";
    const UNENCRYPTED: &'static str = "unencrypted.txt";
    const ENCRYPTED: &'static str = "encrypted.ares";
    const DECRYPTED: &'static str = "decrypted.txt";

    fn delete_files()
    {
        remove_file(KEY).ok();
        remove_file(UNENCRYPTED).ok();
        remove_file(ENCRYPTED).ok();
        remove_file(DECRYPTED).ok();
    }

    #[test]
    fn full_chain_test()
    {
        delete_files();

        let mut msg_file = File::create(UNENCRYPTED).unwrap();
        let mut key_file = File::create(KEY).unwrap();

        let msg = "This message is super secret.";
        msg_file.write_all(msg.as_bytes()).unwrap();

        let key = "supersecretkey12";
        key_file.write_all(key.as_bytes()).unwrap();

        encrypt::encrypt(UNENCRYPTED, ENCRYPTED);
        decrypt::decrypt(ENCRYPTED, DECRYPTED);
        assert_eq!(msg.as_bytes(), read(DECRYPTED).unwrap().as_slice());

        let swap_key = "supersecretkey13";
        remove_file(DECRYPTED).unwrap();

        key_file = File::create(KEY).unwrap();
        key_file.write_all(swap_key.as_bytes()).unwrap();
        decrypt::decrypt(ENCRYPTED, DECRYPTED);

        assert_eq!(Path::new(DECRYPTED).exists(), false);

        delete_files();
    }
}