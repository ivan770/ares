extern crate block_modes;

mod key;
mod file;
mod encrypt;
mod decrypt;
mod encrypted_file;

use encrypt::encrypt;
use decrypt::decrypt;
use clap::{App, Arg};

fn main() {
    let matches = App::new("ares")
        .version("1.0")
        .about("AES file encryption made easy")
        .author("ivan770")
        .subcommand(
            App::new("encrypt")
                .about("Encrypt file")
                .version("1.0")
                .author("ivan770")
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
                .version("1.0")
                .author("ivan770")
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
            encrypt(submatches.value_of("from").unwrap(), submatches.value_of("to").unwrap());
        },
        Some("decrypt") => {
            let submatches = matches.subcommand_matches("decrypt").unwrap();
            decrypt(submatches.value_of("from").unwrap(), submatches.value_of("to").unwrap());
        },
        _ => println!("Command not found. Use --help flag to open help"),
    }
}
