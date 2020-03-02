use ares::ciphers::aes_256::Aes256Cbc;
use ares::ciphers::Cipher;
use ares::encrypted_file::EncryptedFile;
use ares::hashers::sha3_512::Sha3_512;
use ares::raw_key::RawKey;
use ares::signers::hmac::Hmac;
use ares::signers::Signer;
use hex_literal::hex;

#[test]
fn full_chain_lib_test() {
    let key: &'static str = "Super secret key";

    let raw_key = RawKey::from_string::<Sha3_512>(key);
    let mac = raw_key.to_mac::<Hmac>();

    let buffer = raw_key
        .to_cipher::<Aes256Cbc>()
        .encrypt(&hex!("4920616D20656E637279707465642074657374203A29"));

    let sign = mac.sign(&buffer);

    let encrypted_file = EncryptedFile {
        iv: raw_key.iv,
        buffer,
        mac: sign,
    };

    let mac = raw_key.to_mac::<Hmac>();

    mac.verify(&encrypted_file.buffer, &encrypted_file.mac)
        .unwrap();

    assert_eq!(
        &raw_key
            .to_cipher::<Aes256Cbc>()
            .decrypt(&encrypted_file.buffer)
            .unwrap(),
        &hex!("4920616D20656E637279707465642074657374203A29")
    );
}
