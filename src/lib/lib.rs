pub mod ciphers;
pub mod encrypted_file;
pub mod hashers;
pub mod iv;
pub mod raw_key;

use hmac::Hmac as BaseHmac;
use sha3::Sha3_256;

pub type Hmac = BaseHmac<Sha3_256>;

#[cfg(test)]
mod tests {
    use crate::hashers::sha3_512::Sha3_512;
    use crate::hashers::Hasher;
    use crate::iv::Iv;
    use crate::raw_key::RawKey;
    use hex_literal::hex;
    use hmac::crypto_mac::Mac;

    #[test]
    fn is_signing_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = Sha3_512::make("testkey");
        let rawkey = RawKey::make(key, iv);

        let msg = String::from("123");

        let mut sign = rawkey.to_mac();
        sign.input(msg.as_bytes());
        assert_eq!(
            sign.result().code().as_slice(),
            hex!("4606943e0582b639e375a78628358d12783e45c74635a8fd3d26812633b34d14")
        );
    }
}
