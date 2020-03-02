use crate::raw_key::RawKey;
use crate::signers::{Error, Signer};
use hmac::crypto_mac::Mac;
use hmac::Hmac as BaseHmac;
use sha3::Sha3_256;
use std::convert::TryInto;

type Conjuncted = BaseHmac<Sha3_256>;

pub struct Hmac {
    pub hmac: Conjuncted,
}

impl Signer for Hmac {
    fn make(key: &[u8]) -> Self {
        Hmac {
            hmac: Conjuncted::new_varkey(key).unwrap(),
        }
    }

    fn sign(&self, buffer: &[u8]) -> [u8; 32] {
        let mut hmac = self.hmac.clone();
        hmac.input(buffer);
        hmac.result().code().as_slice().try_into().unwrap()
    }

    fn verify(&self, buffer: &[u8], mac: &[u8]) -> Result<(), Error> {
        let mut hmac = self.hmac.clone();
        hmac.input(buffer);
        Ok(hmac.verify(mac).map_err(|_| Error::InvalidSignature)?)
    }
}

impl<'a> From<&'a RawKey> for Hmac {
    fn from(raw_key: &'a RawKey) -> Self {
        Hmac::make(&raw_key.key.mac)
    }
}

#[cfg(test)]
mod tests {
    use crate::hashers::sha3_512::Sha3_512;
    use crate::hashers::Hasher;
    use crate::iv::Iv;
    use crate::raw_key::RawKey;
    use crate::signers::hmac::Hmac;
    use crate::signers::Signer;
    use hex_literal::hex;

    #[test]
    fn is_signing_correctly() {
        let iv = Iv {
            iv: hex!("746f74616c6c7972616e646f6d766563"),
        };
        let key = Sha3_512::make("testkey");
        let raw_key = RawKey::make(key, iv);

        let msg = String::from("123");

        let sign = Hmac::from(&raw_key);
        let result = sign.sign(msg.as_bytes());
        assert_eq!(
            result,
            hex!("4606943e0582b639e375a78628358d12783e45c74635a8fd3d26812633b34d14")
        );
    }
}
