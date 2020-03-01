use crate::cipher::iv::Iv;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub iv: Iv,
    pub buffer: Vec<u8>,
    pub mac: [u8; 32],
}
