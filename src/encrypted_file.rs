use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub iv: [u8; 16],
    pub buffer: Vec<u8>
}
