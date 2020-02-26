use crate::cipher::iv::Iv;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub iv: Iv,
    pub buffer: Vec<u8>
}
