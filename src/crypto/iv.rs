use rand::random;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Iv {
    pub iv: [u8; 16],
}

impl Iv {
    pub fn random() -> Self {
        Iv { iv: random() }
    }
}
