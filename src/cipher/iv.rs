use rand::random;
use serde::{Serialize, Deserialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Iv {
    pub iv: [u8; 16]
}

impl Iv {
    pub fn random() -> Self
    {
        Iv {
            iv: random()
        }
    }
}