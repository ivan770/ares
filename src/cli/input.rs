use ares::hashers::Hasher;
use ares::iv::Iv;
use ares::raw_key::RawKey;
use crate::Hasher as HasherImpl;
use std::io::Error;

pub struct Input {
    input: String,
}

impl Input {
    #[allow(dead_code)]
    fn from_dialoguer() -> Result<Self, Error> {
        let input = dialoguer::PasswordInput::new()
            .with_prompt("Encryption key")
            .with_confirmation("Confirm encryption key", "Inputs do not match")
            .interact()?;

        Ok(Input::make(input))
    }

    #[allow(dead_code)]
    fn from_file() -> Result<Self, Error> {
        let input = String::from_utf8(std::fs::read("key.txt").unwrap()).unwrap();
        Ok(Input::make(input))
    }

    pub fn make(input: String) -> Self {
        Input { input }
    }

    pub fn make_from_cfg() -> Result<Self, Error> {
        #[cfg(test)]
        return Input::from_file();

        #[cfg(not(test))]
        return Input::from_dialoguer();
    }

    pub fn to_raw_key(&self) -> RawKey {
        RawKey::from_string::<HasherImpl>(&self.input)
    }

    pub fn to_raw_key_iv(&self, iv: Iv) -> RawKey {
        RawKey::make(HasherImpl::make(&self.input), iv)
    }
}
