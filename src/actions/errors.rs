use std::fmt;

pub enum Error {
    FileOpen,
    InvalidFileFormat,
    InvalidEncryptionKey,
    WritingDecryptedToFile,
    WritingEncryptedToFile,
    InvalidInput
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::FileOpen => "Unable to open file",
                Error::InvalidFileFormat => "Invalid file format",
                Error::InvalidEncryptionKey => "Invalid encryption key",
                Error::WritingDecryptedToFile => "Error writing decrypted data",
                Error::WritingEncryptedToFile => "Error writing encrypted data",
                Error::InvalidInput => "IO error",
            }
        )
    }
}