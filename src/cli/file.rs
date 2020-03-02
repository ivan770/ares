use std::fs::read;
use std::fs::File;
use std::io::Error;
use std::io::Write;

pub fn open_file(name: &str) -> Result<Vec<u8>, Error> {
    read(name)
}

pub fn write_file(name: &str, buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(name)?;
    file.write_all(buffer)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    const FILE_NAME: &'static str = "fstest";

    use super::{open_file, write_file};
    use rand::random;
    use std::fs::remove_file;
    use std::path::Path;

    #[test]
    fn uses_fs_correctly() {
        let buffer: [u8; 16] = random();

        remove_file(FILE_NAME).ok();
        write_file(FILE_NAME, &buffer).unwrap();
        assert_eq!(Path::new(FILE_NAME).exists(), true);
        assert_eq!(open_file(FILE_NAME).unwrap().as_slice(), buffer);

        remove_file(FILE_NAME).ok();
    }
}
