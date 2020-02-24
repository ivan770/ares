use std::fs::read;
use std::io::Error;
use std::fs::File;
use std::io::Write;

pub fn open_file(name: &str) -> Result<Vec<u8>, Error>
{
    read(name)
}

pub fn write_file(name: &str, buffer: &[u8]) -> Result<(), Box<dyn std::error::Error>>
{
    let mut file = File::create(name)?;
    file.write_all(buffer)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    const FILE_NAME: &'static str = "fstest";
    
    use rand::random;
    use super::{write_file, open_file};
    use std::path::Path;
    use std::fs::remove_file;

    #[test]
    fn uses_fs_correctly()
    {
        let buffer: [u8; 16] = random();

        remove_file(FILE_NAME).ok();
        write_file(FILE_NAME, &buffer).unwrap();
        assert_eq!(Path::new(FILE_NAME).exists(), true);
        assert_eq!(open_file(FILE_NAME).unwrap().as_slice(), buffer);
    }
}