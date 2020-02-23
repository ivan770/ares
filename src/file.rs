use std::fs::read;
use std::io::Error;
use std::fs::File;
use std::io::Write;

pub fn open_file(name: &str) -> Result<Vec<u8>, Error>
{
    read(name)
}

pub fn write_file(name: &str, buffer: &[u8])
{
    let mut file = File::create(name).unwrap();
    file.write_all(buffer).unwrap();
}
