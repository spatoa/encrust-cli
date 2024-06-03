use rand::Rng;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

const KEY_SIZE: usize = 32; // 256-bit key for AES

pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; KEY_SIZE];
    rng.fill(&mut key);
    key
}

pub fn save_key_to_file(key: &[u8], file_path: &str) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(key)?;
    Ok(())
}

pub fn load_key_from_file(file_path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut key = Vec::new();
    file.read_to_end(&mut key)?;
    Ok(key)
}
