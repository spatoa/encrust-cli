use crate::Algorithm;
use clap::error;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, generic_array::GenericArray},
    XChaCha20Poly1305, Nonce
};
use std::fs::{File, read, write};
use std::io::{self, BufReader};

const KEY_SIZE: usize = 32; // 256-bit key size
const NONCE_SIZE: usize = 24; // 192-bit nonce size

fn seeded_key(seed: u64) -> [u8; KEY_SIZE] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = [0u8; KEY_SIZE];
    rng.fill(&mut bytes[..]);
    bytes
}

fn seeded_nonce(seed: u64) -> [u8; NONCE_SIZE] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = [0u8; NONCE_SIZE];
    rng.fill(&mut bytes[..]);
    bytes
}

fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_file(input_file_contents: Vec<u8>, algorithm: Algorithm, output_file_path: &str) {
    match algorithm {
        Algorithm::Aes => {
            println!("Encrypting with AES");
        },
        Algorithm::Chacha => {
            println!("Encrypting with ChaCha");
            encrypt_chacha(&seeded_key(123), &seeded_nonce(123), input_file_contents, output_file_path);
        },
        _ => {
            println!("You lose the game.")
        }
    }

    println!("Encrypted!");
}

fn encrypt_aes(input_file: &str, key: &str, algorithm: Algorithm) {
    println!("Uh oh, this hasn't been implemented yet...");
}

fn encrypt_chacha(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], plaintext: Vec<u8>, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
    let ciphertext = cipher.encrypt(GenericArray::from_slice(nonce), plaintext.as_ref())
        .map_err(|_| "encryption failure!")?;
    write(output_path, ciphertext)?;
    Ok(())
}