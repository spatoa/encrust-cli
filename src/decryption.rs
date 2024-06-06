use crate::Algorithm;
use rand::{Rng, SeedableRng, rngs::StdRng};
use chacha20poly1305::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    XChaCha20Poly1305
};
use std::fs::write;

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

pub fn decrypt_file(input_file_contents: Vec<u8>, algorithm: Algorithm, output_file_path: &str) {
    match algorithm {
        Algorithm::Aes => {
            println!("Decrypting with AES");
        },
        Algorithm::Chacha => {
            println!("Decrypting with ChaCha");
            decrypt_chacha(&seeded_key(123), &seeded_nonce(123), input_file_contents, output_file_path);
        },
        _ => {
            println!("You lose the game.")
        }
    }

    println!("Decrypted!");
}

fn decrypt_aes() {
    println!("Uh oh, this hasn't been implemented yet...");
}

fn decrypt_chacha(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], ciphertext: Vec<u8>, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext.as_ref())
        .map_err(|_| "encryption failure!")?;
    write(output_path, plaintext)?;
    Ok(())
}