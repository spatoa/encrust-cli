use crate::Algorithm;
use aes_gcm::{
    aead::{
        generic_array::GenericArray as AesGenericArray, Aead as AesAead, KeyInit as AesKeyInit,
    },
    {Aes256Gcm, Key as AesKey, Nonce as AesNonce},
};
use chacha20poly1305::{
    aead::{
        generic_array::GenericArray as ChaChaGenericArray, Aead as ChaChaAead,
        KeyInit as ChaChaKeyInit,
    },
    {XChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce},
};
use rand::{rngs::StdRng, Rng, SeedableRng};

const KEY_SIZE: usize = 32; // 256-bit key size
const AES_NONCE_SIZE: usize = 12; // Standard size for GCM mode
const CHACHA_NONCE_SIZE: usize = 24; // Standard size for XChaCha20-Poly1305

fn seeded_key(seed: u64) -> [u8; KEY_SIZE] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = [0u8; KEY_SIZE];
    rng.fill(&mut bytes[..]);
    bytes
}

fn aes_seeded_nonce(seed: u64) -> [u8; AES_NONCE_SIZE] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = [0u8; AES_NONCE_SIZE];
    rng.fill(&mut bytes[..]);
    bytes
}

fn chacha_seeded_nonce(seed: u64) -> [u8; CHACHA_NONCE_SIZE] {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut bytes = [0u8; CHACHA_NONCE_SIZE];
    rng.fill(&mut bytes[..]);
    bytes
}

pub fn decrypt_ciphertext(input_file_contents: Vec<u8>, algorithm: Algorithm) -> Vec<u8> {
    match algorithm {
        Algorithm::Aes => {
            println!("Decrypting with AES");
            decrypt_aes(
                &seeded_key(123),
                &aes_seeded_nonce(123),
                input_file_contents,
            )
        }
        Algorithm::Chacha => {
            println!("Decrypting with ChaCha");
            decrypt_chacha(
                &seeded_key(123),
                &chacha_seeded_nonce(123),
                input_file_contents,
            )
        }
    }
}

fn decrypt_aes(key: &[u8; KEY_SIZE], nonce: &[u8; AES_NONCE_SIZE], ciphertext: Vec<u8>) -> Vec<u8> {
    let cipher = Aes256Gcm::new(AesGenericArray::from_slice(key));

    let plaintext = cipher
        .encrypt(AesNonce::from_slice(nonce), ciphertext.as_ref())
        .expect("Could not decrypt file with AES.");

    plaintext
}

fn decrypt_chacha(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; CHACHA_NONCE_SIZE],
    ciphertext: Vec<u8>,
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));

    let plaintext = cipher
        .decrypt(ChaChaGenericArray::from_slice(nonce), ciphertext.as_ref())
        .expect("Could not decrypt file with ChaCha.");

    plaintext
}
