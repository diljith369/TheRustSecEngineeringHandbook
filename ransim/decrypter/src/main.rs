use rsa::{Oaep,  RsaPrivateKey, pkcs8::DecodePrivateKey, sha2::Sha256};
use aes_gcm::{ Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use std::{env, fs};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let encrtpted_file_path = &args[1];
    let encrypted_file_data = fs::read(encrtpted_file_path)?;
    let pvt_pem = fs::read_to_string("private_key.pem")?;
    let pvt_key = RsaPrivateKey::from_pkcs8_pem(&pvt_pem)?;
    let nonce_bytes = &encrypted_file_data[0..12];
    let encryptee_aes_key = &encrypted_file_data[12..268];
    let encrypted_data = &encrypted_file_data[268..];
    let aes_key = pvt_key.decrypt(Oaep::new::<Sha256>(), encryptee_aes_key)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref()).map_err(|e| e.to_string())?;
    fs::write("decrypted_file", &decrypted_data)?;
    println!("File decrypted successfully and saved as 'decrypted_file'");
    Ok(())
}
