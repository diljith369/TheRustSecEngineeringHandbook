use std::{env, fs};

use aes_gcm::{aead:: {Aead, KeyInit}, Aes256Gcm,Nonce, Key};
use pbkdf2::pbkdf2_hmac;
use rand::{ RngCore, rngs::OsRng};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("AES-GCM encryption module");
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Usage: {} <enc/dec> <password> <filepath>", args[0]);
        return Ok(());
    }

    let mode = &args[1];
    let password = &args[2];
    let filepath = &args[3];
    match mode.as_str() {
        "enc" => {
            println!("Encrypting file: {} with password: {}", filepath, password);
            aesgcm_encrypt(filepath, password)?;
        }
        "dec" => {
            println!("Decrypting file: {} with password: {}", filepath, password);
            aesgcm_decrypt(filepath, password)?;
        }
        _ => {
            println!("Invalid mode. Use 'enc' for encryption or 'dec' for decryption.");
        }
    }
    Ok(())


}
fn aesgcm_encrypt(_filepath: &str, _password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(
        _password.as_bytes(),
        &salt,
        100_000,
        &mut key_bytes,
    );
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = fs::read(_filepath)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("Encryption Failed");
    let mut output_data = Vec::new();
                output_data.extend_from_slice(&salt);
                output_data.extend_from_slice(&nonce_bytes);
                output_data.extend_from_slice(&ciphertext);

    fs::write(format!("{}.enc", _filepath), output_data)?;
    Ok(())

}

fn aesgcm_decrypt(_filepath: &str, _password: &str) -> Result<(), Box<dyn std::error::Error>> {
 let file_data = fs::read(_filepath)?;
 let salt = &file_data[0..16];
            let nonce_bytes = &file_data[16..28];
            let ciphertext = &file_data[28..];
            let mut key_bytes = [0u8; 32];
            pbkdf2_hmac::<sha2::Sha256>(_password.as_bytes(), salt, 100_000, &mut key_bytes);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
            let nonce = Nonce::from_slice(nonce_bytes);
            let plaintext = cipher.decrypt(nonce, ciphertext)
                .expect("decryption failure!");
            fs::write("decrpted.txt", plaintext)?;
            Ok(())  
}
