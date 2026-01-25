use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey,LineEnding};
use std::fs::File;
use std::io::Write;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut  rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let mut file = File::create("private_key.pem")?;
    file.write_all(private_pem.as_bytes())?;
    let public_pem = public_key.to_public_key_pem(LineEnding::CRLF)?;
    let mut file = File::create("public_key.pem")?;
    file.write_all(public_pem.as_bytes())?;
    println!("Private key and public key generated successfully.");

    Ok(())
}
