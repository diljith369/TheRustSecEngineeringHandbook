use rand::{rngs::OsRng, RngCore};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::{fs,env};

#[derive(Debug, Clone, Copy,PartialEq)]
enum Mode {
    Encrypt,
    Decrypt
}
#[derive(Debug, Clone, Copy,PartialEq)]
enum Algorithm {
    AES,
    XOR
}

#[derive(Debug, Clone, Copy,PartialEq)]
enum Format {
    Hex0x,
    HexSlashX
}

struct Config {
    mode: Mode,
    algorithm: Algorithm,
    format: Format,    
    password: String,
    path: String
}

impl Config {
    fn build(args: &Vec<String>) -> Result<Config, String> {
        if args.len() < 6 {
            return Err(format!(
                "Usage: {} <mode: enc/dec> <algo: xor/aes> <format: 0x/\\x> <pass> <path>",
                args[0]
            ));
        }
        let mode = match args[1].as_str() {
            "encrypt" => Mode::Encrypt,
            "decrypt" => Mode::Decrypt,
            _ => return Err("Invalid mode: use 'enc' or 'dec'".into()),
        };
        let algorithm = match args[2].as_str() {
            "aes" => Algorithm::AES,
            "xor" => Algorithm::XOR,
            _ => return Err("Invalid algo: use 'xor' or 'aes'".into()),
        };
        let format = match args[3].as_str() {
            "hex0x" => Format::Hex0x,
            "hexslashx" => Format::HexSlashX,
            _ => return Err("Invalid format: use '0x' or '\\x'".into()),
        };
       

        Ok(Config {
            mode,
            algorithm,
            format,
             password: args[4].clone(),
            path: args[5].clone(),
        })
    }
}

trait ShellCodeCipher {
    fn encrypt(&self, data: &[u8], password: &str) -> Vec<u8>;
    fn decrypt(&self, data: &[u8], password: &str) -> Result<Vec<u8>, String>;
}

struct XorCipher;
impl ShellCodeCipher for XorCipher {
    fn encrypt(&self, input: &[u8], key: &str) -> Vec<u8> {
        let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    let input_len = input.len();
    let mut xored_bytes:Vec<u8> = Vec::with_capacity(input_len);

    for i in 0..input_len {
        let input_byte = input[i];
        let key_byte = key_bytes[i % key_len];
        let xored_byte = input_byte ^ key_byte;
        xored_bytes.push(xored_byte);
    }
    xored_bytes
    }

    fn decrypt(&self, data: &[u8], password: &str) -> Result<Vec<u8>, String> {
        Ok(self.encrypt(data, password))
    }
}

struct AesCipher;
impl ShellCodeCipher for AesCipher {
    fn encrypt(&self, data: &[u8], pass: &str) -> Vec<u8> {
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(pass.as_bytes(), &salt, 600_000, &mut key);

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), data).expect("AES Error");

        let mut package = salt.to_vec();
        package.extend(nonce_bytes);
        package.extend(ciphertext);
        package
    }

    fn decrypt(&self, data: &[u8], pass: &str) -> Result<Vec<u8>, String> {
        if data.len() < 28 { return Err("Payload too short".into()); }
        let salt = &data[0..16];
        let nonce = &data[16..28];
        let ciphertext = &data[28..];

        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, 600_000, &mut key);

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| "Decryption Failed".into())
    }
}

struct ShellCodeFormatter;
impl ShellCodeFormatter {
    fn parse(input: &str) -> Vec<u8> {
        let mut result = Vec::new();
        let shell_splits = input.split(",");
        
        for shell_byte in shell_splits {
            let trimmed = shell_byte.trim();
            if trimmed.is_empty() { continue; }

            let cleaned = if trimmed.starts_with("0x") || trimmed.starts_with("\\x") {
                &trimmed[2..]
            } else {
                trimmed
            };

            match u8::from_str_radix(cleaned, 16) {
                Ok(b) => result.push(b),
                Err(_) => eprintln!("Warning: Skipping invalid byte sequence: {}", cleaned),
            }
        }

        result
    }

    fn format(bytes: &[u8], format: Format) -> String {
        bytes.iter()
            .map(|b| match format {
                Format::Hex0x => format!("0x{:02x}", b),
                Format::HexSlashX => format!("\\x{:02x}", b),
            })
            .collect::<Vec<String>>()
            .join(", ")
    }
}

fn main() {
let args: Vec<String> = env::args().collect();

    let config = match Config::build(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let raw_content = fs::read_to_string(&config.path).expect("Could not read file");
    let shellcode = ShellCodeFormatter::parse(&raw_content);


    println!("algo: {:?}", config.algorithm);
    println!("mode: {:?}", config.mode);
    println!("pass: {:?}", config.password);
    let engine: Box<dyn ShellCodeCipher> = match config.algorithm {
        Algorithm::XOR => Box::new(XorCipher),
        Algorithm::AES => Box::new(AesCipher),
    };

    let result = match config.mode {
        Mode::Encrypt => Ok(engine.encrypt(&shellcode, &config.password)),
        Mode::Decrypt => engine.decrypt(&shellcode, &config.password),
    };

    match result {
        Ok(data) => println!("{}", ShellCodeFormatter::format(&data, config.format)),
        Err(err) => eprintln!("Execution Error: {}", err),
    }
}