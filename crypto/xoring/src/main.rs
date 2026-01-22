use std::env;
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <input> <key>", args[0]);
        return;
    }

    let input = &args[1].clone();
    let key = &args[2].clone();
    let xored = xoring(input, key);
    println!("Xored Input: {xored}");
    let decrypted = xoring(&xored, key);
    println!("Decrypted Input: {decrypted}");
}

fn xoring(input: &str, key: &str) -> String {
    let input_bytes = input.as_bytes();
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    let input_len = input_bytes.len();
let mut xored_bytes = Vec::with_capacity(input_len);

    for i in 0..input_len {
        let input_byte = input_bytes[i];
        let key_byte = key_bytes[i % key_len];
        let xored_byte = input_byte ^ key_byte;
        xored_bytes.push(xored_byte);
    }

    String::from_utf8(xored_bytes).expect("Invalid UTF-8 sequence")
}
