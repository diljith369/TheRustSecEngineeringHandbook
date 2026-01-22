# Rust Security Engineering & Offensive Tooling
This repository contains a collection of security-focused tools and simulations developed in Rust. The project is organized as a Cargo Workspace to demonstrate modularity, efficient dependency management, and professional project structure for security researchers and developers.

## Project Architecture
The repository is structured to separate different offensive and defensive logic into independent crates:
 - crypto : (Current Release) CLI tools for performing and analyzing XOR and AES-GCM encryption.
 - shellcode-obfuscation: (Upcoming) Techniques for evading AV/EDR using AES-GCM and XOR-based shellcode wrappers.
 - key-gen: (Upcoming) RSA-4096 key pair generation for hybrid cryptographic schemes.
 - ransomware-sim: (Upcoming) A hybrid encryption payload (The Encrypter) utilizing pinned public keys.
 - recovery-tool: (Upcoming) A decryption utility (The Decrypter) designed to reverse the ransomware simulation.
## Getting Started
### Prerequisites
- Rust (Latest Stable)
- Cargo
### Installation
Clone the repository and build the entire workspace:
```
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
cargo build --release
```
To run a specific tool within the workspace:
```
cargo run -p crypto -- [args]
```

## ⚖️ Educational Disclaimer
The code provided in this repository is for educational and authorized security research purposes only. The goal is to provide security professionals and students with a deeper understanding of offensive engineering to build more resilient defensive systems. Misuse of this information for malicious activity is strictly prohibited.


## License
MIT
**Free Software, Hell Yeah!**

