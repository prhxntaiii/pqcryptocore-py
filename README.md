# PQCryptoCore (Kyber1024 + AES-256-GCM)

PQCryptoCore is a voluntary, user-initiated file encryption tool designed to protect sensitive data such as:

- NDA files
- Legal documents
- Intellectual property
- Offline backups
- Confidential research data

It implements hybrid post-quantum encryption using:

- CRYSTALS-Kyber (Kyber1024) via libOQS
- AES-256-GCM via OpenSSL EVP (hardware-accelerated when available)

This tool has no network activity, no persistence, no automation, and no extortion logic.
Files are encrypted only when explicitly selected by the user.

>⚠️ Note:
>Apple Silicon (M1, M2, etc.) is not supported at this time.
>Supported platforms: Windows, Linux, macOS (Intel), Android (Termux ARM64 and x86_64).

## Threat Model

Protects Against:

- Unauthorized access to files at rest
- Data exposure from lost or stolen storage devices
- Long-term cryptographic compromise (“harvest now, decrypt later”)

Does NOT Protect Against

- Compromised operating systems
- Key exfiltration or memory scraping
- Active malware on the host
- User error (loss of private key)

## How It Works

1. A Kyber1024 keypair is generated if it does not already exist.
2. A random AES-256 session key is encapsulated using the Kyber public key.
3. The file is encrypted using AES-256-GCM (OpenSSL EVP), providing confidentiality and integrity.
4. The encrypted file and cryptographic material are stored in a dedicated directory.

This follows the envelope encryption model used by modern KMS systems and secure storage solutions.

## File Organization

Each encrypted file is stored in its own directory to avoid key reuse or conflicts:

pq_encrypted/<original_filename>/

├── <original_filename>.enc   # Encrypted file

├── kyber_pub.bin             # Kyber public key

└── kyber_priv.bin            # Kyber private key

## Installation

Install dependencies:

pip install -r requirements.txt

## Usage

### Encrypt a file

python encryptor.py "/path/to/file/example.jpg"

> You can also drag & drop a file onto the script.

### Decrypt a file

python decryptor.py "pq_encrypted/example.jpg/example.jpg.enc"

> You can also drag & drop the encrypted file.

>ℹ️ The .dec suffix is not removed automatically.
>You may rename the file manually to restore the original filename.

If your private key is stored elsewhere, you can pass its path explicitly.

## Security Notes

- AES-GCM provides authenticated encryption; tampered files will fail to decrypt.
- Each encryption uses a fresh random nonce.
- Hardware acceleration (AES-NI) is used automatically when supported by the CPU.
- No directory scanning or automatic encryption is performed.
- Designed strictly for manual, consent-based use.

## Legal & Ethical Use

This tool is intended solely for defensive security and personal data protection.
Do not use it on systems or files you do not own or have explicit authorization to protect.

