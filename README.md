# Hybrid File Encryption Tool (Kyber + AES-GCM)

## Overview

This tool provides voluntary, user-initiated file encryption for protecting sensitive documents such as:

- NDA files
- Legal documents
- Intellectual property
- Offline backups
- Confidential research data

It implements hybrid encryption using:

- CRYSTALS-Kyber (Kyber1024) for post-quantum key encapsulation
- AES-256-GCM for authenticated file encryption

There is no network activity, no persistence, no automation, and no extortion logic.
The user explicitly selects the file to encrypt.

---

## Threat Model

### Protects against

- Unauthorized access to files at rest
- Data leaks from lost or stolen storage
- Offline compromise of sensitive documents

### Does NOT protect against

- Compromised operating systems
- Key exfiltration
- Active malware on the host
- User error (loss of private key)

---

## How It Works


1. A Kyber1024 keypair is generated if not present.
2. A random AES-256 key is encapsulated using the Kyber public key.
3. The file is encrypted using AES-GCM (confidentiality + integrity).
4. The Kyber ciphertext and AES-GCM metadata are stored with the encrypted file.

This follows the same envelope encryption model used by modern cloud KMS systems.

---
## Installation

pip install -r requirements.txt

## Usage

python encryptor.py "file_to_encrypt.txt" or drag and drop

python decryptor.py "file_to_encrypt.txt" or drag and drop


### If no key files exist, they will be generated automatically:

kyber_pub.bin

kyber_priv.bin

Output:
file_to_encrypt.txt.enc


## Decryption

Decryption requires:

-The original encrypted file
-The corresponding Kyber private key

A compatible decryptor must be used. Encryption is reversible by design.

Security Notes

-AES-GCM provides authentication; tampered files will fail to decrypt.
-Each encryption uses a fresh random nonce.
-The tool does not scan directories or encrypt files automatically.
-Designed for manual, consent-based use only.

## Legal & Ethical Use

This tool is intended for defensive security and data protection purposes only.
Do not use it on systems or files you do not own or have explicit authorization to protect.

## File Organization Recommendation

For proper file management and traceability, it is strongly recommended to group all related artifacts into a single directory.

After encrypting a file, place the following items together in one folder:

- The original file (before encryption)
- The encrypted file (`.enc`)
- The Kyber public key (`kyber_pub.bin`)
- The Kyber private key (`kyber_priv.bin`)
- Any generated hash values (e.g. SHA-256)

This structure helps maintain clarity, prevents key or file mismatches, and simplifies secure storage, backups, or future decryption workflows.

Example:

secure_docs/

├── example.pdf

├── example.pdf.enc

├── kyber_pub.bin

├── kyber_priv.bin

└── hashes.txt



