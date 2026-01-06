# PQCryptoCore (Kyber + AES-GCM)

## Overview

PQCryptoCore is a voluntary, user-initiated file encryption tool designed to protect sensitive documents such as:

- NDA files  
- Legal documents  
- Intellectual property  
- Offline backups  
- Confidential research data  

It implements **hybrid encryption** using:

- **CRYSTALS-Kyber (Kyber1024)** for post-quantum key encapsulation
- **AES-256-GCM** for authenticated file encryption  

This tool has **no network activity, no persistence, no automation, and no extortion logic**.  

The user explicitly selects the files to encrypt.

> ⚠️ **Note:** Currently, this tool **does not support Apple Silicon (M1, M2, etc.)**.  
> It works on macOS with Intel processors, Windows, and Linux. Support for Apple Silicon may be added in future releases.

---

## Threat Model

### Protects Against

- Unauthorized access to files at rest  
- Data leaks from lost or stolen storage devices  
- Offline compromise of sensitive documents  

### Does NOT Protect Against

- Compromised operating systems  
- Key exfiltration  
- Active malware on the host  
- User error (loss of private key)  

---

## How It Works

1. A **Kyber1024 keypair** is generated if not already present.  
2. A random **AES-256 key** is encapsulated using the Kyber public key.  
3. The file is encrypted using **AES-GCM**, providing confidentiality and integrity.  
4. The Kyber ciphertext, AES-GCM metadata, and keys are stored in a dedicated folder under `/output/<filename>/`.  

This follows the **envelope encryption** model used by modern cloud KMS systems.

---

## File Organization

Each encrypted file gets its own folder under `/output` to avoid key conflicts:

/output/<original_filename>/
├── <original_filename>.enc # Encrypted file
├── kyber_pub.bin # Public key
└── kyber_priv.bin # Private key

---

## Installation

Install dependencies:

pip install -r requirements.txt

>⚠️ Note: This tool is not compatible with Apple Silicon (M1/M2).
>
>Works on macOS Intel, Windows, and Linux.

## Usage
Encrypt a file:

python encryptor.py "/path/to/file/example.jpg"
Or simply drag & drop the file onto the script.

Decrypt a file:

python decryptor.py "/output/example.jpg/example.jpg.enc"

Or drag & drop the encrypted file.

> Note: The .dec suffix is not removed automatically. You must delete it manually if you want the original filename restored.

If your private keys are stored in a different location, you can specify the path manually.
By default, decrypted files are saved as /output/<filename>/<filename>.dec.
You can rename the output if you want to restore the original filename.

## Security Notes

- AES-GCM provides authentication; tampered files will fail to decrypt.
- Each encryption uses a fresh random nonce.
- The tool does not scan directories or encrypt files automatically.
- Designed for manual, consent-based use only.

## Legal & Ethical Use
This tool is intended for defensive security and data protection purposes only.
Do not use it on systems or files you do not own or have explicit authorization to protect.




