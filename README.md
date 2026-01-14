# PQCryptoCore (Kyber1024 + AES-256-GCM)

**PQCryptoCore** is a **manual, user-initiated file encryption tool** designed to protect sensitive information, including:

* NDA documents  
* Legal files  
* Intellectual property  
* Offline backups  
* Confidential research data  

It uses **hybrid post-quantum encryption**, combining:

* **CRYSTALS-Kyber (Kyber1024)** via libOQS  
* **AES-256-GCM** via OpenSSL EVP  
* **Hardware-accelerated** automatically when AES-NI is available

> ⚠️ **Note:**
>  
> Apple Silicon (M1/M2/M3) is **not supported natively** To run on these Macs, use Rosetta 2.  
> Supported platforms: **Windows (x64 and x86), Linux x64, macOS Intel, Android (Termux ARM64 and x86_64)**

PQCryptoCore does **not** include networking, persistence, automation, or extortion functionality. Files are encrypted only when explicitly chosen by the user.

---

## Threat Model

### Protects Against

* Unauthorized access to files at rest  
* Data exposure from lost or stolen storage devices  
* Long-term cryptographic compromise (“harvest now, decrypt later”)

### Does NOT Protect Against

* Compromised operating systems  
* Active malware on the host  
* Key exfiltration or memory scraping  
* Human error (loss of private key)

---

## How It Works

1. A **Kyber1024 keypair** is generated if none exists.  
2. A **random AES-256 session key** is encapsulated using the Kyber public key.  
3. The file is encrypted using **AES-256-GCM in streaming mode**.  
4. The encrypted file and cryptographic material are stored in a dedicated directory.  

This follows the **envelope encryption model** used in modern KMS and secure storage solutions.

---

## Streaming & Memory Usage

* Files are **never loaded entirely into RAM**.  
* Processed in **2 MB chunks** for constant memory usage, even for multi-GB files.  
* No temporary files in `/temp` or elsewhere.  
* Reduces memory exhaustion, accidental leaks, and exposure via system temp directories.

---

## Passphrase Usage

To further secure your files, **PQCryptoCore** allows the use of a **passphrase** to derive an additional AES key via **PBKDF2-HMAC-SHA256**.

### How it works:
- When encrypting, if you choose to provide a passphrase, it will be used to **derive a unique AES-256 key**.  
- This passphrase-derived key is **combined** with the Kyber-encapsulated session key for encryption.
- During decryption, the passphrase is used to **verify the AES key** and ensure file integrity.

> ⚠️ **Important Note:**  
> If you lose the passphrase, there is **no way to recover** the encrypted file. Make sure to store it securely.

----

## File Organization

Each encrypted file is stored in its own directory to avoid key reuse or conflicts:

pq_encrypted/<original_filename>/

├── <original_filename>.enc # Encrypted file

├── kyber_pub.bin # Kyber public key

└── kyber_priv.bin # Kyber private key

---

## Installation

**Install dependencies:**

```bash
pip install -r requirements.txt
```
---

## Usage

**Encrypt a file**

```bash
python encryptor.py "/path/to/file/example.pdf"
```
You can also drag & drop a file onto the script.

**Decrypt a file**
```bash
python decryptor.py "pq_encrypted/example.pdf/example.pdf.enc"
```

>ℹ️ The .dec suffix is not removed automatically. Rename the file manually if needed.
>You can pass an alternate path to your private key if stored elsewhere.

Security Notes

- AES-GCM provides authenticated encryption: tampered files will fail to decrypt
- Each encryption uses a fresh, random nonce
- Hardware acceleration (AES-NI) is used automatically when available; otherwise, software AES is used
- No directory scanning or automatic encryption
- Strictly manual, consent-based usage

## Legal & Ethical Use
- PQCryptoCore is intended solely for defensive security and personal data protection.
- Do not use it on systems or files you do not own or have explicit authorization to protect.


