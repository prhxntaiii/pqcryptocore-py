import sys
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from backend.oqs_backend import KEM

# --- Función SHA256 ---
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.digest()

# --- Rutas de salida ---
def get_output_paths(infile):
    base_output = os.path.join(os.path.dirname(infile), "pq_encrypted")
    os.makedirs(base_output, exist_ok=True)
    filename = os.path.basename(infile)

    enc_file = os.path.join(base_output, filename + ".enc")
    pub_file = os.path.join(base_output, "kyber_pub.bin")
    priv_file = os.path.join(base_output, "kyber_priv.bin")

    return enc_file, pub_file, priv_file

# --- Genera claves Kyber si no existen ---
def ensure_kyber_keys(pub_file, priv_file):
    if not os.path.exists(pub_file) or not os.path.exists(priv_file):
        kem = KEM("Kyber1024")
        pk, sk = kem.generate_keypair()
        kem.free()
        with open(pub_file, "wb") as f: f.write(pk)
        with open(priv_file, "wb") as f: f.write(sk)
        print(f"[+] Claves Kyber generadas: {pub_file}, {priv_file}")

# --- Cifra el archivo ---
def encrypt_file(infile, enc_file, pub_file):
    data = open(infile, "rb").read()
    original_hash = sha256_file(infile)

    kem = KEM("Kyber1024")
    pk = open(pub_file, "rb").read()
    ct_kyber, aes_key = kem.encapsulate(pk)
    kem.free()

    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(enc_file, "wb") as f:
        f.write(len(ct_kyber).to_bytes(4, "big"))
        f.write(ct_kyber)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    print("[+] Encrypted File:", enc_file)
    print("    SHA256 Original File :", original_hash.hex())
    print("    SHA256 Encrypted File  :", sha256_file(enc_file).hex())

# --- Main ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Use: python encryptor.py "archivo_a_cifrar"')
        sys.exit(1)

    infile = sys.argv[1]
    enc_file, pub_file, priv_file = get_output_paths(infile)

    ensure_kyber_keys(pub_file, priv_file)
    encrypt_file(infile, enc_file, pub_file)
