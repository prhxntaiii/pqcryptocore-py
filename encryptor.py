import sys
import os
import hashlib

from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_encrypt, aesni_status


# =============================
#  SHA256
# =============================

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.digest()


# =============================
#  RUTAS
# =============================

def get_output_paths(infile):
    base_output = os.path.join(os.path.dirname(infile), "pq_encrypted")
    os.makedirs(base_output, exist_ok=True)

    filename = os.path.basename(infile)
    enc_file = os.path.join(base_output, filename + ".enc")
    pub_file = os.path.join(base_output, "kyber_pub.bin")
    priv_file = os.path.join(base_output, "kyber_priv.bin")

    return enc_file, pub_file, priv_file


# =============================
#  KYBER
# =============================

def ensure_kyber_keys(pub_file, priv_file):
    if not os.path.exists(pub_file) or not os.path.exists(priv_file):
        kem = KEM("Kyber1024")
        pk, sk = kem.generate_keypair()
        kem.free()

        with open(pub_file, "wb") as f:
            f.write(pk)
        with open(priv_file, "wb") as f:
            f.write(sk)

        print(f"[+] Claves Kyber generadas")


# =============================
#  CIFRADO
# =============================

def encrypt_file(infile, enc_file, pub_file):
    data = open(infile, "rb").read()
    original_hash = sha256_file(infile)

    # --- PQC ---
    kem = KEM("Kyber1024")
    pk = open(pub_file, "rb").read()
    ct_kyber, aes_key = kem.encapsulate(pk)
    kem.free()

    # --- AES-GCM (OpenSSL) ---
    iv = os.urandom(12)
    ciphertext, tag = aes_gcm_encrypt(
        key=aes_key,
        iv=iv,
        plaintext=data
    )

    # --- Escritura ---
    with open(enc_file, "wb") as f:
        f.write(len(ct_kyber).to_bytes(4, "big"))
        f.write(ct_kyber)
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)

    print("[+] Encrypted File:", enc_file)
    print("    SHA256 Original  :", original_hash.hex())
    print("    SHA256 Encrypted :", sha256_file(enc_file).hex())


# =============================
#  MAIN
# =============================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Uso: python encryptor.py "archivo"')
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")


    infile = sys.argv[1]
    enc_file, pub_file, priv_file = get_output_paths(infile)

    ensure_kyber_keys(pub_file, priv_file)
    encrypt_file(infile, enc_file, pub_file)
