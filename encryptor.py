import os
import sys
import getpass
import hmac
import hashlib
from hashlib import pbkdf2_hmac

from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_encrypt_stream, aesni_status
from backend.blake3.blake3_wrapper import BLAKE3

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB

# =============================
#  KEYSTORE (priv key NO al lado del ciphertext)
# =============================
KEYSTORE_DIR = os.environ.get("PQ_KEYSTORE_DIR", os.path.expanduser("~/.pq_keystore"))

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

# =============================
#  RUTAS
# =============================
def get_output_paths(infile):
    base_output = os.path.join(os.path.dirname(infile), "pq_encrypted")
    os.makedirs(base_output, exist_ok=True)

    filename = os.path.basename(infile)

    folder_base = filename.replace(".", "_")
    file_folder = os.path.join(base_output, folder_base)

    counter = 1
    while os.path.exists(file_folder):
        file_folder = os.path.join(base_output, f"{folder_base}_{counter}")
        counter += 1

    os.makedirs(file_folder, exist_ok=True)

    # Ciphertext
    enc_file = os.path.join(file_folder, filename + ".enc")

    # Public key junto al ciphertext
    pub_file = os.path.join(file_folder, "kyber_pub.bin")

    # Private key en keystore, con la MISMA carpeta (incluye counter)
    ensure_dir(KEYSTORE_DIR)
    priv_subdir = os.path.join(KEYSTORE_DIR, os.path.basename(file_folder))
    os.makedirs(priv_subdir, exist_ok=True)
    priv_file = os.path.join(priv_subdir, "kyber_priv.bin")

    return enc_file, pub_file, priv_file

# =============================
#  HKDF-SHA256 (simple y estándar)
# =============================
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Extract(salt, IKM) + HKDF-Expand(PRK, info, L)
    RFC 5869 con SHA-256.
    """
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1

    return okm[:length]

# =============================
#  KYBER KEYS
# =============================
def ensure_kyber_keys(pub_file, priv_file):
    # Si falta cualquiera, generamos (pub se deja junto a ciphertext, priv en keystore)
    if not os.path.exists(pub_file) or not os.path.exists(priv_file):
        kem = KEM("Kyber1024")
        pk, sk = kem.generate_keypair()
        kem.free()

        with open(pub_file, "wb") as f:
            f.write(pk)

        with open(priv_file, "wb") as f:
            f.write(sk)

        print(f"[+] Kyber keys generated:")
        print(f"    pub: {pub_file}")
        print(f"    priv: {priv_file}")

# =============================
#  DERIVACIÓN DESDE PASSPHRASE
# =============================
def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Deriva 32 bytes desde passphrase con PBKDF2-HMAC-SHA256.
    """
    return pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=32)

# =============================
#  CIFRADO (híbrido real: Kyber + passphrase)
# =============================
def encrypt_file(infile, enc_file, pub_file, passphrase: str | None = None):
    iv = os.urandom(12)
    pk = open(pub_file, "rb").read()

    kem = KEM("Kyber1024")
    ct_kyber, kyber_ss = kem.encapsulate(pk)   # kyber_ss = shared secret
    kem.free()

    # Sal para la parte passphrase (se guarda en header)
    salt_pw = os.urandom(16)

    # --- CLAVE FINAL: NO reemplazar Kyber, mezclar ---
    if passphrase:
        print("[i] Processing passphrase (hybrid mode)...")
        pw_key = derive_key_from_passphrase(passphrase, salt_pw)  # 32 bytes
        ikm = kyber_ss + pw_key
        info = b"pq-hybrid:kyber1024+pbkdf2-sha256->aes-256-gcm"
    else:
        print("[i] No passphrase (PQC-only mode)...")
        ikm = kyber_ss
        info = b"pq-only:kyber1024->aes-256-gcm"

    # HKDF para sacar una key AES uniforme y bien derivada
    aes_key = hkdf_sha256(ikm=ikm, salt=salt_pw, info=info, length=32)

    print("[i] Key processing complete.")

    with open(infile, "rb") as fin, open(enc_file, "wb") as fout:
        # Header:
        # [ct_len(4)] [ct_kyber] [iv(12)] [salt_pw(16)] [tag(16 placeholder)] [ciphertext...]
        fout.write(len(ct_kyber).to_bytes(4, "big"))
        fout.write(ct_kyber)
        fout.write(iv)
        fout.write(salt_pw)

        tag_pos = fout.tell()
        fout.write(b"\x00" * 16)

        tag = aes_gcm_encrypt_stream(aes_key, iv, fin, fout)

        fout.seek(tag_pos)
        fout.write(tag)

    print("[+] Encrypted File:", enc_file)
    print("    BLAKE3 Original :", BLAKE3.hash_file(infile).hex())
    print("    BLAKE3 Encrypted:", BLAKE3.hash_file(enc_file).hex())

# =============================
#  MAIN
# =============================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Use: python encryptor.py "file"')
        sys.exit(1)

    infile = sys.argv[1]

    if not os.path.exists(infile):
        print(f"[!] Error: The file '{infile}' does not exist.")
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")

    passphrase = getpass.getpass("INSERT PASSPHRASE OR PRESS ENTER FOR NONE: ")
    if passphrase == "":
        passphrase = None

    enc_file, pub_file, priv_file = get_output_paths(infile)

    ensure_kyber_keys(pub_file, priv_file)
    encrypt_file(infile, enc_file, pub_file, passphrase)
