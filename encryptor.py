# encryptor.py
import os
import sys
from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_encrypt_stream, aesni_status
from backend.blake3.blake3_wrapper import BLAKE3

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB

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
#  KYBER KEYS
# =============================
def ensure_kyber_keys(pub_file, priv_file):
    if not os.path.exists(pub_file) or not os.path.exists(priv_file):
        kem = KEM("Kyber1024")
        pk, sk = kem.generate_keypair()
        kem.free()
        with open(pub_file, "wb") as f: f.write(pk)
        with open(priv_file, "wb") as f: f.write(sk)
        print(f"[+] Claves Kyber generadas: {pub_file}, {priv_file}")

# =============================
#  CIFRADO CON STREAMING CORRECTO
# =============================
def encrypt_file(infile, enc_file, pub_file):
    iv = os.urandom(12)
    pk = open(pub_file, "rb").read()

    kem = KEM("Kyber1024")
    ct_kyber, aes_key = kem.encapsulate(pk)
    kem.free()

    with open(infile, "rb") as fin, open(enc_file, "wb") as fout:
        fout.write(len(ct_kyber).to_bytes(4, "big"))
        fout.write(ct_kyber)
        fout.write(iv)

        # reservamos espacio para el tag
        tag_pos = fout.tell()
        fout.write(b"\x00" * 16)

        tag = aes_gcm_encrypt_stream(aes_key, iv, fin, fout)

        # escribir tag real
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
        print('Uso: python encryptor.py "archivo"')
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")

    infile = sys.argv[1]
    enc_file, pub_file, priv_file = get_output_paths(infile)

    ensure_kyber_keys(pub_file, priv_file)
    encrypt_file(infile, enc_file, pub_file)
