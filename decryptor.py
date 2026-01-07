import sys
import os

from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_decrypt, aesni_status


# =============================
#  RUTA CLAVE PRIVADA
# =============================

def get_priv_file(enc_file, priv_file_arg=None):
    if priv_file_arg:
        return priv_file_arg
    base_dir = os.path.dirname(enc_file)
    return os.path.join(base_dir, "kyber_priv.bin")


# =============================
#  DESCIFRADO
# =============================

def decrypt_file(enc_file, priv_file):
    if not os.path.exists(priv_file):
        print("[!] Private key not found:", priv_file)
        return

    try:
        with open(enc_file, "rb") as f:
            ct_len = int.from_bytes(f.read(4), "big")
            ct_kyber = f.read(ct_len)
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        sk = open(priv_file, "rb").read()

        kem = KEM("Kyber1024")
        aes_key = kem.decapsulate(ct_kyber, sk)
        kem.free()

        plaintext = aes_gcm_decrypt(
            key=aes_key,
            iv=iv,
            ciphertext=ciphertext,
            tag=tag
        )

        outfile = enc_file.replace(".enc", ".dec")
        with open(outfile, "wb") as f:
            f.write(plaintext)

        print("[+] Decrypted File:", outfile)

    except RuntimeError as e:
        print("[!] Authentication failed or corrupted file:", e)
    except Exception as e:
        print("[!] Unexpected error:", e)


# =============================
#  MAIN
# =============================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Uso: python decryptor.py "archivo.enc" [kyber_priv.bin]')
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")

    enc_file = sys.argv[1]
    priv_file_arg = sys.argv[2] if len(sys.argv) > 2 else None

    priv_file = get_priv_file(enc_file, priv_file_arg)
    decrypt_file(enc_file, priv_file)
