import sys
import os
from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_decrypt_stream, aesni_status
from backend.blake3.blake3_wrapper import BLAKE3

CHUNK_SIZE = 2 * 1024 * 1024

def get_priv_file(enc_file, priv_arg=None):
    if priv_arg:
        return priv_arg
    return os.path.join(os.path.dirname(enc_file), "kyber_priv.bin")

def decrypt_file(enc_file, priv_file):
    if not os.path.exists(priv_file):
        print("[!] Private key not found:", priv_file)
        return

    with open(enc_file, "rb") as f:
        ct_len = int.from_bytes(f.read(4), "big")
        ct_kyber = f.read(ct_len)
        iv = f.read(12)
        tag = f.read(16)

        ciphertext_offset = f.tell()

        sk = open(priv_file, "rb").read()
        kem = KEM("Kyber1024")
        aes_key = kem.decapsulate(ct_kyber, sk)
        kem.free()

        outfile = enc_file.replace(".enc", ".dec")
        with open(outfile, "wb") as fout:
            f.seek(ciphertext_offset)
            aes_gcm_decrypt_stream(aes_key, iv, tag, f, fout, CHUNK_SIZE)

    print("[+] Decrypted File:", outfile)
    print("    BLAKE3 Decrypted:", BLAKE3.hash_file(outfile).hex())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Use: python decryptor.py "file.enc" [kyber_priv.bin]')
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")

    enc_file = sys.argv[1]
    priv_arg = sys.argv[2] if len(sys.argv) > 2 else None
    decrypt_file(enc_file, get_priv_file(enc_file, priv_arg))

