import sys
import os
from Crypto.Cipher import AES
from backend.oqs_backend import KEM

# --- Obtiene las rutas de claves ---
def get_priv_file(enc_file, priv_file_arg=None):
    if priv_file_arg:
        return priv_file_arg  # si el usuario pasa ruta, la usamos
    base_dir = os.path.dirname(enc_file)
    priv_file = os.path.join(base_dir, "kyber_priv.bin")
    return priv_file

# --- Descifra archivo ---
def decrypt_file(enc_file, priv_file):
    if not os.path.exists(priv_file):
        print("[!] Private key not found:", priv_file)
        return

    try:
        with open(enc_file, "rb") as f:
            ct_len = int.from_bytes(f.read(4), "big")
            ct_kyber = f.read(ct_len)
            nonce = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        sk = open(priv_file, "rb").read()

        kem = KEM("Kyber1024")
        aes_key = kem.decapsulate(ct_kyber, sk)
        kem.free()

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        outfile = enc_file.replace(".enc", ".dec")
        with open(outfile, "wb") as f:
            f.write(data)

        print("[+] Decrypted File:", outfile)
    except ValueError as e:
        print("[!] Error during decryption or authentication failed:", e)
    except Exception as e:
        print("[!] Unexpected error:", e)

# --- Main ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Use: python decryptor.py "archivo_cifrado" [ruta_privada_opcional]')
        sys.exit(1)

    enc_file = sys.argv[1]
    priv_file_arg = sys.argv[2] if len(sys.argv) > 2 else None

    priv_file = get_priv_file(enc_file, priv_file_arg)
    decrypt_file(enc_file, priv_file)
