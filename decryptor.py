import sys, os, hashlib
from Crypto.Cipher import AES
import kybercffi

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.digest()

def decrypt_file(encfile, priv_file):
    sk = open(priv_file, "rb").read()

    with open(encfile, "rb") as f:
        ky_len = int.from_bytes(f.read(4),"big")
        ct_kyber = f.read(ky_len)
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    ky = kybercffi.Kyber1024()
    aes_key = ky.decapsulate(ct_kyber, sk)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # Recuperar nombre original
    if encfile.endswith(".enc"):
        out_file = encfile[:-4]  # quita .enc
    else:
        out_file = encfile + ".dec"

    with open(out_file, "wb") as f:
        f.write(data)

    print("[+] Archivo descifrado:", out_file)
    print("    SHA256 descifrado:", sha256_file(out_file).hex())

if __name__=="__main__":
    if len(sys.argv) < 2:
        print('Uso: python decryptor.py "archivo.enc" [llave_privada]')
        sys.exit(1)

    encfile = sys.argv[1]
    priv_file = sys.argv[2] if len(sys.argv) >= 3 else "kyber_priv.bin"

    if not os.path.exists(priv_file):
        print("Clave privada no existe:", priv_file)
        sys.exit(1)

    decrypt_file(encfile, priv_file)