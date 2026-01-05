import sys, os, hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import kybercffi

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.digest()

def ensure_kyber_keys(pub_file, priv_file):
    if not os.path.exists(pub_file) or not os.path.exists(priv_file):
        ky = kybercffi.Kyber1024()
        pk, sk = ky.generate_keypair()
        with open(pub_file, "wb") as f: f.write(pk)
        with open(priv_file, "wb") as f: f.write(sk)
        print(f"[+] Kyber keys generadas: {pub_file}, {priv_file}")

def encrypt_file(infile, pub_file):
    original_hash = sha256_file(infile)
    data = open(infile, "rb").read()

    ky = kybercffi.Kyber1024()
    pk = open(pub_file, "rb").read()

    # Encapsular: genera ciphertext Kyber + llave AES de 32 bytes
    ct_kyber, aes_key = ky.encapsulate(pk)

    # AES-256-GCM con nonce único
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    out_file = infile + ".enc"
    with open(out_file, "wb") as f:
        f.write(len(ct_kyber).to_bytes(4, "big"))
        f.write(ct_kyber)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    print("[+] Archivo cifrado:", out_file)
    print("    SHA256 original:", original_hash.hex())
    print("    SHA256 cifrado:", sha256_file(out_file).hex())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Uso: python encryptor.py "archivo a cifrar" [llave_publica]')
        sys.exit(1)

    infile = sys.argv[1]
    pub_file = sys.argv[2] if len(sys.argv) >= 3 else "kyber_pub.bin"
    priv_file = pub_file.replace("pub", "priv")

    ensure_kyber_keys(pub_file, priv_file)
    encrypt_file(infile, pub_file)
