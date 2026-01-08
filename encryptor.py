import os
import sys
import hashlib
import getpass
from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_encrypt_stream, aesni_status
from backend.blake3.blake3_wrapper import BLAKE3
from hashlib import pbkdf2_hmac

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB

# ============================= 
#  RUTAS
# ============================= 
def get_output_paths(infile):
    base_output = os.path.join(os.path.dirname(infile), "pq_encrypted")
    os.makedirs(base_output, exist_ok=True)

    filename = os.path.basename(infile)

    # Carpeta base para evitar sobreescritura
    folder_base = filename.replace(".", "_")
    file_folder = os.path.join(base_output, folder_base)

    # Evitar sobrescritura: sumando un sufijo _1, _2, _3, etc.
    counter = 1
    while os.path.exists(file_folder):
        file_folder = os.path.join(base_output, f"{folder_base}_{counter}")
        counter += 1

    os.makedirs(file_folder, exist_ok=True)

    # Archivos
    enc_file = os.path.join(file_folder, filename + ".enc")
    pub_file = os.path.join(file_folder, "kyber_pub.bin")
    priv_file = os.path.join(file_folder, "kyber_priv.bin")
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
        print(f"[+] Kyber keys generated: {pub_file}, {priv_file}")

# ============================= 
#  DERIVACIÓN DE CLAVE DESDE EL PASSPHRASE
# ============================= 
def derive_key_from_passphrase(passphrase, salt=None, iterations=100000):
    """
    Deriva una clave AES de 32 bytes a partir del passphrase usando PBKDF2-HMAC-SHA256.
    """
    if salt is None:
        salt = os.urandom(16)  # Generar una sal aleatoria si no se pasa una
    derived_key = pbkdf2_hmac('sha256', passphrase.encode(), salt, iterations, dklen=32)
    return derived_key, salt

# ============================= 
#  CIFRADO CON STREAMING CORRECTO
# ============================= 
def encrypt_file(infile, enc_file, pub_file, passphrase=None):
    iv = os.urandom(12)
    pk = open(pub_file, "rb").read()

    kem = KEM("Kyber1024")
    ct_kyber, aes_key = kem.encapsulate(pk)
    kem.free()

    # Generar sal
    salt = os.urandom(16)  # Generar una sal aleatoria

    # Derivar clave si se usa un passphrase
    if passphrase:
        print("[i] Processing passphrase...")
        aes_key, salt = derive_key_from_passphrase(passphrase, salt)
    
    print(f"[i] Key processing complete.")

    with open(infile, "rb") as fin, open(enc_file, "wb") as fout:
        fout.write(len(ct_kyber).to_bytes(4, "big"))
        fout.write(ct_kyber)
        fout.write(iv)
        fout.write(salt)  # Guardar sal en el archivo cifrado

        # Reservar espacio para el tag
        tag_pos = fout.tell()
        fout.write(b"\x00" * 16)

        tag = aes_gcm_encrypt_stream(aes_key, iv, fin, fout)

        # Escribir tag real
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

    # Verificar si el archivo existe antes de pedir el passphrase
    if not os.path.exists(infile):
        print(f"[!] Error: The file '{infile}' does not exist.")
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")

    # Pedir el passphrase si no se pasa como argumento
    passphrase = getpass.getpass("INSERT PASSPHRASE OR PRESS ENTER FOR NONE: ")

    enc_file, pub_file, priv_file = get_output_paths(infile)

    ensure_kyber_keys(pub_file, priv_file)
    encrypt_file(infile, enc_file, pub_file, passphrase)
