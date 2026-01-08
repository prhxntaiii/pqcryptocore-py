import os
import sys
import getpass
from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_decrypt_stream, aesni_status
from backend.blake3.blake3_wrapper import BLAKE3
from hashlib import pbkdf2_hmac

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB

# ============================= 
#  DERIVACIÓN DE CLAVE DESDE EL PASSPHRASE
# ============================= 
def derive_key_from_passphrase(passphrase, salt, iterations=100000):
    """
    Deriva una clave AES de 32 bytes a partir del passphrase usando PBKDF2-HMAC-SHA256.
    """
    derived_key = pbkdf2_hmac('sha256', passphrase.encode(), salt, iterations, dklen=32)
    return derived_key

# ============================= 
#  RUTAS DE PRIVADA Y SALIDA
# ============================= 
def get_priv_file(enc_file, priv_arg=None):
    if priv_arg:
        return priv_arg
    
    # Obtener la subcarpeta donde se guardan las claves
    file_folder = os.path.dirname(enc_file)
    
    # El archivo de clave privada está en la misma subcarpeta
    return os.path.join(file_folder, "kyber_priv.bin")




def get_decrypted_output_path(enc_file):
    """
    Devuelve la ruta de salida para el archivo decifrado.
    No crea el archivo todavía; se hará solo si la decripción es exitosa.
    """
    base_name = os.path.basename(enc_file).replace(".enc", ".dec")
    return os.path.join(os.path.dirname(enc_file), base_name)


# ============================= 
#  DESCIFRADO CON STREAMING
# ============================= 
# Leer la sal del archivo cifrado y derivar la clave
def decrypt_file(enc_file, priv_file, passphrase=None):
    if not os.path.exists(enc_file):
        print("[!] Encrypted file not found:", enc_file)
        return

    if not os.path.exists(priv_file):
        print("[!] Private key not found:", priv_file)
        return

    # Intentamos derivar la clave desde el passphrase si se pasa
    try:
        with open(enc_file, "rb") as f:
            ct_len = int.from_bytes(f.read(4), "big")
            ct_kyber = f.read(ct_len)
            iv = f.read(12)
            salt = f.read(16)  # Leer la sal guardada

            tag = f.read(16)

            ciphertext_offset = f.tell()

            sk = open(priv_file, "rb").read()
            kem = KEM("Kyber1024")
            aes_key = kem.decapsulate(ct_kyber, sk)
            kem.free()

            # Si el passphrase no es None, derivamos la clave adicional a partir del passphrase y la sal
            if passphrase:
                print("[i] Deriving key from passphrase...")
                aes_key = derive_key_from_passphrase(passphrase, salt)
                print(f"[i] Key derivation complete.")

            outfile = get_decrypted_output_path(enc_file)

            # Intentamos descifrar
            try:
                with open(outfile, "wb") as fout:
                    f.seek(ciphertext_offset)
                    aes_gcm_decrypt_stream(aes_key, iv, tag, f, fout, CHUNK_SIZE)
                print("[+] Decrypted File:", outfile)
                print("    BLAKE3 Decrypted:", BLAKE3.hash_file(outfile).hex())
            except Exception as e:
                if os.path.exists(outfile):
                    os.remove(outfile)  # Eliminar archivo .dec si no se pudo descifrar
                print("[!] Error during decryption:", str(e))
                print("[!] Please verify the file and passphrase.")
                sys.exit(1)
    except Exception as e:
        print("[!] Error reading encrypted file or during decryption:", str(e))
        sys.exit(1)


# ============================= 
#  MAIN
# ============================= 
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Use: python decryptor.py "file.enc" [kyber_priv.bin]')
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}")

    enc_file = sys.argv[1]
    priv_arg = sys.argv[2] if len(sys.argv) > 2 else None

    # Pedir el passphrase si no se pasa como argumento
    passphrase = getpass.getpass("INSERT PASSPHRASE OR PRESS ENTER FOR NONE: ")

    decrypt_file(enc_file, get_priv_file(enc_file, priv_arg), passphrase)
