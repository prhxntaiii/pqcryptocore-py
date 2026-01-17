import os
import sys
import getpass
import hmac
import hashlib
from hashlib import pbkdf2_hmac

from backend.oqs.oqs_backend import KEM
from backend.openssl.openssl_backend import aes_gcm_decrypt_stream, aesni_status
from backend.blake3.blake3_wrapper import BLAKE3

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB

# =============================
#  KEYSTORE (priv key NO al lado del ciphertext)
# =============================
KEYSTORE_DIR = os.environ.get("PQ_KEYSTORE_DIR", os.path.expanduser("~/.pq_keystore"))

# =============================
#  HKDF-SHA256 (RFC 5869)
# =============================
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
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
#  DERIVACIÓN DESDE PASSPHRASE
# =============================
def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    return pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=32)

# =============================
#  RUTA DE PRIVADA
# =============================
def get_priv_file(enc_file: str, priv_arg: str | None = None) -> str:
    # Si el usuario la pasa por argumento, usar esa (prioridad máxima)
    if priv_arg:
        return priv_arg

    # enc_file está en: .../pq_encrypted/<CARPETA>/archivo.xxx.enc
    enc_dir = os.path.dirname(enc_file)      # .../pq_encrypted/<CARPETA>
    folder = os.path.basename(enc_dir)       # <CARPETA>

    # Private key en: KEYSTORE_DIR/<CARPETA>/kyber_priv.bin
    return os.path.join(KEYSTORE_DIR, folder, "kyber_priv.bin")

def get_decrypted_output_path(enc_file: str) -> str:
    base_name = os.path.basename(enc_file)
    if base_name.endswith(".enc"):
        base_name = base_name[:-4]
    return os.path.join(os.path.dirname(enc_file), base_name + ".dec")

# =============================
#  DESCIFRADO (híbrido real)
# =============================
def decrypt_file(enc_file: str, priv_file: str, passphrase: str | None = None) -> None:
    if not os.path.exists(enc_file):
        print("[!] Encrypted file not found:", enc_file, flush=True)
        sys.exit(1)

    if not os.path.exists(priv_file):
        print("[!] Private key not found:", priv_file, flush=True)
        sys.exit(1)

    try:
        with open(enc_file, "rb") as f:
            # Header esperado:
            # [ct_len(4)] [ct_kyber] [iv(12)] [salt_pw(16)] [tag(16)] [ciphertext...]

            raw = f.read(4)
            if len(raw) != 4:
                raise ValueError("Invalid file: can't read ct_len")

            ct_len = int.from_bytes(raw, "big")
            if ct_len <= 0 or ct_len > 1_000_000:
                raise ValueError(f"Invalid ct_len: {ct_len}")

            ct_kyber = f.read(ct_len)
            if len(ct_kyber) != ct_len:
                raise ValueError("Invalid file: truncated ct_kyber")

            iv = f.read(12)
            if len(iv) != 12:
                raise ValueError("Invalid file: truncated iv")

            salt_pw = f.read(16)
            if len(salt_pw) != 16:
                raise ValueError("Invalid file: truncated salt_pw")

            tag = f.read(16)
            if len(tag) != 16:
                raise ValueError("Invalid file: truncated tag")

            ciphertext_offset = f.tell()

            print("[i] Header OK", flush=True)

            # --- Kyber decapsulation ---
            sk = open(priv_file, "rb").read()
            kem = KEM("Kyber1024")
            kyber_ss = kem.decapsulate(ct_kyber, sk)
            kem.free()

            # --- Derivación de clave final ---
            if passphrase is not None:
                print("[i] Processing passphrase (hybrid mode)...", flush=True)
                pw_key = derive_key_from_passphrase(passphrase, salt_pw)
                ikm = kyber_ss + pw_key
                info = b"pq-hybrid:kyber1024+pbkdf2-sha256->aes-256-gcm"
            else:
                print("[i] No passphrase (PQC-only mode)...", flush=True)
                ikm = kyber_ss
                info = b"pq-only:kyber1024->aes-256-gcm"

            aes_key = hkdf_sha256(
                ikm=ikm,
                salt=salt_pw,
                info=info,
                length=32
            )

            outfile = get_decrypted_output_path(enc_file)

            # --- DESCIFRADO STREAM ---
            try:
                print("[i] Starting AES-GCM stream decrypt...", flush=True)

                with open(outfile, "wb") as fout:
                    f.seek(ciphertext_offset)
                    aes_gcm_decrypt_stream(
                        aes_key,
                        iv,
                        tag,
                        f,
                        fout,
                        CHUNK_SIZE
                    )

                print("[i] Finished AES-GCM stream decrypt.", flush=True)
                print("[+] Decrypted File:", outfile, flush=True)

                abs_outfile = os.path.abspath(outfile)

                # --- BLAKE3 (opcional, no mata el éxito) ---
                try:
                    if not os.path.exists(abs_outfile):
                        raise FileNotFoundError(abs_outfile)

                    print(
                        "    BLAKE3 Decrypted:",
                        BLAKE3.hash_file(abs_outfile).hex(),
                        flush=True
                    )

                except Exception as e:
                    print(
                        "[!] Decrypted OK but BLAKE3 failed:",
                        str(e),
                        flush=True
                    )

            except Exception as e:
                if os.path.exists(outfile):
                    os.remove(outfile)

                print("[!] Error during decryption:", str(e), flush=True)
                print(
                    "[!] Verify: correct privkey, correct passphrase, and file integrity.",
                    flush=True
                )
                sys.exit(1)

    except Exception as e:
        print("[!] Error reading encrypted file or during decryption:", str(e), flush=True)
        sys.exit(1)

# =============================
#  MAIN
# =============================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Use: python decryptor.py "file.enc" [kyber_priv.bin]', flush=True)
        sys.exit(1)

    print(f"[i] AES-NI: {aesni_status()}", flush=True)

    enc_file = sys.argv[1]
    priv_arg = sys.argv[2] if len(sys.argv) > 2 else None

    # IMPORTANT: sin strip() (espacios cuentan)
    passphrase = getpass.getpass("INSERT PASSPHRASE OR PRESS ENTER FOR NONE: ")
    if passphrase == "":
        passphrase = None

    decrypt_file(enc_file, get_priv_file(enc_file, priv_arg), passphrase)
