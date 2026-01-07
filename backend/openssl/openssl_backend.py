import os
import platform
import ctypes

# --- Detecta la raíz del proyecto ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SYSTEM = platform.system()
MACHINE = platform.machine().lower()

# --- Ruta libcrypto ---
if SYSTEM == "Windows":
    LIB_PATH = os.path.join(BASE_DIR, "native", "openssl", "windows", "lib", "libcrypto.dll")
elif SYSTEM == "Darwin":
    LIB_PATH = os.path.join(BASE_DIR, "native", "openssl", "macos", "lib", "libcrypto.dylib")
elif SYSTEM == "Linux":
    if "android" in platform.platform().lower() or "termux" in platform.platform().lower():
        if "aarch64" in MACHINE or "arm64" in MACHINE:
            LIB_PATH = os.path.join(BASE_DIR, "native", "openssl", "termux", "arm64-v8a", "lib", "libcrypto.so")
        elif "x86_64" in MACHINE:
            LIB_PATH = os.path.join(BASE_DIR, "native", "openssl", "termux", "x86_64", "lib", "libcrypto.so")
        else:
            raise OSError(f"Arquitectura no soportada: {MACHINE}")
    else:
        LIB_PATH = os.path.join(BASE_DIR, "native", "openssl", "linux", "lib", "libcrypto.so")
else:
    raise OSError(f"Sistema no soportado: {SYSTEM}")

if not os.path.exists(LIB_PATH):
    raise OSError(f"No se encontró libcrypto en {LIB_PATH}")

# =============================
#  CARGA REAL DE OPENSSL
# =============================

libcrypto = ctypes.CDLL(LIB_PATH)

# =============================
#  CONSTANTES
# =============================

EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG   = 0x10
EVP_CTRL_GCM_SET_TAG   = 0x11

# =============================
#  PROTOTIPOS
# =============================

EVP_CIPHER_CTX_new = libcrypto.EVP_CIPHER_CTX_new
EVP_CIPHER_CTX_new.restype = ctypes.c_void_p

EVP_CIPHER_CTX_free = libcrypto.EVP_CIPHER_CTX_free
EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

EVP_aes_256_gcm = libcrypto.EVP_aes_256_gcm
EVP_aes_256_gcm.restype = ctypes.c_void_p

EVP_EncryptInit_ex = libcrypto.EVP_EncryptInit_ex
EVP_EncryptInit_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p
]

EVP_EncryptUpdate = libcrypto.EVP_EncryptUpdate
EVP_EncryptUpdate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_void_p,
    ctypes.c_int
]

EVP_EncryptFinal_ex = libcrypto.EVP_EncryptFinal_ex
EVP_EncryptFinal_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_int)
]

EVP_CIPHER_CTX_ctrl = libcrypto.EVP_CIPHER_CTX_ctrl
EVP_CIPHER_CTX_ctrl.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_void_p
]

EVP_DecryptInit_ex = libcrypto.EVP_DecryptInit_ex
EVP_DecryptInit_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p
]
EVP_DecryptInit_ex.restype = ctypes.c_int

EVP_DecryptUpdate = libcrypto.EVP_DecryptUpdate
EVP_DecryptUpdate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_void_p,
    ctypes.c_int
]
EVP_DecryptUpdate.restype = ctypes.c_int

EVP_DecryptFinal_ex = libcrypto.EVP_DecryptFinal_ex
EVP_DecryptFinal_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_int)
]
EVP_DecryptFinal_ex.restype = ctypes.c_int

# =============================
#  AES-GCM ENCRYPT
# =============================

def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    ctx = EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")

    outbuf = ctypes.create_string_buffer(len(plaintext) + 16)
    outlen = ctypes.c_int()
    tmplen = ctypes.c_int()

    try:
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), None, None, None)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
        EVP_EncryptInit_ex(ctx, None, None, key, iv)

        EVP_EncryptUpdate(
            ctx,
            outbuf,
            ctypes.byref(outlen),
            plaintext,
            len(plaintext)
        )

        EVP_EncryptFinal_ex(
            ctx,
            ctypes.byref(outbuf, outlen.value),
            ctypes.byref(tmplen)
        )

        tag = ctypes.create_string_buffer(16)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)

        return outbuf.raw[:outlen.value], tag.raw

    finally:
        EVP_CIPHER_CTX_free(ctx)

# =============================
#  AES-GCM DECRYPT
# =============================

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes):
    ctx = EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")

    outbuf = ctypes.create_string_buffer(len(ciphertext))
    outlen = ctypes.c_int()
    tmplen = ctypes.c_int()

    try:
        # Init
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), None, None, None)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
        EVP_DecryptInit_ex(ctx, None, None, key, iv)

        # Decrypt
        EVP_DecryptUpdate(
            ctx,
            outbuf,
            ctypes.byref(outlen),
            ciphertext,
            len(ciphertext)
        )

        # Set tag BEFORE final
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, len(tag), tag)

        # Final (verifica tag aquí)
        if EVP_DecryptFinal_ex(
            ctx,
            ctypes.byref(outbuf, outlen.value),
            ctypes.byref(tmplen)
        ) != 1:
            raise RuntimeError("GCM tag verification failed")

        return outbuf.raw[:outlen.value]

    finally:
        EVP_CIPHER_CTX_free(ctx)


# =============================
#  AES-NI STATUS
# =============================

def aesni_status():
    try:
        import cpuinfo
        flags = cpuinfo.get_cpu_info().get("flags", [])
        return "Enabled" if "aes" in flags else "Disabled"
    except Exception:
        return "Unknown"
