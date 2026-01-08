import os
import platform
import ctypes

# --- Detecta la raíz del proyecto ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))  

# --- Detecta el sistema operativo y define la ruta de la librería ---
SYSTEM = platform.system()
MACHINE = platform.machine().lower()  # útil para termux: arm64, x86_64, etc.

if SYSTEM == "Windows":
    LIB_PATH = os.path.join(BASE_DIR, "native", "oqs", "windows", "lib", "oqs.dll")
elif SYSTEM == "Darwin":
    LIB_PATH = os.path.join(BASE_DIR, "native", "oqs", "macos", "lib", "liboqs.dylib")
elif SYSTEM == "Linux":
    if "android" in platform.platform().lower() or "termux" in SYSTEM.lower():
        # Termux
        if "aarch64" in MACHINE or "arm64" in MACHINE:
            LIB_PATH = os.path.join(BASE_DIR, "native", "oqs", "termux", "arm64-v8a", "lib", "liboqs.so")
        elif "x86_64" in MACHINE:
            LIB_PATH = os.path.join(BASE_DIR, "native", "oqs", "termux", "x86_64", "lib", "liboqs.so")
        else:
            raise OSError(f"Termux architecture not supported: {MACHINE}")
    else:
        LIB_PATH = os.path.join(BASE_DIR, "native", "oqs", "linux", "lib", "liboqs.so")
else:
    raise OSError(f"System not supported: {SYSTEM}")

# --- Verifica existencia de la librería ---
if not os.path.exists(LIB_PATH):
    raise OSError(f"The library wasn't found in {LIB_PATH}")

# --- Carga de la librería ---
oqs = ctypes.CDLL(LIB_PATH)

# --- Prototipos para ctypes ---
oqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
oqs.OQS_KEM_new.restype = ctypes.c_void_p

oqs.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
oqs.OQS_KEM_keypair.restype = ctypes.c_int

oqs.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
oqs.OQS_KEM_encaps.restype = ctypes.c_int

oqs.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
oqs.OQS_KEM_decaps.restype = ctypes.c_int

oqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]
oqs.OQS_KEM_free.restype = None

# --- Clase KEM ---
class KEM:
    _ALG_SIZES = {
        "Kyber1024": {
            "pub_len": 1568,
            "priv_len": 3168,
            "ct_len": 1568,
            "key_len": 32
        }
    }

    def __init__(self, alg_name: str):
        self.alg_name = alg_name.encode("utf-8")
        self._kem = oqs.OQS_KEM_new(self.alg_name)
        if not self._kem:
            raise ValueError(f"Algorithm not supported: {alg_name}")

        sizes = self._ALG_SIZES.get(alg_name)
        if not sizes:
            raise ValueError(f"There are no defined sizes for {alg_name}")

        self.pub_len = sizes["pub_len"]
        self.priv_len = sizes["priv_len"]
        self.ct_len = sizes["ct_len"]
        self.key_len = sizes["key_len"]

    def generate_keypair(self):
        pk = ctypes.create_string_buffer(self.pub_len)
        sk = ctypes.create_string_buffer(self.priv_len)
        ret = oqs.OQS_KEM_keypair(self._kem, pk, sk)
        if ret != 0:
            raise RuntimeError("Error generating keypair")
        return pk.raw, sk.raw

    def encapsulate(self, pk_bytes):
        pk = ctypes.create_string_buffer(pk_bytes, len(pk_bytes))
        ct = ctypes.create_string_buffer(self.ct_len)
        key = ctypes.create_string_buffer(self.key_len)
        ret = oqs.OQS_KEM_encaps(self._kem, ct, key, pk)
        if ret != 0:
            raise RuntimeError("Error encapsulating")
        return ct.raw, key.raw

    def decapsulate(self, ct_bytes, sk_bytes):
        ct = ctypes.create_string_buffer(ct_bytes, len(ct_bytes))
        sk = ctypes.create_string_buffer(sk_bytes, len(sk_bytes))
        key = ctypes.create_string_buffer(self.key_len)
        ret = oqs.OQS_KEM_decaps(self._kem, key, ct, sk)
        if ret != 0:
            raise RuntimeError("Error decapsulating")
        return key.raw

    def free(self):
        if self._kem:
            oqs.OQS_KEM_free(self._kem)
            self._kem = None
