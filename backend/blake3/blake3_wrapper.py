import blake3

class BLAKE3:
    HASH_LEN = 32

    def __init__(self):
        self._hasher = blake3.blake3()

    def update(self, data: bytes):
        self._hasher.update(data)

    def finalize(self) -> bytes:
        return self._hasher.digest()

    @classmethod
    def hash_file(cls, filepath: str) -> bytes:
        h = cls()
        CHUNK = 4 * 1024 * 1024  # 4MB por chunk
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
        return h.finalize()

    @staticmethod
    def to_hex(digest: bytes) -> str:
        return digest.hex()
