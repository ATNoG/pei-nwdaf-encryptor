from typing import Optional


class EncryptorBase:

    def __init__(self) -> None:
        self._shared_key: Optional[bytes] = None

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, encrypted_data: bytes) -> bytes:
        raise NotImplementedError
