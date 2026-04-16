from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class CipherStrategy(ABC):

    @abstractmethod
    def encrypt(self, data : bytes, key : bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data : bytes, key : bytes) -> bytes:
        pass


class AESGCMStrategy(CipherStrategy):
    """AES-256-GCM encryption strategy with 96-bit nonce."""

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext

