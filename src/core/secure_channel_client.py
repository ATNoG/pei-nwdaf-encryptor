from core.secure_channel_base import EncryptorBase
from crypto.encryptor import Encryptor
from transport.http_client import HttpClient


class EncryptorClient(EncryptorBase):

    def __init__(self) -> None:
        super().__init__()
        self._encryptor = Encryptor()
        self._http_client = HttpClient(self._encryptor)

    def handshake(self, url: str) -> None:
        self._shared_key = self._http_client.handshake(url)

    def encrypt(self, data: bytes) -> bytes:
        if self._shared_key is None:
            raise RuntimeError("Handshake not performed yet")
        return self._encryptor.encrypt(data, self._shared_key)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        if self._shared_key is None:
            raise RuntimeError("Handshake not performed yet")
        return self._encryptor.decrypt(encrypted_data, self._shared_key)
