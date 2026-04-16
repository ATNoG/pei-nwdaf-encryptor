"""
This should be responsible for wrapping the key-exchange requests
"""

import httpx
from encryptor.crypto.encryptor import Encryptor


class HttpClient:

    def __init__(self, encryptor: Encryptor) -> None:
        self._encryptor = encryptor

    def handshake(self, url: str) -> tuple[bytes, str]:
        """Returns (shared_key, session_token)."""
        pub_pem: bytes = self._encryptor.get_public_key()
        salt: bytes = self._encryptor.get_salt()

        payload = {
            "public_key": pub_pem.decode(),
            "salt": salt.hex(),
        }

        with httpx.Client() as client:
            response = client.post(f"{url}/crypto/handshake", json=payload)
            response.raise_for_status()
            data = response.json()
        server_pub_pem: bytes = data["public_key"].encode()
        echoed_salt: bytes = bytes.fromhex(data["salt"])
        session_token: str = data["session_token"]

        shared_key = self._encryptor.derive_shared_key(server_pub_pem, echoed_salt)
        return shared_key, session_token
