"""
This should be the exposed interface for users
"""

from core.secure_channel_base import EncryptorBase
from server.app import app as fastapi_app


class EncryptorServer(EncryptorBase):

    def __init__(self) -> None:
        super().__init__()

    def start_server(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        import uvicorn
        uvicorn.run(fastapi_app, host=host, port=port)

    def encrypt(self, data: bytes) -> bytes:
        self._shared_key = getattr(fastapi_app.state, 'shared_key', None)
        if self._shared_key is None:
            raise RuntimeError("No shared key — handshake not completed")
        return fastapi_app.state.encryptor.encrypt(data, self._shared_key)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        self._shared_key = getattr(fastapi_app.state, 'shared_key', None)
        if self._shared_key is None:
            raise RuntimeError("No shared key — handshake not completed")
        return fastapi_app.state.encryptor.decrypt(encrypted_data, self._shared_key)
