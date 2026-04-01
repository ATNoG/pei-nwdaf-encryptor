"""
This should be the exposed interface for users
"""

from core.secure_channel_base import EncryptorBase


class EncryptorServer(EncryptorBase):
    def __init__(self) -> None:
        pass

    def start_server(self) -> None:
        pass


