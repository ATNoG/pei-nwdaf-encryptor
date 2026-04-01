from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

"""
This should be responsible for the encryption of the data (maybe apply stratergy pattern to support multiples types of encryption)
"""

class Encryptor:

    def __init__(self) -> None:
        self.parameters : dh.DHParameters = dh.generate_parameters(generator=2, key_size=2048)
        self._private_key : dh.DHPrivateKey
    
    def generatePrivateKey(self) -> None:
        self._private_key = self.parameters.generate_private_key()
    
    def get_public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding = Encoding.PEM,
            format = PublicFormat.SubjectPublicKeyInfo
        )

    def deriveSharedKey(self,peer_public_key : dh.DHPublicKey) -> bytes:
        shared_key = self._private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key

    def encrypt(self, data_decrypted : bytes, key : bytes) -> bytes:
        pass

    def decrypt(self, data_encrypted : bytes, key : bytes) -> bytes:
        pass
