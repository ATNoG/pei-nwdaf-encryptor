import os
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from .CipherStrategy import CipherStrategy, AESGCMStrategy

"""
This should be responsible for the encryption of the data (maybe apply stratergy pattern to support multiples types of encryption)
"""

_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
_G = 2
_RFC3526_PARAMETERS: dh.DHParameters = dh.DHParameterNumbers(_P, _G).parameters()

class Encryptor:

    def __init__(self, strategy : Optional[CipherStrategy] = None) -> None:
        self.parameters : dh.DHParameters = _RFC3526_PARAMETERS
        self._private_key : dh.DHPrivateKey
        self.generate_private_key()

        self._strategy : CipherStrategy = strategy if strategy else AESGCMStrategy()
        self.salt : bytes 
        self.generate_salt()

    def generate_private_key(self) -> None:
        self._private_key = self.parameters.generate_private_key()
    
    def generate_salt(self) -> None:
        self.salt = os.urandom(16)

    def get_public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding = Encoding.PEM,
            format = PublicFormat.SubjectPublicKeyInfo
        )

    def get_salt(self) -> bytes:
        return self.salt

    def derive_shared_key(self,peer_public_key_pem : bytes, peer_salt : bytes) -> bytes:
        peer_public_key = load_pem_public_key(peer_public_key_pem)
        shared_key = self._private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=peer_salt,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key

    def encrypt(self, data_decrypted : bytes, key : bytes) -> bytes:
        return self._strategy.encrypt(data_decrypted, key)

    def decrypt(self, data_encrypted : bytes, key : bytes) -> bytes:
        return self._strategy.decrypt(data_encrypted, key)

