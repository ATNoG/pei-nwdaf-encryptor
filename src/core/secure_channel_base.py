class EncryptorBase:
    
    def __init__(self) -> None:
        pass

    def encrypt(self, data, key) -> bytes:
        pass

    def decrypt(self, encrypted_data, key) -> bytes:
        pass
