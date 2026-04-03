import sys
sys.path.insert(0, 'src')

from core.secure_channel_client import EncryptorClient

client = EncryptorClient()
client.handshake('http://localhost:8000')

ciphertext = client.encrypt(b'hello from client')
print('encrypted:', ciphertext.hex())
print('decrypted:', client.decrypt(ciphertext))
