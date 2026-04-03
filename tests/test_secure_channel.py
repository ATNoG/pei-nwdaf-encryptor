"""Tests for EncryptorServer and EncryptorClient secure channel classes."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from server.app import app as fastapi_app
from core.secure_channel_server import EncryptorServer
from core.secure_channel_client import EncryptorClient
from crypto.encryptor import Encryptor


# =============================================================================
# EncryptorServer Tests
# =============================================================================

class TestEncryptorServer:

    def setup_method(self):
        """Reset app state before each test."""
        fastapi_app.state.shared_key = None
        fastapi_app.state.encryptor = Encryptor()

    def test_shared_key_starts_as_none(self):
        """_shared_key should be None before any handshake."""
        server = EncryptorServer()
        assert server._shared_key is None

    def test_encrypt_raises_when_no_shared_key(self):
        """encrypt() should raise RuntimeError if no handshake has occurred."""
        server = EncryptorServer()
        fastapi_app.state.shared_key = None
        with pytest.raises(RuntimeError, match="No shared key"):
            server.encrypt(b"data")

    def test_decrypt_raises_when_no_shared_key(self):
        """decrypt() should raise RuntimeError if no handshake has occurred."""
        server = EncryptorServer()
        fastapi_app.state.shared_key = None
        with pytest.raises(RuntimeError, match="No shared key"):
            server.decrypt(b"data")

    def test_encrypt_syncs_shared_key_from_app_state(self):
        """encrypt() should sync _shared_key from app state."""
        server = EncryptorServer()
        key = os.urandom(32)
        fastapi_app.state.shared_key = key

        server.encrypt(b"hello")

        assert server._shared_key == key

    def test_decrypt_syncs_shared_key_from_app_state(self):
        """decrypt() should sync _shared_key from app state."""
        server = EncryptorServer()
        key = os.urandom(32)
        fastapi_app.state.shared_key = key

        ciphertext = fastapi_app.state.encryptor.encrypt(b"hello", key)
        server.decrypt(ciphertext)

        assert server._shared_key == key

    def test_shared_key_updated_when_app_state_changes(self):
        """_shared_key should reflect the latest app state on each call."""
        server = EncryptorServer()

        key1 = os.urandom(32)
        fastapi_app.state.shared_key = key1
        server.encrypt(b"first")
        assert server._shared_key == key1

        key2 = os.urandom(32)
        fastapi_app.state.shared_key = key2
        server.encrypt(b"second")
        assert server._shared_key == key2

    def test_encrypt_decrypt_roundtrip(self):
        """encrypt() and decrypt() should roundtrip correctly using app state key."""
        server = EncryptorServer()
        key = os.urandom(32)
        fastapi_app.state.shared_key = key

        plaintext = b"secret message"
        ciphertext = server.encrypt(plaintext)
        decrypted = server.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_no_unused_encryptor_import(self):
        """Encryptor should not be imported in secure_channel_server module."""
        import core.secure_channel_server as module
        assert 'Encryptor' not in dir(module)


# =============================================================================
# EncryptorClient Tests
# =============================================================================

class TestEncryptorClient:

    def test_shared_key_starts_as_none(self):
        """_shared_key should be None before handshake."""
        client = EncryptorClient()
        assert client._shared_key is None

    def test_encrypt_raises_before_handshake(self):
        """encrypt() should raise RuntimeError before handshake."""
        client = EncryptorClient()
        with pytest.raises(RuntimeError, match="Handshake not performed yet"):
            client.encrypt(b"data")

    def test_decrypt_raises_before_handshake(self):
        """decrypt() should raise RuntimeError before handshake."""
        client = EncryptorClient()
        with pytest.raises(RuntimeError, match="Handshake not performed yet"):
            client.decrypt(b"data")

    def test_shared_key_set_after_handshake(self):
        """_shared_key should be set after a successful handshake."""
        from unittest.mock import patch, MagicMock
        client = EncryptorClient()
        mock_key = os.urandom(32)

        with patch.object(client._http_client, 'handshake', return_value=mock_key):
            client.handshake("http://localhost:8000")

        assert client._shared_key == mock_key

    def test_encrypt_uses_shared_key_after_handshake(self):
        """encrypt() should use _shared_key set during handshake."""
        from unittest.mock import patch
        client = EncryptorClient()
        mock_key = os.urandom(32)

        with patch.object(client._http_client, 'handshake', return_value=mock_key):
            client.handshake("http://localhost:8000")

        plaintext = b"hello"
        ciphertext = client.encrypt(plaintext)
        decrypted = client.decrypt(ciphertext)
        assert decrypted == plaintext
