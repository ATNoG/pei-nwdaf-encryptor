"""Tests for the HTTP transport layer."""
import pytest
from unittest.mock import MagicMock, patch
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import httpx
from crypto.encryptor import Encryptor
from transport.http_client import HttpClient


@pytest.fixture
def encryptor():
    return Encryptor()


@pytest.fixture
def http_client(encryptor):
    return HttpClient(encryptor)


def make_mock_response(server_encryptor: Encryptor, client_salt_hex: str, status_code: int = 200):
    """Build a mock httpx response that mimics the server."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = {
        "public_key": server_encryptor.get_public_key().decode(),
        "salt": client_salt_hex,
    }
    mock_response.raise_for_status = MagicMock()
    return mock_response


# =============================================================================
# HttpClient Tests
# =============================================================================

class TestHttpClient:
    """Tests for HttpClient handshake."""

    def test_handshake_returns_bytes(self, encryptor):
        """handshake() should return bytes."""
        server_enc = Encryptor()
        client_salt_hex = encryptor.get_salt().hex()
        mock_response = make_mock_response(server_enc, client_salt_hex)

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
            result = HttpClient(encryptor).handshake("http://localhost:8000")

        assert isinstance(result, bytes)

    def test_handshake_returns_32_byte_key(self, encryptor):
        """Derived shared key should be 32 bytes (AES-256)."""
        server_enc = Encryptor()
        mock_response = make_mock_response(server_enc, encryptor.get_salt().hex())

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
            result = HttpClient(encryptor).handshake("http://localhost:8000")

        assert len(result) == 32

    def test_handshake_posts_to_correct_url(self, encryptor):
        """handshake() should POST to {url}/crypto/handshake."""
        server_enc = Encryptor()
        mock_response = make_mock_response(server_enc, encryptor.get_salt().hex())

        with patch("httpx.Client") as mock_client_cls:
            mock_post = mock_client_cls.return_value.__enter__.return_value.post
            mock_post.return_value = mock_response
            HttpClient(encryptor).handshake("http://localhost:8000")

        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert call_url == "http://localhost:8000/crypto/handshake"

    def test_handshake_sends_public_key_and_salt(self, encryptor):
        """handshake() should send public_key and salt in the request body."""
        server_enc = Encryptor()
        mock_response = make_mock_response(server_enc, encryptor.get_salt().hex())

        with patch("httpx.Client") as mock_client_cls:
            mock_post = mock_client_cls.return_value.__enter__.return_value.post
            mock_post.return_value = mock_response
            HttpClient(encryptor).handshake("http://localhost:8000")

        payload = mock_post.call_args[1]["json"]
        assert "public_key" in payload
        assert "salt" in payload
        assert payload["public_key"] == encryptor.get_public_key().decode()
        assert payload["salt"] == encryptor.get_salt().hex()

    def test_handshake_derives_same_key_as_server(self, encryptor):
        """Client and server should derive the same shared key."""
        server_enc = Encryptor()
        client_salt_hex = encryptor.get_salt().hex()
        mock_response = make_mock_response(server_enc, client_salt_hex)

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
            client_key = HttpClient(encryptor).handshake("http://localhost:8000")

        # Server derives key using client's public key and client's salt
        server_key = server_enc.derive_shared_key(
            encryptor.get_public_key(),
            bytes.fromhex(client_salt_hex),
        )

        assert client_key == server_key

    def test_handshake_calls_raise_for_status(self, encryptor):
        """handshake() should call raise_for_status on the response."""
        server_enc = Encryptor()
        mock_response = make_mock_response(server_enc, encryptor.get_salt().hex())

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
            HttpClient(encryptor).handshake("http://localhost:8000")

        mock_response.raise_for_status.assert_called_once()

    def test_handshake_raises_on_http_error(self, encryptor):
        """handshake() should propagate HTTP errors."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock()
        )

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
            with pytest.raises(httpx.HTTPStatusError):
                HttpClient(encryptor).handshake("http://localhost:8000")

    def test_handshake_raises_on_connection_error(self, encryptor):
        """handshake() should propagate connection errors."""
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
                httpx.ConnectError("Connection refused")
            )
            with pytest.raises(httpx.ConnectError):
                HttpClient(encryptor).handshake("http://localhost:8000")

    def test_handshake_uses_echoed_salt_for_derivation(self, encryptor):
        """handshake() should use the salt echoed in the response, not a hardcoded one."""
        server_enc = Encryptor()
        # Server echoes a different salt than what the client sent
        different_salt_hex = os.urandom(16).hex()
        mock_response = make_mock_response(server_enc, different_salt_hex)

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
            client_key = HttpClient(encryptor).handshake("http://localhost:8000")

        # Key should be derived using the echoed salt
        expected_key = encryptor.derive_shared_key(
            server_enc.get_public_key(),
            bytes.fromhex(different_salt_hex),
        )
        assert client_key == expected_key

    def test_two_clients_with_same_server_get_different_keys(self):
        """Two independent clients handshaking with the same server get different keys."""
        server_enc = Encryptor()
        client_a = Encryptor()
        client_b = Encryptor()

        def do_handshake(client_enc):
            salt_hex = client_enc.get_salt().hex()
            mock_response = make_mock_response(server_enc, salt_hex)
            with patch("httpx.Client") as mock_client_cls:
                mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_response
                return HttpClient(client_enc).handshake("http://localhost:8000")

        key_a = do_handshake(client_a)
        key_b = do_handshake(client_b)

        assert key_a != key_b
