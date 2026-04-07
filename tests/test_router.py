"""Tests for the handshake router."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fastapi.testclient import TestClient
from server.app import create_app
from crypto.encryptor import Encryptor


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_encryptor():
    return Encryptor()


# =============================================================================
# Handshake Endpoint Tests
# =============================================================================

class TestHandshakeEndpoint:
    """Tests for POST /crypto/handshake."""

    def test_handshake_returns_200(self, client, client_encryptor):
        """Successful handshake should return 200."""
        response = client.post("/crypto/handshake", json={
            "public_key": client_encryptor.get_public_key().decode(),
            "salt": client_encryptor.get_salt().hex(),
        })
        assert response.status_code == 200

    def test_handshake_response_contains_public_key(self, client, client_encryptor):
        """Response should contain a PEM public key."""
        response = client.post("/crypto/handshake", json={
            "public_key": client_encryptor.get_public_key().decode(),
            "salt": client_encryptor.get_salt().hex(),
        })
        data = response.json()
        assert "public_key" in data
        assert data["public_key"].startswith("-----BEGIN PUBLIC KEY-----")

    def test_handshake_response_echoes_salt(self, client, client_encryptor):
        """Response should echo back the client's salt."""
        salt_hex = client_encryptor.get_salt().hex()
        response = client.post("/crypto/handshake", json={
            "public_key": client_encryptor.get_public_key().decode(),
            "salt": salt_hex,
        })
        assert response.json()["salt"] == salt_hex

    def test_handshake_stores_shared_key_on_app_state(self, app, client_encryptor):
        """After handshake, shared_key should be set on app state."""
        with TestClient(app) as c:
            assert app.state.shared_key is None
            c.post("/crypto/handshake", json={
                "public_key": client_encryptor.get_public_key().decode(),
                "salt": client_encryptor.get_salt().hex(),
            })
            assert app.state.shared_key is not None
            assert len(app.state.shared_key) == 32

    def test_handshake_derives_same_key_as_client(self, app, client_encryptor):
        """Server and client should derive the same shared key."""
        with TestClient(app) as c:
            pub_pem = client_encryptor.get_public_key().decode()
            salt_hex = client_encryptor.get_salt().hex()

            response = c.post("/crypto/handshake", json={
                "public_key": pub_pem,
                "salt": salt_hex,
            })

            server_pub_pem = response.json()["public_key"].encode()
            client_key = client_encryptor.derive_shared_key(
                server_pub_pem, bytes.fromhex(salt_hex)
            )

            assert client_key == app.state.shared_key

    def test_handshake_missing_public_key_returns_422(self, client, client_encryptor):
        """Missing public_key field should return 422."""
        response = client.post("/crypto/handshake", json={
            "salt": client_encryptor.get_salt().hex(),
        })
        assert response.status_code == 422

    def test_handshake_missing_salt_returns_422(self, client, client_encryptor):
        """Missing salt field should return 422."""
        response = client.post("/crypto/handshake", json={
            "public_key": client_encryptor.get_public_key().decode(),
        })
        assert response.status_code == 422

    def test_handshake_empty_body_returns_422(self, client):
        """Empty body should return 422."""
        response = client.post("/crypto/handshake", json={})
        assert response.status_code == 422

    def test_handshake_invalid_public_key_returns_400(self, client, client_encryptor):
        """Invalid PEM public key should return 400."""
        response = client.post("/crypto/handshake", json={
            "public_key": "not-a-valid-pem",
            "salt": client_encryptor.get_salt().hex(),
        })
        assert response.status_code == 400

    def test_handshake_invalid_salt_hex_returns_400(self, client, client_encryptor):
        """Non-hex salt should return 400."""
        response = client.post("/crypto/handshake", json={
            "public_key": client_encryptor.get_public_key().decode(),
            "salt": "not-hex!!",
        })
        assert response.status_code == 400

    def test_handshake_overwrites_previous_shared_key(self, app):
        """A second handshake should overwrite the previous shared key."""
        client_a = Encryptor()
        client_b = Encryptor()

        with TestClient(app) as c:
            c.post("/crypto/handshake", json={
                "public_key": client_a.get_public_key().decode(),
                "salt": client_a.get_salt().hex(),
            })
            key_after_first = app.state.shared_key

            c.post("/crypto/handshake", json={
                "public_key": client_b.get_public_key().decode(),
                "salt": client_b.get_salt().hex(),
            })
            key_after_second = app.state.shared_key

        assert key_after_first != key_after_second

    def test_handshake_server_public_key_is_consistent(self, app, client_encryptor):
        """Server should return the same public key across multiple handshakes within a session."""
        with TestClient(app) as c:
            r1 = c.post("/crypto/handshake", json={
                "public_key": client_encryptor.get_public_key().decode(),
                "salt": client_encryptor.get_salt().hex(),
            })
            r2 = c.post("/crypto/handshake", json={
                "public_key": client_encryptor.get_public_key().decode(),
                "salt": client_encryptor.get_salt().hex(),
            })

            assert r1.json()["public_key"] == r2.json()["public_key"]
