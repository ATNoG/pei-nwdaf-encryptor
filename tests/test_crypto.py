"""Tests for the crypto package (DH key exchange and GCM encryption)."""
import pytest
from cryptography.hazmat.primitives.asymmetric import dh

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'encryptor'))

from crypto.CipherStrategy import CipherStrategy, AESGCMStrategy
from crypto.encryptor import Encryptor


# =============================================================================
# AESGCMStrategy Tests
# =============================================================================

class TestAESGCMStrategy:
    """Tests for AESGCMStrategy cipher implementation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.strategy = AESGCMStrategy()
        self.key = os.urandom(32)  # 256-bit key
        self.plaintext = b"Hello, secure world!"

    def test_encrypt_returns_bytes(self):
        """Encrypt should return bytes."""
        ciphertext = self.strategy.encrypt(self.plaintext, self.key)
        assert isinstance(ciphertext, bytes)

    def test_encrypt_adds_nonce_overhead(self):
        """Encrypt should add 12-byte nonce overhead."""
        ciphertext = self.strategy.encrypt(self.plaintext, self.key)
        assert len(ciphertext) >= len(self.plaintext) + 12 + 16

    def test_decrypt_recovers_plaintext(self):
        """Decrypt should recover original plaintext."""
        ciphertext = self.strategy.encrypt(self.plaintext, self.key)
        decrypted = self.strategy.decrypt(ciphertext, self.key)
        assert decrypted == self.plaintext

    def test_decrypt_wrong_key_raises(self):
        """Decrypt with wrong key should raise."""
        ciphertext = self.strategy.encrypt(self.plaintext, self.key)
        wrong_key = os.urandom(32)
        with pytest.raises(Exception):
            self.strategy.decrypt(ciphertext, wrong_key)

    def test_decrypt_tampered_data_raises(self):
        """Decrypt tampered ciphertext should raise InvalidTag."""
        ciphertext = self.strategy.encrypt(self.plaintext, self.key)
        tampered = ciphertext[:-1]
        with pytest.raises(Exception):
            self.strategy.decrypt(tampered, self.key)

    def test_decrypt_empty_ciphertext_raises(self):
        """Decrypt empty data should raise."""
        with pytest.raises(Exception):
            self.strategy.decrypt(b"", self.key)

    def test_encrypt_different_nonces(self):
        """Each encryption should use different nonce."""
        ciphertext1 = self.strategy.encrypt(self.plaintext, self.key)
        ciphertext2 = self.strategy.encrypt(self.plaintext, self.key)
        assert ciphertext1[:12] != ciphertext2[:12]

    def test_roundtrip_multiple_messages(self):
        """Roundtrip should work for multiple different messages."""
        messages = [b"", b"Short", b"A" * 1000, b"\x00\x01\x02\x03"]
        for msg in messages:
            ciphertext = self.strategy.encrypt(msg, self.key)
            decrypted = self.strategy.decrypt(ciphertext, self.key)
            assert decrypted == msg


# =============================================================================
# Encryptor Tests (DH Key Exchange + GCM Encryption)
# =============================================================================

class TestEncryptor:
    """Tests for Encryptor DH key exchange and encryption."""

    def test_init_generates_parameters(self):
        """Encryptor should generate DH parameters on init."""
        encryptor = Encryptor()
        assert encryptor.parameters is not None

    def test_init_generates_private_key(self):
        """Encryptor should generate private key on init."""
        encryptor = Encryptor()
        assert encryptor._private_key is not None
        assert isinstance(encryptor._private_key, dh.DHPrivateKey)

    def test_get_public_key_returns_pem(self):
        """get_public_key should return PEM-encoded bytes."""
        encryptor = Encryptor()
        pub_key = encryptor.get_public_key()
        assert isinstance(pub_key, bytes)
        assert pub_key.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_derive_shared_key_same_salt(self):
        """derive_shared_key should produce same key when using same salt."""
        alice = Encryptor()
        bob = Encryptor()

        alice_pub_pem = alice.get_public_key()
        bob_pub_pem = bob.get_public_key()
        shared_salt = alice.get_salt()

        alice_shared = alice.derive_shared_key(bob_pub_pem, shared_salt)
        bob_shared = bob.derive_shared_key(alice_pub_pem, shared_salt)

        assert len(alice_shared) == 32
        assert len(bob_shared) == 32
        assert alice_shared == bob_shared

    def test_derive_shared_key_different_salts(self):
        """derive_shared_key should produce different keys when using different salts."""
        alice = Encryptor()
        bob = Encryptor()
        charlie = Encryptor()

        alice_pub_pem = alice.get_public_key()
        bob_pub_pem = bob.get_public_key()
        charlie_pub_pem = charlie.get_public_key()

        alice_salt = alice.get_salt()
        bob_salt = bob.get_salt()

        # Alice and Bob derive keys using Alice's salt
        alice_shared_with_alice_salt = alice.derive_shared_key(bob_pub_pem, alice_salt)
        bob_shared_with_alice_salt = bob.derive_shared_key(alice_pub_pem, alice_salt)

        # Alice derives key using Bob's salt
        alice_shared_with_bob_salt = alice.derive_shared_key(bob_pub_pem, bob_salt)

        # Keys should be different when using different salts
        assert alice_shared_with_alice_salt != alice_shared_with_bob_salt

        # Keys should be the same when both parties use the same salt
        assert alice_shared_with_alice_salt == bob_shared_with_alice_salt


    def test_encrypt_decrypt_roundtrip(self):
        """Full encrypt/decrypt roundtrip should work."""
        encryptor = Encryptor()
        key = os.urandom(32)

        plaintext = b"Secret message!"
        ciphertext = encryptor.encrypt(plaintext, key)
        decrypted = encryptor.decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_full_dh_encryption_flow(self):
        """Full DH exchange + encryption flow between two parties."""
        alice = Encryptor()
        bob = Encryptor()

        alice_pub_pem = alice.get_public_key()
        bob_pub_pem = bob.get_public_key()

        shared_salt = alice.get_salt()
        alice_key = alice.derive_shared_key(bob_pub_pem, shared_salt)
        bob_key = bob.derive_shared_key(alice_pub_pem, shared_salt)

        assert alice_key == bob_key

        message = b"Top secret data!"
        ciphertext = alice.encrypt(message, alice_key)
        decrypted = bob.decrypt(ciphertext, bob_key)

        assert decrypted == message

    def test_custom_strategy_injection(self):
        """Encryptor should accept custom cipher strategy."""
        custom_strategy = AESGCMStrategy()
        encryptor = Encryptor(strategy=custom_strategy)

        key = os.urandom(32)
        plaintext = b"Custom strategy test"
        ciphertext = encryptor.encrypt(plaintext, key)
        decrypted = encryptor.decrypt(ciphertext, key)

        assert decrypted == plaintext

    def test_decrypt_tampered_data_raises(self):
        """Decrypting tampered data should raise InvalidTag."""
        encryptor = Encryptor()
        key = os.urandom(32)

        plaintext = b"Integrity check"
        ciphertext = encryptor.encrypt(plaintext, key)
        tampered = ciphertext[:-1]

        with pytest.raises(Exception):
            encryptor.decrypt(tampered, key)

    def test_generate_private_key_method(self):
        """generate_private_key should create new private key."""
        encryptor = Encryptor()
        old_key = encryptor._private_key
        encryptor.generate_private_key()
        new_key = encryptor._private_key
        assert old_key != new_key
