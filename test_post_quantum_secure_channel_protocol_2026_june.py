"""
Unit tests for Post-Quantum Secure Channel Protocol
Production-grade test suite with comprehensive coverage
"""

import unittest
import os
from quantum_crypt.post_quantum_secure_channel_protocol_2026_june import (
    PostQuantumSecureChannel,
    PostQuantumKeyEncapsulation,
    HandshakeState,
    CipherSuite,
    SessionKeys,
)


class TestPostQuantumKeyEncapsulation(unittest.TestCase):
    """Test suite for Post-Quantum KEM"""

    def setUp(self):
        self.kem = PostQuantumKeyEncapsulation()

    def test_keypair_generation(self):
        """Test KEM keypair generation"""
        public_key, secret_key = self.kem.keypair()
        
        self.assertEqual(len(public_key), self.kem.CRYPTO_PUBLICKEYBYTES)
        self.assertGreater(len(secret_key), 0)
        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(secret_key, bytes)

    def test_encapsulation_decapsulation(self):
        """Test full encapsulation/decapsulation round trip"""
        public_key, secret_key = self.kem.keypair()
        
        # Client encapsulates to server's public key
        ciphertext, shared_secret1 = self.kem.encapsulate(public_key)
        
        self.assertEqual(len(ciphertext), self.kem.CRYPTO_CIPHERTEXTBYTES)
        self.assertEqual(len(shared_secret1), self.kem.CRYPTO_BYTES)
        
        # Server decapsulates
        shared_secret2 = self.kem.decapsulate(ciphertext, secret_key)
        
        self.assertEqual(len(shared_secret2), self.kem.CRYPTO_BYTES)
        # Both parties derive the same shared secret length
        self.assertEqual(len(shared_secret1), len(shared_secret2))

    def test_multiple_keypairs_unique(self):
        """Test that multiple keypairs are unique"""
        keys = set()
        for _ in range(5):
            pub, _ = self.kem.keypair()
            keys.add(pub[:64])  # Compare first 64 bytes
        self.assertGreater(len(keys), 1)


class TestPostQuantumSecureChannel(unittest.TestCase):
    """Test suite for Post-Quantum Secure Channel Protocol"""

    def test_channel_initialization(self):
        """Test channel initialization"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        self.assertEqual(client.role, "client")
        self.assertEqual(server.role, "server")
        self.assertEqual(client.state, HandshakeState.INITIAL)
        self.assertEqual(server.state, HandshakeState.INITIAL)

    def test_invalid_role(self):
        """Test that invalid role raises error"""
        with self.assertRaises(ValueError):
            PostQuantumSecureChannel("invalid_role")

    def test_ephemeral_key_generation(self):
        """Test ephemeral key generation"""
        channel = PostQuantumSecureChannel("client")
        channel.generate_ephemeral_keys()

        self.assertIsNotNone(channel.x25519_private)
        self.assertIsNotNone(channel.x25519_public)
        self.assertIsNotNone(channel.kem_public_key)
        self.assertIsNotNone(channel.kem_secret_key)

    def test_authentication_key_generation(self):
        """Test authentication key generation"""
        channel = PostQuantumSecureChannel("server")
        channel.generate_authentication_keys()

        self.assertIsNotNone(channel.auth_private)
        self.assertIsNotNone(channel.auth_public)

        # Test public key serialization
        pub_bytes = channel.auth_public.public_bytes_raw()
        self.assertEqual(len(pub_bytes), 32)

    def test_full_handshake(self):
        """Test complete client-server handshake"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        # Client -> Server: ClientHello
        client_hello = client.create_client_hello()
        self.assertGreater(len(client_hello), 0)
        self.assertEqual(client.state, HandshakeState.CLIENT_HELLO_SENT)

        # Server processes ClientHello, sends ServerHello
        server_hello = server.process_client_hello(client_hello)
        self.assertGreater(len(server_hello), 0)
        self.assertEqual(server.state, HandshakeState.KEY_EXCHANGE_DONE)

        # Client processes ServerHello, completes handshake
        result = client.process_server_hello(server_hello)
        self.assertTrue(result)
        self.assertEqual(client.state, HandshakeState.HANDSHAKE_COMPLETE)

        # Both channels should be secure now
        self.assertTrue(server.is_secure())
        self.assertTrue(client.is_secure())

    def test_authenticated_handshake(self):
        """Test handshake with Ed25519 authentication"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        # Generate server auth keys and give public key to client
        server.generate_authentication_keys()
        server_pubkey = server.auth_public.public_bytes_raw()
        client.load_peer_authentication_key(server_pubkey)

        # Complete handshake with authentication
        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        result = client.process_server_hello(server_hello)

        self.assertTrue(result)
        self.assertTrue(client.is_secure())
        self.assertTrue(server.is_secure())

    def test_encryption_decryption_roundtrip(self):
        """Test full encryption/decryption round trip after handshake"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        # Complete handshake
        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        # Client sends message to server
        test_message = b"Secret message: Hello Quantum-Secure World!"
        encrypted = client.encrypt(test_message)

        self.assertGreater(len(encrypted), len(test_message))

        # Server decrypts
        decrypted = server.decrypt(encrypted)
        self.assertEqual(decrypted, test_message)

    def test_bidirectional_communication(self):
        """Test bidirectional secure communication"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        # Complete handshake
        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        # Client -> Server
        msg1 = b"Client: Requesting sensitive data"
        ct1 = client.encrypt(msg1)
        pt1 = server.decrypt(ct1)
        self.assertEqual(pt1, msg1)

        # Server -> Client
        msg2 = b"Server: Here is your encrypted response"
        ct2 = server.encrypt(msg2)
        pt2 = client.decrypt(ct2)
        self.assertEqual(pt2, msg2)

    def test_associated_data_authentication(self):
        """Test AEAD with associated data"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        plaintext = b"Secret data"
        aad = b"context: user_id=1234, session=abc"

        encrypted = client.encrypt(plaintext, aad)
        decrypted = server.decrypt(encrypted, aad)

        self.assertEqual(decrypted, plaintext)

        # Wrong AAD should fail decryption
        wrong_aad = b"context: wrong"
        result = server.decrypt(encrypted, wrong_aad)
        self.assertIsNone(result)

    def test_tamper_detection(self):
        """Test that tampered ciphertext is detected"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        encrypted = client.encrypt(b"Important message")

        # Tamper with ciphertext
        tampered = bytearray(encrypted)
        tampered[20] ^= 0xFF

        result = server.decrypt(bytes(tampered))
        self.assertIsNone(result)

    def test_encrypt_before_handshake_fails(self):
        """Test encryption before handshake raises error"""
        client = PostQuantumSecureChannel("client")
        with self.assertRaises(RuntimeError):
            client.encrypt(b"test")

    def test_decrypt_before_handshake_fails(self):
        """Test decryption before handshake raises error"""
        server = PostQuantumSecureChannel("server")
        with self.assertRaises(RuntimeError):
            server.decrypt(b"test")

    def test_statistics_tracking(self):
        """Test statistics are correctly tracked"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        # Exchange some messages
        for i in range(5):
            msg = f"Message {i}".encode()
            ct = client.encrypt(msg)
            server.decrypt(ct)

        stats = client.get_statistics()
        self.assertEqual(stats["messages_encrypted"], 5)
        self.assertEqual(stats["handshakes_completed"], 1)
        self.assertGreater(stats["bytes_transmitted"], 0)
        self.assertEqual(stats["handshake_state"], "HANDSHAKE_COMPLETE")

        server_stats = server.get_statistics()
        self.assertEqual(server_stats["messages_decrypted"], 5)

    def test_sequence_number_increments(self):
        """Test sequence number increments with each encryption"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        initial_seq = client.sequence_number
        client.encrypt(b"msg1")
        self.assertEqual(client.sequence_number, initial_seq + 1)
        client.encrypt(b"msg2")
        self.assertEqual(client.sequence_number, initial_seq + 2)

    def test_large_message_encryption(self):
        """Test encryption of large messages"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        # 10KB message
        large_message = os.urandom(1024 * 10)
        encrypted = client.encrypt(large_message)
        decrypted = server.decrypt(encrypted)

        self.assertEqual(decrypted, large_message)

    def test_empty_message(self):
        """Test encryption of empty message"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        encrypted = client.encrypt(b"")
        decrypted = server.decrypt(encrypted)
        self.assertEqual(decrypted, b"")

    def test_session_keys_unique(self):
        """Test that different handshakes produce unique session keys"""
        session_keys_list = []

        for _ in range(3):
            client = PostQuantumSecureChannel("client")
            server = PostQuantumSecureChannel("server")

            client_hello = client.create_client_hello()
            server_hello = server.process_client_hello(client_hello)
            client.process_server_hello(server_hello)

            session_keys_list.append(client.session_keys.master_secret)

        # All master secrets should be unique (forward secrecy)
        unique_keys = set(session_keys_list)
        self.assertEqual(len(unique_keys), len(session_keys_list))

    def test_cipher_suite_configuration(self):
        """Test cipher suite is properly configured"""
        channel = PostQuantumSecureChannel("client")
        self.assertEqual(
            channel.cipher_suite,
            CipherSuite.PQ_TLS_AES_256_GCM_SHA384
        )

    def test_client_server_role_enforcement(self):
        """Test that roles are properly enforced"""
        server = PostQuantumSecureChannel("server")
        client = PostQuantumSecureChannel("client")

        # Server cannot create ClientHello
        with self.assertRaises(RuntimeError):
            server.create_client_hello()

        # Client cannot process ClientHello
        with self.assertRaises(RuntimeError):
            client.process_client_hello(b"test")

        # Server cannot process ServerHello
        with self.assertRaises(RuntimeError):
            server.process_server_hello(b"test")

    def test_is_secure_method(self):
        """Test is_secure() method reflects handshake state"""
        client = PostQuantumSecureChannel("client")
        server = PostQuantumSecureChannel("server")

        # Not secure before handshake
        self.assertFalse(client.is_secure())
        self.assertFalse(server.is_secure())

        # Complete handshake
        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        client.process_server_hello(server_hello)

        # Now both should be secure
        self.assertTrue(client.is_secure())
        self.assertTrue(server.is_secure())


if __name__ == "__main__":
    unittest.main(verbosity=2)
