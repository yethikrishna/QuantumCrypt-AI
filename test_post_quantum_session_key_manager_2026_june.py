#!/usr/bin/env python3
"""
Test suite for Post-Quantum Session Key Manager
Real, working tests that verify actual functionality
"""

import sys
import time
import unittest

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_session_key_manager_2026_june import (
    PostQuantumSessionKeyManager,
    PostQuantumHKDF,
    PostQuantumKeyExchangeSimulator,
    SessionKey,
    KeyStrength,
    SessionStatus
)


class TestPostQuantumHKDF(unittest.TestCase):
    """Test HKDF implementation"""

    def test_hkdf_basic_derivation(self):
        """Test basic HKDF key derivation"""
        hkdf = PostQuantumHKDF('sha256')
        
        ikm = b'test_input_key_material_12345'
        salt = b'secure_salt_value'
        info = b'context_information'
        
        key = hkdf.derive_key(ikm, salt, info, length=32)
        
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key, bytes)

    def test_hkdf_deterministic(self):
        """Test HKDF produces same output for same inputs"""
        hkdf = PostQuantumHKDF('sha256')
        
        ikm = b'test_ikm'
        salt = b'test_salt'
        info = b'test_info'
        
        key1 = hkdf.derive_key(ikm, salt, info, 32)
        key2 = hkdf.derive_key(ikm, salt, info, 32)
        
        self.assertEqual(key1, key2)

    def test_hkdf_different_inputs(self):
        """Test HKDF produces different keys for different inputs"""
        hkdf = PostQuantumHKDF('sha256')
        
        key1 = hkdf.derive_key(b'ikm1', b'salt', b'info', 32)
        key2 = hkdf.derive_key(b'ikm2', b'salt', b'info', 32)
        
        self.assertNotEqual(key1, key2)

    def test_hkdf_variable_length(self):
        """Test HKDF can produce different key lengths"""
        hkdf = PostQuantumHKDF('sha256')
        
        key16 = hkdf.derive_key(b'ikm', None, b'', 16)
        key32 = hkdf.derive_key(b'ikm', None, b'', 32)
        key64 = hkdf.derive_key(b'ikm', None, b'', 64)
        
        self.assertEqual(len(key16), 16)
        self.assertEqual(len(key32), 32)
        self.assertEqual(len(key64), 64)


class TestKeyExchangeSimulator(unittest.TestCase):
    """Test post-quantum key exchange simulation"""

    def test_keypair_generation(self):
        """Test keypair generation"""
        private, public = PostQuantumKeyExchangeSimulator.generate_keypair()
        
        self.assertEqual(len(private), 64)
        self.assertEqual(len(public), 64)
        self.assertNotEqual(private, public)

    def test_encapsulation_decapsulation(self):
        """Test encapsulation/decapsulation flow"""
        private, public = PostQuantumKeyExchangeSimulator.generate_keypair()
        
        ciphertext, shared1 = PostQuantumKeyExchangeSimulator.encapsulate(public)
        shared2 = PostQuantumKeyExchangeSimulator.decapsulate(private, ciphertext)
        
        self.assertEqual(len(ciphertext), 64)
        self.assertEqual(len(shared1), 32)
        self.assertEqual(len(shared2), 32)


class TestSessionKeyManager(unittest.TestCase):
    """Test session key manager"""

    def setUp(self):
        """Set up test manager"""
        self.manager = PostQuantumSessionKeyManager(
            default_key_lifetime_seconds=3600,
            max_rotations_per_session=10
        )

    def test_session_establishment(self):
        """Test basic session establishment"""
        session_id, session = self.manager.establish_session(
            context_info="test_session"
        )
        
        self.assertIsNotNone(session_id)
        self.assertEqual(len(session_id), 32)  # 16 bytes hex
        self.assertEqual(len(session.key_material), KeyStrength.AES_256.value)
        self.assertEqual(session.status, SessionStatus.ACTIVE)
        self.assertIn(session_id, self.manager.active_sessions)

    def test_session_with_peer_key(self):
        """Test session establishment with peer public key"""
        _, peer_public = PostQuantumKeyExchangeSimulator.generate_keypair()
        
        session_id, session = self.manager.establish_session(
            peer_public_key=peer_public,
            context_info="pq_secure_session"
        )
        
        self.assertIsNotNone(session)
        self.assertEqual(len(session.key_material), 32)

    def test_subkey_derivation(self):
        """Test purpose-specific subkey derivation"""
        session_id, _ = self.manager.establish_session()
        
        enc_key = self.manager.derive_subkey(session_id, "encryption")
        auth_key = self.manager.derive_subkey(session_id, "authentication")
        sign_key = self.manager.derive_subkey(session_id, "signing")
        
        self.assertEqual(len(enc_key), 32)
        self.assertEqual(len(auth_key), 32)
        self.assertEqual(len(sign_key), 32)
        
        # Different purposes should produce different keys
        self.assertNotEqual(enc_key, auth_key)
        self.assertNotEqual(auth_key, sign_key)

    def test_subkey_custom_length(self):
        """Test subkey derivation with custom length"""
        session_id, _ = self.manager.establish_session()
        
        key16 = self.manager.derive_subkey(session_id, "test", length=16)
        key64 = self.manager.derive_subkey(session_id, "test", length=64)
        
        self.assertEqual(len(key16), 16)
        self.assertEqual(len(key64), 64)

    def test_key_rotation(self):
        """Test key rotation with forward secrecy"""
        session_id, old_session = self.manager.establish_session()
        old_key = old_session.key_material
        
        new_session = self.manager.rotate_session_key(session_id)
        
        self.assertIsNotNone(new_session)
        self.assertEqual(new_session.session_id, session_id)
        self.assertEqual(new_session.rotation_count, 1)
        self.assertNotEqual(new_session.key_material, old_key)
        
        # Old key should be zeroed
        self.assertEqual(old_session.key_material, b'\x00' * 32)
        self.assertEqual(old_session.status, SessionStatus.ROTATING)

    def test_multiple_rotations(self):
        """Test multiple sequential rotations"""
        session_id, _ = self.manager.establish_session()
        
        for i in range(5):
            session = self.manager.rotate_session_key(session_id)
            self.assertEqual(session.rotation_count, i + 1)
        
        final_session = self.manager.get_session(session_id)
        self.assertEqual(final_session.rotation_count, 5)

    def test_max_rotations_limit(self):
        """Test rotation limit enforcement"""
        manager = PostQuantumSessionKeyManager(max_rotations_per_session=3)
        session_id, _ = manager.establish_session()
        
        # Perform 3 rotations successfully
        for _ in range(3):
            session = manager.rotate_session_key(session_id)
            self.assertIsNotNone(session)
        
        # 4th rotation should fail
        result = manager.rotate_session_key(session_id)
        self.assertIsNone(result)

    def test_session_revocation(self):
        """Test session revocation"""
        session_id, session = self.manager.establish_session()
        
        result = self.manager.revoke_session(session_id)
        
        self.assertTrue(result)
        self.assertNotIn(session_id, self.manager.active_sessions)
        self.assertEqual(session.status, SessionStatus.REVOKED)
        self.assertEqual(session.key_material, b'\x00' * 32)

    def test_expired_session_cleanup(self):
        """Test expired session cleanup"""
        # Create short-lived session
        session_id, _ = self.manager.establish_session(custom_lifetime=1)
        
        # Wait for expiration
        time.sleep(1.1)
        
        cleaned = self.manager.cleanup_expired_sessions()
        
        self.assertEqual(cleaned, 1)
        self.assertNotIn(session_id, self.manager.active_sessions)

    def test_get_sessions_needing_rotation(self):
        """Test detection of sessions needing rotation"""
        # Create sessions with different lifetimes
        self.manager.establish_session(custom_lifetime=1000)  # Long-lived
        self.manager.establish_session(custom_lifetime=100)   # Needs rotation soon
        
        needing_rotation = self.manager.get_sessions_needing_rotation(threshold_seconds=200)
        
        self.assertEqual(len(needing_rotation), 1)

    def test_session_metrics(self):
        """Test session metrics collection"""
        # Create some sessions
        for i in range(5):
            self.manager.establish_session()
        
        # Rotate one session
        session_id = list(self.manager.active_sessions.keys())[0]
        self.manager.rotate_session_key(session_id)
        
        metrics = self.manager.get_session_metrics()
        
        self.assertEqual(metrics["active_sessions"], 5)
        self.assertEqual(metrics["total_rotations_performed"], 1)
        self.assertEqual(metrics["key_strength_bytes"], 32)

    def test_different_key_strengths(self):
        """Test different key strength levels"""
        manager128 = PostQuantumSessionKeyManager(key_strength=KeyStrength.AES_128)
        manager256 = PostQuantumSessionKeyManager(key_strength=KeyStrength.AES_256)
        
        _, session128 = manager128.establish_session()
        _, session256 = manager256.establish_session()
        
        self.assertEqual(len(session128.key_material), 16)
        self.assertEqual(len(session256.key_material), 32)

    def test_hybrid_key_exchange(self):
        """Test hybrid key exchange functionality"""
        _, peer_public = PostQuantumKeyExchangeSimulator.generate_keypair()
        
        ciphertext, shared = self.manager.perform_hybrid_key_exchange(peer_public)
        
        self.assertEqual(len(ciphertext), 64)
        self.assertEqual(len(shared), 64)

    def test_session_expiration_check(self):
        """Test session expiration checking"""
        session_id, session = self.manager.establish_session(custom_lifetime=1)
        
        self.assertFalse(session.is_expired())
        
        time.sleep(1.1)
        
        self.assertTrue(session.is_expired())

    def test_session_age_calculation(self):
        """Test session age calculation"""
        session_id, session = self.manager.establish_session()
        
        time.sleep(0.1)
        
        age = session.get_age_seconds()
        self.assertGreater(age, 0.09)
        self.assertLess(age, 0.2)


def run_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("Post-Quantum Session Key Manager - Test Suite")
    print("=" * 60)
    print()
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPostQuantumHKDF))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyExchangeSimulator))
    suite.addTests(loader.loadTestsFromTestCase(TestSessionKeyManager))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
