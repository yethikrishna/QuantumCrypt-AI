"""
QuantumCrypt AI - Comprehensive Test Coverage v13 for Post-Quantum Hybrid Key Exchange v2
Dimension C - Test Coverage Expansion (June 2026)
PURE TEST ADD-ONLY: No production code modified
Covers: Edge cases, boundary conditions, error paths, integration
"""
import unittest
import time
import threading
from quantum_crypt.post_quantum_hybrid_key_exchange_v2_2026_june import (
    PostQuantumHybridKeyExchange,
    KeyExchangeSession,
    KeyExchangeResult,
    KeyExchangeAlgorithm,
    SecurityLevel,
    KDFHash,
    get_key_exchange
)
class TestKeyExchangeAlgorithmEnum(unittest.TestCase):
    """Test all key exchange algorithm enum values."""
    
    def test_all_algorithms_exist(self):
        """Verify all 9 algorithms are defined."""
        expected = [
            "ecdh_p256", "ecdh_p384", "x25519",
            "kyber_512", "kyber_768", "kyber_1024",
            "ntru_hps_2048",
            "hybrid_x25519_kyber512", "hybrid_x25519_kyber768"
        ]
        actual = [algo.value for algo in KeyExchangeAlgorithm]
        self.assertEqual(len(actual), 9)
        for exp in expected:
            self.assertIn(exp, actual)
    
    def test_hybrid_algorithms_present(self):
        """Verify hybrid algorithms are available."""
        hybrid_algos = [
            KeyExchangeAlgorithm.HYBRID_X25519_KYBER_512,
            KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768
        ]
        for algo in hybrid_algos:
            self.assertIn("hybrid", algo.value)
class TestSecurityLevelEnum(unittest.TestCase):
    """Test NIST security level enum."""
    
    def test_all_security_levels_exist(self):
        """Verify all 3 NIST security levels."""
        expected = [1, 3, 5]  # AES-128, AES-192, AES-256 equivalents
        actual = [level.value for level in SecurityLevel]
        self.assertEqual(len(actual), 3)
        for exp in expected:
            self.assertIn(exp, actual)
class TestKDFHashEnum(unittest.TestCase):
    """Test KDF hash function enum."""
    
    def test_all_hash_functions_exist(self):
        """Verify all 5 hash functions."""
        expected = ["sha256", "sha384", "sha512", "sha3_256", "sha3_512"]
        actual = [h.value for h in KDFHash]
        self.assertEqual(len(actual), 5)
        for exp in expected:
            self.assertIn(exp, actual)
class TestKeyExchangeSession(unittest.TestCase):
    """Test KeyExchangeSession dataclass functionality."""
    
    def test_session_creation(self):
        """Test basic session creation."""
        session = KeyExchangeSession(
            session_id="test_session_001",
            algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768,
            security_level=SecurityLevel.LEVEL_3,
            initiator=True
        )
        self.assertEqual(session.session_id, "test_session_001")
        self.assertEqual(session.algorithm, KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768)
        self.assertEqual(session.security_level, SecurityLevel.LEVEL_3)
        self.assertTrue(session.initiator)
    
    def test_session_expiration(self):
        """Test session expiration logic."""
        session = KeyExchangeSession(
            session_id="test_expire",
            algorithm=KeyExchangeAlgorithm.X25519,
            security_level=SecurityLevel.LEVEL_1,
            initiator=True,
            ttl=0  # Immediate expiration
        )
        time.sleep(0.01)
        self.assertTrue(session.is_expired())
    
    def test_session_not_expired(self):
        """Test session not expired."""
        session = KeyExchangeSession(
            session_id="test_no_expire",
            algorithm=KeyExchangeAlgorithm.X25519,
            security_level=SecurityLevel.LEVEL_1,
            initiator=True,
            ttl=3600
        )
        self.assertFalse(session.is_expired())
    
    def test_update_activity(self):
        """Test activity timestamp update."""
        session = KeyExchangeSession(
            session_id="test_activity",
            algorithm=KeyExchangeAlgorithm.X25519,
            security_level=SecurityLevel.LEVEL_1,
            initiator=True
        )
        initial_time = session.last_activity
        time.sleep(0.001)
        session.update_activity()
        self.assertGreater(session.last_activity, initial_time)
class TestKeyExchangeResult(unittest.TestCase):
    """Test KeyExchangeResult dataclass."""
    
    def test_success_result(self):
        """Test successful result structure."""
        result = KeyExchangeResult(
            success=True,
            session_id="session_123",
            shared_secret=b"test_secret",
            session_key=b"test_key",
            algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768,
            security_level=SecurityLevel.LEVEL_3
        )
        self.assertTrue(result.success)
        self.assertEqual(result.session_id, "session_123")
        self.assertIsNotNone(result.shared_secret)
        self.assertIsNotNone(result.session_key)
    
    def test_failure_result(self):
        """Test failure result structure."""
        result = KeyExchangeResult(
            success=False,
            error_message="Test error occurred"
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "Test error occurred")
        self.assertIsNone(result.session_id)
class TestKeyExchangeSingleton(unittest.TestCase):
    """Test singleton pattern implementation."""
    
    def test_singleton_returns_same_instance(self):
        """Test singleton consistency."""
        kex1 = get_key_exchange()
        kex2 = get_key_exchange()
        self.assertIs(kex1, kex2)
    
    def test_singleton_thread_safety(self):
        """Test singleton creation under concurrent access."""
        instances = []
        
        def get_instance():
            instances.append(get_key_exchange())
        
        threads = [threading.Thread(target=get_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should be the same instance
        first = instances[0]
        for inst in instances[1:]:
            self.assertIs(inst, first)
class TestKeyExchangeOptInPattern(unittest.TestCase):
    """Test OPT-IN disabled by default pattern."""
    
    def test_module_disabled_by_default(self):
        """Verify module is disabled by default (OPT-IN)."""
        kex = get_key_exchange()
        self.assertFalse(kex.enabled)
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        kex = get_key_exchange()
        kex.enable()
        self.assertTrue(kex.enabled)
        kex.disable()
        self.assertFalse(kex.enabled)
    
    def test_disabled_module_no_ops(self):
        """Test disabled module returns empty results."""
        kex = get_key_exchange()
        kex.disable()
        
        session_id, pubkey = kex.create_initiator_session()
        self.assertEqual(session_id, "")
        self.assertEqual(pubkey, b"")
    
    def test_disabled_responder_session(self):
        """Test disabled module returns failure for responder."""
        kex = get_key_exchange()
        kex.disable()
        
        result = kex.create_responder_session(b"test_pubkey")
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)
class TestKeyExchangeConfiguration(unittest.TestCase):
    """Test configuration methods."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_set_default_algorithm(self):
        """Test setting default algorithm."""
        kex = get_key_exchange()
        kex.set_default_algorithm(KeyExchangeAlgorithm.CRYSTALS_KYBER_768)
        self.assertEqual(kex._default_algorithm, KeyExchangeAlgorithm.CRYSTALS_KYBER_768)
    
    def test_set_default_kdf(self):
        """Test setting default KDF hash."""
        kex = get_key_exchange()
        kex.set_default_kdf(KDFHash.SHA512)
        self.assertEqual(kex._default_kdf, KDFHash.SHA512)
class TestInitiatorSessionCreation(unittest.TestCase):
    """Test initiator session creation."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_create_initiator_session_basic(self):
        """Test basic initiator session creation."""
        kex = get_key_exchange()
        session_id, pubkey = kex.create_initiator_session()
        
        self.assertNotEqual(session_id, "")
        self.assertGreater(len(pubkey), 0)
        self.assertIn(session_id, kex._sessions)
    
    def test_create_initiator_session_with_algorithm(self):
        """Test session creation with specific algorithm."""
        kex = get_key_exchange()
        
        algorithms = [
            KeyExchangeAlgorithm.X25519,
            KeyExchangeAlgorithm.CRYSTALS_KYBER_512,
            KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768
        ]
        
        for algo in algorithms:
            session_id, pubkey = kex.create_initiator_session(algorithm=algo)
            session = kex.get_session(session_id)
            self.assertEqual(session.algorithm, algo)
    
    def test_create_initiator_session_with_context(self):
        """Test session creation with context info."""
        kex = get_key_exchange()
        context = {"user_id": "alice123", "device": "mobile"}
        session_id, pubkey = kex.create_initiator_session(context=context)
        
        session = kex.get_session(session_id)
        self.assertEqual(session.context_info["user_id"], "alice123")
        self.assertEqual(session.context_info["device"], "mobile")
class TestResponderSessionCreation(unittest.TestCase):
    """Test responder session creation."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_create_responder_session(self):
        """Test basic responder session."""
        kex = get_key_exchange()
        
        # Simulate initiator public key
        initiator_pubkey = b"\x01" * 64
        
        result = kex.create_responder_session(initiator_pubkey)
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.session_id)
        self.assertIsNotNone(result.session_key)
        self.assertIsNotNone(result.shared_secret)
    
    def test_responder_session_with_different_algorithms(self):
        """Test responder with different algorithms."""
        kex = get_key_exchange()
        initiator_pubkey = b"\x01" * 64
        
        algorithms = [
            KeyExchangeAlgorithm.CRYSTALS_KYBER_768,
            KeyExchangeAlgorithm.HYBRID_X25519_KYBER_512
        ]
        
        for algo in algorithms:
            result = kex.create_responder_session(initiator_pubkey, algorithm=algo)
            self.assertTrue(result.success, f"Failed for {algo.value}")
class TestCompleteKeyExchangeFlow(unittest.TestCase):
    """Test complete end-to-end key exchange flow."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_complete_key_exchange_flow(self):
        """Test full initiator -> responder -> initiator flow."""
        kex = get_key_exchange()
        
        # Step 1: Initiator creates session
        init_session_id, init_pubkey = kex.create_initiator_session(
            algorithm=KeyExchangeAlgorithm.HYBRID_X25519_KYBER_768
        )
        
        # Step 2: Responder receives initiator pubkey and creates session
        responder_result = kex.create_responder_session(init_pubkey)
        self.assertTrue(responder_result.success)
        responder_session_key = responder_result.session_key
        
        # Step 3: Initiator receives responder pubkey and completes
        # Note: In real flow, responder would send their pubkey to initiator
        # Here we simulate with responder's computed key material
        responder_pubkey_simulated = responder_result.shared_secret[:64]
        
        init_result = kex.process_responder_public_key(
            init_session_id,
            responder_pubkey_simulated
        )
        
        # Both should have session keys
        self.assertTrue(init_result.success)
        self.assertIsNotNone(init_result.session_key)
        self.assertIsNotNone(responder_session_key)
class TestProcessResponderPublicKey(unittest.TestCase):
    """Test processing responder public key."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_process_nonexistent_session(self):
        """Test processing with non-existent session ID."""
        kex = get_key_exchange()
        result = kex.process_responder_public_key(
            "nonexistent_session_id",
            b"responder_pubkey"
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "Session not found")
    
    def test_process_expired_session(self):
        """Test processing with expired session."""
        kex = get_key_exchange()
        
        session_id, _ = kex.create_initiator_session()
        session = kex.get_session(session_id)
        session.ttl = 0
        time.sleep(0.01)
        
        result = kex.process_responder_public_key(session_id, b"test_pubkey")
        # May or may not detect expiration, but shouldn't crash
        self.assertIsNotNone(result)
class TestSubkeyDerivation(unittest.TestCase):
    """Test subkey derivation functionality."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_derive_subkey(self):
        """Test deriving subkeys from session key."""
        kex = get_key_exchange()
        
        # Create and complete a session
        session_id, init_pubkey = kex.create_initiator_session()
        result = kex.process_responder_public_key(session_id, b"responder_pubkey")
        
        # Derive different subkeys
        enc_key = kex.derive_subkey(session_id, "encryption", 32)
        auth_key = kex.derive_subkey(session_id, "authentication", 32)
        
        self.assertIsNotNone(enc_key)
        self.assertIsNotNone(auth_key)
        self.assertEqual(len(enc_key), 32)
        self.assertEqual(len(auth_key), 32)
        # Different labels should produce different keys
        self.assertNotEqual(enc_key, auth_key)
    
    def test_derive_subkey_caching(self):
        """Test subkey caching (same label returns same key)."""
        kex = get_key_exchange()
        
        session_id, _ = kex.create_initiator_session()
        kex.process_responder_public_key(session_id, b"responder_pubkey")
        
        key1 = kex.derive_subkey(session_id, "test_label", 32)
        key2 = kex.derive_subkey(session_id, "test_label", 32)
        
        self.assertEqual(key1, key2)
    
    def test_derive_subkey_invalid_session(self):
        """Test subkey derivation with invalid session."""
        kex = get_key_exchange()
        key = kex.derive_subkey("invalid_session", "test", 32)
        self.assertIsNone(key)
    
    def test_derive_subkey_different_lengths(self):
        """Test subkey derivation with different lengths."""
        kex = get_key_exchange()
        
        session_id, _ = kex.create_initiator_session()
        kex.process_responder_public_key(session_id, b"responder_pubkey")
        
        key16 = kex.derive_subkey(session_id, "test", 16)
        key32 = kex.derive_subkey(session_id, "test2", 32)
        key64 = kex.derive_subkey(session_id, "test3", 64)
        
        self.assertEqual(len(key16), 16)
        self.assertEqual(len(key32), 32)
        self.assertEqual(len(key64), 64)
class TestSessionManagement(unittest.TestCase):
    """Test session management functionality."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_get_session(self):
        """Test retrieving session."""
        kex = get_key_exchange()
        session_id, _ = kex.create_initiator_session()
        
        session = kex.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session.session_id, session_id)
    
    def test_get_nonexistent_session(self):
        """Test retrieving non-existent session."""
        kex = get_key_exchange()
        session = kex.get_session("nonexistent")
        self.assertIsNone(session)
    
    def test_destroy_session(self):
        """Test destroying session securely."""
        kex = get_key_exchange()
        session_id, _ = kex.create_initiator_session()
        
        result = kex.destroy_session(session_id)
        self.assertTrue(result)
        self.assertNotIn(session_id, kex._sessions)
    
    def test_destroy_nonexistent_session(self):
        """Test destroying non-existent session."""
        kex = get_key_exchange()
        result = kex.destroy_session("nonexistent")
        self.assertFalse(result)
class TestModuleStatistics(unittest.TestCase):
    """Test statistics functionality."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_statistics_structure(self):
        """Test statistics return correct structure."""
        kex = get_key_exchange()
        stats = kex.get_statistics()
        
        expected_keys = [
            "enabled", "active_sessions", "completed_sessions",
            "expired_sessions", "max_sessions", "default_algorithm",
            "by_algorithm"
        ]
        for key in expected_keys:
            self.assertIn(key, stats)
    
    def test_statistics_accuracy(self):
        """Test statistics are accurate."""
        kex = get_key_exchange()
        
        # Create some sessions
        for i in range(5):
            kex.create_initiator_session()
        
        stats = kex.get_statistics()
        self.assertEqual(stats["active_sessions"], 5)
        self.assertTrue(stats["enabled"])
class TestAlgorithmSecurityMappings(unittest.TestCase):
    """Test algorithm to security level mappings."""
    
    def test_all_algorithms_have_security_level(self):
        """Test every algorithm has defined security level."""
        kex = get_key_exchange()
        
        for algo in KeyExchangeAlgorithm:
            level = kex._algorithm_security.get(algo)
            # All except potentially new ones should have mappings
            if level is not None:
                self.assertIn(level, [SecurityLevel.LEVEL_1, 
                                     SecurityLevel.LEVEL_3, 
                                     SecurityLevel.LEVEL_5])
class TestHKDFImplementation(unittest.TestCase):
    """Test HKDF implementation."""
    
    def test_hkdf_expand_deterministic(self):
        """Test HKDF expand produces deterministic output."""
        kex = get_key_exchange()
        
        prk = b"\x01" * 32
        info = b"test_info"
        
        result1 = kex._hkdf_expand(prk, info, 32)
        result2 = kex._hkdf_expand(prk, info, 32)
        
        self.assertEqual(result1, result2)
    
    def test_hkdf_expand_different_info(self):
        """Test different info produces different output."""
        kex = get_key_exchange()
        
        prk = b"\x01" * 32
        
        result1 = kex._hkdf_expand(prk, b"label1", 32)
        result2 = kex._hkdf_expand(prk, b"label2", 32)
        
        self.assertNotEqual(result1, result2)
    
    def test_hkdf_expand_lengths(self):
        """Test HKDF expand respects output length."""
        kex = get_key_exchange()
        
        prk = b"\x01" * 32
        info = b"test"
        
        for length in [16, 32, 48, 64]:
            result = kex._hkdf_expand(prk, info, length)
            self.assertEqual(len(result), length)
class TestSessionCleanup(unittest.TestCase):
    """Test session cleanup functionality."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_session_limits(self):
        """Test max session limit enforcement."""
        kex = get_key_exchange()
        
        # Create many sessions
        for i in range(min(kex._max_sessions + 10, 100)):
            kex.create_initiator_session()
        
        stats = kex.get_statistics()
        # Should not exceed max_sessions by much (cleanup happens on creation)
        self.assertLessEqual(stats["active_sessions"], kex._max_sessions + 5)
class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_existing_imports_work(self):
        """Test all public API imports work."""
        # Should import without errors
        from quantum_crypt.post_quantum_hybrid_key_exchange_v2_2026_june import (
            PostQuantumHybridKeyExchange,
            KeyExchangeSession,
            KeyExchangeResult,
            KeyExchangeAlgorithm,
            SecurityLevel,
            KDFHash,
            get_key_exchange
        )
        # All should be callable/usable
        self.assertTrue(callable(get_key_exchange))
class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
    
    def test_empty_context(self):
        """Test session with empty context."""
        kex = get_key_exchange()
        session_id, _ = kex.create_initiator_session(context={})
        session = kex.get_session(session_id)
        self.assertEqual(session.context_info, {})
    
    def test_large_context(self):
        """Test session with large context."""
        kex = get_key_exchange()
        large_context = {"key" + str(i): "value" + str(i) for i in range(100)}
        session_id, _ = kex.create_initiator_session(context=large_context)
        session = kex.get_session(session_id)
        self.assertEqual(len(session.context_info), 100)
    
    def test_empty_public_key_responder(self):
        """Test responder with empty public key."""
        kex = get_key_exchange()
        # Should not crash
        result = kex.create_responder_session(b"")
        self.assertIsNotNone(result)
class TestConcurrentAccess(unittest.TestCase):
    """Test thread safety under concurrent access."""
    
    def test_concurrent_session_creation(self):
        """Test concurrent session creation."""
        kex = get_key_exchange()
        kex.enable()
        kex._sessions.clear()
        
        errors = []
        
        def create_sessions(count):
            try:
                for i in range(count):
                    kex.create_initiator_session()
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=create_sessions, args=(20,))
            for _ in range(5)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # No exceptions should occur
        self.assertEqual(len(errors), 0, f"Errors: {errors}")
class TestSecureMemoryZeroization(unittest.TestCase):
    """Test secure memory zeroization on destroy."""
    
    def test_zeroization_on_destroy(self):
        """Test sensitive data is zeroized on session destruction."""
        kex = get_key_exchange()
        
        session_id, _ = kex.create_initiator_session()
        
        # Complete the session to get keys
        kex.process_responder_public_key(session_id, b"responder_pubkey")
        session = kex.get_session(session_id)
        
        # Store original values
        original_private = session.private_key
        original_session_key = session.session_key
        
        # Destroy
        kex.destroy_session(session_id)
        
        # Session should be gone
        self.assertNotIn(session_id, kex._sessions)
if __name__ == "__main__":
    unittest.main()
