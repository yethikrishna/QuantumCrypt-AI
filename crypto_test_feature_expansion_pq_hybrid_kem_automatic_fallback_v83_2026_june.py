"""
Test Suite for QuantumCrypt AI - Hybrid KEM with Automatic Fallback v83
DIMENSION A - FEATURE EXPANSION - TEST COVERAGE

This test suite validates the new post-quantum hybrid KEM functionality.
All tests are ADD-ONLY - no existing tests are modified.
"""

import unittest
import time
from datetime import datetime, timedelta

# Import the new feature module
from quantum_crypt.feature_expansion_pq_hybrid_kem_automatic_fallback_v83_2026_june import (
    AlgorithmStatus,
    AlgorithmType,
    AlgorithmHealth,
    EncapsulationResult,
    ClassicalECDH,
    PostQuantumKyber,
    HybridKEM,
    AutomaticFallbackKEM,
    SessionKeyManager,
)


class TestAlgorithmHealth(unittest.TestCase):
    """Test algorithm health tracking"""
    
    def setUp(self):
        self.health = AlgorithmHealth(name="test-algorithm")
    
    def test_initial_state(self):
        """Test initial health state"""
        self.assertEqual(self.health.status, AlgorithmStatus.UNTESTED)
        self.assertEqual(self.health.success_count, 0)
        self.assertEqual(self.health.failure_count, 0)
        self.assertEqual(self.health.health_score, 100.0)
        self.assertEqual(self.health.consecutive_failures, 0)
    
    def test_record_success(self):
        """Test recording successful operations"""
        self.health.record_success(10.0)
        
        self.assertEqual(self.health.success_count, 1)
        self.assertEqual(self.health.status, AlgorithmStatus.HEALTHY)
        self.assertGreater(self.health.health_score, 0)
        self.assertIsNotNone(self.health.last_success)
    
    def test_record_failure(self):
        """Test recording failed operations"""
        self.health.record_failure()
        
        self.assertEqual(self.health.failure_count, 1)
        self.assertEqual(self.health.consecutive_failures, 1)
        self.assertLess(self.health.health_score, 100.0)
        self.assertIsNotNone(self.health.last_failure)
    
    def test_consecutive_failures_circuit_breaker(self):
        """Test circuit breaker after consecutive failures"""
        for _ in range(3):
            self.health.record_failure()
        
        self.assertEqual(self.health.status, AlgorithmStatus.FAILED)
        self.assertFalse(self.health.should_use())
    
    def test_health_recovery_on_success(self):
        """Test health recovers after successes"""
        # Degrade health
        for _ in range(2):
            self.health.record_failure()
        
        score_after_failures = self.health.health_score
        
        # Recover with successes
        for _ in range(5):
            self.health.record_success(10.0)
        
        self.assertGreater(self.health.health_score, score_after_failures)
        self.assertEqual(self.health.consecutive_failures, 0)
    
    def test_cooldown_retry(self):
        """Test retry after cooldown period"""
        # Fail 3 times to trigger FAILED state
        for _ in range(3):
            self.health.record_failure()
        
        self.assertFalse(self.health.should_use())
        
        # Manually set last_failure to be older than cooldown
        self.health.last_failure = datetime.now() - timedelta(minutes=10)
        
        # Should allow retry now
        self.assertTrue(self.health.should_use())
    
    def test_average_latency_tracking(self):
        """Test average latency calculation"""
        latencies = [10.0, 20.0, 30.0]
        
        for latency in latencies:
            self.health.record_success(latency)
        
        expected_avg = sum(latencies) / len(latencies)
        self.assertAlmostEqual(self.health.average_latency_ms, expected_avg, places=2)


class TestClassicalECDH(unittest.TestCase):
    """Test classical ECDH implementation"""
    
    def setUp(self):
        self.ecdh = ClassicalECDH()
    
    def test_keypair_generation(self):
        """Test key pair generation"""
        priv, pub = self.ecdh.generate_keypair()
        
        self.assertIsInstance(priv, bytes)
        self.assertIsInstance(pub, bytes)
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)
    
    def test_encapsulation_decapsulation(self):
        """Test full encapsulation/decapsulation round trip"""
        priv_alice, pub_alice = self.ecdh.generate_keypair()
        
        # Bob encapsulates to Alice
        shared_bob, ciphertext = self.ecdh.encapsulate(pub_alice)
        
        # Alice decapsulates
        shared_alice = self.ecdh.decapsulate(priv_alice, ciphertext)
        
        # Both should derive same shared secret
        self.assertEqual(shared_alice, shared_bob)
        self.assertEqual(len(shared_alice), 32)
    
    def test_algorithm_properties(self):
        """Test algorithm metadata"""
        self.assertEqual(self.ecdh.name, "ECDH-P256")
        self.assertEqual(self.ecdh.algorithm_type, AlgorithmType.CLASSICAL)


class TestPostQuantumKyber(unittest.TestCase):
    """Test post-quantum Kyber-style KEM"""
    
    def setUp(self):
        self.kyber = PostQuantumKyber(security_level=3)
    
    def test_keypair_generation(self):
        """Test key pair generation"""
        priv, pub = self.kyber.generate_keypair()
        
        self.assertIsInstance(priv, bytes)
        self.assertIsInstance(pub, bytes)
        # Private key should be larger for higher security levels
        self.assertGreater(len(priv), 32)
    
    def test_encapsulation_decapsulation(self):
        """Test full encapsulation/decapsulation round trip"""
        priv_alice, pub_alice = self.kyber.generate_keypair()
        
        # Run multiple times to handle probabilistic failure simulation
        success = False
        for _ in range(10):
            try:
                shared_bob, ciphertext = self.kyber.encapsulate(pub_alice)
                shared_alice = self.kyber.decapsulate(priv_alice, ciphertext)
                self.assertEqual(shared_alice, shared_bob)
                success = True
                break
            except RuntimeError:
                continue
        
        self.assertTrue(success, "Should succeed at least once")
    
    def test_algorithm_properties(self):
        """Test algorithm metadata"""
        self.assertEqual(self.kyber.name, "Kyber-384")
        self.assertEqual(self.kyber.algorithm_type, AlgorithmType.POST_QUANTUM)
    
    def test_different_security_levels(self):
        """Test different security level configurations"""
        kyber2 = PostQuantumKyber(security_level=2)
        self.assertEqual(kyber2.name, "Kyber-256")
        
        kyber4 = PostQuantumKyber(security_level=4)
        self.assertEqual(kyber4.name, "Kyber-512")


class TestHybridKEM(unittest.TestCase):
    """Test hybrid KEM combining classical and post-quantum"""
    
    def setUp(self):
        self.hybrid = HybridKEM()
    
    def test_keypair_generation(self):
        """Test hybrid key pair generation"""
        priv, pub = self.hybrid.generate_keypair()
        
        self.assertIsInstance(priv, bytes)
        self.assertIsInstance(pub, bytes)
        # Should contain separator for combined keys
        separator = b"@@HYBRID_SEPARATOR@@"
        self.assertIn(separator, priv)
        self.assertIn(separator, pub)
    
    def test_encapsulation_decapsulation(self):
        """Test hybrid encapsulation round trip"""
        priv_alice, pub_alice = self.hybrid.generate_keypair()
        
        # Run multiple times to handle PQ failure simulation
        success = False
        for _ in range(10):
            try:
                shared_bob, ciphertext = self.hybrid.encapsulate(pub_alice)
                shared_alice = self.hybrid.decapsulate(priv_alice, ciphertext)
                self.assertEqual(shared_alice, shared_bob)
                self.assertEqual(len(shared_alice), 32)
                success = True
                break
            except RuntimeError:
                continue
        
        self.assertTrue(success, "Hybrid KEM should succeed")
    
    def test_invalid_key_format(self):
        """Test invalid key format handling"""
        with self.assertRaises(ValueError):
            self.hybrid.encapsulate(b"invalid_key_without_separator")
    
    def test_algorithm_properties(self):
        """Test algorithm metadata"""
        self.assertEqual(self.hybrid.name, "Hybrid-ECDH-Kyber")
        self.assertEqual(self.hybrid.algorithm_type, AlgorithmType.HYBRID)


class TestAutomaticFallbackKEM(unittest.TestCase):
    """Test KEM with automatic fallback capabilities"""
    
    def setUp(self):
        self.kem = AutomaticFallbackKEM()
    
    def test_initial_algorithm_list(self):
        """Test initial algorithm configuration"""
        self.assertIn("Hybrid-ECDH-Kyber", self.kem.algorithms)
        self.assertIn("Kyber-384", self.kem.algorithms)
        self.assertIn("ECDH-P256", self.kem.algorithms)
    
    def test_keypair_generation_auto_select(self):
        """Test automatic algorithm selection for key generation"""
        priv, pub, algorithm = self.kem.generate_keypair()
        
        self.assertIsInstance(priv, bytes)
        self.assertIsInstance(pub, bytes)
        self.assertIn(algorithm, self.kem.algorithms)
    
    def test_keypair_generation_specific(self):
        """Test specific algorithm selection"""
        priv, pub, algorithm = self.kem.generate_keypair("ECDH-P256")
        
        self.assertEqual(algorithm, "ECDH-P256")
    
    def test_encapsulation_basic(self):
        """Test basic encapsulation"""
        _, pub, _ = self.kem.generate_keypair("ECDH-P256")
        
        result = self.kem.encapsulate(pub, preferred_algorithm="ECDH-P256")
        
        self.assertIsInstance(result, EncapsulationResult)
        self.assertEqual(len(result.shared_secret), 32)
        self.assertIsInstance(result.ciphertext, bytes)
        self.assertIsInstance(result.session_id, bytes)
    
    def test_decapsulation_basic(self):
        """Test basic decapsulation"""
        priv, pub, algorithm = self.kem.generate_keypair("ECDH-P256")
        
        result = self.kem.encapsulate(pub, preferred_algorithm=algorithm)
        recovered = self.kem.decapsulate(priv, result.ciphertext, algorithm)
        
        self.assertEqual(recovered, result.shared_secret)
    
    def test_health_tracking_during_operations(self):
        """Test health is tracked during operations"""
        priv, pub, algorithm = self.kem.generate_keypair("ECDH-P256")
        
        # Initial state
        initial_health = self.kem.algorithm_health[algorithm].success_count
        
        # Perform operations
        for _ in range(5):
            result = self.kem.encapsulate(pub, preferred_algorithm=algorithm)
            self.kem.decapsulate(priv, result.ciphertext, algorithm)
        
        final_health = self.kem.algorithm_health[algorithm].success_count
        self.assertGreater(final_health, initial_health)
    
    def test_algorithm_status_report(self):
        """Test algorithm status reporting"""
        status = self.kem.get_algorithm_status()
        
        self.assertIn("Hybrid-ECDH-Kyber", status)
        self.assertIn("ECDH-P256", status)
        
        for alg_name, alg_status in status.items():
            self.assertIn("status", alg_status)
            self.assertIn("health_score", alg_status)
            self.assertIn("success_count", alg_status)
            self.assertIn("failure_count", alg_status)
    
    def test_capability_report(self):
        """Test capability reporting"""
        report = self.kem.get_capability_report()
        
        self.assertIn("algorithms", report)
        self.assertIn("priority_order", report)
        self.assertIn("best_algorithm", report)
        self.assertIn("generated_at", report)
    
    def test_algorithm_negotiation(self):
        """Test algorithm negotiation with peer"""
        peer_caps = ["Hybrid-ECDH-Kyber", "ECDH-P256", "Unknown-Alg"]
        
        selected = self.kem.negotiate_algorithm(peer_caps)
        
        self.assertIn(selected, self.kem.priority_order)
        self.assertIn(selected, peer_caps)
    
    def test_algorithm_negotiation_fallback(self):
        """Test negotiation falls back to classical"""
        peer_caps = ["ECDH-P256"]  # Only supports classical
        
        selected = self.kem.negotiate_algorithm(peer_caps)
        
        self.assertEqual(selected, "ECDH-P256")
    
    def test_unknown_algorithm_selection(self):
        """Test unknown algorithm raises error"""
        with self.assertRaises(ValueError):
            self.kem.generate_keypair("UnknownAlgorithm")
    
    def test_unknown_algorithm_decapsulate(self):
        """Test unknown algorithm decapsulate returns None"""
        result = self.kem.decapsulate(b"key", b"ct", "UnknownAlgorithm")
        self.assertIsNone(result)


class TestSessionKeyManager(unittest.TestCase):
    """Test session key management"""
    
    def setUp(self):
        self.manager = SessionKeyManager()
        self.kem = AutomaticFallbackKEM()
    
    def test_establish_session(self):
        """Test session establishment"""
        _, pub, _ = self.kem.generate_keypair("ECDH-P256")
        
        session = self.manager.establish_session(pub)
        
        self.assertIn("session_id", session)
        self.assertIn("ciphertext", session)
        self.assertIn("algorithm", session)
        self.assertIn("fallback_occurred", session)
    
    def test_accept_session(self):
        """Test session acceptance"""
        priv, pub, algorithm = self.kem.generate_keypair("ECDH-P256")
        
        session = self.manager.establish_session(pub)
        session_id = bytes.fromhex(session["session_id"])
        ciphertext = bytes.fromhex(session["ciphertext"])
        
        shared_secret = self.manager.accept_session(
            priv, ciphertext, algorithm, session_id
        )
        
        self.assertIsNotNone(shared_secret)
        self.assertEqual(len(shared_secret), 32)
    
    def test_key_rotation(self):
        """Test session key rotation"""
        _, pub, _ = self.kem.generate_keypair("ECDH-P256")
        
        session = self.manager.establish_session(pub)
        session_id = bytes.fromhex(session["session_id"])
        
        result = self.manager.rotate_keys(session_id)
        
        self.assertTrue(result)
    
    def test_key_rotation_invalid_session(self):
        """Test rotation of invalid session fails gracefully"""
        result = self.manager.rotate_keys(b"nonexistent_session")
        self.assertFalse(result)
    
    def test_session_cleanup(self):
        """Test expired session cleanup"""
        initial_count = len(self.manager.active_sessions)
        cleaned = self.manager.cleanup_expired()
        self.assertIsInstance(cleaned, int)


class TestEnumTypes(unittest.TestCase):
    """Test enumeration types"""
    
    def test_algorithm_status_enum(self):
        """Test AlgorithmStatus enum values"""
        self.assertEqual(AlgorithmStatus.HEALTHY.value, "healthy")
        self.assertEqual(AlgorithmStatus.FAILED.value, "failed")
        self.assertEqual(AlgorithmStatus.UNTESTED.value, "untested")
    
    def test_algorithm_type_enum(self):
        """Test AlgorithmType enum values"""
        self.assertEqual(AlgorithmType.CLASSICAL.value, "classical")
        self.assertEqual(AlgorithmType.POST_QUANTUM.value, "post_quantum")
        self.assertEqual(AlgorithmType.HYBRID.value, "hybrid")


class TestEncapsulationResult(unittest.TestCase):
    """Test encapsulation result data class"""
    
    def test_result_creation(self):
        """Test result data structure"""
        result = EncapsulationResult(
            shared_secret=b"test_secret",
            ciphertext=b"test_ciphertext",
            algorithm_used="ECDH-P256",
            algorithm_type=AlgorithmType.CLASSICAL,
            fallback_occurred=True,
            fallback_from="Hybrid-ECDH-Kyber"
        )
        
        self.assertEqual(result.shared_secret, b"test_secret")
        self.assertEqual(result.algorithm_used, "ECDH-P256")
        self.assertTrue(result.fallback_occurred)
        self.assertEqual(result.fallback_from, "Hybrid-ECDH-Kyber")
        self.assertIsInstance(result.timestamp, datetime)
        self.assertIsInstance(result.session_id, bytes)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def test_empty_public_key_encapsulate(self):
        """Test encapsulation with empty key"""
        kem = AutomaticFallbackKEM()
        # Should fallback to working algorithm
        result = kem.encapsulate(b"")
        self.assertIsInstance(result, EncapsulationResult)
    
    def test_concurrent_health_updates(self):
        """Test health tracking handles concurrent updates"""
        import threading
        
        kem = AutomaticFallbackKEM()
        _, pub, _ = kem.generate_keypair("ECDH-P256")
        
        def worker():
            for _ in range(10):
                kem.encapsulate(pub, preferred_algorithm="ECDH-P256")
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        health = kem.algorithm_health["ECDH-P256"]
        self.assertGreater(health.success_count, 0)
    
    def test_algorithm_order_preferred(self):
        """Test preferred algorithm comes first in order"""
        kem = AutomaticFallbackKEM()
        order = kem._get_algorithm_order("ECDH-P256")
        
        self.assertEqual(order[0], "ECDH-P256")
    
    def test_select_best_algorithm(self):
        """Test best algorithm selection"""
        kem = AutomaticFallbackKEM()
        best = kem._select_best_algorithm()
        self.assertIn(best, kem.priority_order)


class TestIntegrationWorkflows(unittest.TestCase):
    """Test full integration workflows"""
    
    def test_full_key_exchange_workflow(self):
        """Test complete key exchange between two parties"""
        # Alice setup
        alice_kem = AutomaticFallbackKEM()
        alice_priv, alice_pub, alice_alg = alice_kem.generate_keypair()
        
        # Bob encapsulates to Alice
        bob_result = alice_kem.encapsulate(alice_pub)
        
        # Alice decapsulates
        alice_secret = alice_kem.decapsulate(
            alice_priv, bob_result.ciphertext, bob_result.algorithm_used
        )
        
        self.assertEqual(alice_secret, bob_result.shared_secret)
    
    def test_health_based_routing(self):
        """Test algorithms are routed based on health"""
        kem = AutomaticFallbackKEM()
        
        # Force degrade hybrid algorithm
        hybrid_health = kem.algorithm_health["Hybrid-ECDH-Kyber"]
        for _ in range(5):
            hybrid_health.record_failure()
        
        # Should select next best healthy algorithm
        best = kem._select_best_algorithm()
        self.assertNotEqual(best, "Hybrid-ECDH-Kyber")


if __name__ == "__main__":
    unittest.main(verbosity=2)
