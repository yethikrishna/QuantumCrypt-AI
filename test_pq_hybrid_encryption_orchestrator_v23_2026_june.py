"""
Test suite for Post-Quantum Hybrid Encryption Orchestrator v23 (June 2026)
Dimension A - Feature Expansion

Tests verify all functionality works correctly.
All existing tests should continue to pass - this is ADD-ONLY.
"""

import unittest
import sys
import os

# Add the module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from pq_hybrid_encryption_orchestrator_v23_2026_june import (
    AlgorithmType,
    SecurityLevel,
    PerformanceProfile,
    ThreatModel,
    AlgorithmInfo,
    EncryptionResult,
    DecryptionResult,
    SelectionCriteria,
    AlgorithmRegistry,
    AlgorithmSelector,
    HybridEncryptionOrchestrator,
)


class TestAlgorithmRegistry(unittest.TestCase):
    """Tests for algorithm registry functionality"""

    def setUp(self):
        self.registry = AlgorithmRegistry()

    def test_default_algorithms_registered(self):
        """Test default algorithms are registered"""
        algorithms = self.registry.list_algorithms()
        self.assertGreaterEqual(len(algorithms), 10)
        self.assertIn("AES-256-GCM", algorithms)
        self.assertIn("CRYSTALS-Kyber-768", algorithms)
        self.assertIn("Kyber-768+AES-256-GCM", algorithms)

    def test_get_algorithm(self):
        """Test getting algorithm info"""
        algo = self.registry.get_algorithm("AES-256-GCM")
        self.assertIsNotNone(algo)
        self.assertEqual(algo.name, "AES-256-GCM")
        self.assertEqual(algo.algorithm_type, AlgorithmType.CLASSICAL)
        self.assertEqual(algo.security_level, SecurityLevel.LEVEL_5)

    def test_get_nonexistent_algorithm(self):
        """Test getting non-existent algorithm"""
        algo = self.registry.get_algorithm("NonExistent-Algo")
        self.assertIsNone(algo)

    def test_filter_by_type(self):
        """Test filtering algorithms by type"""
        pq_algos = self.registry.filter_algorithms(
            algorithm_type=AlgorithmType.POST_QUANTUM
        )
        self.assertGreaterEqual(len(pq_algos), 4)

        classical = self.registry.filter_algorithms(
            algorithm_type=AlgorithmType.CLASSICAL
        )
        self.assertGreaterEqual(len(classical), 2)

        hybrid = self.registry.filter_algorithms(
            algorithm_type=AlgorithmType.HYBRID
        )
        self.assertGreaterEqual(len(hybrid), 2)

    def test_filter_by_security_level(self):
        """Test filtering algorithms by security level"""
        level5 = self.registry.filter_algorithms(
            min_security_level=SecurityLevel.LEVEL_5
        )
        self.assertGreaterEqual(len(level5), 2)

    def test_filter_by_nist_standardized(self):
        """Test filtering by NIST standardized flag"""
        nist_algos = self.registry.filter_algorithms(require_nist=True)
        self.assertEqual(len(nist_algos), len(self.registry.list_algorithms()))

    def test_register_new_algorithm(self):
        """Test registering a new algorithm"""
        new_algo = AlgorithmInfo(
            name="Test-Algo",
            algorithm_type=AlgorithmType.CLASSICAL,
            security_level=SecurityLevel.LEVEL_3,
            performance_score=8.0,
            memory_usage_kb=128,
            supported_operations=["encrypt", "decrypt"],
        )
        self.registry.register_algorithm(new_algo)
        self.assertIn("Test-Algo", self.registry.list_algorithms())


class TestAlgorithmSelector(unittest.TestCase):
    """Tests for automatic algorithm selection"""

    def setUp(self):
        self.registry = AlgorithmRegistry()
        self.selector = AlgorithmSelector(self.registry)

    def test_select_standard_criteria(self):
        """Test selection with standard criteria"""
        criteria = SelectionCriteria()
        ranked = self.selector.select_algorithms(criteria)
        self.assertGreater(len(ranked), 0)

    def test_select_quantum_resistant(self):
        """Test selection for quantum-resistant threat model"""
        criteria = SelectionCriteria(
            threat_model=ThreatModel.QUANTUM_RESISTANT,
        )
        ranked = self.selector.select_algorithms(criteria)
        self.assertGreater(len(ranked), 0)
        
        # Top algorithms should be PQ or Hybrid
        top_algo = self.registry.get_algorithm(ranked[0])
        self.assertIn(top_algo.algorithm_type, 
                     (AlgorithmType.POST_QUANTUM, AlgorithmType.HYBRID))

    def test_select_long_term_storage(self):
        """Test selection for long-term storage"""
        criteria = SelectionCriteria(
            threat_model=ThreatModel.LONG_TERM_STORAGE,
        )
        ranked = self.selector.select_algorithms(criteria)
        self.assertGreater(len(ranked), 0)
        
        # Hybrid should be preferred for long-term
        top_algo = self.registry.get_algorithm(ranked[0])
        self.assertEqual(top_algo.algorithm_type, AlgorithmType.HYBRID)

    def test_select_speed_optimized(self):
        """Test speed-optimized selection"""
        criteria = SelectionCriteria(
            performance_profile=PerformanceProfile.SPEED_OPTIMIZED,
        )
        ranked = self.selector.select_algorithms(criteria)
        self.assertGreater(len(ranked), 0)

    def test_select_memory_optimized(self):
        """Test memory-optimized selection"""
        criteria = SelectionCriteria(
            performance_profile=PerformanceProfile.MEMORY_OPTIMIZED,
        )
        ranked = self.selector.select_algorithms(criteria)
        self.assertGreater(len(ranked), 0)

    def test_select_with_memory_constraint(self):
        """Test selection with memory constraint"""
        criteria = SelectionCriteria(
            max_memory_kb=100,  # Very strict memory limit
        )
        ranked = self.selector.select_algorithms(criteria)
        # Should only get classical algorithms
        for name in ranked:
            algo = self.registry.get_algorithm(name)
            self.assertLessEqual(algo.memory_usage_kb, 100)

    def test_select_best(self):
        """Test selecting single best algorithm"""
        criteria = SelectionCriteria(
            min_security_level=SecurityLevel.LEVEL_3,
        )
        best = self.selector.select_best(criteria)
        self.assertIsNotNone(best)

    def test_selection_caching(self):
        """Test that selection results are cached"""
        criteria = SelectionCriteria()
        result1 = self.selector.select_algorithms(criteria)
        result2 = self.selector.select_algorithms(criteria)
        self.assertEqual(result1, result2)


class TestHybridEncryptionOrchestrator(unittest.TestCase):
    """Tests for encryption orchestrator"""

    def setUp(self):
        self.orchestrator = HybridEncryptionOrchestrator()

    def test_generate_key(self):
        """Test key generation"""
        key_id, key = self.orchestrator.generate_key("AES-256-GCM")
        self.assertIsNotNone(key_id)
        self.assertIsInstance(key, bytes)
        self.assertGreater(len(key), 0)

    def test_generate_key_unknown_algorithm(self):
        """Test key generation with unknown algorithm"""
        with self.assertRaises(ValueError):
            self.orchestrator.generate_key("Unknown-Algo")

    def test_encrypt_explicit_algorithm(self):
        """Test encryption with explicit algorithm"""
        plaintext = b"Secret message to encrypt"
        result = self.orchestrator.encrypt(
            plaintext,
            algorithm_name="AES-256-GCM",
        )
        
        self.assertIsInstance(result, EncryptionResult)
        self.assertEqual(result.algorithm_used, "AES-256-GCM")
        self.assertIsInstance(result.ciphertext, bytes)
        self.assertNotEqual(result.ciphertext, plaintext)
        self.assertGreater(len(result.key_id), 0)

    def test_encrypt_auto_select(self):
        """Test encryption with auto-selected algorithm"""
        plaintext = b"Auto-selected encryption"
        result = self.orchestrator.encrypt(plaintext)
        
        self.assertIsInstance(result, EncryptionResult)
        self.assertIsInstance(result.ciphertext, bytes)
        self.assertIn(result.algorithm_used, self.orchestrator.registry.list_algorithms())

    def test_encrypt_auto_with_criteria(self):
        """Test encryption with criteria-based auto-selection"""
        plaintext = b"High security data"
        criteria = SelectionCriteria(
            min_security_level=SecurityLevel.LEVEL_5,
            threat_model=ThreatModel.NATION_STATE,
        )
        result = self.orchestrator.encrypt(plaintext, criteria=criteria)
        
        self.assertIsInstance(result, EncryptionResult)
        self.assertGreaterEqual(result.security_level.value, SecurityLevel.LEVEL_5.value)

    def test_encrypt_auto_convenience(self):
        """Test convenience auto-encrypt method"""
        plaintext = b"Convenience method test"
        result = self.orchestrator.encrypt_auto(
            plaintext,
            min_security=SecurityLevel.LEVEL_3,
            threat_model=ThreatModel.QUANTUM_RESISTANT,
        )
        
        self.assertIsInstance(result, EncryptionResult)

    def test_decrypt_success(self):
        """Test successful decryption"""
        plaintext = b"Test roundtrip encryption"
        
        # Encrypt
        enc_result = self.orchestrator.encrypt(
            plaintext,
            algorithm_name="AES-256-GCM",
        )
        
        # Decrypt
        dec_result = self.orchestrator.decrypt(
            enc_result.ciphertext,
            key_id=enc_result.key_id,
            algorithm_name=enc_result.algorithm_used,
        )
        
        self.assertTrue(dec_result.success)
        self.assertTrue(dec_result.verified)
        self.assertEqual(dec_result.plaintext, plaintext)

    def test_decrypt_key_not_found(self):
        """Test decryption with non-existent key"""
        result = self.orchestrator.decrypt(
            b"encrypted data",
            key_id="non-existent-key",
            algorithm_name="AES-256-GCM",
        )
        
        self.assertFalse(result.success)
        self.assertEqual(result.plaintext, b"")
        self.assertEqual(result.metadata.get("error"), "Key not found")

    def test_decrypt_unknown_algorithm(self):
        """Test decryption with unknown algorithm"""
        key_id, _ = self.orchestrator.generate_key("AES-256-GCM")
        result = self.orchestrator.decrypt(
            b"encrypted data",
            key_id=key_id,
            algorithm_name="Unknown-Algo",
        )
        
        self.assertFalse(result.success)
        self.assertEqual(result.metadata.get("error"), "Unknown algorithm")

    def test_encrypt_decrypt_all_algorithms(self):
        """Test encrypt/decrypt roundtrip for all algorithms"""
        plaintext = b"Test all algorithms"
        
        for algo_name in self.orchestrator.registry.list_algorithms():
            with self.subTest(algorithm=algo_name):
                enc_result = self.orchestrator.encrypt(plaintext, algorithm_name=algo_name)
                dec_result = self.orchestrator.decrypt(
                    enc_result.ciphertext,
                    key_id=enc_result.key_id,
                    algorithm_name=algo_name,
                )
                self.assertTrue(dec_result.success)
                self.assertEqual(dec_result.plaintext, plaintext)

    def test_statistics(self):
        """Test statistics collection"""
        # Perform some operations
        for i in range(5):
            self.orchestrator.encrypt(b"Test data " + bytes([i]))
        
        stats = self.orchestrator.get_statistics()
        
        self.assertEqual(stats["total_operations"], 5)
        self.assertEqual(stats["encrypt_operations"], 5)
        self.assertEqual(stats["decrypt_operations"], 0)
        self.assertGreater(stats["keys_stored"], 0)
        self.assertGreater(stats["algorithms_registered"], 0)


class TestEnums(unittest.TestCase):
    """Tests for enum classes"""

    def test_algorithm_type_enum(self):
        """Test AlgorithmType enum values"""
        self.assertEqual(AlgorithmType.CLASSICAL.value, "classical")
        self.assertEqual(AlgorithmType.POST_QUANTUM.value, "post_quantum")
        self.assertEqual(AlgorithmType.HYBRID.value, "hybrid")

    def test_security_level_enum(self):
        """Test SecurityLevel enum values"""
        self.assertEqual(SecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(SecurityLevel.LEVEL_3.value, 3)
        self.assertEqual(SecurityLevel.LEVEL_5.value, 5)

    def test_performance_profile_enum(self):
        """Test PerformanceProfile enum values"""
        self.assertEqual(PerformanceProfile.BALANCED.value, "balanced")
        self.assertEqual(PerformanceProfile.SPEED_OPTIMIZED.value, "speed_optimized")
        self.assertEqual(PerformanceProfile.MEMORY_OPTIMIZED.value, "memory_optimized")
        self.assertEqual(PerformanceProfile.SECURITY_OPTIMIZED.value, "security_optimized")

    def test_threat_model_enum(self):
        """Test ThreatModel enum values"""
        self.assertEqual(ThreatModel.STANDARD.value, "standard")
        self.assertEqual(ThreatModel.QUANTUM_RESISTANT.value, "quantum_resistant")
        self.assertEqual(ThreatModel.NATION_STATE.value, "nation_state")
        self.assertEqual(ThreatModel.LONG_TERM_STORAGE.value, "long_term_storage")


class TestDataClasses(unittest.TestCase):
    """Tests for data classes"""

    def test_algorithm_info_dataclass(self):
        """Test AlgorithmInfo dataclass"""
        info = AlgorithmInfo(
            name="Test-Algo",
            algorithm_type=AlgorithmType.CLASSICAL,
            security_level=SecurityLevel.LEVEL_3,
            performance_score=8.5,
            memory_usage_kb=128,
            supported_operations=["encrypt"],
            nist_standardized=True,
        )
        
        self.assertEqual(info.name, "Test-Algo")
        self.assertEqual(info.security_level, SecurityLevel.LEVEL_3)
        self.assertTrue(info.nist_standardized)

    def test_encryption_result_dataclass(self):
        """Test EncryptionResult dataclass"""
        result = EncryptionResult(
            ciphertext=b"encrypted",
            algorithm_used="AES-256-GCM",
            algorithm_type=AlgorithmType.CLASSICAL,
            security_level=SecurityLevel.LEVEL_5,
            key_id="test-key",
        )
        
        self.assertEqual(result.ciphertext, b"encrypted")
        self.assertEqual(result.algorithm_used, "AES-256-GCM")

    def test_decryption_result_dataclass(self):
        """Test DecryptionResult dataclass"""
        result = DecryptionResult(
            plaintext=b"decrypted",
            algorithm_used="AES-256-GCM",
            success=True,
            verified=True,
        )
        
        self.assertEqual(result.plaintext, b"decrypted")
        self.assertTrue(result.success)
        self.assertTrue(result.verified)

    def test_selection_criteria_defaults(self):
        """Test SelectionCriteria default values"""
        criteria = SelectionCriteria()
        
        self.assertEqual(criteria.min_security_level, SecurityLevel.LEVEL_3)
        self.assertEqual(criteria.performance_profile, PerformanceProfile.BALANCED)
        self.assertEqual(criteria.threat_model, ThreatModel.STANDARD)
        self.assertTrue(criteria.require_nist_standardized)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestAlgorithmRegistry))
    suite.addTests(loader.loadTestsFromTestCase(TestAlgorithmSelector))
    suite.addTests(loader.loadTestsFromTestCase(TestHybridEncryptionOrchestrator))
    suite.addTests(loader.loadTestsFromTestCase(TestEnums))
    suite.addTests(loader.loadTestsFromTestCase(TestDataClasses))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
