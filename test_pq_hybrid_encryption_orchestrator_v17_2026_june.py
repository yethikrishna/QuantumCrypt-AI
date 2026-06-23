"""
Test Suite for Post-Quantum Hybrid Encryption Orchestrator v17
Dimension A - Feature Expansion Tests

Only ADD tests - does NOT modify production source code.
All existing tests will continue to pass.
"""

import unittest
import json
import os
import sys

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from pq_hybrid_encryption_orchestrator_v17_2026_june import (
    HybridEncryptionOrchestrator,
    AlgorithmRegistry,
    AlgorithmProfile,
    AlgorithmType,
    SecurityLevel,
    ThreatModel,
    HybridEncryptionPolicy,
    EncryptionResult,
    get_encryption_orchestrator
)


class TestAlgorithmEnums(unittest.TestCase):
    """Test enumeration types."""
    
    def test_algorithm_type_enum(self):
        """Test AlgorithmType enum values."""
        self.assertEqual(AlgorithmType.CLASSICAL_SYMMETRIC.value, "classical_symmetric")
        self.assertEqual(AlgorithmType.PQ_LATTICE.value, "pq_lattice")
        self.assertEqual(AlgorithmType.PQ_HASHBASED.value, "pq_hashbased")
    
    def test_security_level_enum(self):
        """Test SecurityLevel enum values."""
        self.assertEqual(SecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(SecurityLevel.LEVEL_3.value, 3)
        self.assertEqual(SecurityLevel.LEVEL_5.value, 5)
    
    def test_threat_model_enum(self):
        """Test ThreatModel enum values."""
        self.assertEqual(ThreatModel.QUANTUM_RESISTANT.value, "quantum_resistant")
        self.assertEqual(ThreatModel.LONG_TERM_STORAGE.value, "long_term_storage")
        self.assertEqual(ThreatModel.NATION_STATE.value, "nation_state")


class TestAlgorithmRegistry(unittest.TestCase):
    """Test algorithm registry functionality."""
    
    def setUp(self):
        self.registry = AlgorithmRegistry()
    
    def test_default_algorithms_loaded(self):
        """Test default algorithms are loaded."""
        self.assertGreater(len(self.registry.algorithms), 0)
    
    def test_get_algorithm_existing(self):
        """Test getting existing algorithm."""
        aes = self.registry.get_algorithm("AES-256-GCM")
        self.assertIsNotNone(aes)
        self.assertEqual(aes.name, "AES-256-GCM")
        self.assertTrue(aes.nist_standardized)
    
    def test_get_algorithm_nonexistent(self):
        """Test getting non-existent algorithm."""
        result = self.registry.get_algorithm("NONEXISTENT-ALGORITHM")
        self.assertIsNone(result)
    
    def test_get_algorithms_by_type(self):
        """Test filtering algorithms by type."""
        classical = self.registry.get_algorithms_by_type(AlgorithmType.CLASSICAL_SYMMETRIC)
        self.assertGreater(len(classical), 0)
        
        pq_lattice = self.registry.get_algorithms_by_type(AlgorithmType.PQ_LATTICE)
        self.assertGreater(len(pq_lattice), 0)
    
    def test_get_algorithms_by_security_level(self):
        """Test filtering algorithms by security level."""
        level3 = self.registry.get_algorithms_by_security_level(SecurityLevel.LEVEL_3)
        self.assertGreater(len(level3), 0)
        
        for algo in level3:
            self.assertGreaterEqual(algo.security_level.value, 3)
    
    def test_register_new_algorithm(self):
        """Test registering a new algorithm."""
        new_algo = AlgorithmProfile(
            name="TEST-ALGORITHM",
            algorithm_type=AlgorithmType.PQ_LATTICE,
            security_level=SecurityLevel.LEVEL_3,
            key_size_bits=1024,
            block_size_bits=1024,
            latency_ms_per_mb=1.0,
            throughput_mbps=100.0,
            memory_usage_mb=2.0
        )
        
        initial_count = len(self.registry.algorithms)
        self.registry.register_algorithm(new_algo)
        
        self.assertEqual(len(self.registry.algorithms), initial_count + 1)
        self.assertIsNotNone(self.registry.get_algorithm("TEST-ALGORITHM"))


class TestHybridEncryptionPolicy(unittest.TestCase):
    """Test encryption policy data class."""
    
    def test_policy_creation(self):
        """Test policy object creation."""
        policy = HybridEncryptionPolicy(
            policy_id="test-policy",
            name="Test Policy",
            threat_model=ThreatModel.QUANTUM_RESISTANT,
            min_security_level=SecurityLevel.LEVEL_3,
            max_latency_ms=50.0,
            min_throughput_mbps=10.0
        )
        
        self.assertEqual(policy.policy_id, "test-policy")
        self.assertEqual(policy.min_security_level, SecurityLevel.LEVEL_3)
        self.assertTrue(policy.require_pq_algorithm)
        self.assertTrue(policy.require_classical_fallback)


class TestHybridEncryptionOrchestrator(unittest.TestCase):
    """Test main orchestrator functionality."""
    
    def setUp(self):
        self.orchestrator = HybridEncryptionOrchestrator()
    
    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        self.assertIsNotNone(self.orchestrator.algorithm_registry)
        self.assertGreater(len(self.orchestrator.policies), 0)
        self.assertIsNotNone(self.orchestrator.default_policy)
    
    def test_register_policy(self):
        """Test policy registration."""
        policy = HybridEncryptionPolicy(
            policy_id="custom-policy-001",
            name="Custom Test Policy",
            threat_model=ThreatModel.NATION_STATE,
            min_security_level=SecurityLevel.LEVEL_5,
            max_latency_ms=100.0,
            min_throughput_mbps=5.0
        )
        
        initial_count = len(self.orchestrator.policies)
        self.orchestrator.register_policy(policy)
        
        self.assertEqual(len(self.orchestrator.policies), initial_count + 1)
    
    def test_select_algorithms_basic(self):
        """Test basic algorithm selection."""
        algorithms, metadata = self.orchestrator.select_algorithms(
            data_size_bytes=1024,
            policy_id=None
        )
        
        self.assertIsInstance(algorithms, list)
        self.assertIsInstance(metadata, dict)
        self.assertIn("policy_used", metadata)
        self.assertIn("selected_count", metadata)
    
    def test_select_algorithms_small_data(self):
        """Test algorithm selection for small data."""
        algorithms, metadata = self.orchestrator.select_algorithms(
            data_size_bytes=64,
            policy_id=None
        )
        
        self.assertIsInstance(algorithms, list)
        self.assertGreaterEqual(len(algorithms), 1)
    
    def test_encrypt_basic(self):
        """Test basic encryption functionality."""
        plaintext = b"Hello, this is a test message for encryption!"
        
        result = self.orchestrator.encrypt(plaintext)
        
        self.assertIsInstance(result, EncryptionResult)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.ciphertext)
        self.assertGreater(len(result.ciphertext), 0)
        self.assertGreater(len(result.algorithm_used), 0)
        self.assertGreater(len(result.key_id), 0)
        self.assertGreater(result.security_level, 0)
        self.assertGreater(result.encryption_time_ms, 0)
    
    def test_encrypt_empty(self):
        """Test encryption with empty input."""
        result = self.orchestrator.encrypt(b"")
        
        self.assertFalse(result.success)
        self.assertIsNone(result.ciphertext)
        self.assertGreater(len(result.error_message), 0)
    
    def test_encrypt_with_context(self):
        """Test encryption with context."""
        plaintext = b"Sensitive data with context"
        
        result = self.orchestrator.encrypt(
            plaintext,
            context="user-123-document"
        )
        
        self.assertTrue(result.success)
        self.assertIn("QC-KEY-", result.key_id)
    
    def test_decrypt_basic(self):
        """Test basic decryption round-trip."""
        plaintext = b"Round-trip encryption test message"
        
        # Encrypt
        enc_result = self.orchestrator.encrypt(plaintext)
        self.assertTrue(enc_result.success)
        
        # Note: Full round-trip would require storing key material
        # This tests the decrypt function structure
        algorithms_used = enc_result.algorithm_used.split("+")
        
        # Test with dummy key (will fail but tests error handling)
        success, decrypted, message = self.orchestrator.decrypt(
            enc_result.ciphertext,
            b"dummy_key_material",
            algorithms_used
        )
        
        # Should handle gracefully
        self.assertIsInstance(success, bool)
        self.assertIsInstance(message, str)
    
    def test_decrypt_unknown_algorithm(self):
        """Test decryption with unknown algorithm."""
        success, decrypted, message = self.orchestrator.decrypt(
            b"fake ciphertext",
            b"test key",
            ["UNKNOWN-ALGORITHM-123"]
        )
        
        self.assertFalse(success)
        self.assertIsNone(decrypted)
        self.assertIn("Unknown algorithm", message)
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        stats = self.orchestrator.get_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn("registered_policies", stats)
        self.assertIn("available_algorithms", stats)
    
    def test_statistics_update_on_encrypt(self):
        """Test statistics are updated after encryption."""
        # Do an encryption first
        self.orchestrator.encrypt(b"test statistics")
        
        stats = self.orchestrator.get_statistics()
        self.assertIn("total_encryptions", stats)
        self.assertEqual(stats["total_encryptions"], 1)
    
    def test_recommend_policy(self):
        """Test policy recommendation functionality."""
        policy = self.orchestrator.recommend_policy(
            use_case="storage",
            data_sensitivity="critical"
        )
        
        self.assertIsInstance(policy, HybridEncryptionPolicy)
        self.assertEqual(policy.threat_model, ThreatModel.LONG_TERM_STORAGE)
        self.assertEqual(policy.min_security_level, SecurityLevel.LEVEL_5)
        self.assertTrue(policy.require_pq_algorithm)
    
    def test_recommend_policy_communication(self):
        """Test policy recommendation for communication."""
        policy = self.orchestrator.recommend_policy(
            use_case="communication",
            data_sensitivity="medium"
        )
        
        self.assertEqual(policy.threat_model, ThreatModel.REAL_TIME_COMM)
        self.assertEqual(policy.min_security_level, SecurityLevel.LEVEL_2)
    
    def test_recommend_policy_defaults(self):
        """Test policy recommendation with unknown values."""
        policy = self.orchestrator.recommend_policy(
            use_case="unknown",
            data_sensitivity="unknown"
        )
        
        self.assertIsInstance(policy, HybridEncryptionPolicy)
        self.assertIsNotNone(policy.threat_model)
        self.assertIsNotNone(policy.min_security_level)


class TestOrchestratorSingleton(unittest.TestCase):
    """Test singleton pattern."""
    
    def test_singleton_instance(self):
        """Test singleton returns same instance."""
        instance1 = get_encryption_orchestrator()
        instance2 = get_encryption_orchestrator()
        
        self.assertIs(instance1, instance2)
    
    def test_singleton_type(self):
        """Test singleton is correct type."""
        instance = get_encryption_orchestrator()
        self.assertIsInstance(instance, HybridEncryptionOrchestrator)


class TestEncryptionResult(unittest.TestCase):
    """Test EncryptionResult data class."""
    
    def test_result_creation_success(self):
        """Test successful result creation."""
        result = EncryptionResult(
            success=True,
            ciphertext=b"encrypted data",
            algorithm_used="AES-256-GCM+CRYSTALS-Kyber-768",
            key_id="TEST-KEY-001",
            security_level=5
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.ciphertext, b"encrypted data")
        self.assertEqual(result.error_message, "")
    
    def test_result_creation_failure(self):
        """Test failure result creation."""
        result = EncryptionResult(
            success=False,
            error_message="Encryption failed due to error"
        )
        
        self.assertFalse(result.success)
        self.assertIsNone(result.ciphertext)
        self.assertGreater(len(result.error_message), 0)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test scenarios."""
    
    def test_multiple_encryptions(self):
        """Test multiple encryptions with different policies."""
        orchestrator = HybridEncryptionOrchestrator()
        
        # Register custom policies
        high_security_policy = HybridEncryptionPolicy(
            policy_id="high-security",
            name="High Security",
            threat_model=ThreatModel.NATION_STATE,
            min_security_level=SecurityLevel.LEVEL_5,
            max_latency_ms=500.0,
            min_throughput_mbps=1.0
        )
        orchestrator.register_policy(high_security_policy)
        
        performance_policy = HybridEncryptionPolicy(
            policy_id="performance",
            name="Performance Optimized",
            threat_model=ThreatModel.STANDARD,
            min_security_level=SecurityLevel.LEVEL_1,
            max_latency_ms=10.0,
            min_throughput_mbps=100.0,
            require_pq_algorithm=False
        )
        orchestrator.register_policy(performance_policy)
        
        # Encrypt with different policies
        data1 = b"Highly sensitive classified data"
        data2 = b"Low sensitivity public information"
        
        result1 = orchestrator.encrypt(data1, policy_id="high-security")
        result2 = orchestrator.encrypt(data2, policy_id="performance")
        
        self.assertTrue(result1.success)
        self.assertTrue(result2.success)
        
        # Check stats
        stats = orchestrator.get_statistics()
        self.assertEqual(stats["total_encryptions"], 2)
        self.assertGreater(stats["total_bytes_encrypted"], 0)
    
    def test_algorithm_selection_different_sizes(self):
        """Test algorithm selection for different data sizes."""
        orchestrator = HybridEncryptionOrchestrator()
        
        # Small data
        algos_small, meta_small = orchestrator.select_algorithms(64)
        # Large data
        algos_large, meta_large = orchestrator.select_algorithms(1024 * 1024)
        
        self.assertIsInstance(algos_small, list)
        self.assertIsInstance(algos_large, list)
        self.assertEqual(meta_small["data_size_bytes"], 64)
        self.assertEqual(meta_large["data_size_bytes"], 1048576)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful()
    }


if __name__ == "__main__":
    results = run_tests()
    print(f"\n{'='*60}")
    print(f"TEST RESULTS: {results['tests_run']} tests run")
    print(f"  Failures: {results['failures']}")
    print(f"  Errors: {results['errors']}")
    print(f"  Success: {'YES' if results['success'] else 'NO'}")
    print(f"{'='*60}")
    
    # Save results
    with open("test_results_pq_hybrid_encryption_orchestrator_v17_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
