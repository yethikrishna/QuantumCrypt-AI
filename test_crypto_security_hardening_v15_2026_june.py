"""
Test Suite for QuantumCrypt-AI Crypto Security Hardening v15
Dimension B - Security Hardening
ADD-ONLY VERIFICATION - Tests verify new functionality without breaking existing code
"""

import unittest
import secrets
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_security_hardening_v15_2026_june import (
    NISTSecurityLevel,
    KeyType,
    AlgorithmCategory,
    ValidatedKey,
    ConstantTimeOperations,
    KeyMaterialValidator,
    SecureKeyLifecycleManager,
    PQSecurityHardeningWrapper,
    AlgorithmDowngradeProtection,
    CryptoSecurityHardeningPipeline
)


class TestConstantTimeOperations(unittest.TestCase):
    """Test side-channel resistant constant-time operations."""
    
    def test_constant_time_compare_equal(self):
        """Test equal bytes compare correctly."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        self.assertTrue(ConstantTimeOperations.compare(a, b))
    
    def test_constant_time_compare_not_equal(self):
        """Test non-equal bytes compare correctly."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        self.assertFalse(ConstantTimeOperations.compare(a, b))
    
    def test_constant_time_string_compare(self):
        """Test string comparison."""
        self.assertTrue(ConstantTimeOperations.compare_strings("test", "test"))
        self.assertFalse(ConstantTimeOperations.compare_strings("test", "TEST"))
    
    def test_secure_memzero(self):
        """Test memory zeroization."""
        buffer = bytearray(secrets.token_bytes(32))
        original = bytes(buffer)
        
        ConstantTimeOperations.secure_memzero(buffer)
        
        # Buffer should be all zeros
        self.assertEqual(len(buffer), 32)
        self.assertEqual(sum(buffer), 0)
        # Original content should be gone
        self.assertNotEqual(bytes(buffer), original)
    
    def test_timing_jitter(self):
        """Test timing jitter function executes without error."""
        # Should complete without raising exceptions
        ConstantTimeOperations.timing_noise_jitter(base_delay_ms=0.1, max_jitter_ms=0.5)


class TestKeyMaterialValidator(unittest.TestCase):
    """Test key material validation."""
    
    def setUp(self):
        self.validator = KeyMaterialValidator()
    
    def test_valid_key_validation(self):
        """Test valid 32-byte key passes validation."""
        good_key = secrets.token_bytes(32)  # 256 bits = NIST Level 5
        
        validated = self.validator.validate_key(
            good_key, KeyType.SYMMETRIC, "AES-256-GCM", NISTSecurityLevel.NIST_LEVEL_5
        )
        
        self.assertTrue(validated.validation_passed)
        self.assertEqual(validated.byte_length, 32)
        self.assertEqual(validated.key_type, KeyType.SYMMETRIC)
        self.assertGreater(len(validated.key_id), 0)
    
    def test_short_key_fails_validation(self):
        """Test too-short key fails validation."""
        short_key = secrets.token_bytes(8)  # Only 64 bits
        
        validated = self.validator.validate_key(
            short_key, KeyType.SYMMETRIC, "AES-256-GCM", NISTSecurityLevel.NIST_LEVEL_5
        )
        
        self.assertFalse(validated.validation_passed)
    
    def test_weak_pattern_detection(self):
        """Test obviously weak patterns are detected."""
        weak_key = b'\x00' * 32  # All zeros
        
        validated = self.validator.validate_key(
            weak_key, KeyType.SYMMETRIC, "AES-256-GCM", NISTSecurityLevel.NIST_LEVEL_5
        )
        
        self.assertFalse(validated.validation_passed)
    
    def test_algorithm_categorization(self):
        """Test algorithm categorization works."""
        # Post-quantum algorithm
        pq_key = secrets.token_bytes(32)
        validated_pq = self.validator.validate_key(
            pq_key, KeyType.PQ_KEM_PRIVATE, "KYBER-768", NISTSecurityLevel.NIST_LEVEL_3
        )
        self.assertEqual(validated_pq.category, AlgorithmCategory.POST_QUANTUM)
        
        # Classical algorithm
        classical_key = secrets.token_bytes(32)
        validated_classical = self.validator.validate_key(
            classical_key, KeyType.SYMMETRIC, "AES-256-GCM", NISTSecurityLevel.NIST_LEVEL_5
        )
        self.assertEqual(validated_classical.category, AlgorithmCategory.CLASSICAL)
    
    def test_validation_stats(self):
        """Test validation statistics are tracked."""
        validator = KeyMaterialValidator()
        
        # Validate some keys
        validator.validate_key(secrets.token_bytes(32), KeyType.SYMMETRIC, "AES-256")
        validator.validate_key(secrets.token_bytes(8), KeyType.SYMMETRIC, "WEAK")
        
        stats = validator.get_validation_stats()
        
        self.assertGreaterEqual(stats["total_validated"], 2)
        self.assertIn("passed", stats)
        self.assertIn("failed", stats)


class TestSecureKeyLifecycleManager(unittest.TestCase):
    """Test secure key lifecycle management."""
    
    def setUp(self):
        self.manager = SecureKeyLifecycleManager(max_key_uses=100)
        self.validator = KeyMaterialValidator()
    
    def test_key_registration(self):
        """Test valid key registration."""
        key_material = secrets.token_bytes(32)
        validated = self.validator.validate_key(
            key_material, KeyType.SYMMETRIC, "AES-256", NISTSecurityLevel.NIST_LEVEL_5
        )
        
        self.manager.register_key(validated)
        
        status = self.manager.get_key_status(validated.key_id)
        self.assertIsNotNone(status)
        self.assertTrue(status["validation_passed"])
        self.assertFalse(status["zeroized"])
    
    def test_unvalidated_key_rejected(self):
        """Test unvalidated keys cannot be registered."""
        invalid_key = ValidatedKey(
            key_id="test",
            key_type=KeyType.SYMMETRIC,
            algorithm="TEST",
            nist_level=NISTSecurityLevel.NIST_LEVEL_1,
            category=AlgorithmCategory.CLASSICAL,
            byte_length=32,
            created_timestamp=0.0,
            validation_passed=False
        )
        
        with self.assertRaises(ValueError):
            self.manager.register_key(invalid_key)
    
    def test_key_usage_tracking(self):
        """Test key usage is tracked."""
        key_material = secrets.token_bytes(32)
        validated = self.validator.validate_key(
            key_material, KeyType.SYMMETRIC, "AES-256", NISTSecurityLevel.NIST_LEVEL_5
        )
        self.manager.register_key(validated)
        
        # Track usage multiple times
        for i in range(50):
            self.manager.track_key_usage(validated.key_id)
        
        status = self.manager.get_key_status(validated.key_id)
        self.assertEqual(status["usage_count"], 50)
    
    def test_key_zeroization(self):
        """Test secure key zeroization."""
        key_material = secrets.token_bytes(32)
        key_buffer = bytearray(key_material)
        validated = self.validator.validate_key(
            key_material, KeyType.SYMMETRIC, "AES-256", NISTSecurityLevel.NIST_LEVEL_5
        )
        self.manager.register_key(validated)
        
        self.manager.secure_zeroize_key(validated.key_id, key_buffer)
        
        # Buffer should be zeroed
        self.assertEqual(sum(key_buffer), 0)
        
        # Key should be marked as zeroized and removed from active keys
        status = self.manager.get_key_status(validated.key_id)
        self.assertIsNone(status)


class TestPQSecurityHardeningWrapper(unittest.TestCase):
    """Test post-quantum security hardening wrapper."""
    
    def setUp(self):
        self.wrapper = PQSecurityHardeningWrapper()
    
    def test_key_generation_wrapping(self):
        """Test wrapping key generation functions."""
        def mock_key_gen():
            return secrets.token_bytes(32)
        
        key_material, validated = self.wrapper.wrap_key_generation(
            mock_key_gen, "KYBER-768", KeyType.PQ_KEM_PRIVATE
        )
        
        self.assertEqual(len(key_material), 32)
        self.assertTrue(validated.validation_passed)
        self.assertEqual(validated.algorithm, "KYBER-768")
        self.assertEqual(validated.category, AlgorithmCategory.POST_QUANTUM)
    
    def test_constant_time_secret_comparison(self):
        """Test secret comparison."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        c = secrets.token_bytes(32)
        
        self.assertTrue(self.wrapper.constant_time_compare_secrets(a, b))
        self.assertFalse(self.wrapper.constant_time_compare_secrets(a, c))
    
    def test_operation_stats(self):
        """Test operation statistics."""
        def mock_gen():
            return secrets.token_bytes(32)
        
        self.wrapper.wrap_key_generation(mock_gen, "KYBER-768", KeyType.PQ_KEM_PRIVATE)
        
        stats = self.wrapper.get_operation_stats()
        self.assertGreaterEqual(stats["key_generation"], 1)


class TestAlgorithmDowngradeProtection(unittest.TestCase):
    """Test algorithm downgrade attack protection."""
    
    def setUp(self):
        self.protection = AlgorithmDowngradeProtection(
            minimum_security_level=NISTSecurityLevel.NIST_LEVEL_1
        )
    
    def test_valid_algorithm_negotiation(self):
        """Test valid algorithm negotiation."""
        allowed, selected = self.protection.validate_algorithm_negotiation(
            "KYBER-768", "AES-256-GCM"
        )
        
        self.assertTrue(allowed)
        self.assertIn(selected, ["KYBER-768", "AES-256-GCM"])
    
    def test_strongest_algorithm_selected(self):
        """Test that strongest common algorithm is always selected."""
        # KYBER-1024 (Level 5) vs AES-128-GCM (Level 1)
        allowed, selected = self.protection.validate_algorithm_negotiation(
            "KYBER-1024", "AES-128-GCM"
        )
        
        self.assertTrue(allowed)
        self.assertEqual(selected, "KYBER-1024")  # Should pick stronger one
    
    def test_weak_algorithm_blocked(self):
        """Test weak algorithms below minimum level are blocked."""
        strict_protection = AlgorithmDowngradeProtection(
            minimum_security_level=NISTSecurityLevel.NIST_LEVEL_5
        )
        
        # AES-128 is only Level 1, should be blocked
        allowed, selected = strict_protection.validate_algorithm_negotiation(
            "AES-128-GCM", "AES-128-GCM"
        )
        
        self.assertFalse(allowed)
    
    def test_unknown_algorithm_blocked(self):
        """Test unknown algorithms are blocked."""
        allowed, selected = self.protection.validate_algorithm_negotiation(
            "WEAK-CRYPTO", "AES-256-GCM"
        )
        
        self.assertFalse(allowed)
    
    def test_downgrade_protection_stats(self):
        """Test downgrade protection statistics."""
        stats = self.protection.get_downgrade_protection_stats()
        self.assertIn("allowed_algorithms_count", stats)
        self.assertIn("downgrade_attempts_blocked", stats)
        self.assertGreater(stats["allowed_algorithms_count"], 0)


class TestCryptoSecurityHardeningPipeline(unittest.TestCase):
    """Test complete crypto security hardening pipeline."""
    
    def test_pipeline_creation(self):
        """Test pipeline can be created with various configurations."""
        pipeline = CryptoSecurityHardeningPipeline(
            enable_constant_time=True,
            enable_key_validation=True,
            enable_lifecycle=True,
            enable_pq_hardening=True,
            enable_downgrade_protection=True
        )
        self.assertIsNotNone(pipeline)
    
    def test_secure_operation_wrapping(self):
        """Test wrapping operations with security hardening."""
        pipeline = CryptoSecurityHardeningPipeline()
        
        def mock_encrypt(data: bytes) -> bytes:
            return data[::-1]  # Dummy "encryption"
        
        test_data = b"test message"
        result = pipeline.secure_operation("encryption", mock_encrypt, test_data)
        
        self.assertEqual(result, mock_encrypt(test_data))
        
        stats = pipeline.get_pipeline_stats()
        self.assertGreaterEqual(stats["operations_secured"], 1)
    
    def test_pipeline_with_modules_disabled(self):
        """Test pipeline works with modules disabled."""
        pipeline = CryptoSecurityHardeningPipeline(
            enable_constant_time=False,
            enable_key_validation=False,
            enable_lifecycle=False,
            enable_pq_hardening=False,
            enable_downgrade_protection=False
        )
        
        def mock_op():
            return "success"
        
        result = pipeline.secure_operation("test", mock_op)
        self.assertEqual(result, "success")


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of all security hardening components."""
    
    def test_concurrent_key_validation(self):
        """Test validator handles concurrent validation."""
        validator = KeyMaterialValidator()
        errors = []
        
        def validate_worker():
            try:
                for i in range(20):
                    key = secrets.token_bytes(32)
                    validator.validate_key(key, KeyType.SYMMETRIC, f"ALGO_{i}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=validate_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
    
    def test_concurrent_lifecycle_management(self):
        """Test lifecycle manager handles concurrent access."""
        manager = SecureKeyLifecycleManager()
        validator = KeyMaterialValidator()
        errors = []
        
        # Register a test key
        key = secrets.token_bytes(32)
        validated = validator.validate_key(key, KeyType.SYMMETRIC, "TEST")
        manager.register_key(validated)
        key_id = validated.key_id
        
        def usage_worker():
            try:
                for i in range(50):
                    manager.track_key_usage(key_id)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=usage_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        
        status = manager.get_key_status(key_id)
        self.assertEqual(status["usage_count"], 500)  # 10 threads × 50 iterations


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestConstantTimeOperations)
    suite.addTests(loader.loadTestsFromTestCase(TestKeyMaterialValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureKeyLifecycleManager))
    suite.addTests(loader.loadTestsFromTestCase(TestPQSecurityHardeningWrapper))
    suite.addTests(loader.loadTestsFromTestCase(TestAlgorithmDowngradeProtection))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoSecurityHardeningPipeline))
    suite.addTests(loader.loadTestsFromTestCase(TestThreadSafety))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY - QuantumCrypt-AI Security Hardening v15")
    print(f"{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
