#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Password Hasher & KDF
June 2026 Production Release
Real working tests with actual execution
"""

import sys
import time
import unittest
import hmac

# Add module path
sys.path.insert(0, '.')

from quantum_crypt.post_quantum_password_hasher_kdf_2026_june import (
    PostQuantumPasswordHasher,
    SecurityLevel,
    HashAlgorithm,
    HashResult,
    VerificationResult
)


class TestPostQuantumPasswordHasher(unittest.TestCase):
    """Real working tests for password hasher and KDF"""

    def setUp(self):
        """Set up test hasher instances"""
        self.standard_hasher = PostQuantumPasswordHasher(
            security_level=SecurityLevel.STANDARD
        )
        self.elevated_hasher = PostQuantumPasswordHasher(
            security_level=SecurityLevel.ELEVATED
        )

    def test_initialization(self):
        """Test proper initialization"""
        self.assertIsNotNone(self.standard_hasher)
        self.assertEqual(self.standard_hasher.security_level, SecurityLevel.STANDARD)
        self.assertEqual(self.standard_hasher.algorithm, HashAlgorithm.SHA3_512)
        self.assertGreater(self.standard_hasher.iterations, 0)
        self.assertGreater(self.standard_hasher.memory_cost, 0)
        print("✓ Initialization test passed")

    def test_salt_generation(self):
        """Test cryptographically secure salt generation"""
        salt1 = self.standard_hasher.generate_salt()
        salt2 = self.standard_hasher.generate_salt()

        # Salts should be proper length
        self.assertEqual(len(salt1), self.standard_hasher.salt_length)
        self.assertEqual(len(salt2), self.standard_hasher.salt_length)

        # Salts should be unique
        self.assertNotEqual(salt1, salt2)

        print("✓ Salt generation test passed")

    def test_password_hashing_basic(self):
        """Test basic password hashing functionality"""
        password = "MySecurePassword123!"
        result = self.standard_hasher.hash_password(password)

        # Verify result structure
        self.assertIsInstance(result, HashResult)
        self.assertIsNotNone(result.hash_hex)
        self.assertIsNotNone(result.salt_hex)
        self.assertGreater(len(result.hash_hex), 0)
        self.assertGreater(len(result.salt_hex), 0)

        # Hash should be hex string
        int(result.hash_hex, 16)  # Should not raise ValueError
        int(result.salt_hex, 16)

        print("✓ Basic password hashing test passed")

    def test_hashing_determinism_with_salt(self):
        """Test that same password + same salt = same hash"""
        password = "TestPassword456!"
        salt = self.standard_hasher.generate_salt()

        result1 = self.standard_hasher.hash_password(password, salt)
        result2 = self.standard_hasher.hash_password(password, salt)

        # Hashes should be identical
        self.assertEqual(result1.hash_hex, result2.hash_hex)
        self.assertEqual(result1.salt_hex, result2.salt_hex)

        print("✓ Hashing determinism test passed")

    def test_hashing_uniqueness(self):
        """Test that different passwords produce different hashes"""
        result1 = self.standard_hasher.hash_password("Password1")
        result2 = self.standard_hasher.hash_password("Password2")

        # Hashes should be different
        self.assertNotEqual(result1.hash_hex, result2.hash_hex)
        # Salts should be different
        self.assertNotEqual(result1.salt_hex, result2.salt_hex)

        print("✓ Hashing uniqueness test passed")

    def test_password_verification_correct(self):
        """Test verification of correct password"""
        password = "CorrectHorseBatteryStaple"
        hash_result = self.standard_hasher.hash_password(password)

        stored_params = {
            'iterations': hash_result.iterations,
            'memory_cost': hash_result.memory_cost,
            'algorithm': hash_result.algorithm
        }

        verification = self.standard_hasher.verify_password(
            password,
            hash_result.hash_hex,
            hash_result.salt_hex,
            stored_params
        )

        self.assertIsInstance(verification, VerificationResult)
        self.assertTrue(verification.verified)
        self.assertTrue(verification.hash_match)
        self.assertGreater(verification.verification_time_ms, 0)

        print("✓ Correct password verification test passed")

    def test_password_verification_incorrect(self):
        """Test verification rejects wrong password"""
        correct_password = "RealPassword123"
        wrong_password = "FakePassword456"

        hash_result = self.standard_hasher.hash_password(correct_password)

        stored_params = {
            'iterations': hash_result.iterations,
            'memory_cost': hash_result.memory_cost,
            'algorithm': hash_result.algorithm
        }

        verification = self.standard_hasher.verify_password(
            wrong_password,
            hash_result.hash_hex,
            hash_result.salt_hex,
            stored_params
        )

        self.assertFalse(verification.verified)
        self.assertFalse(verification.hash_match)

        print("✓ Incorrect password rejection test passed")

    def test_key_derivation(self):
        """Test key derivation functionality"""
        password = "MasterPassword123"
        salt = self.standard_hasher.generate_salt()

        # Derive different keys for different contexts
        key1 = self.standard_hasher.derive_key(password, salt, context="encryption", key_length=32)
        key2 = self.standard_hasher.derive_key(password, salt, context="authentication", key_length=32)

        # Keys should be correct length
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)

        # Different contexts should produce different keys
        self.assertNotEqual(key1, key2)

        # Same context should be deterministic
        key1_again = self.standard_hasher.derive_key(password, salt, context="encryption", key_length=32)
        self.assertEqual(key1, key1_again)

        print("✓ Key derivation test passed")

    def test_storage_string_format(self):
        """Test PHC-style storage string creation and parsing"""
        password = "StorageTest789"
        hash_result = self.standard_hasher.hash_password(password)

        # Create storage string
        storage_str = self.standard_hasher.create_storage_string(hash_result)

        # Should start with version marker
        self.assertTrue(storage_str.startswith('$pqphv1$'))

        # Parse it back
        parsed_hash, parsed_salt, parsed_params = self.standard_hasher.parse_storage_string(storage_str)

        # Should match original
        self.assertEqual(parsed_hash, hash_result.hash_hex)
        self.assertEqual(parsed_salt, hash_result.salt_hex)
        self.assertEqual(parsed_params['iterations'], hash_result.iterations)

        print("✓ Storage string format test passed")

    def test_security_levels(self):
        """Test different security levels produce different behavior"""
        password = "SecurityLevelTest"

        # Standard level should be faster
        start_standard = time.time()
        self.standard_hasher.hash_password(password)
        time_standard = time.time() - start_standard

        # Elevated level should take longer
        start_elevated = time.time()
        self.elevated_hasher.hash_password(password)
        time_elevated = time.time() - start_elevated

        # Both should complete
        self.assertGreater(time_standard, 0)
        self.assertGreater(time_elevated, 0)

        # Elevated should have higher memory cost
        self.assertGreater(self.elevated_hasher.memory_cost, self.standard_hasher.memory_cost)

        print("✓ Security levels test passed")

    def test_different_algorithms(self):
        """Test different hash algorithms work"""
        algorithms = [HashAlgorithm.SHA3_256, HashAlgorithm.SHA3_512, HashAlgorithm.BLAKE2B]

        for algo in algorithms:
            hasher = PostQuantumPasswordHasher(algorithm=algo)
            result = hasher.hash_password("AlgorithmTest")
            self.assertEqual(result.algorithm, algo.value)
            self.assertGreater(len(result.hash_hex), 0)

        print("✓ Different algorithms test passed")

    def test_upgrade_detection(self):
        """Test parameter upgrade recommendation"""
        # Create hash with standard parameters
        hasher = PostQuantumPasswordHasher(security_level=SecurityLevel.STANDARD)
        result = hasher.hash_password("UpgradeTest")

        # Verify with same hasher - should match, no upgrade needed
        stored_params = {
            'iterations': result.iterations,
            'memory_cost': result.memory_cost,
            'algorithm': result.algorithm
        }
        verification = hasher.verify_password(
            "UpgradeTest",
            result.hash_hex,
            result.salt_hex,
            stored_params
        )

        # Should verify correctly
        self.assertTrue(verification.hash_match)
        self.assertTrue(verification.parameters_match)
        self.assertFalse(verification.upgrade_recommended)

        # Now simulate weaker old parameters
        old_params = {
            'iterations': 1,  # Weaker than current
            'memory_cost': 32768,  # Weaker than current
            'algorithm': result.algorithm
        }

        # Check if upgrade would be recommended
        verification2 = hasher.verify_password(
            "UpgradeTest",
            result.hash_hex,
            result.salt_hex,
            old_params
        )

        # Hash matches but old parameters trigger upgrade recommendation
        self.assertTrue(verification2.hash_match)
        self.assertFalse(verification2.parameters_match)
        self.assertTrue(verification2.upgrade_recommended)

        print("✓ Upgrade detection test passed")

    def test_benchmark_functionality(self):
        """Test benchmarking functionality"""
        benchmark = self.standard_hasher.benchmark()

        self.assertIn('hash_time_ms', benchmark)
        self.assertIn('memory_cost_mb', benchmark)
        self.assertIn('iterations', benchmark)
        self.assertGreater(benchmark['hash_time_ms'], 0)
        self.assertGreater(benchmark['memory_cost_mb'], 0)

        print("✓ Benchmark functionality test passed")

    def test_empty_password_handling(self):
        """Test handling of empty passwords"""
        result = self.standard_hasher.hash_password("")
        self.assertIsNotNone(result.hash_hex)
        self.assertGreater(len(result.hash_hex), 0)

        # Should verify correctly
        stored_params = {'iterations': result.iterations, 'memory_cost': result.memory_cost}
        verification = self.standard_hasher.verify_password(
            "", result.hash_hex, result.salt_hex, stored_params
        )
        self.assertTrue(verification.verified)

        print("✓ Empty password handling test passed")

    def test_long_password(self):
        """Test handling of very long passwords"""
        long_password = "A" * 1000  # 1000 character password
        result = self.standard_hasher.hash_password(long_password)
        self.assertIsNotNone(result.hash_hex)

        verification = self.standard_hasher.verify_password(
            long_password, result.hash_hex, result.salt_hex,
            {'iterations': result.iterations, 'memory_cost': result.memory_cost}
        )
        self.assertTrue(verification.verified)

        print("✓ Long password handling test passed")


def run_comprehensive_test():
    """Run all tests and generate comprehensive report"""
    print("=" * 70)
    print("POST-QUANTUM PASSWORD HASHER & KDF - TEST SUITE")
    print("June 2026 Production Release")
    print("=" * 70)
    print()

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPostQuantumPasswordHasher)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'✓ ALL TESTS PASSED' if result.wasSuccessful() else '✗ SOME TESTS FAILED'}")
    print()

    # Demonstration of actual usage
    print("=" * 70)
    print("LIVE DEMONSTRATION - ACTUAL PASSWORD HASHING")
    print("=" * 70)

    hasher = PostQuantumPasswordHasher(security_level=SecurityLevel.STANDARD)
    test_passwords = [
        "user_password_123",
        "MySecurePass!2026",
        "correct horse battery staple",
        "a" * 100,
    ]

    print("\nHashing real passwords...")
    for i, password in enumerate(test_passwords, 1):
        start = time.time()
        result = hasher.hash_password(password)
        elapsed = (time.time() - start) * 1000

        print(f"\n  Password {i}: '{password[:20]}...'")
        print(f"    Hash: {result.hash_hex[:32]}...")
        print(f"    Salt: {result.salt_hex[:16]}...")
        print(f"    Time: {elapsed:.2f}ms")

        # Verify
        verify_result = hasher.verify_password(
            password, result.hash_hex, result.salt_hex,
            {'iterations': result.iterations, 'memory_cost': result.memory_cost}
        )
        print(f"    Verified: {'✓ PASS' if verify_result.verified else '✗ FAIL'}")

    # Key derivation demo
    print("\n" + "=" * 70)
    print("KEY DERIVATION DEMONSTRATION")
    print("=" * 70)

    master_password = "MasterSecretKey2026!"
    salt = hasher.generate_salt()

    for context in ["encryption", "authentication", "backup"]:
        key = hasher.derive_key(master_password, salt, context=context, key_length=32)
        print(f"\n  Context: {context}")
        print(f"    Key: {key.hex()}")

    print("\n" + "=" * 70)
    print("PERFORMANCE BENCHMARK")
    print("=" * 70)

    for level in [SecurityLevel.STANDARD, SecurityLevel.ELEVATED]:
        benchmark_hasher = PostQuantumPasswordHasher(security_level=level)
        bench = benchmark_hasher.benchmark()
        print(f"\n  {level.value.upper()}:")
        print(f"    Hash Time: {bench['hash_time_ms']:.2f}ms")
        print(f"    Memory: {bench['memory_cost_mb']} MB")
        print(f"    Iterations: {bench['iterations']}")

    print()
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)
