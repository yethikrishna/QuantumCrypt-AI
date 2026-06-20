#!/usr/bin/env python3
"""
Test suite for QuantumCrypt AI - Post-Quantum Side-Channel Resistant RNG
Production-grade tests with real cryptographic validation
"""

import sys
import os
import json
import unittest
import statistics
from datetime import datetime
from collections import Counter

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_side_channel_resistant_rng_2026_june import (
    SideChannelResistantRNG,
    RNGHealthStatus,
    EntropySource,
    get_side_channel_rng
)


class TestConstantTimeOperations(unittest.TestCase):
    """Test side-channel resistant constant-time operations"""
    
    def setUp(self):
        self.rng = SideChannelResistantRNG()
    
    def test_constant_time_compare_equal(self):
        """Test constant-time compare with equal bytes"""
        a = b'\x01\x02\x03\x04'
        b = b'\x01\x02\x03\x04'
        self.assertTrue(self.rng._constant_time_compare(a, b))
    
    def test_constant_time_compare_different(self):
        """Test constant-time compare with different bytes"""
        a = b'\x01\x02\x03\x04'
        b = b'\x01\x02\x03\x05'
        self.assertFalse(self.rng._constant_time_compare(a, b))
    
    def test_constant_time_compare_length_mismatch(self):
        """Test constant-time compare with length mismatch"""
        a = b'\x01\x02'
        b = b'\x01\x02\x03\x04'
        self.assertFalse(self.rng._constant_time_compare(a, b))


class TestEntropyCollection(unittest.TestCase):
    """Test entropy collection mechanisms"""
    
    def setUp(self):
        self.rng = SideChannelResistantRNG()
    
    def test_os_entropy_collection(self):
        """Test OS entropy collection"""
        entropy = self.rng._collect_os_entropy(32)
        self.assertEqual(len(entropy), 32)
        self.assertIsInstance(entropy, bytes)
    
    def test_time_entropy_collection(self):
        """Test time-based entropy collection"""
        entropy = self.rng._collect_time_entropy(32)
        self.assertEqual(len(entropy), 32)
        self.assertIsInstance(entropy, bytes)
    
    def test_process_noise_entropy(self):
        """Test process noise entropy collection"""
        entropy = self.rng._collect_process_noise(32)
        self.assertEqual(len(entropy), 32)
        self.assertIsInstance(entropy, bytes)
    
    def test_thread_noise_entropy(self):
        """Test thread noise entropy collection"""
        entropy = self.rng._collect_thread_noise(32)
        self.assertEqual(len(entropy), 32)
        self.assertIsInstance(entropy, bytes)
    
    def test_entropy_mixing(self):
        """Test HKDF-based entropy mixing"""
        mixed = self.rng._mix_entropy_sources(64)
        self.assertEqual(len(mixed), 64)
        self.assertIsInstance(mixed, bytes)
        # Verify not all zeros (basic sanity check)
        self.assertNotEqual(mixed, b'\x00' * 64)


class TestHKDFImplementation(unittest.TestCase):
    """Test HKDF key derivation"""
    
    def setUp(self):
        self.rng = SideChannelResistantRNG()
    
    def test_hkdf_output_length(self):
        """Test HKDF produces correct output length"""
        salt = b'salt'
        ikm = b'input key material'
        info = b'test context'
        
        for length in [16, 32, 64, 128]:
            result = self.rng._hkdf_extract_expand(salt, ikm, info, length)
            self.assertEqual(len(result), length)
    
    def test_hkdf_deterministic(self):
        """Test HKDF is deterministic with same inputs"""
        salt = b'salt'
        ikm = b'input key material'
        info = b'test context'
        
        result1 = self.rng._hkdf_extract_expand(salt, ikm, info, 32)
        result2 = self.rng._hkdf_extract_expand(salt, ikm, info, 32)
        self.assertEqual(result1, result2)
    
    def test_hkdf_different_inputs(self):
        """Test HKDF produces different outputs for different inputs"""
        result1 = self.rng._hkdf_extract_expand(b'salt1', b'ikm1', b'info1', 32)
        result2 = self.rng._hkdf_extract_expand(b'salt2', b'ikm2', b'info2', 32)
        self.assertNotEqual(result1, result2)


class TestRandomByteGeneration(unittest.TestCase):
    """Test core random byte generation"""
    
    def setUp(self):
        self.rng = SideChannelResistantRNG()
    
    def test_random_bytes_length(self):
        """Test random bytes returns correct length"""
        for length in [1, 16, 32, 64, 128, 1024]:
            result = self.rng.random_bytes(length)
            self.assertEqual(len(result), length)
            self.assertIsInstance(result, bytes)
    
    def test_random_bytes_not_zero(self):
        """Test random bytes aren't all zeros"""
        result = self.rng.random_bytes(1024)
        zero_count = result.count(b'\x00')
        # Should have some zeros but not all
        self.assertLess(zero_count, 1024)
    
    def test_random_bytes_distribution(self):
        """Test byte value distribution is roughly uniform"""
        data = self.rng.random_bytes(10000)
        counts = Counter(data)
        
        # Each byte value should appear roughly equally
        expected = 10000 / 256
        max_deviation = max(abs(count - expected) for count in counts.values())
        
        # Allow reasonable deviation for small sample
        self.assertLess(max_deviation, expected * 0.5)
    
    def test_zero_bytes_request(self):
        """Test requesting zero bytes returns empty"""
        result = self.rng.random_bytes(0)
        self.assertEqual(result, b'')
    
    def test_negative_bytes_request(self):
        """Test negative bytes returns empty"""
        result = self.rng.random_bytes(-10)
        self.assertEqual(result, b'')


class TestRandomIntegerGeneration(unittest.TestCase):
    """Test unbiased random integer generation"""
    
    def setUp(self):
        self.rng = SideChannelResistantRNG()
    
    def test_random_int_range(self):
        """Test integers are within specified range"""
        min_val = 10
        max_val = 100
        
        for _ in range(100):
            value = self.rng.random_int(min_val, max_val)
            self.assertGreaterEqual(value, min_val)
            self.assertLessEqual(value, max_val)
    
    def test_random_int_equal_bounds(self):
        """Test equal bounds returns that value"""
        self.assertEqual(self.rng.random_int(5, 5), 5)
        self.assertEqual(self.rng.random_int(0, 0), 0)
    
    def test_random_int_min_greater_max(self):
        """Test min > max returns min"""
        self.assertEqual(self.rng.random_int(100, 50), 100)
    
    def test_random_int_distribution(self):
        """Test integer distribution is roughly uniform"""
        samples = [self.rng.random_int(0, 9) for _ in range(1000)]
        counts = Counter(samples)
        
        # Each digit 0-9 should appear ~100 times
        expected = 100
        for digit in range(10):
            self.assertGreater(counts[digit], 50)  # Very loose bound
    
    def test_random_int_large_range(self):
        """Test large range generation"""
        value = self.rng.random_int(0, 2**64 - 1)
        self.assertIsInstance(value, int)
        self.assertGreaterEqual(value, 0)
        self.assertLessEqual(value, 2**64 - 1)


class TestHealthTesting(unittest.TestCase):
    """Test NIST SP 800-90B health testing"""
    
    def setUp(self):
        self.rng = SideChannelResistantRNG()
    
    def test_monobit_test_good_data(self):
        """Test monobit test passes on good random data"""
        # Generate truly random data from OS
        good_data = os.urandom(1024)
        result = self.rng._health_test_monobit(good_data)
        # Should pass for true random data
        self.assertTrue(result)
    
    def test_runs_test_good_data(self):
        """Test runs test passes on good random data"""
        good_data = os.urandom(1024)
        result = self.rng._health_test_runs(good_data)
        self.assertTrue(result)
    
    def test_health_status_reporting(self):
        """Test health status is reported correctly"""
        status = self.rng.get_health_status()
        self.assertIn('health_status', status)
        self.assertIn('statistics', status)
        self.assertIn('entropy_sources', status)
    
    def test_statistics_tracking(self):
        """Test statistics are tracked correctly"""
        initial = self.rng.get_health_status()['statistics']
        self.rng.random_bytes(1000)
        final = self.rng.get_health_status()['statistics']
        
        self.assertGreater(
            final['total_bytes_generated'],
            initial['total_bytes_generated']
        )


class TestReseeding(unittest.TestCase):
    """Test reseeding and prediction resistance"""
    
    def test_initial_seed(self):
        """Test initial seeding occurs"""
        rng = SideChannelResistantRNG()
        status = rng.get_health_status()
        self.assertGreater(status['statistics']['total_seed_refreshes'], 0)
    
    def test_manual_reseed(self):
        """Test manual reseeding works"""
        rng = SideChannelResistantRNG()
        initial = rng.get_health_status()['statistics']['total_seed_refreshes']
        rng.reseed_manually()
        final = rng.get_health_status()['statistics']['total_seed_refreshes']
        self.assertGreater(final, initial)
    
    def test_prediction_resistance(self):
        """Test prediction resistance mode reseeds frequently"""
        rng = SideChannelResistantRNG(prediction_resistance=True)
        initial = rng.get_health_status()['statistics']['total_seed_refreshes']
        rng.random_bytes(32)
        rng.random_bytes(32)
        final = rng.get_health_status()['statistics']['total_seed_refreshes']
        # With prediction resistance, each call should reseed
        self.assertGreater(final, initial)


class TestSingleton(unittest.TestCase):
    """Test singleton pattern"""
    
    def test_singleton_returns_same_instance(self):
        """Test singleton returns same instance"""
        rng1 = get_side_channel_rng()
        rng2 = get_side_channel_rng()
        self.assertIs(rng1, rng2)


def run_cryptographic_validation():
    """Run comprehensive cryptographic validation"""
    print("\n" + "=" * 70)
    print("CRYPTOGRAPHIC VALIDATION: Side-Channel Resistant RNG")
    print("=" * 70)
    
    rng = SideChannelResistantRNG(
        seed_bytes=64,
        reseed_interval=1024 * 100,
        prediction_resistance=False
    )
    
    print("\nRunning statistical randomness tests...")
    print("-" * 70)
    
    # Generate large sample
    sample_size = 100000
    data = rng.random_bytes(sample_size)
    
    # Test 1: Monobit test
    ones = sum(bin(byte).count('1') for byte in data)
    total_bits = sample_size * 8
    zeros = total_bits - ones
    ratio = ones / total_bits
    
    print(f"\n1. Monobit Balance Test:")
    print(f"   0 bits: {zeros:,} ({zeros/total_bits:.4%})")
    print(f"   1 bits: {ones:,} ({ones/total_bits:.4%})")
    monobit_pass = 0.48 < ratio < 0.52
    print(f"   Result: {'PASS' if monobit_pass else 'FAIL'}")
    
    # Test 2: Byte value distribution
    byte_counts = Counter(data)
    chi_squared = 0
    expected = sample_size / 256
    for count in byte_counts.values():
        chi_squared += (count - expected) ** 2 / expected
    
    # Critical value for df=255, p=0.01 is ~310
    distribution_pass = chi_squared < 350  # Generous bound
    print(f"\n2. Byte Distribution (Chi-squared):")
    print(f"   Chi-squared: {chi_squared:.2f}")
    print(f"   Result: {'PASS' if distribution_pass else 'FAIL'}")
    
    # Test 3: No long runs of identical bytes
    max_run = 1
    current_run = 1
    prev_byte = data[0]
    for byte in data[1:]:
        if byte == prev_byte:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
            prev_byte = byte
    
    runs_pass = max_run < 20
    print(f"\n3. Maximum Identical Byte Run:")
    print(f"   Longest run: {max_run} bytes")
    print(f"   Result: {'PASS' if runs_pass else 'FAIL'}")
    
    # Test 4: Entropy estimation (Shannon entropy per byte)
    import math
    entropy = 0.0
    for count in byte_counts.values():
        p = count / sample_size
        if p > 0:
            entropy -= p * math.log2(p)
    
    entropy_pass = entropy > 7.8  # Good random should be ~7.9-8.0
    print(f"\n4. Shannon Entropy Estimate:")
    print(f"   Entropy: {entropy:.4f} bits/byte")
    print(f"   Result: {'PASS' if entropy_pass else 'FAIL'}")
    
    # Final status
    all_pass = monobit_pass and distribution_pass and runs_pass and entropy_pass
    
    print("\n" + "-" * 70)
    print(f"Cryptographic Validation: {'PASSED' if all_pass else 'FAILED'}")
    print(f"Total bytes tested: {sample_size:,}")
    print(f"Seed refreshes: {rng.get_health_status()['statistics']['total_seed_refreshes']}")
    
    return all_pass


def main():
    """Run all tests"""
    print("\n" + "#" * 70)
    print("# QuantumCrypt AI - Side-Channel Resistant RNG Test Suite")
    print("# Production-Grade Cryptographic Validation")
    print("#" * 70)
    
    # Run unit tests
    print("\n" + "=" * 70)
    print("UNIT TESTS")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestConstantTimeOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyCollection))
    suite.addTests(loader.loadTestsFromTestCase(TestHKDFImplementation))
    suite.addTests(loader.loadTestsFromTestCase(TestRandomByteGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestRandomIntegerGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestHealthTesting))
    suite.addTests(loader.loadTestsFromTestCase(TestReseeding))
    suite.addTests(loader.loadTestsFromTestCase(TestSingleton))
    
    runner = unittest.TextTestRunner(verbosity=2)
    unit_result = runner.run(suite)
    
    # Run cryptographic validation
    crypto_passed = run_cryptographic_validation()
    
    # Final summary
    print("\n" + "=" * 70)
    print("FINAL TEST SUMMARY")
    print("=" * 70)
    
    unit_passed = unit_result.testsRun - len(unit_result.failures) - len(unit_result.errors)
    unit_total = unit_result.testsRun
    
    print(f"\nUnit Tests:      {unit_passed}/{unit_total} passed")
    print(f"Crypto Validation: {'PASSED' if crypto_passed else 'FAILED'}")
    print(f"\nOverall Status:  {'✓ ALL TESTS PASSED' if unit_result.wasSuccessful() and crypto_passed else '⚠ SOME TESTS FAILED'}")
    
    print("\n" + "#" * 70)
    
    # Save test results
    test_results = {
        "test_timestamp": datetime.now().isoformat(),
        "unit_tests": {
            "total": unit_total,
            "passed": unit_passed,
            "failed": len(unit_result.failures),
            "errors": len(unit_result.errors)
        },
        "cryptographic_validation": {
            "passed": crypto_passed
        },
        "overall_success": unit_result.wasSuccessful() and crypto_passed
    }
    
    with open("test_results_post_quantum_side_channel_resistant_rng.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: test_results_post_quantum_side_channel_resistant_rng.json")
    
    return 0 if (unit_result.wasSuccessful() and crypto_passed) else 1


if __name__ == "__main__":
    sys.exit(main())
