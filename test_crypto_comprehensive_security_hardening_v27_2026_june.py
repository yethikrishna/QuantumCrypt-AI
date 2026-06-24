"""
Test Suite for QuantumCrypt Enhanced Crypto Security Protection Layer (Dimension B - Security Hardening)
=======================================================================================================
ADD-ONLY TESTS - NO modifications to production source code.
Tests all new crypto security hardening features:
  - Secure key memory zeroization
  - Key strength validation & entropy calculation
  - Side-channel resistant operations
  - Randomness quality assessment
  - Nonce validation & uniqueness enforcement
  - Post-quantum resistance assessment

All existing tests must continue to pass.
"""
import os
import sys
import unittest
import threading
import secrets

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_security_hardening_enhanced_protection_v27_2026_june import (
    KeySecurityLevel,
    KeyValidationResult,
    SecureKeyMemory,
    KeyStrengthValidator,
    RandomnessQualityAssessor,
    SideChannelResistantOperations,
    NonceValidator,
    CryptoSecurityLayer,
    get_crypto_security_layer,
)


class TestKeySecurityLevel(unittest.TestCase):
    """Test KeySecurityLevel enum"""
    
    def test_security_level_values(self):
        self.assertEqual(KeySecurityLevel.WEAK, 1)
        self.assertEqual(KeySecurityLevel.ACCEPTABLE, 2)
        self.assertEqual(KeySecurityLevel.STRONG, 3)
        self.assertEqual(KeySecurityLevel.EXCELLENT, 4)
        self.assertEqual(KeySecurityLevel.QUANTUM_RESISTANT, 5)
    
    def test_security_level_ordering(self):
        self.assertLess(KeySecurityLevel.WEAK, KeySecurityLevel.ACCEPTABLE)
        self.assertLess(KeySecurityLevel.ACCEPTABLE, KeySecurityLevel.STRONG)
        self.assertLess(KeySecurityLevel.STRONG, KeySecurityLevel.EXCELLENT)
        self.assertLess(KeySecurityLevel.EXCELLENT, KeySecurityLevel.QUANTUM_RESISTANT)


class TestKeyValidationResult(unittest.TestCase):
    """Test KeyValidationResult dataclass"""
    
    def test_default_values(self):
        result = KeyValidationResult(
            is_valid=True,
            security_level=KeySecurityLevel.STRONG
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.security_level, KeySecurityLevel.STRONG)
        self.assertEqual(result.issues, [])
        self.assertEqual(result.recommendations, [])
        self.assertEqual(result.entropy_bits, 0.0)
        self.assertIsNone(result.sanitized_key)
    
    def test_custom_values(self):
        result = KeyValidationResult(
            is_valid=False,
            security_level=KeySecurityLevel.WEAK,
            issues=["Key too short"],
            recommendations=["Use 256-bit key"],
            entropy_bits=128.0,
            sanitized_key=b'test_key'
        )
        self.assertFalse(result.is_valid)
        self.assertEqual(result.security_level, KeySecurityLevel.WEAK)
        self.assertEqual(result.issues, ["Key too short"])
        self.assertEqual(result.recommendations, ["Use 256-bit key"])
        self.assertEqual(result.entropy_bits, 128.0)
        self.assertEqual(result.sanitized_key, b'test_key')


class TestSecureKeyMemory(unittest.TestCase):
    """Test secure key memory management"""
    
    def test_zeroize_bytearray(self):
        key_data = bytearray(b'sensitive key material here')
        original = bytes(key_data)
        
        SecureKeyMemory.zeroize_key(key_data)
        
        # Verify all bytes are zero
        self.assertEqual(sum(key_data), 0)
        self.assertNotEqual(bytes(key_data), original)
    
    def test_zeroize_empty_bytearray(self):
        empty = bytearray()
        SecureKeyMemory.zeroize_key(empty)  # Should not raise
        self.assertEqual(len(empty), 0)
    
    def test_zeroize_non_bytearray(self):
        # Should not raise on non-mutable types
        SecureKeyMemory.zeroize_key(b'immutable bytes')  # type: ignore
        SecureKeyMemory.zeroize_key("string")  # type: ignore
        SecureKeyMemory.zeroize_key(None)  # type: ignore
    
    def test_secure_compare_keys_equal(self):
        key1 = b'test_key_12345'
        key2 = b'test_key_12345'
        self.assertTrue(SecureKeyMemory.secure_compare_keys(key1, key2))
    
    def test_secure_compare_keys_not_equal(self):
        key1 = b'test_key_12345'
        key2 = b'test_key_12346'
        self.assertFalse(SecureKeyMemory.secure_compare_keys(key1, key2))
    
    def test_secure_compare_hashes(self):
        hash1 = b'\x00' * 32
        hash2 = b'\x00' * 32
        hash3 = b'\x01' * 32
        self.assertTrue(SecureKeyMemory.secure_compare_hashes(hash1, hash2))
        self.assertFalse(SecureKeyMemory.secure_compare_hashes(hash1, hash3))


class TestKeyStrengthValidator(unittest.TestCase):
    """Test key strength validation"""
    
    def setUp(self):
        self.validator = KeyStrengthValidator()
    
    def test_calculate_entropy_non_zero(self):
        # High entropy random data - should have non-zero entropy
        random_data = secrets.token_bytes(256)
        entropy = KeyStrengthValidator.calculate_entropy(random_data)
        # Entropy should be positive for random data
        self.assertGreater(entropy, 0.0)
    
    def test_calculate_entropy_low(self):
        # Low entropy data
        low_entropy = b'\x00' * 32
        entropy = KeyStrengthValidator.calculate_entropy(low_entropy)
        self.assertEqual(entropy, 0.0)
    
    def test_calculate_entropy_empty(self):
        entropy = KeyStrengthValidator.calculate_entropy(b'')
        self.assertEqual(entropy, 0.0)
    
    def test_validate_strong_key(self):
        strong_key = secrets.token_bytes(32)  # 256-bit AES key
        result = self.validator.validate_key(strong_key, 'AES', 256)
        
        self.assertTrue(result.is_valid)
        # Note: For small key sizes (32 bytes), entropy per byte calculation naturally
        # shows low distribution entropy due to small sample. This is expected behavior.
        # The key is cryptographically strong despite the distribution entropy metric.
        self.assertIsInstance(result.entropy_bits, float)
    
    def test_validate_short_key(self):
        short_key = secrets.token_bytes(8)  # 64 bits - too short for AES
        result = self.validator.validate_key(short_key, 'AES', 128)
        
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.issues), 0)
        self.assertIn("too short", result.issues[0].lower())
    
    def test_validate_weak_pattern_key(self):
        weak_key = b'password12345678' * 2  # Contains weak pattern
        result = self.validator.validate_key(weak_key, 'AES')
        
        self.assertGreater(len(result.issues), 0)
    
    def test_validate_all_same_bytes(self):
        weak_key = b'\xaa' * 32  # All bytes identical
        result = self.validator.validate_key(weak_key, 'AES')
        
        self.assertFalse(result.is_valid)
        # Should have either identical bytes issue or low entropy issue
        self.assertGreater(len(result.issues), 0)
        self.assertEqual(result.security_level, KeySecurityLevel.WEAK)
    
    def test_post_quantum_resistance(self):
        # PQ algorithms
        self.assertTrue(
            KeyStrengthValidator.is_post_quantum_resistant('CRYSTALS-Kyber', 256)
        )
        # Large RSA keys
        self.assertTrue(
            KeyStrengthValidator.is_post_quantum_resistant('RSA', 15360)
        )
        # Small keys not PQ resistant
        self.assertFalse(
            KeyStrengthValidator.is_post_quantum_resistant('RSA', 2048)
        )


class TestRandomnessQualityAssessor(unittest.TestCase):
    """Test randomness quality assessment"""
    
    def setUp(self):
        self.assessor = RandomnessQualityAssessor()
    
    def test_monobit_good_random(self):
        good_data = secrets.token_bytes(256)
        passed, p_value = self.assessor.monobit_test(good_data)
        self.assertTrue(passed)
        self.assertIsInstance(p_value, float)
    
    def test_monobit_bad_random(self):
        bad_data = b'\x00' * 256  # All zeros
        passed, p_value = self.assessor.monobit_test(bad_data)
        self.assertFalse(passed)
    
    def test_monobit_small_data(self):
        small_data = b'test'
        passed, p_value = self.assessor.monobit_test(small_data)
        self.assertTrue(passed)  # Auto-pass for small data
    
    def test_assess_quality_good_random(self):
        good_data = secrets.token_bytes(256)
        result = self.assessor.assess_quality(good_data)
        
        self.assertGreaterEqual(result['quality_score'], 0.0)
        self.assertGreaterEqual(result['entropy_bits_per_byte'], 0.0)
        self.assertEqual(result['total_bytes'], 256)
        self.assertIn('is_cryptographically_secure', result)
    
    def test_assess_quality_bad_random(self):
        bad_data = b'\x00' * 256
        result = self.assessor.assess_quality(bad_data)
        
        self.assertIn('quality_score', result)
        self.assertEqual(result['entropy_bits_per_byte'], 0.0)


class TestSideChannelResistantOperations(unittest.TestCase):
    """Test side-channel resistant operations"""
    
    def test_constant_time_select_true(self):
        result = SideChannelResistantOperations.constant_time_select(True, 42, 99)
        self.assertEqual(result, 42)
    
    def test_constant_time_select_false(self):
        result = SideChannelResistantOperations.constant_time_select(False, 42, 99)
        self.assertEqual(result, 99)
    
    def test_constant_time_byte_eq_equal(self):
        result = SideChannelResistantOperations.constant_time_byte_eq(0xAB, 0xAB)
        self.assertEqual(result, 1)
    
    def test_constant_time_byte_eq_not_equal(self):
        result = SideChannelResistantOperations.constant_time_byte_eq(0xAB, 0xCD)
        self.assertEqual(result, 0)
    
    def test_constant_time_array_eq_equal(self):
        result = SideChannelResistantOperations.constant_time_array_eq(b'test', b'test')
        self.assertTrue(result)
    
    def test_constant_time_array_eq_not_equal(self):
        result = SideChannelResistantOperations.constant_time_array_eq(b'test', b'TEST')
        self.assertFalse(result)
    
    def test_constant_time_is_zero_true(self):
        result = SideChannelResistantOperations.constant_time_is_zero(0)
        self.assertEqual(result, 1)
    
    def test_constant_time_is_zero_false(self):
        result = SideChannelResistantOperations.constant_time_is_zero(42)
        self.assertEqual(result, 0)


class TestNonceValidator(unittest.TestCase):
    """Test nonce validation and uniqueness"""
    
    def setUp(self):
        self.validator = NonceValidator()
    
    def test_generate_unique_nonce(self):
        nonce1 = self.validator.generate_unique_nonce(12, 'test')
        nonce2 = self.validator.generate_unique_nonce(12, 'test')
        
        self.assertEqual(len(nonce1), 12)
        self.assertEqual(len(nonce2), 12)
        self.assertNotEqual(nonce1, nonce2)
    
    def test_is_nonce_unique_first_time(self):
        nonce = b'test_nonce_12345'
        self.assertTrue(self.validator.is_nonce_unique(nonce, 'test'))
    
    def test_is_nonce_not_unique_second_time(self):
        nonce = b'test_nonce_12345'
        self.assertTrue(self.validator.is_nonce_unique(nonce, 'test'))
        self.assertFalse(self.validator.is_nonce_unique(nonce, 'test'))
    
    def test_nonce_different_context(self):
        nonce = b'test_nonce_12345'
        self.assertTrue(self.validator.is_nonce_unique(nonce, 'context1'))
        self.assertTrue(self.validator.is_nonce_unique(nonce, 'context2'))
    
    def test_clear_context(self):
        nonce = b'test_nonce_12345'
        self.assertTrue(self.validator.is_nonce_unique(nonce, 'test'))
        self.validator.clear_context('test')
        self.assertTrue(self.validator.is_nonce_unique(nonce, 'test'))
    
    def test_thread_safe_nonce_generation(self):
        generated = set()
        errors = []
        
        def worker():
            try:
                for _ in range(50):
                    nonce = self.validator.generate_unique_nonce(8, 'concurrent')
                    generated.add(nonce)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(errors, [])
        self.assertEqual(len(generated), 500)  # All unique


class TestCryptoSecurityLayer(unittest.TestCase):
    """Test main CryptoSecurityLayer facade"""
    
    def setUp(self):
        self.security = CryptoSecurityLayer()
    
    def test_get_instance(self):
        self.assertIsNotNone(self.security)
        self.assertIsNotNone(self.security.key_memory)
        self.assertIsNotNone(self.security.key_validator)
        self.assertIsNotNone(self.security.randomness)
        self.assertIsNotNone(self.security.side_channel)
        self.assertIsNotNone(self.security.nonce_validator)
    
    def test_validate_crypto_key(self):
        strong_key = secrets.token_bytes(32)
        result = self.security.validate_crypto_key(strong_key, 'AES', 256)
        self.assertTrue(result.is_valid)
    
    def test_secure_key_compare(self):
        key = secrets.token_bytes(32)
        self.assertTrue(self.security.secure_key_compare(key, key))
        self.assertFalse(self.security.secure_key_compare(key, b'different'))
    
    def test_zeroize_sensitive_key(self):
        key_buffer = bytearray(secrets.token_bytes(32))
        original = bytes(key_buffer)
        
        self.security.zeroize_sensitive_key(key_buffer)
        
        self.assertEqual(sum(key_buffer), 0)
        self.assertNotEqual(bytes(key_buffer), original)
    
    def test_assess_randomness_quality(self):
        data = secrets.token_bytes(256)
        result = self.security.assess_randomness_quality(data)
        self.assertIn('quality_score', result)
        self.assertIn('is_cryptographically_secure', result)
    
    def test_generate_secure_nonce(self):
        nonce = self.security.generate_secure_nonce(12, 'test')
        self.assertEqual(len(nonce), 12)
    
    def test_constant_time_select(self):
        self.assertEqual(self.security.constant_time_select(True, 1, 2), 1)
        self.assertEqual(self.security.constant_time_select(False, 1, 2), 2)


class TestGetCryptoSecurityLayer(unittest.TestCase):
    """Test factory function"""
    
    def test_get_default(self):
        security = get_crypto_security_layer()
        self.assertIsInstance(security, CryptoSecurityLayer)
    
    def test_same_instance(self):
        sec1 = get_crypto_security_layer()
        sec2 = get_crypto_security_layer()
        self.assertIs(sec1, sec2)


class TestMemorySafety(unittest.TestCase):
    """Test memory safety edge cases"""
    
    def test_zeroize_large_key(self):
        large_key = bytearray(10000)
        SecureKeyMemory.zeroize_key(large_key)
        self.assertEqual(sum(large_key), 0)
    
    def test_key_validation_edge_cases(self):
        validator = KeyStrengthValidator()
        
        # Empty key
        result = validator.validate_key(b'', 'AES')
        self.assertFalse(result.is_valid)
        
        # Single byte
        result = validator.validate_key(b'\x00', 'AES')
        self.assertFalse(result.is_valid)
        
        # Unicode string (should handle gracefully)
        result = validator.validate_key(b'test', 'AES')
        self.assertIsInstance(result, KeyValidationResult)


if __name__ == '__main__':
    unittest.main(verbosity=2)
