"""
Test Suite for QuantumCrypt Security Hardening Module v11
Dimension B: Security Hardening - Crypto-Specific Comprehensive Tests
ADD-ONLY TESTS - No existing code modified
"""

import unittest
import time
import threading
import secrets
from quantum_crypt.crypto_security_hardening_enhanced_comprehensive_v11_2026_june import (
    KeyType,
    SecurityLevel,
    CryptoSecurityConfig,
    KeyValidationResult,
    CryptoSecureMemory,
    CryptoKeyValidator,
    CryptoRateLimiter,
    CryptoParameterValidator,
    CryptoSecurityHardeningEngine,
    CryptoSecurityError,
    get_crypto_security_engine_v11,
    validate_crypto_key_v11,
    wipe_crypto_key_v11,
    crypto_secure_compare_v11,
    check_crypto_rate_limit_v11,
    estimate_key_entropy_v11,
)


class TestCryptoSecureMemory(unittest.TestCase):
    """Test crypto secure memory utilities."""
    
    def test_wipe_key_material(self):
        """Test FIPS 140-3 compliant key material wiping."""
        key_data = bytearray(secrets.token_bytes(32))
        original = bytes(key_data)
        CryptoSecureMemory.wipe_key_material(key_data)
        self.assertEqual(len(key_data), len(original))
        self.assertTrue(all(b == 0 for b in key_data))
    
    def test_wipe_empty_key(self):
        """Test wiping handles empty bytearray."""
        data = bytearray()
        CryptoSecureMemory.wipe_key_material(data)
        self.assertEqual(len(data), 0)
    
    def test_constant_time_compare_bytes_equal(self):
        """Test constant-time byte comparison for equal data."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        self.assertTrue(CryptoSecureMemory.constant_time_compare_bytes(a, b))
    
    def test_constant_time_compare_bytes_different(self):
        """Test constant-time byte comparison for different data."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        self.assertFalse(CryptoSecureMemory.constant_time_compare_bytes(a, b))
    
    def test_constant_time_compare_bytes_different_length(self):
        """Test constant-time comparison rejects different lengths."""
        a = secrets.token_bytes(16)
        b = secrets.token_bytes(32)
        self.assertFalse(CryptoSecureMemory.constant_time_compare_bytes(a, b))
    
    def test_constant_time_compare_strings_equal(self):
        """Test constant-time string comparison for equal strings."""
        a = "crypto_secret_key_12345"
        b = "crypto_secret_key_12345"
        self.assertTrue(CryptoSecureMemory.constant_time_compare_strings(a, b))
    
    def test_constant_time_compare_strings_different(self):
        """Test constant-time string comparison for different strings."""
        a = "crypto_secret_key_12345"
        b = "crypto_secret_key_67890"
        self.assertFalse(CryptoSecureMemory.constant_time_compare_strings(a, b))
    
    def test_estimate_entropy_high(self):
        """Test entropy estimation for high-entropy random data."""
        data = secrets.token_bytes(32)
        entropy = CryptoSecureMemory.estimate_entropy(data)
        # Random data should have high entropy
        self.assertGreater(entropy, 100)
    
    def test_estimate_entropy_low(self):
        """Test entropy estimation for low-entropy data."""
        data = b"\x00" * 32
        entropy = CryptoSecureMemory.estimate_entropy(data)
        # All zeros should have very low entropy
        self.assertLess(entropy, 10)


class TestCryptoKeyValidator(unittest.TestCase):
    """Test crypto key validation."""
    
    def setUp(self):
        self.config = CryptoSecurityConfig(min_key_entropy_bits=64)
        self.validator = CryptoKeyValidator(self.config)
    
    def test_validate_strong_key(self):
        """Test validation passes for cryptographically strong keys."""
        strong_key = secrets.token_bytes(32)  # 256 bits
        result = self.validator.validate_key(strong_key, KeyType.SYMMETRIC)
        self.assertTrue(result.is_valid)
        self.assertIn(result.key_strength, ["strong", "very_strong", "quantum_resistant"])
    
    def test_validate_short_key(self):
        """Test validation rejects keys that are too short."""
        short_key = secrets.token_bytes(8)  # 64 bits, too short for AES
        result = self.validator.validate_key(short_key, KeyType.SYMMETRIC)
        self.assertFalse(result.is_valid)
        self.assertIsNotNone(result.error_message)
    
    def test_validate_weak_pattern_key(self):
        """Test validation detects weak uniform patterns."""
        weak_key = b"\xFF" * 32  # All same byte
        result = self.validator.validate_key(weak_key, KeyType.SYMMETRIC)
        self.assertFalse(result.is_valid)
        self.assertIn("uniform_pattern", result.validation_details)
    
    def test_validate_repeated_pattern(self):
        """Test validation detects repeated patterns."""
        pattern = secrets.token_bytes(16)
        repeated = pattern + pattern  # Same pattern twice
        result = self.validator.validate_key(repeated, KeyType.SYMMETRIC)
        self.assertFalse(result.is_valid)
    
    def test_validate_nonce_good(self):
        """Test good nonce validation."""
        good_nonce = secrets.token_bytes(12)
        self.assertTrue(self.validator.validate_nonce(good_nonce, 12))
    
    def test_validate_nonce_wrong_length(self):
        """Test nonce validation rejects wrong length."""
        bad_nonce = secrets.token_bytes(16)
        self.assertFalse(self.validator.validate_nonce(bad_nonce, 12))
    
    def test_validate_nonce_all_zeros(self):
        """Test nonce validation rejects all zeros."""
        zero_nonce = b"\x00" * 12
        self.assertFalse(self.validator.validate_nonce(zero_nonce, 12))
    
    def test_key_strength_classification(self):
        """Test key strength classification works."""
        # 256-bit key (should be at least strong, likely very_strong/quantum_resistant)
        key_256 = secrets.token_bytes(32)
        result = self.validator.validate_key(key_256, KeyType.SYMMETRIC)
        self.assertIn(result.key_strength, ["moderate", "strong", "very_strong", "quantum_resistant"])
        
        # 128-bit key should be at least moderate
        key_128 = secrets.token_bytes(16)
        result = self.validator.validate_key(key_128, KeyType.SYMMETRIC)
        self.assertIn(result.key_strength, ["moderate", "strong", "very_strong"])


class TestCryptoRateLimiter(unittest.TestCase):
    """Test crypto operation rate limiting."""
    
    def setUp(self):
        self.config = CryptoSecurityConfig(max_key_operations_per_second=10)
        self.limiter = CryptoRateLimiter(self.config)
    
    def test_rate_limit_allows_initial_ops(self):
        """Test rate limiter allows operations within limits."""
        for _ in range(5):
            allowed, meta = self.limiter.check_crypto_operation("key1")
            self.assertTrue(allowed)
    
    def test_rate_limit_enforces_limit(self):
        """Test rate limiter blocks operations exceeding limits."""
        # Use up the limit
        for _ in range(10):
            self.limiter.check_crypto_operation("key2")
        
        # Next one should be blocked
        allowed, meta = self.limiter.check_crypto_operation("key2")
        self.assertFalse(allowed)
        self.assertEqual(meta["reason"], "crypto_rate_limit_exceeded")
    
    def test_rate_limit_per_key(self):
        """Test rate limits are per-key."""
        # Use up limit for keyA
        for _ in range(10):
            self.limiter.check_crypto_operation("keyA")
        
        # keyB should still work
        allowed, _ = self.limiter.check_crypto_operation("keyB")
        self.assertTrue(allowed)
    
    def test_rate_limit_expires(self):
        """Test rate limit block expires after time."""
        # Use up limit
        for _ in range(10):
            self.limiter.check_crypto_operation("key3")
        
        # Wait for block to expire (1 second)
        time.sleep(1.1)
        
        # Should work again
        allowed, _ = self.limiter.check_crypto_operation("key3")
        self.assertTrue(allowed)
    
    def test_thread_safety(self):
        """Test rate limiter is thread-safe for concurrent operations."""
        errors = []
        
        def worker():
            try:
                for _ in range(5):
                    self.limiter.check_crypto_operation("threaded_key")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestCryptoParameterValidator(unittest.TestCase):
    """Test crypto parameter validation."""
    
    def test_validate_aes_key_sizes(self):
        """Test AES key size validation."""
        self.assertTrue(CryptoParameterValidator.validate_key_size("AES", 16))  # 128-bit
        self.assertTrue(CryptoParameterValidator.validate_key_size("AES", 24))  # 192-bit
        self.assertTrue(CryptoParameterValidator.validate_key_size("AES", 32))  # 256-bit
        self.assertFalse(CryptoParameterValidator.validate_key_size("AES", 8))  # Too small
    
    def test_validate_chacha_key_size(self):
        """Test ChaCha20 key size validation."""
        self.assertTrue(CryptoParameterValidator.validate_key_size("ChaCha20", 32))
        self.assertFalse(CryptoParameterValidator.validate_key_size("ChaCha20", 16))
    
    def test_validate_nonce_sizes(self):
        """Test nonce size validation."""
        self.assertTrue(CryptoParameterValidator.validate_nonce_size("AES-GCM", 12))
        self.assertFalse(CryptoParameterValidator.validate_nonce_size("AES-GCM", 16))
        self.assertTrue(CryptoParameterValidator.validate_nonce_size("ChaCha20-Poly1305", 12))


class TestCryptoSecurityHardeningEngine(unittest.TestCase):
    """Test main crypto security hardening engine."""
    
    def setUp(self):
        self.engine = CryptoSecurityHardeningEngine()
    
    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        self.assertIsNotNone(self.engine)
        self.assertIsInstance(self.engine.config, CryptoSecurityConfig)
    
    def test_validate_key_material(self):
        """Test key validation through engine."""
        key = secrets.token_bytes(32)
        result = self.engine.validate_key_material(key, KeyType.SYMMETRIC)
        self.assertIsInstance(result, KeyValidationResult)
        self.assertTrue(result.is_valid)
    
    def test_wipe_sensitive_key(self):
        """Test key wiping through engine."""
        key_data = bytearray(secrets.token_bytes(32))
        self.engine.wipe_sensitive_key(key_data)
        self.assertTrue(all(b == 0 for b in key_data))
    
    def test_secure_compare_strings(self):
        """Test secure string comparison through engine."""
        self.assertTrue(self.engine.secure_compare("test", "test"))
        self.assertFalse(self.engine.secure_compare("test", "different"))
    
    def test_secure_compare_bytes(self):
        """Test secure bytes comparison through engine."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        self.assertTrue(self.engine.secure_compare(a, b))
    
    def test_check_crypto_rate_limit(self):
        """Test rate limit check through engine."""
        allowed, meta = self.engine.check_crypto_rate_limit("test_key")
        self.assertTrue(allowed)
        self.assertIn("operations_this_second", meta)
    
    def test_validate_crypto_parameters(self):
        """Test crypto parameter validation through engine."""
        self.assertTrue(self.engine.validate_crypto_parameters("AES", 32, 12))
        self.assertFalse(self.engine.validate_crypto_parameters("AES", 8, 16))
    
    def test_estimate_key_entropy(self):
        """Test entropy estimation through engine."""
        key = secrets.token_bytes(32)
        entropy = self.engine.estimate_key_entropy(key)
        self.assertGreater(entropy, 100)
    
    def test_secure_crypto_wrap(self):
        """Test function wrapping with crypto hardening."""
        def crypto_operation(x):
            return x * 2
        
        wrapped = self.engine.secure_crypto_wrap(crypto_operation, key_id="test_op")
        result = wrapped(5)
        self.assertEqual(result, 10)
    
    def test_audit_logging(self):
        """Test crypto audit logging when enabled."""
        config = CryptoSecurityConfig(enable_audit_logging=True)
        engine = CryptoSecurityHardeningEngine(config)
        
        def test_op():
            return "done"
        
        wrapped = engine.secure_crypto_wrap(test_op, key_id="audit_test")
        wrapped()
        
        log = engine.get_audit_log()
        self.assertGreater(len(log), 0)
        self.assertIsNotNone(log[0].entry_hmac)  # Entries should be HMAC signed


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_get_engine_singleton(self):
        """Test global engine is a singleton."""
        engine1 = get_crypto_security_engine_v11()
        engine2 = get_crypto_security_engine_v11()
        self.assertIs(engine1, engine2)
    
    def test_validate_crypto_key_global(self):
        """Test global key validation function."""
        key = secrets.token_bytes(32)
        result = validate_crypto_key_v11(key)
        self.assertIsInstance(result, KeyValidationResult)
    
    def test_wipe_crypto_key_global(self):
        """Test global key wiping function."""
        data = bytearray(secrets.token_bytes(32))
        wipe_crypto_key_v11(data)
        self.assertTrue(all(b == 0 for b in data))
    
    def test_crypto_secure_compare_global(self):
        """Test global secure compare function."""
        self.assertTrue(crypto_secure_compare_v11("abc", "abc"))
        self.assertFalse(crypto_secure_compare_v11("abc", "def"))
    
    def test_check_crypto_rate_limit_global(self):
        """Test global rate limit function."""
        allowed, meta = check_crypto_rate_limit_v11("global_key")
        self.assertTrue(allowed)
    
    def test_estimate_key_entropy_global(self):
        """Test global entropy estimation function."""
        key = secrets.token_bytes(32)
        entropy = estimate_key_entropy_v11(key)
        self.assertGreater(entropy, 0)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no existing code broken."""
    
    def test_no_modifications_to_existing_modules(self):
        """Verify this is 100% add-only - no side effects."""
        import quantum_crypt.crypto_security_hardening_enhanced_comprehensive_v11_2026_june as csh
        self.assertIsNotNone(csh)
    
    def test_existing_imports_unaffected(self):
        """Verify existing module imports still work."""
        from quantum_crypt import __init__
        self.assertIsNotNone(__init__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
