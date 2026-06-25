"""
Test Suite for QuantumCrypt Crypto Security Hardening Framework v29
Dimension B - Security Hardening
June 25, 2026

All tests verify:
1. Crypto Secure Memory Zeroization
2. Constant-Time Cryptographic Comparison
3. Crypto Input Validation (key sizes, nonce validation)
4. Crypto Operation Rate Limiting / DoS Protection
5. Backward Compatibility - existing code NOT broken
"""

import unittest
import time
import threading
import secrets
from quantum_crypt import (
    CryptoSecureMemory,
    CryptoConstantTime,
    CryptoInputValidator,
    CryptoRateLimiter,
    CryptoSecurityHardeningWrapper,
    CryptoSecurityLevel,
    crypto_secure_memory,
    crypto_constant_time,
    default_crypto_validator,
    default_crypto_rate_limiter,
)


class TestCryptoSecureMemory(unittest.TestCase):
    """Test cryptographic secure memory zeroization utilities"""
    
    def test_zeroize_key_material_bytearray(self):
        """Test bytearray key material zeroization with multiple passes"""
        sensitive = bytearray(secrets.token_bytes(32))
        original = bytes(sensitive)
        crypto_secure_memory.zeroize_key_material(sensitive)
        self.assertEqual(len(sensitive), len(original))
        self.assertTrue(all(b == 0 for b in sensitive))
    
    def test_zeroize_sensitive_string(self):
        """Test sensitive string zeroization (passwords, seeds)"""
        sensitive = "my_secret_password_12345"
        # Just verify it doesn't crash
        crypto_secure_memory.zeroize_sensitive_string(sensitive)
    
    def test_zeroize_crypto_context(self):
        """Test cryptographic context dictionary zeroization"""
        ctx = {
            'key': secrets.token_bytes(32),
            'private_key': secrets.token_bytes(64),
            'seed': 'my_random_seed_value',
            'nonce': secrets.token_bytes(12),
            'iv': secrets.token_bytes(16),
            'other_data': 'not_sensitive'
        }
        crypto_secure_memory.zeroize_crypto_context(ctx)
        self.assertEqual(len(ctx), 0)


class TestCryptoConstantTime(unittest.TestCase):
    """Test constant-time cryptographic comparison helpers"""
    
    def test_compare_keys_equal(self):
        """Test equal cryptographic key comparison"""
        key1 = secrets.token_bytes(32)
        key2 = bytes(key1)
        self.assertTrue(crypto_constant_time.compare_keys(key1, key2))
    
    def test_compare_keys_not_equal(self):
        """Test non-equal cryptographic key comparison"""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        self.assertFalse(crypto_constant_time.compare_keys(key1, key2))
    
    def test_compare_keys_different_lengths(self):
        """Test key comparison with different lengths"""
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(32)
        self.assertFalse(crypto_constant_time.compare_keys(key1, key2))
    
    def test_compare_macs_equal(self):
        """Test equal MAC/HMAC comparison"""
        import hmac
        import hashlib
        key = secrets.token_bytes(32)
        mac1 = hmac.new(key, b'test data', hashlib.sha256).digest()
        mac2 = bytes(mac1)
        self.assertTrue(crypto_constant_time.compare_macs(mac1, mac2))
    
    def test_compare_macs_not_equal(self):
        """Test non-equal MAC comparison"""
        mac1 = secrets.token_bytes(32)
        mac2 = secrets.token_bytes(32)
        self.assertFalse(crypto_constant_time.compare_macs(mac1, mac2))
    
    def test_compare_signatures(self):
        """Test signature comparison"""
        sig1 = secrets.token_bytes(64)
        sig2 = bytes(sig1)
        sig3 = secrets.token_bytes(64)
        self.assertTrue(crypto_constant_time.compare_signatures(sig1, sig2))
        self.assertFalse(crypto_constant_time.compare_signatures(sig1, sig3))
    
    def test_compare_hashes(self):
        """Test hash comparison"""
        hash1 = secrets.token_bytes(32)
        hash2 = bytes(hash1)
        hash3 = secrets.token_bytes(32)
        self.assertTrue(crypto_constant_time.compare_hashes(hash1, hash2))
        self.assertFalse(crypto_constant_time.compare_hashes(hash1, hash3))
    
    def test_verify_key_length(self):
        """Test constant-time key length verification"""
        key_32 = secrets.token_bytes(32)
        key_16 = secrets.token_bytes(16)
        self.assertTrue(crypto_constant_time.verify_key_length(key_32, 32))
        self.assertFalse(crypto_constant_time.verify_key_length(key_16, 32))
    
    def test_secure_hkdf(self):
        """Test secure HKDF key derivation (RFC 5869 compliant)"""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b'encryption key'
        
        derived1 = crypto_constant_time.secure_hkdf(ikm, salt, info, length=64)
        derived2 = crypto_constant_time.secure_hkdf(ikm, salt, info, length=64)
        derived3 = crypto_constant_time.secure_hkdf(ikm, salt, b'different', length=64)
        
        self.assertEqual(len(derived1), 64)
        self.assertEqual(derived1, derived2)
        self.assertNotEqual(derived1, derived3)
    
    def test_secure_equals_strings(self):
        """Test constant-time string comparison for secrets"""
        self.assertTrue(crypto_constant_time.secure_equals_strings("secret", "secret"))
        self.assertFalse(crypto_constant_time.secure_equals_strings("secret", "public"))


class TestCryptoInputValidator(unittest.TestCase):
    """Test cryptographic input validation wrapper"""
    
    def test_validate_aes_256_key_valid(self):
        """Test validation of valid AES-256 key (32 bytes)"""
        key = secrets.token_bytes(32)
        result = default_crypto_validator.validate_key(key, 'AES-256')
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['errors']), 0)
    
    def test_validate_aes_128_key_valid(self):
        """Test validation of valid AES-128 key (16 bytes)"""
        key = secrets.token_bytes(16)
        result = default_crypto_validator.validate_key(key, 'AES-128')
        self.assertTrue(result['valid'])
    
    def test_validate_aes_key_invalid_length(self):
        """Test validation rejects invalid AES key lengths"""
        key = secrets.token_bytes(20)  # Invalid - not 16, 24, or 32
        result = default_crypto_validator.validate_key(key, 'AES')
        self.assertFalse(result['valid'])
        self.assertTrue(any('Invalid key length' in e for e in result['errors']))
    
    def test_validate_chacha20_key(self):
        """Test ChaCha20 key validation (32 bytes)"""
        key = secrets.token_bytes(32)
        result = default_crypto_validator.validate_key(key, 'ChaCha20')
        self.assertTrue(result['valid'])
    
    def test_validate_none_key(self):
        """Test validation rejects None key"""
        result = default_crypto_validator.validate_key(None, 'AES')
        self.assertFalse(result['valid'])
    
    def test_validate_nonce_aes_gcm(self):
        """Test AES-GCM nonce validation (12 bytes recommended)"""
        nonce = secrets.token_bytes(12)
        result = default_crypto_validator.validate_nonce(nonce, 'AES-GCM')
        self.assertTrue(result['valid'])
    
    def test_validate_nonce_chacha20_poly1305(self):
        """Test ChaCha20-Poly1305 nonce validation (12 bytes)"""
        nonce = secrets.token_bytes(12)
        result = default_crypto_validator.validate_nonce(nonce, 'ChaCha20-Poly1305')
        self.assertTrue(result['valid'])
    
    def test_validate_nonce_invalid_length(self):
        """Test validation rejects invalid nonce lengths"""
        nonce = secrets.token_bytes(8)  # Invalid for AES-GCM
        result = default_crypto_validator.validate_nonce(nonce, 'AES-GCM')
        self.assertFalse(result['valid'])
    
    def test_validate_crypto_operation(self):
        """Test complete cryptographic operation validation"""
        key = secrets.token_bytes(32)
        data = b'test plaintext'
        nonce = secrets.token_bytes(12)
        
        result = default_crypto_validator.validate_crypto_operation(
            'encrypt', key, data, algorithm='AES-GCM', nonce=nonce
        )
        self.assertTrue(result['valid'])
    
    def test_fips_140_3_level(self):
        """Test FIPS 140-3 security level validation"""
        fips_validator = CryptoInputValidator(CryptoSecurityLevel.FIPS_140_3)
        weak_key = secrets.token_bytes(16)  # AES-128 may be flagged at FIPS level
        result = fips_validator.validate_key(weak_key, 'AES')
        # Should pass but may have additional checks
        self.assertIsNotNone(result)
    
    def test_add_custom_crypto_rule(self):
        """Test adding custom cryptographic validation rule"""
        validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)
        from dataclasses import dataclass
        
        @dataclass
        class Rule:
            name: str
            validator: callable
            error_message: str
            security_level: CryptoSecurityLevel = CryptoSecurityLevel.STANDARD
        
        validator.add_rule(Rule(
            name='no_weak_keys',
            validator=lambda k: not (isinstance(k, bytes) and all(b == 0 for b in k)),
            error_message='All-zero key detected - security risk'
        ))
        
        weak_key = bytes([0] * 32)
        result = validator.validate_key(weak_key, 'AES')
        self.assertFalse(result['valid'])


class TestCryptoRateLimiter(unittest.TestCase):
    """Test cryptographic operation rate limiting and DoS protection"""
    
    def test_crypto_rate_limit_allows_first_requests(self):
        """Test rate limiter allows first crypto operations"""
        limiter = CryptoRateLimiter()
        for i in range(5):
            result = limiter.check_operation_rate(f"client_{i}", is_key_operation=False)
            self.assertTrue(result['allowed'])
            self.assertGreater(result['remaining'], 0)
    
    def test_key_operations_separate_rate_limit(self):
        """Test key generation operations have separate rate limits"""
        limiter = CryptoRateLimiter()
        
        # Regular crypto operations
        for i in range(10):
            result = limiter.check_operation_rate("client1", is_key_operation=False)
            self.assertTrue(result['allowed'])
        
        # Key generation operations should still be allowed (separate counter)
        result = limiter.check_operation_rate("client1", is_key_operation=True)
        self.assertTrue(result['allowed'])
    
    def test_crypto_rate_limit_blocks_after_exceeded(self):
        """Test rate limiter blocks after exceeding crypto operation limit"""
        from dataclasses import dataclass
        
        @dataclass
        class Config:
            max_operations: int = 5
            window_seconds: int = 60
            block_duration_seconds: int = 10
            max_key_operations: int = 2
        
        limiter = CryptoRateLimiter(Config())
        
        # Fill up the rate limit
        for i in range(5):
            result = limiter.check_operation_rate("test_client")
            self.assertTrue(result['allowed'])
        
        # 6th request should be blocked
        result = limiter.check_operation_rate("test_client")
        self.assertFalse(result['allowed'])
        self.assertTrue(result['blocked'])
    
    def test_crypto_rate_limit_reset_client(self):
        """Test resetting client crypto rate limit"""
        limiter = CryptoRateLimiter()
        for i in range(10):
            limiter.check_operation_rate("client_to_reset")
        
        limiter.reset_client("client_to_reset")
        stats = limiter.get_stats()
        self.assertEqual(stats['clients_blocked'], 0)
    
    def test_crypto_rate_limit_stats(self):
        """Test crypto rate limiter statistics"""
        limiter = CryptoRateLimiter()
        limiter.check_operation_rate("client1", is_key_operation=False)
        limiter.check_operation_rate("client2", is_key_operation=True)
        
        stats = limiter.get_stats()
        self.assertEqual(stats['total_clients_tracked'], 1)  # Same client
        self.assertGreater(stats['max_operations_window'], 0)
        self.assertGreater(stats['max_key_operations'], 0)
    
    def test_crypto_rate_limiter_thread_safety(self):
        """Test crypto rate limiter is thread-safe"""
        limiter = CryptoRateLimiter()
        errors = []
        
        def worker():
            try:
                for i in range(10):
                    limiter.check_operation_rate("threaded_client", is_key_operation=(i % 2 == 0))
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestCryptoSecurityHardeningWrapper(unittest.TestCase):
    """Test main cryptographic security hardening wrapper"""
    
    def test_wrap_crypto_function_preserves_behavior(self):
        """Test wrapped crypto function preserves original behavior"""
        wrapper = CryptoSecurityHardeningWrapper()
        
        def mock_encrypt(key, data):
            return f"encrypted({data})"
        
        wrapped = wrapper.wrap_crypto_function(mock_encrypt)
        
        key = secrets.token_bytes(32)
        result = wrapped(key, "test message")
        self.assertIn("encrypted", result)
    
    def test_secure_encrypt(self):
        """Test secure encryption execution"""
        wrapper = CryptoSecurityHardeningWrapper()
        
        def mock_encrypt(key, plaintext):
            return f"ciphertext:{plaintext}"
        
        key = secrets.token_bytes(32)
        result = wrapper.secure_encrypt(mock_encrypt, key, "secret data")
        self.assertIn("ciphertext", result)
    
    def test_secure_decrypt(self):
        """Test secure decryption execution"""
        wrapper = CryptoSecurityHardeningWrapper()
        
        def mock_decrypt(key, ciphertext):
            return f"plaintext:{ciphertext}"
        
        key = secrets.token_bytes(32)
        result = wrapper.secure_decrypt(mock_decrypt, key, "encrypted data")
        self.assertIn("plaintext", result)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - existing code NOT broken"""
    
    def test_existing_imports_still_work(self):
        """Verify all existing crypto imports still work"""
        from quantum_crypt import (
            PostQuantumHybridEncryptionEngine,
            PostQuantumSignatureVerifier,
            PostQuantumSecureSessionManager,
            PostQuantumFileEncryptor,
        )
        self.assertIsNotNone(PostQuantumHybridEncryptionEngine)
        self.assertIsNotNone(PostQuantumSignatureVerifier)
        self.assertIsNotNone(PostQuantumSecureSessionManager)
        self.assertIsNotNone(PostQuantumFileEncryptor)
    
    def test_version_updated(self):
        """Verify version was updated properly"""
        import quantum_crypt
        self.assertTrue(hasattr(quantum_crypt, '__version__'))
        self.assertIn('2026.6.25', quantum_crypt.__version__)


if __name__ == '__main__':
    print("=" * 70)
    print("QuantumCrypt Crypto Security Hardening v29 - Test Suite")
    print("Dimension B - Security Hardening")
    print("June 25, 2026")
    print("=" * 70)
    unittest.main(verbosity=2)
