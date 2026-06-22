"""
Test Suite for Cryptographic Security Hardening Comprehensive Module v2
Dimension B: Security Hardening - ADD-ONLY implementation

All tests verify the cryptographic security hardening utilities work correctly.
No existing production code is modified or tested - only new features.
"""

import unittest
import time
import threading
import sys
import os
import hmac
import hashlib

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_security_hardening_comprehensive_v2_2026_june import (
    CryptoSecurityLevel,
    CryptoSecurityConfig,
    CryptoSecureMemory,
    CryptoConstantTime,
    CryptoParameterValidation,
    CryptoRateLimiter,
    SideChannelResistant,
    CryptoSecurityAuditor,
    crypto_secure_compare,
    crypto_zeroize_key,
    crypto_validate_key,
    crypto_check_rate_limit,
)


class TestCryptoSecureMemory(unittest.TestCase):
    """Test secure key memory handling."""
    
    def test_key_material_zeroization_bytearray(self):
        """Test that key material bytearrays are properly zeroized."""
        key = bytearray(b'this is a very secret key material')
        original = bytes(key)
        
        CryptoSecureMemory.zeroize_key_material(key)
        
        # After zeroization, all bytes should be 0
        self.assertEqual(len(key), len(original))
        self.assertTrue(all(b == 0 for b in key))
    
    def test_create_secure_key_buffer(self):
        """Test creating secure key buffer."""
        buffer = CryptoSecureMemory.create_secure_key_buffer(32)
        
        self.assertEqual(len(buffer), 32)
        self.assertIsInstance(buffer, bytearray)
        # Should be zero-initialized
        self.assertTrue(all(b == 0 for b in buffer))
    
    def test_copy_to_secure_buffer(self):
        """Test copying to mutable secure buffer."""
        immutable_key = b'immutable secret key 12345'
        mutable = CryptoSecureMemory.copy_to_secure_key_buffer(immutable_key)
        
        self.assertEqual(bytes(mutable), immutable_key)
        self.assertIsInstance(mutable, bytearray)
        
        # Can modify and zeroize
        CryptoSecureMemory.zeroize_key_material(mutable)
        self.assertTrue(all(b == 0 for b in mutable))
    
    def test_generate_ephemeral_key(self):
        """Test ephemeral key generation."""
        key_bytes, key_buffer = CryptoSecureMemory.generate_ephemeral_key(32)
        
        self.assertEqual(len(key_bytes), 32)
        self.assertEqual(len(key_buffer), 32)
        self.assertEqual(bytes(key_buffer), key_bytes)
        
        # Can zeroize the buffer
        CryptoSecureMemory.zeroize_key_material(key_buffer)
        self.assertTrue(all(b == 0 for b in key_buffer))
    
    def test_secure_compare_keys(self):
        """Test secure key comparison."""
        key1 = b'secret key 123'
        key2 = b'secret key 123'
        key3 = b'different key'
        
        self.assertTrue(CryptoSecureMemory.secure_compare_keys(key1, key2))
        self.assertFalse(CryptoSecureMemory.secure_compare_keys(key1, key3))
    
    def test_list_zeroization(self):
        """Test list zeroization."""
        key_parts = ['secret', 'key', 'parts']
        
        CryptoSecureMemory.zeroize_key_material(key_parts)
        
        self.assertEqual(len(key_parts), 0)
    
    def test_dict_zeroization(self):
        """Test dictionary zeroization."""
        key_dict = {'key1': 'secret', 'key2': 'material'}
        
        CryptoSecureMemory.zeroize_key_material(key_dict)
        
        self.assertEqual(len(key_dict), 0)


class TestCryptoConstantTime(unittest.TestCase):
    """Test constant-time cryptographic operations."""
    
    def test_compare_digest_equal(self):
        """Test constant-time digest comparison with equal values."""
        a = hashlib.sha256(b'test').digest()
        b = hashlib.sha256(b'test').digest()
        
        self.assertTrue(CryptoConstantTime.compare_digest(a, b))
    
    def test_compare_digest_not_equal(self):
        """Test constant-time digest comparison with different values."""
        a = hashlib.sha256(b'test1').digest()
        b = hashlib.sha256(b'test2').digest()
        
        self.assertFalse(CryptoConstantTime.compare_digest(a, b))
    
    def test_select_secure(self):
        """Test constant-time conditional selection."""
        a = b'value if true'
        b = b'value if false'
        
        result_true = CryptoConstantTime.select_secure(True, a, b)
        result_false = CryptoConstantTime.select_secure(False, a, b)
        
        self.assertEqual(result_true, a)
        self.assertEqual(result_false, b)
    
    def test_verify_hmac_constant_time(self):
        """Test constant-time HMAC verification."""
        key = b'secret hmac key 12345'
        data = b'message to authenticate'
        expected = hmac.new(key, data, 'sha3_256').digest()
        
        self.assertTrue(
            CryptoConstantTime.verify_hmac_constant_time(key, data, expected, 'sha3_256')
        )
    
    def test_verify_hmac_wrong(self):
        """Test constant-time HMAC verification with wrong MAC."""
        key = b'secret hmac key 12345'
        data = b'message to authenticate'
        wrong_mac = b'0' * 32
        
        self.assertFalse(
            CryptoConstantTime.verify_hmac_constant_time(key, data, wrong_mac, 'sha3_256')
        )
    
    def test_constant_time_xor(self):
        """Test constant-time XOR operation."""
        a = b'\x01\x02\x03\x04'
        b = b'\x04\x03\x02\x01'
        
        result = CryptoConstantTime.constant_time_xor(a, b)
        
        self.assertEqual(result, b'\x05\x01\x01\x05')
    
    def test_constant_time_pad(self):
        """Test constant-time padding."""
        data = b'test'
        padded = CryptoConstantTime.pad_to_length_constant_time(data, 16)
        
        self.assertEqual(len(padded), 16)
        self.assertTrue(padded.startswith(data))
    
    def test_pad_truncates_long(self):
        """Test padding truncates long input."""
        data = b'very long data that exceeds target'
        padded = CryptoConstantTime.pad_to_length_constant_time(data, 8)
        
        self.assertEqual(len(padded), 8)
        self.assertEqual(padded, data[:8])


class TestCryptoParameterValidation(unittest.TestCase):
    """Test cryptographic parameter validation."""
    
    def setUp(self):
        self.validator = CryptoParameterValidation()
    
    def test_valid_aes_256_key(self):
        """Test validation of valid AES-256 key."""
        import secrets
        key = secrets.token_bytes(32)  # AES-256 key
        
        is_valid, issues = self.validator.validate_key_length(key, 'aes-256')
        
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)
    
    def test_invalid_key_length(self):
        """Test validation of wrong length key."""
        key = b'short key'  # Too short for AES-256
        
        is_valid, issues = self.validator.validate_key_length(key, 'aes-256')
        
        self.assertFalse(is_valid)
        self.assertGreater(len(issues), 0)
    
    def test_all_zeros_key(self):
        """Test detection of all-zeros weak key."""
        key = b'\x00' * 32
        
        is_valid, issues = self.validator.validate_key_length(key, 'aes-256')
        
        self.assertFalse(is_valid)
        self.assertTrue(any('all zeros' in issue.lower() for issue in issues))
    
    def test_all_ones_key(self):
        """Test detection of all-ones weak key."""
        key = b'\xFF' * 32
        
        is_valid, issues = self.validator.validate_key_length(key, 'aes-256')
        
        self.assertFalse(is_valid)
        self.assertTrue(any('all ones' in issue.lower() for issue in issues))
    
    def test_valid_nonce(self):
        """Test validation of valid AES-GCM nonce."""
        import secrets
        nonce = secrets.token_bytes(12)  # NIST recommended
        
        is_valid, issues = self.validator.validate_nonce_length(nonce, 'aes-gcm')
        
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)
    
    def test_short_nonce(self):
        """Test validation of short nonce."""
        nonce = b'short'
        
        is_valid, issues = self.validator.validate_nonce_length(nonce, 'aes-gcm')
        
        self.assertFalse(is_valid)
        self.assertGreater(len(issues), 0)
    
    def test_valid_ciphertext(self):
        """Test validation of valid ciphertext."""
        ciphertext = b'x' * 32
        
        is_valid, issues = self.validator.validate_ciphertext_integrity(ciphertext)
        
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)
    
    def test_short_ciphertext(self):
        """Test validation of too-short ciphertext."""
        ciphertext = b'short'
        
        is_valid, issues = self.validator.validate_ciphertext_integrity(
            ciphertext, min_length=16
        )
        
        self.assertFalse(is_valid)
        self.assertGreater(len(issues), 0)
    
    def test_empty_ciphertext(self):
        """Test validation of empty ciphertext."""
        ciphertext = b''
        
        is_valid, issues = self.validator.validate_ciphertext_integrity(ciphertext)
        
        self.assertFalse(is_valid)
        self.assertTrue(any('empty' in issue.lower() for issue in issues))
    
    def test_secure_decorator(self):
        """Test validation decorator wraps functions."""
        @self.validator.secure_decorator
        def encrypt_func(key, data):
            return f"encrypted with {len(key)} byte key"
        
        import secrets
        key = secrets.token_bytes(32)
        result = encrypt_func(key, "test data")
        
        self.assertIn('32 byte key', result)
    
    def test_crypto_validate_key_convenience(self):
        """Test crypto_validate_key convenience function."""
        import secrets
        good_key = secrets.token_bytes(32)
        bad_key = b'short'
        
        self.assertTrue(crypto_validate_key(good_key, 'aes-256'))
        self.assertFalse(crypto_validate_key(bad_key, 'aes-256'))


class TestCryptoRateLimiter(unittest.TestCase):
    """Test cryptographic operation rate limiting."""
    
    def test_initial_capacity(self):
        """Test rate limiter starts with full capacity."""
        limiter = CryptoRateLimiter(max_ops_per_second=50, burst_size=50)
        
        self.assertEqual(limiter.get_available_capacity(), 50)
    
    def test_acquire_basic_operation(self):
        """Test acquiring basic operation tokens."""
        limiter = CryptoRateLimiter(max_ops_per_second=100, burst_size=10)
        
        # Should allow 10 operations
        for _ in range(10):
            self.assertTrue(limiter.try_acquire_operation('default'))
        
        # 11th should fail
        self.assertFalse(limiter.try_acquire_operation('default'))
    
    def test_operation_costs(self):
        """Test different operations have different costs."""
        limiter = CryptoRateLimiter(max_ops_per_second=100, burst_size=20)
        
        # Key exchange is expensive (10 tokens)
        self.assertTrue(limiter.try_acquire_operation('key_exchange'))
        
        # Should have ~10 tokens left (allow small epsilon for timing refill)
        remaining = limiter.get_available_capacity()
        self.assertLessEqual(remaining, 10.1)
    
    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = CryptoRateLimiter(
            max_ops_per_second=100,
            per_seconds=1.0,
            burst_size=10
        )
        
        # Use all tokens
        for _ in range(10):
            limiter.try_acquire_operation()
        
        self.assertFalse(limiter.try_acquire_operation())
        
        # Wait for refill
        time.sleep(0.15)
        
        # Should have tokens back
        capacity = limiter.get_available_capacity()
        self.assertGreater(capacity, 0)
    
    def test_crypto_check_rate_limit_convenience(self):
        """Test crypto_check_rate_limit convenience function."""
        result = crypto_check_rate_limit('encryption')
        self.assertIsInstance(result, bool)


class TestSideChannelResistant(unittest.TestCase):
    """Test side-channel attack mitigations."""
    
    def test_timing_noise(self):
        """Test timing noise adds delay."""
        start = time.time()
        SideChannelResistant.add_timing_noise(base_delay=0.001, max_jitter=0.001)
        elapsed = time.time() - start
        
        # Should have added at least some delay
        self.assertGreater(elapsed, 0.0005)
    
    def test_blind_operation(self):
        """Test operation blinding."""
        data = b'sensitive data to blind'
        
        blinded, factor = SideChannelResistant.blind_operation(data)
        
        # Blinded should be different
        self.assertNotEqual(blinded, data)
        self.assertEqual(len(blinded), len(data))
    
    def test_unblind_operation(self):
        """Test unblinding recovers original data."""
        data = b'sensitive data'
        
        blinded, factor = SideChannelResistant.blind_operation(data)
        unblinded = SideChannelResistant.unblind_operation(blinded, factor)
        
        self.assertEqual(unblinded, data)
    
    def test_blind_with_custom_factor(self):
        """Test blinding with custom factor."""
        data = b'test data'
        factor = b'\xAA' * len(data)
        
        blinded, returned_factor = SideChannelResistant.blind_operation(data, factor)
        
        # Should use provided factor
        self.assertEqual(returned_factor, factor)
        
        # Unblind should work
        unblinded = SideChannelResistant.unblind_operation(blinded, factor)
        self.assertEqual(unblinded, data)
    
    def test_dummy_operations(self):
        """Test dummy operations execute without error."""
        # Should not raise any exceptions
        SideChannelResistant.dummy_operations(count=5)


class TestCryptoSecurityAuditor(unittest.TestCase):
    """Test cryptographic security auditing."""
    
    def test_log_operation(self):
        """Test logging cryptographic operations."""
        auditor = CryptoSecurityAuditor(max_events=100)
        
        auditor.log_crypto_operation(
            operation='encryption',
            algorithm='AES-256-GCM',
            success=True,
            duration=0.001,
            details={'key_size': 256}
        )
        
        stats = auditor.get_crypto_statistics()
        self.assertEqual(stats['total_operations'], 1)
    
    def test_failure_tracking(self):
        """Test failure tracking in auditor."""
        auditor = CryptoSecurityAuditor()
        
        # Log some successes and failures
        for i in range(8):
            auditor.log_crypto_operation('sign', 'ECDSA', True, 0.001)
        for i in range(2):
            auditor.log_crypto_operation('sign', 'ECDSA', False, 0.001)
        
        stats = auditor.get_crypto_statistics()
        self.assertEqual(stats['total_operations'], 10)
        
        # Should have 20% failure rate
        failure_rate = stats['failure_rates']['sign:ECDSA']
        self.assertAlmostEqual(failure_rate, 0.2, places=1)
    
    def test_anomaly_detection(self):
        """Test anomaly detection for high failure rates."""
        auditor = CryptoSecurityAuditor()
        
        # High failure rate (50%)
        for i in range(5):
            auditor.log_crypto_operation('decrypt', 'AES', True, 0.001)
        for i in range(5):
            auditor.log_crypto_operation('decrypt', 'AES', False, 0.001)
        
        anomalies = auditor.detect_anomalies()
        self.assertGreater(len(anomalies), 0)
        
        # Should find high failure rate anomaly
        self.assertTrue(
            any(a['type'] == 'high_failure_rate' for a in anomalies)
        )


class TestCryptoSecurityConfig(unittest.TestCase):
    """Test cryptographic security configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = CryptoSecurityConfig()
        
        self.assertEqual(config.security_level, CryptoSecurityLevel.NIST_CATEGORY_5)
        self.assertTrue(config.enable_key_zeroization)
        self.assertTrue(config.enable_constant_time)
        self.assertEqual(config.key_zeroization_passes, 5)
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = CryptoSecurityConfig(
            security_level=CryptoSecurityLevel.QUANTUM_RESISTANT,
            max_crypto_ops_per_second=25,
            min_symmetric_key_bytes=32
        )
        
        self.assertEqual(config.security_level, CryptoSecurityLevel.QUANTUM_RESISTANT)
        self.assertEqual(config.max_crypto_ops_per_second, 25)
        self.assertEqual(config.min_symmetric_key_bytes, 32)


class TestConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_crypto_secure_compare(self):
        """Test crypto_secure_compare convenience function."""
        self.assertTrue(crypto_secure_compare(b'test', b'test'))
        self.assertFalse(crypto_secure_compare(b'test', b'different'))
    
    def test_crypto_zeroize_key(self):
        """Test crypto_zeroize_key convenience function."""
        key = bytearray(b'secret key material')
        crypto_zeroize_key(key)
        self.assertTrue(all(b == 0 for b in key))


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of crypto security utilities."""
    
    def test_rate_limiter_thread_safety(self):
        """Test rate limiter thread safety."""
        limiter = CryptoRateLimiter(max_ops_per_second=1000, burst_size=200)
        results = []
        
        def worker():
            for _ in range(20):
                results.append(limiter.try_acquire_operation())
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should have completed
        self.assertEqual(len(results), 100)
    
    def test_auditor_thread_safety(self):
        """Test auditor thread safety."""
        auditor = CryptoSecurityAuditor()
        
        def worker():
            for i in range(10):
                auditor.log_crypto_operation(
                    'test', 'TEST-ALG', True, 0.001
                )
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = auditor.get_crypto_statistics()
        self.assertEqual(stats['total_operations'], 50)


if __name__ == '__main__':
    unittest.main(verbosity=2)
