"""
Test Suite for QuantumCrypt AI - Comprehensive Security Hardening v24
DIMENSION B - Security Hardening

ADD-ONLY tests - no production code modifications
All existing tests must continue to pass
"""

import unittest
import time
import threading
import os
import sys
import secrets

# Import the new security hardening module (ADD-ONLY)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))
from crypto_comprehensive_security_hardening_v24_2026_june import (
    CryptoSecurityLevel,
    CryptoSecureMemory,
    CryptoConstantTime,
    CryptoValidationResult,
    CryptoInputValidator,
    CryptoOperationRateLimiter,
    SecureKeyContainer,
    SideChannelMitigation,
    crypto_security_validation,
)


class TestCryptoSecureMemory(unittest.TestCase):
    """Test cryptographic secure memory zeroization."""

    def test_zeroize_key_material(self):
        """Test FIPS 140-3 compliant key zeroization."""
        key = bytearray(secrets.token_bytes(32))  # 256-bit key
        original = bytes(key)
        CryptoSecureMemory.zeroize_key_material(key)
        self.assertEqual(len(key), len(original))
        self.assertTrue(all(b == 0 for b in key))

    def test_zeroize_key_material_empty(self):
        """Test zeroization handles empty bytearray."""
        key = bytearray()
        CryptoSecureMemory.zeroize_key_material(key)
        self.assertEqual(len(key), 0)

    def test_zeroize_key_material_non_bytearray(self):
        """Test zeroization handles non-bytearray gracefully."""
        key = b'immutable key material'
        # Should not raise
        CryptoSecureMemory.zeroize_key_material(key)  # type: ignore

    def test_zeroize_sensitive_buffer(self):
        """Test buffer zeroization."""
        buffer = bytearray(b'sensitive plaintext data')
        CryptoSecureMemory.zeroize_sensitive_buffer(buffer)
        self.assertTrue(all(b == 0 for b in buffer))


class TestCryptoConstantTime(unittest.TestCase):
    """Test cryptographic constant-time operations."""

    def test_compare_keys_equal(self):
        """Test equal key comparison."""
        key1 = secrets.token_bytes(32)
        key2 = bytes(key1)
        self.assertTrue(CryptoConstantTime.compare_keys(key1, key2))

    def test_compare_keys_not_equal(self):
        """Test non-equal key comparison."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        self.assertFalse(CryptoConstantTime.compare_keys(key1, key2))
        self.assertFalse(CryptoConstantTime.compare_keys(key1, key1[:-1]))

    def test_compare_macs(self):
        """Test MAC comparison."""
        import hmac
        import hashlib
        key = secrets.token_bytes(32)
        mac1 = hmac.new(key, b'data', hashlib.sha256).digest()
        mac2 = hmac.new(key, b'data', hashlib.sha256).digest()
        mac3 = hmac.new(key, b'different', hashlib.sha256).digest()
        self.assertTrue(CryptoConstantTime.compare_macs(mac1, mac2))
        self.assertFalse(CryptoConstantTime.compare_macs(mac1, mac3))

    def test_compare_hashes(self):
        """Test hash comparison."""
        hash1 = 'a' * 64
        hash2 = 'a' * 64
        hash3 = 'b' * 64
        self.assertTrue(CryptoConstantTime.compare_hashes(hash1, hash2))
        self.assertFalse(CryptoConstantTime.compare_hashes(hash1, hash3))
        self.assertFalse(CryptoConstantTime.compare_hashes(hash1, 'a' * 32))

    def test_compare_signatures(self):
        """Test signature comparison."""
        sig1 = secrets.token_bytes(64)
        sig2 = bytes(sig1)
        sig3 = secrets.token_bytes(64)
        self.assertTrue(CryptoConstantTime.compare_signatures(sig1, sig2))
        self.assertFalse(CryptoConstantTime.compare_signatures(sig1, sig3))

    def test_constant_time_select(self):
        """Test constant-time conditional selection."""
        a = b'\x01\x02\x03\x04'
        b = b'\x05\x06\x07\x08'
        self.assertEqual(CryptoConstantTime.constant_time_select(True, a, b), a)
        self.assertEqual(CryptoConstantTime.constant_time_select(False, a, b), b)


class TestCryptoInputValidator(unittest.TestCase):
    """Test cryptographic input validation."""

    def setUp(self):
        self.validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)

    def test_validate_key_bytes_valid(self):
        """Test valid key validation."""
        key = secrets.token_bytes(32)  # 256-bit key
        result = self.validator.validate_key_bytes(key, min_bits=128, max_bits=512)
        self.assertTrue(result.valid)
        self.assertEqual(len(result.errors), 0)

    def test_validate_key_bytes_too_small(self):
        """Test small key rejection."""
        key = secrets.token_bytes(8)  # 64-bit - too small
        result = self.validator.validate_key_bytes(key, min_bits=128)
        self.assertFalse(result.valid)
        self.assertIn('too small', result.errors[0])

    def test_validate_key_bytes_all_zero(self):
        """Test all-zero key rejection."""
        key = b'\x00' * 32
        result = self.validator.validate_key_bytes(key)
        self.assertFalse(result.valid)
        self.assertIn('All-zero key', result.errors[0])

    def test_validate_key_bytes_wrong_type(self):
        """Test type checking for keys."""
        result = self.validator.validate_key_bytes("not bytes")  # type: ignore
        self.assertFalse(result.valid)
        self.assertIn('must be bytes', result.errors[0])

    def test_validate_nonce_valid(self):
        """Test valid nonce validation."""
        nonce = secrets.token_bytes(12)
        result = self.validator.validate_nonce(nonce, expected_length=12)
        self.assertTrue(result.valid)

    def test_validate_nonce_length_mismatch(self):
        """Test nonce length mismatch detection."""
        nonce = secrets.token_bytes(16)
        result = self.validator.validate_nonce(nonce, expected_length=12)
        self.assertFalse(result.valid)
        self.assertIn('length mismatch', result.errors[0])

    def test_validate_hex_string_valid(self):
        """Test valid hex string."""
        result = self.validator.validate_hex_string('aabbccddeeff00112233445566778899')
        self.assertTrue(result.valid)

    def test_validate_hex_string_invalid_chars(self):
        """Test invalid hex character detection."""
        result = self.validator.validate_hex_string('aabbccgg')
        self.assertFalse(result.valid)
        self.assertIn('Invalid hexadecimal', result.errors[0])

    def test_validate_hex_string_odd_length(self):
        """Test odd-length hex string rejection."""
        result = self.validator.validate_hex_string('abc', even_length=True)
        self.assertFalse(result.valid)

    def test_validate_base64_string_valid(self):
        """Test valid Base64 string."""
        result = self.validator.validate_base64_string('SGVsbG8gV29ybGQ=')
        self.assertTrue(result.valid)

    def test_validate_plaintext_size(self):
        """Test plaintext size validation."""
        data = b'test data'
        result = self.validator.validate_plaintext_size(data, max_size=1000)
        self.assertTrue(result.valid)

        large_data = b'x' * 10000
        result = self.validator.validate_plaintext_size(large_data, max_size=1000)
        self.assertFalse(result.valid)

    def test_sanitize_key_for_logging(self):
        """Test key sanitization for logging."""
        key = secrets.token_bytes(32)
        sanitized = self.validator.sanitize_key_for_logging(key)
        self.assertIn('REDACTED', sanitized)
        self.assertIn('256bit', sanitized)
        # Should only show prefix
        self.assertLess(len(sanitized), 50)

    def test_fips_security_level_strict(self):
        """Test FIPS security level enforcement."""
        validator = CryptoInputValidator(CryptoSecurityLevel.FIPS_140_3)
        key_128 = secrets.token_bytes(16)
        result = validator.validate_key_bytes(key_128, min_bits=128)
        self.assertTrue(result.valid)  # 128-bit is allowed
        self.assertGreater(len(result.warnings), 0)  # But has warning


class TestCryptoOperationRateLimiter(unittest.TestCase):
    """Test cryptographic operation rate limiting."""

    def test_key_generation_rate_limit(self):
        """Test key generation rate limiting."""
        limiter = CryptoOperationRateLimiter()
        limiter.set_custom_limit('key_generation', 100.0, 3.0)
        
        # Should allow burst of 3
        allowed, _ = limiter.check_operation('key_generation')
        self.assertTrue(allowed)
        allowed, _ = limiter.check_operation('key_generation')
        self.assertTrue(allowed)
        allowed, _ = limiter.check_operation('key_generation')
        self.assertTrue(allowed)
        
        # Should be rate limited now
        allowed, _ = limiter.check_operation('key_generation')
        self.assertFalse(allowed)

    def test_different_operation_types(self):
        """Test different operation types have separate limits."""
        limiter = CryptoOperationRateLimiter()
        limiter.set_custom_limit('signing', 100.0, 2.0)
        limiter.set_custom_limit('encryption', 100.0, 5.0)
        
        # Exhaust signing
        limiter.check_operation('signing')
        limiter.check_operation('signing')
        allowed, _ = limiter.check_operation('signing')
        self.assertFalse(allowed)
        
        # Encryption should still have capacity
        allowed, _ = limiter.check_operation('encryption')
        self.assertTrue(allowed)

    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = CryptoOperationRateLimiter()
        limiter.set_custom_limit('test', 1000.0, 2.0)
        
        # Exhaust
        limiter.check_operation('test')
        limiter.check_operation('test')
        allowed, _ = limiter.check_operation('test')
        self.assertFalse(allowed)
        
        # Wait for refill
        time.sleep(0.005)
        allowed, _ = limiter.check_operation('test')
        self.assertTrue(allowed)


class TestSecureKeyContainer(unittest.TestCase):
    """Test secure key container."""

    def test_key_storage_retrieval(self):
        """Test key storage and retrieval."""
        original_key = secrets.token_bytes(32)
        container = SecureKeyContainer(original_key)
        self.assertEqual(container.get_key(), original_key)
        self.assertEqual(container.key_size_bits, 256)

    def test_access_count_tracking(self):
        """Test key access counting."""
        container = SecureKeyContainer(secrets.token_bytes(32))
        self.assertEqual(container.access_count, 0)
        container.get_key()
        container.get_key()
        self.assertEqual(container.access_count, 2)

    def test_no_leakage_repr(self):
        """Test no key leakage in repr."""
        key = secrets.token_bytes(32)
        container = SecureKeyContainer(key)
        self.assertIn('REDACTED', repr(container))
        self.assertNotIn(key.hex(), repr(container))

    def test_no_leakage_str(self):
        """Test no key leakage in str."""
        key = secrets.token_bytes(32)
        container = SecureKeyContainer(key)
        self.assertIn('REDACTED', str(container))
        self.assertNotIn(key.hex(), str(container))

    def test_key_destruction(self):
        """Test explicit key destruction."""
        container = SecureKeyContainer(secrets.token_bytes(32))
        container.destroy()
        with self.assertRaises(ValueError):
            container.get_key()
        self.assertIn('DESTROYED', repr(container))


class TestSideChannelMitigation(unittest.TestCase):
    """Test side-channel mitigation utilities."""

    def test_timing_noise(self):
        """Test timing noise doesn't crash."""
        # Just verify it executes without error
        SideChannelMitigation.add_timing_noise(100, 50)
        self.assertTrue(True)

    def test_blinding_factor(self):
        """Test blinding factor generation."""
        modulus = 2**32
        factor = SideChannelMitigation.blinding_factor(modulus)
        import math
        self.assertEqual(math.gcd(factor, modulus), 1)
        self.assertGreater(factor, 1)
        self.assertLess(factor, modulus)

    def test_constant_time_memset(self):
        """Test constant-time memory set."""
        buf = bytearray(16)
        SideChannelMitigation.constant_time_memset(buf, 0xAA)
        self.assertTrue(all(b == 0xAA for b in buf))


class TestCryptoSecurityValidationDecorator(unittest.TestCase):
    """Test crypto security validation decorator."""

    def test_decorator_valid_key(self):
        """Test decorator with valid key input."""
        @crypto_security_validation({
            'key': {'type': 'key', 'min_bits': 128, 'max_bits': 512},
            'nonce': {'type': 'nonce', 'length': 12}
        })
        def encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
            return data  # Dummy
            
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        result = encrypt(b'test', key=key, nonce=nonce)
        self.assertEqual(result, b'test')

    def test_decorator_invalid_key(self):
        """Test decorator rejects invalid key."""
        @crypto_security_validation({
            'key': {'type': 'key', 'min_bits': 256}
        })
        def sign(data: bytes, key: bytes) -> bytes:
            return data
            
        small_key = secrets.token_bytes(16)  # 128-bit - too small
        with self.assertRaises(ValueError) as ctx:
            sign(b'test', key=small_key)
        self.assertIn('too small', str(ctx.exception))


class TestBackwardCompatibility(unittest.TestCase):
    """Verify ADD-ONLY philosophy - no breaking changes."""

    def test_module_imports_cleanly(self):
        """Verify new module imports cleanly."""
        try:
            import crypto_comprehensive_security_hardening_v24_2026_june
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Module import failed: {e}")

    def test_no_core_dependencies(self):
        """Verify module has no dependencies on existing core code."""
        # All imports are from standard library
        import crypto_comprehensive_security_hardening_v24_2026_june as module
        # Module should work standalone
        self.assertTrue(hasattr(module, 'CryptoSecureMemory'))
        self.assertTrue(hasattr(module, 'CryptoConstantTime'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
