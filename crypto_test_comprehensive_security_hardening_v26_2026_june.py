"""
Test Suite for QuantumCrypt-AI Comprehensive Security Hardening v26
Dimension B - Security Hardening

Tests verify crypto-specific security features:
1. Secure key material zeroization
2. Constant-time cryptographic comparisons
3. Key and nonce validation
4. Crypto operation rate limiting
5. Secure key context management
6. Hex key sanitization

All existing tests must continue to pass - this is ADD-ONLY code.
"""

import pytest
import time
import threading
import hmac
import hashlib
from quantum_crypt.crypto_comprehensive_security_hardening_v26_2026_june import (
    CryptoSecureMemory,
    CryptoConstantTime,
    CryptoInputValidator,
    CryptoOperationRateLimiter,
    SecureKeyContext,
    SecureCryptoBuffer,
    CryptoSecurityFacade,
    CryptoSecurityLevel,
    CryptoValidationResult,
    TokenBucket,
    get_crypto_security_facade,
    generate_secure_nonce,
)


class TestCryptoSecureMemory:
    """Test cryptographic secure memory zeroization"""
    
    def test_zeroize_key_material(self):
        """Test key material is properly zeroized with multiple passes"""
        key_data = bytearray(b'\x01\x02\x03\x04\x05' * 64)  # 320 bytes of "key material"
        
        CryptoSecureMemory.zeroize_key_material(key_data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in key_data)
        assert len(key_data) == 320  # Length preserved
    
    def test_zeroize_empty_buffer(self):
        """Test empty buffer doesn't crash"""
        empty = bytearray()
        CryptoSecureMemory.zeroize_key_material(empty)
        assert len(empty) == 0
    
    def test_create_secure_key_buffer(self):
        """Test secure key buffer creation"""
        buf = CryptoSecureMemory.create_secure_key_buffer(32)
        assert isinstance(buf, bytearray)
        assert len(buf) == 32
        assert all(b == 0 for b in buf)
    
    def test_secure_compare_digests_equal(self):
        """Test digest comparison for equal values"""
        a = hashlib.sha256(b"test data").digest()
        b = hashlib.sha256(b"test data").digest()
        assert CryptoSecureMemory.secure_compare_digests(a, b) is True
    
    def test_secure_compare_digests_different(self):
        """Test digest comparison for different values"""
        a = hashlib.sha256(b"test data 1").digest()
        b = hashlib.sha256(b"test data 2").digest()
        assert CryptoSecureMemory.secure_compare_digests(a, b) is False
    
    def test_secure_compare_digests_different_length(self):
        """Test digest comparison for different lengths returns False"""
        a = hashlib.sha256(b"test").digest()  # 32 bytes
        b = hashlib.sha512(b"test").digest()  # 64 bytes
        assert CryptoSecureMemory.secure_compare_digests(a, b) is False
    
    def test_wipe_integer_list(self):
        """Test wiping integer list"""
        data = [0xFF, 0xEE, 0xDD, 0xCC]
        CryptoSecureMemory.wipe_object(data)
        assert all(x == 0 for x in data)


class TestCryptoConstantTime:
    """Test constant-time cryptographic utilities"""
    
    def test_compare_keys_equal(self):
        """Test equal key comparison"""
        key1 = b'\x00\x01\x02\x03' * 8
        key2 = b'\x00\x01\x02\x03' * 8
        assert CryptoConstantTime.compare_keys(key1, key2) is True
    
    def test_compare_keys_different(self):
        """Test different key comparison"""
        key1 = b'\x00\x01\x02\x03' * 8
        key2 = b'\xFF\xFE\xFD\xFC' * 8
        assert CryptoConstantTime.compare_keys(key1, key2) is False
    
    def test_compare_signatures(self):
        """Test signature comparison"""
        sig1 = b'SIGNATURE_DATA_12345'
        sig2 = b'SIGNATURE_DATA_12345'
        sig3 = b'SIGNATURE_DATA_67890'
        assert CryptoConstantTime.compare_signatures(sig1, sig2) is True
        assert CryptoConstantTime.compare_signatures(sig1, sig3) is False
    
    def test_verify_hmac_correct(self):
        """Test correct HMAC verification"""
        key = b'test_key_12345'
        data = b'message to authenticate'
        expected = hmac.new(key, data, hashlib.sha256).digest()
        
        assert CryptoConstantTime.verify_hmac(expected, data, key) is True
    
    def test_verify_hmac_incorrect(self):
        """Test incorrect HMAC verification fails"""
        key = b'test_key_12345'
        data = b'message to authenticate'
        wrong_mac = b'X' * 32
        
        assert CryptoConstantTime.verify_hmac(wrong_mac, data, key) is False


class TestCryptoInputValidator:
    """Test cryptographic input validation"""
    
    def test_validate_key_valid_aes256(self):
        """Test valid AES-256 key validation"""
        key = b'\x00' * 32
        result = CryptoInputValidator.validate_key(key, 'AES-256')
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_validate_key_wrong_size(self):
        """Test key with wrong size fails validation"""
        key = b'\x00' * 24  # Wrong size for AES-256 (should be 32)
        result = CryptoInputValidator.validate_key(key, 'AES-256')
        assert result.is_valid is False
        assert any("32 bytes" in e for e in result.errors)
    
    def test_validate_key_none_fails(self):
        """Test None key fails validation"""
        result = CryptoInputValidator.validate_key(None)  # type: ignore
        assert result.is_valid is False
        assert "cannot be None" in result.errors[0]
    
    def test_validate_key_all_zero_fails_high_security(self):
        """Test all-zero key fails at HIGH security level"""
        key = b'\x00' * 32
        result = CryptoInputValidator.validate_key(
            key, security_level=CryptoSecurityLevel.HIGH
        )
        assert result.is_valid is False
        assert any("All-zero key" in e for e in result.errors)
    
    def test_validate_nonce_valid_aes_gcm(self):
        """Test valid AES-GCM nonce"""
        nonce = b'\x00' * 12
        result = CryptoInputValidator.validate_nonce(nonce, 'AES-GCM')
        assert result.is_valid is True
    
    def test_validate_nonce_wrong_size(self):
        """Test nonce with wrong size"""
        nonce = b'\x00' * 16  # Wrong for AES-GCM (should be 12)
        result = CryptoInputValidator.validate_nonce(nonce, 'AES-GCM')
        assert result.is_valid is False
    
    def test_validate_plaintext_size_valid(self):
        """Test valid plaintext size"""
        data = b'x' * 1000
        result = CryptoInputValidator.validate_plaintext_size(data, max_size=10000)
        assert result.is_valid is True
    
    def test_validate_plaintext_too_large(self):
        """Test plaintext exceeding max size"""
        data = b'x' * 100000
        result = CryptoInputValidator.validate_plaintext_size(data, max_size=1000)
        assert result.is_valid is False
    
    def test_sanitize_hex_key_valid(self):
        """Test valid hex key sanitization"""
        result = CryptoInputValidator.sanitize_hex_key("aabbccddeeff00112233445566778899")
        assert result.is_valid is True
        assert result.sanitized_value == bytes.fromhex("aabbccddeeff00112233445566778899")
    
    def test_sanitize_hex_key_with_spaces(self):
        """Test hex key with whitespace is cleaned"""
        result = CryptoInputValidator.sanitize_hex_key("aa bb cc-dd:ee ff")
        assert result.is_valid is True
        assert result.sanitized_value == bytes.fromhex("aabbccddeeff")
    
    def test_sanitize_hex_key_invalid_chars(self):
        """Test hex key with invalid characters fails"""
        result = CryptoInputValidator.sanitize_hex_key("not valid hex!")
        assert result.is_valid is False


class TestTokenBucket:
    """Test token bucket for crypto rate limiting"""
    
    def test_initial_capacity(self):
        """Test bucket starts full"""
        bucket = TokenBucket(rate=10.0, capacity=5.0)
        assert bucket.consume(5.0) is True
    
    def test_empty_bucket_denies(self):
        """Test empty bucket denies requests"""
        bucket = TokenBucket(rate=1.0, capacity=2.0)
        bucket.consume(2.0)
        assert bucket.consume(1.0) is False
    
    def test_tokens_refill(self):
        """Test tokens refill over time"""
        bucket = TokenBucket(rate=100.0, capacity=5.0)
        bucket.consume(5.0)
        time.sleep(0.02)
        assert bucket.consume(1.0) is True


class TestCryptoOperationRateLimiter:
    """Test crypto operation rate limiter"""
    
    def test_key_derivation_limited(self):
        """Test key derivation operations are rate limited"""
        limiter = CryptoOperationRateLimiter()
        
        # Should allow burst of 5 key derivations
        for i in range(5):
            assert limiter.check_operation_allowed('key_derivation') is True
        
        # 6th should be denied
        assert limiter.check_operation_allowed('key_derivation') is False
    
    def test_different_operations_separate_limits(self):
        """Test different operations have separate limits"""
        limiter = CryptoOperationRateLimiter()
        
        # Empty key_derivation bucket
        for _ in range(5):
            limiter.check_operation_allowed('key_derivation')
        
        # Hash operations should still be allowed (separate bucket)
        assert limiter.check_operation_allowed('hash') is True


class TestSecureKeyContext:
    """Test secure key context manager"""
    
    def test_key_available_in_context(self):
        """Test key is accessible within context"""
        original_key = b'my_secret_key_12345'
        
        with SecureKeyContext(original_key) as key:
            assert key == original_key
    
    def test_key_zeroized_after_context(self):
        """Test key copy is zeroized after context exit"""
        original_key = b'secret_data_here'
        ctx = SecureKeyContext(original_key)
        
        with ctx as key:
            pass
        
        # The internal copy should be wiped
        assert len(ctx._key_copy) == 0  # Buffer cleared
    
    def test_nested_contexts(self):
        """Test nested contexts work"""
        with SecureKeyContext(b'key1') as k1:
            with SecureKeyContext(b'key2') as k2:
                assert k1 == b'key1'
                assert k2 == b'key2'


class TestSecureCryptoBuffer:
    """Test secure crypto buffer context manager"""
    
    def test_buffer_created_with_data(self):
        """Test buffer initialized with data"""
        data = b'sensitive plaintext data'
        
        with SecureCryptoBuffer(data) as buf:
            assert isinstance(buf, bytearray)
            assert bytes(buf) == data
    
    def test_buffer_zeroized_after_exit(self):
        """Test buffer is zeroized after context"""
        data = b'sensitive data'
        ctx = SecureCryptoBuffer(data)
        
        with ctx as buf:
            buf_ref = buf
        
        # After exit, buffer should be cleared
        assert len(ctx._buffer) == 0
    
    def test_buffer_size_only(self):
        """Test buffer created by size only"""
        with SecureCryptoBuffer(100) as buf:
            assert len(buf) == 100
            assert all(b == 0 for b in buf)


class TestCryptoSecurityFacade:
    """Test main crypto security facade"""
    
    def test_facade_creation(self):
        """Test facade creation"""
        facade = CryptoSecurityFacade(CryptoSecurityLevel.HIGH)
        assert facade.security_level == CryptoSecurityLevel.HIGH
    
    def test_validate_key_through_facade(self):
        """Test key validation through facade"""
        facade = CryptoSecurityFacade()
        key = b'\x00' * 32
        result = facade.validate_key(key, 'AES-256')
        assert isinstance(result, CryptoValidationResult)
        assert result.is_valid is True
    
    def test_validate_nonce_through_facade(self):
        """Test nonce validation through facade"""
        facade = CryptoSecurityFacade()
        nonce = b'\x00' * 12
        result = facade.validate_nonce(nonce, 'AES-GCM')
        assert result.is_valid is True
    
    def test_secure_key_context_through_facade(self):
        """Test secure key context through facade"""
        facade = CryptoSecurityFacade()
        with facade.secure_key_context(b'test_key') as key:
            assert key == b'test_key'
    
    def test_constant_time_compare_through_facade(self):
        """Test comparison through facade"""
        facade = CryptoSecurityFacade()
        assert facade.constant_time_compare(b"a", b"a") is True
        assert facade.constant_time_compare(b"a", b"b") is False
    
    def test_check_crypto_rate_limit(self):
        """Test rate limiting through facade"""
        facade = CryptoSecurityFacade()
        # Should allow operations initially
        assert facade.check_crypto_rate_limit('encryption') is True
    
    def test_get_security_stats(self):
        """Test security statistics"""
        facade = CryptoSecurityFacade()
        
        facade.validate_key(b'\x00' * 32)
        facade.validate_key(b'\x00' * 32)
        
        stats = facade.get_security_stats()
        assert stats['validations_total'] >= 2
        assert 'validations_failed' in stats
        assert 'operations_rate_limited' in stats
        assert 'keys_protected' in stats
    
    def test_zeroize_sensitive_data(self):
        """Test zeroization through facade"""
        facade = CryptoSecurityFacade()
        data = bytearray(b'sensitive')
        facade.zeroize_sensitive_data(data)
        assert all(b == 0 for b in data)
    
    def test_get_crypto_security_facade_singleton(self):
        """Test default singleton works"""
        facade = get_crypto_security_facade()
        assert isinstance(facade, CryptoSecurityFacade)


class TestGenerateSecureNonce:
    """Test secure nonce generation"""
    
    def test_generate_default_size(self):
        """Test default 12-byte nonce"""
        nonce = generate_secure_nonce()
        assert len(nonce) == 12
        assert isinstance(nonce, bytes)
    
    def test_generate_custom_size(self):
        """Test custom size nonce"""
        nonce = generate_secure_nonce(24)
        assert len(nonce) == 24
    
    def test_generate_random(self):
        """Test generated nonces are random"""
        nonces = set()
        for _ in range(100):
            nonces.add(generate_secure_nonce(8))
        # Should have no collisions
        assert len(nonces) == 100


class TestIntegration:
    """Integration tests - verify no breakage"""
    
    def test_all_modules_importable(self):
        """Test all security classes import without errors"""
        # This test passes if no import errors
        from quantum_crypt.crypto_comprehensive_security_hardening_v26_2026_june import (
            CryptoSecureMemory,
            CryptoConstantTime,
            CryptoInputValidator,
            CryptoOperationRateLimiter,
            SecureKeyContext,
            SecureCryptoBuffer,
            CryptoSecurityFacade,
        )
        assert True
    
    def test_backward_compatible(self):
        """Verify existing modules still import"""
        try:
            from quantum_crypt import __init__
            assert True
        except ImportError:
            pytest.fail("Existing core modules should still import")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
