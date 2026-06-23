"""
Tests for QuantumCrypt Security Hardening - Comprehensive Protection v19
Dimension B: Security Hardening

All tests verify the new crypto security hardening features work correctly
without breaking existing functionality.
"""

import pytest
import threading
import time
import hmac
import hashlib
import base64
import secrets

from quantum_crypt.crypto_security_hardening_comprehensive_protection_v19_2026_june import (
    CryptoSecureMemory,
    SensitiveKeyMaterial,
    CryptoConstantTime,
    CryptoInputValidator,
    KeyValidationResult,
    validate_crypto_inputs,
    KeyOperationRateLimit,
    KeyOperationRateLimiter,
    CryptoTimingResistance,
    CryptoSecurityHardening,
)


class TestCryptoSecureMemory:
    """Tests for cryptographic secure memory zeroization."""
    
    def test_zeroize_key_material(self):
        """Test key material zeroization with multiple passes."""
        key_data = bytearray(secrets.token_bytes(32))
        original = bytes(key_data)
        
        CryptoSecureMemory.zeroize_key_material(key_data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in key_data)
        # Verify original key is gone from memory
        assert bytes(key_data) != original
    
    def test_zeroize_empty_key(self):
        """Test zeroizing empty bytearray doesn't crash."""
        data = bytearray()
        CryptoSecureMemory.zeroize_key_material(data)
        assert len(data) == 0
    
    def test_secure_compare_constant_equal(self):
        """Test constant-time comparison for equal values."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        assert CryptoSecureMemory.secure_compare_constant(a, b) is True
    
    def test_secure_compare_constant_not_equal(self):
        """Test constant-time comparison for different values."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        assert CryptoSecureMemory.secure_compare_constant(a, b) is False
    
    def test_verify_hmac_valid(self):
        """Test HMAC verification with valid MAC."""
        key = secrets.token_bytes(32)
        data = b"test message to authenticate"
        mac = hmac.new(key, data, digestmod='sha256').digest()
        
        assert CryptoSecureMemory.verify_hmac(mac, key, data) is True
    
    def test_verify_hmac_invalid(self):
        """Test HMAC verification with invalid MAC."""
        key = secrets.token_bytes(32)
        data = b"test message"
        wrong_key = secrets.token_bytes(32)
        mac = hmac.new(key, data, digestmod='sha256').digest()
        
        assert CryptoSecureMemory.verify_hmac(mac, wrong_key, data) is False


class TestSensitiveKeyMaterial:
    """Tests for auto-zeroizing key material container."""
    
    def test_key_container_creation(self):
        """Test key container creation and retrieval."""
        test_key = secrets.token_bytes(32)
        with SensitiveKeyMaterial(test_key) as key_container:
            assert key_container.get_key_bytes() == test_key
    
    def test_key_destroy(self):
        """Test explicit destroy zeroizes key material."""
        key_container = SensitiveKeyMaterial(secrets.token_bytes(32))
        key_container.destroy()
        
        with pytest.raises(ValueError):
            key_container.get_key_bytes()
    
    def test_key_context_manager(self):
        """Test context manager auto-destroys key."""
        key_container = None
        with SensitiveKeyMaterial(secrets.token_bytes(32)) as kc:
            key_container = kc
            assert len(key_container.get_key_bytes()) == 32
        
        with pytest.raises(ValueError):
            key_container.get_key_bytes()


class TestCryptoConstantTime:
    """Tests for constant-time cryptographic operations."""
    
    def test_bytes_eq_equal(self):
        """Test byte equality for matching values."""
        data = secrets.token_bytes(64)
        assert CryptoConstantTime.bytes_eq(data, bytes(data)) is True
    
    def test_bytes_eq_different_length(self):
        """Test byte equality for different lengths."""
        a = secrets.token_bytes(16)
        b = secrets.token_bytes(32)
        assert CryptoConstantTime.bytes_eq(a, b) is False
    
    def test_bytes_eq_different_content(self):
        """Test byte equality for different content."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        assert CryptoConstantTime.bytes_eq(a, b) is False
    
    def test_select_byte(self):
        """Test constant-time byte selection."""
        assert CryptoConstantTime.select_byte(True, 0xFF, 0x00) == 0xFF
        assert CryptoConstantTime.select_byte(False, 0xFF, 0x00) == 0x00
    
    def test_verify_signature_constant(self):
        """Test constant-time signature verification."""
        sig1 = secrets.token_bytes(64)
        sig2 = bytes(sig1)
        sig3 = secrets.token_bytes(64)
        
        assert CryptoConstantTime.verify_signature_constant(sig1, sig2) is True
        assert CryptoConstantTime.verify_signature_constant(sig1, sig3) is False
    
    def test_public_key_fingerprint_eq(self):
        """Test fingerprint comparison."""
        fp1 = "SHA256:abcdef1234567890"
        fp2 = "SHA256:abcdef1234567890"
        fp3 = "SHA256:different_value"
        
        assert CryptoConstantTime.public_key_fingerprint_eq(fp1, fp2) is True
        assert CryptoConstantTime.public_key_fingerprint_eq(fp1, fp3) is False


class TestCryptoInputValidator:
    """Tests for cryptographic input validation."""
    
    def test_validate_key_bytes_valid(self):
        """Test valid key passes validation."""
        validator = CryptoInputValidator()
        key = secrets.token_bytes(32)
        result = validator.validate_key_bytes(key, min_length=16)
        
        assert result.is_valid is True
        assert result.sanitized == key
        assert result.key_strength > 0
    
    def test_validate_key_bytes_too_short(self):
        """Test short key fails validation."""
        validator = CryptoInputValidator()
        key = secrets.token_bytes(8)
        result = validator.validate_key_bytes(key, min_length=16)
        
        assert result.is_valid is False
        assert "too short" in result.error_message.lower()
    
    def test_validate_key_bytes_too_long(self):
        """Test oversized key fails validation."""
        validator = CryptoInputValidator()
        key = secrets.token_bytes(2048)
        result = validator.validate_key_bytes(key, max_length=1024)
        
        assert result.is_valid is False
        assert "too long" in result.error_message.lower()
    
    def test_validate_key_bytes_weak_pattern(self):
        """Test weak key patterns are rejected."""
        validator = CryptoInputValidator()
        weak_key = b'\x00' * 16 + secrets.token_bytes(16)
        result = validator.validate_key_bytes(weak_key, min_length=16)
        
        assert result.is_valid is False
        assert "weak" in result.error_message.lower()
    
    def test_validate_nonce_valid(self):
        """Test valid nonce passes."""
        validator = CryptoInputValidator()
        nonce = secrets.token_bytes(12)
        result = validator.validate_nonce(nonce, expected_length=12)
        
        assert result.is_valid is True
    
    def test_validate_nonce_wrong_length(self):
        """Test nonce with wrong length fails."""
        validator = CryptoInputValidator()
        nonce = secrets.token_bytes(16)
        result = validator.validate_nonce(nonce, expected_length=12)
        
        assert result.is_valid is False
    
    def test_validate_nonce_all_zeros(self):
        """Test all-zero nonce is rejected."""
        validator = CryptoInputValidator()
        nonce = b'\x00' * 12
        result = validator.validate_nonce(nonce, expected_length=12)
        
        assert result.is_valid is False
        assert "insecure" in result.error_message.lower()
    
    def test_validate_base64_key_valid(self):
        """Test valid base64 key passes."""
        validator = CryptoInputValidator()
        key = secrets.token_bytes(32)
        b64_key = base64.b64encode(key).decode('ascii')
        result = validator.validate_base64_key(b64_key, min_length=16)
        
        assert result.is_valid is True
        assert result.sanitized == key
    
    def test_validate_base64_key_invalid(self):
        """Test invalid base64 fails."""
        validator = CryptoInputValidator()
        result = validator.validate_base64_key("not!!!base64!!!", min_length=16)
        
        assert result.is_valid is False
        assert "Invalid base64" in result.error_message


class TestValidateCryptoInputsDecorator:
    """Tests for validate_crypto_inputs decorator."""
    
    def test_decorator_valid_key(self):
        """Test decorator allows valid keys."""
        @validate_crypto_inputs(key={'type': 'key_bytes', 'min_length': 16})
        def encrypt(key, plaintext):
            return f"Encrypted with {len(key)} byte key"
        
        key = secrets.token_bytes(32)
        result = encrypt(key=key, plaintext="test")
        assert "32 byte key" in result
    
    def test_decorator_invalid_key(self):
        """Test decorator rejects invalid keys."""
        @validate_crypto_inputs(key={'type': 'key_bytes', 'min_length': 32})
        def decrypt(key, ciphertext):
            return ciphertext
        
        short_key = secrets.token_bytes(16)
        with pytest.raises(ValueError):
            decrypt(key=short_key, ciphertext="test")
    
    def test_decorator_valid_nonce(self):
        """Test decorator validates nonce."""
        @validate_crypto_inputs(nonce={'type': 'nonce', 'length': 12})
        def aes_gcm(nonce, data):
            return data
        
        valid_nonce = secrets.token_bytes(12)
        result = aes_gcm(nonce=valid_nonce, data="test")
        assert result == "test"


class TestKeyOperationRateLimiter:
    """Tests for key operation rate limiter."""
    
    def test_key_generation_limit(self):
        """Test key generation rate limiting."""
        limiter = KeyOperationRateLimiter(
            KeyOperationRateLimit(max_key_generations=3, window_seconds=60)
        )
        
        # First 3 allowed
        for _ in range(3):
            assert limiter.check_key_generation("client1") is True
        
        # 4th should be blocked
        assert limiter.check_key_generation("client1") is False
    
    def test_signature_limit(self):
        """Test signature operation rate limiting."""
        limiter = KeyOperationRateLimiter(
            KeyOperationRateLimit(max_signatures=5, window_seconds=60)
        )
        
        for _ in range(5):
            assert limiter.check_signature("client1") is True
        
        assert limiter.check_signature("client1") is False
    
    def test_verification_limit(self):
        """Test verification rate limiting."""
        limiter = KeyOperationRateLimiter(
            KeyOperationRateLimit(max_verifications=10, window_seconds=60)
        )
        
        for _ in range(10):
            assert limiter.check_verification("client1") is True
        
        assert limiter.check_verification("client1") is False
    
    def test_independent_clients(self):
        """Test clients have independent rate limits."""
        limiter = KeyOperationRateLimiter(
            KeyOperationRateLimit(max_key_generations=2, window_seconds=60)
        )
        
        # Client 1 uses up limit
        limiter.check_key_generation("client1")
        limiter.check_key_generation("client1")
        
        # Client 2 still has full limit
        assert limiter.check_key_generation("client2") is True
        assert limiter.check_key_generation("client2") is True


class TestCryptoTimingResistance:
    """Tests for crypto timing resistance."""
    
    def test_key_op_timing_mask(self):
        """Test timing masking adds delay."""
        start = time.time()
        CryptoTimingResistance.key_op_timing_mask(min_duration=0.002, jitter=0.001)
        elapsed = time.time() - start
        assert elapsed >= 0.002
    
    def test_normalize_key_operation(self):
        """Test key operation time normalization."""
        target_ms = 10.0
        start = time.time()
        
        # Quick work
        x = hashlib.sha256(b"test").digest()
        
        CryptoTimingResistance.normalize_key_operation(target_ms, start)
        elapsed = (time.time() - start) * 1000
        assert elapsed >= target_ms
    
    def test_dummy_key_operations(self):
        """Test dummy operations execute without error."""
        # Should not raise any exceptions
        CryptoTimingResistance.dummy_key_operations(count=5)


class TestCryptoSecurityHardeningFacade:
    """Tests for the unified crypto security facade."""
    
    def test_facade_instantiation(self):
        """Test facade can be created."""
        security = CryptoSecurityHardening()
        assert security is not None
    
    def test_facade_secure_key_compare(self):
        """Test facade key comparison."""
        security = CryptoSecurityHardening()
        key = secrets.token_bytes(32)
        assert security.secure_key_compare(key, bytes(key)) is True
        assert security.secure_key_compare(key, secrets.token_bytes(32)) is False
    
    def test_facade_validate_private_key_valid(self):
        """Test facade validates good private keys."""
        security = CryptoSecurityHardening()
        key = secrets.token_bytes(32)
        result = security.validate_private_key(key)
        assert result == key
    
    def test_facade_validate_private_key_invalid(self):
        """Test facade rejects weak private keys."""
        security = CryptoSecurityHardening()
        weak_key = b'\x00' * 32
        with pytest.raises(ValueError):
            security.validate_private_key(weak_key)
    
    def test_facade_create_sensitive_key(self):
        """Test facade creates sensitive key containers."""
        security = CryptoSecurityHardening()
        key = secrets.token_bytes(32)
        container = security.create_sensitive_key(key)
        assert container.get_key_bytes() == key
        container.destroy()
    
    def test_facade_rate_limits(self):
        """Test facade rate limiting."""
        security = CryptoSecurityHardening()
        assert security.check_key_gen_rate_limit("test_client") is True
        assert security.check_signature_rate_limit("test_client") is True


class TestThreadSafety:
    """Tests for thread safety of security components."""
    
    def test_rate_limiter_thread_safety(self):
        """Test rate limiter under concurrent access."""
        limiter = KeyOperationRateLimiter(
            KeyOperationRateLimit(max_verifications=1000, window_seconds=60)
        )
        errors = []
        
        def worker():
            try:
                for _ in range(50):
                    limiter.check_verification("shared_client")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
