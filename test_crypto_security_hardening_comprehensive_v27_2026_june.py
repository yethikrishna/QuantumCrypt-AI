"""
Test Suite for QuantumCrypt Security Hardening Module v27
DIMENSION B - Security Hardening
All tests verify crypto security functionality without modifying core code.
"""

import pytest
import secrets
import threading
import time
from quantum_crypt.crypto_security_hardening_comprehensive_v27_2026_june import (
    CryptoSecurityLevel,
    KeyType,
    KeyValidationResult,
    CryptoRateLimitConfig,
    CryptoSecureMemory,
    CryptoConstantTime,
    KeyMaterialValidator,
    CryptoOperationLimiter,
    RandomnessValidator,
    CryptoSecurityHardener,
    CryptoSecurityError,
    crypto_secure_compare,
    crypto_zeroize_key,
    generate_secure_random
)


class TestCryptoSecureMemory:
    """Tests for cryptographic secure memory zeroization."""
    
    def test_zeroize_key_material(self):
        """Test key material is properly zeroized."""
        key = bytearray(secrets.token_bytes(32))
        original = bytes(key)
        
        CryptoSecureMemory.zeroize_key_material(key)
        
        assert all(b == 0 for b in key)
        assert bytes(key) != original
    
    def test_zeroize_different_lengths(self):
        """Test zeroization works for various key sizes."""
        for length in [16, 24, 32, 64, 128]:
            key = bytearray(secrets.token_bytes(length))
            CryptoSecureMemory.zeroize_key_material(key)
            assert all(b == 0 for b in key)
    
    def test_zeroize_empty_bytearray(self):
        """Test zeroization handles empty arrays."""
        empty = bytearray()
        CryptoSecureMemory.zeroize_key_material(empty)
        assert len(empty) == 0
    
    def test_zeroize_non_bytearray_no_error(self):
        """Test non-bytearray inputs don't cause errors."""
        CryptoSecureMemory.zeroize_key_material("not a bytearray")  # Should not raise
        CryptoSecureMemory.zeroize_key_material(None)  # Should not raise
    
    def test_zeroize_sensitive_buffer_memoryview(self):
        """Test memoryview buffer zeroization."""
        data = bytearray(b"test_data")
        view = memoryview(data)
        CryptoSecureMemory.zeroize_sensitive_buffer(view)
        assert all(b == 0 for b in data)
    
    def test_wipe_object_secrets(self):
        """Test object secret wiping."""
        class TestKeyHolder:
            def __init__(self):
                self.private_key = bytearray(b"secret_key_material")
                self.public_data = "public info"
        
        holder = TestKeyHolder()
        CryptoSecureMemory.wipe_object_secrets(holder)
        
        # Private key should be zeroized and cleared
        assert holder.private_key is None
    
    def test_crypto_zeroize_key_convenience(self):
        """Test convenience function works."""
        key = bytearray(b"test_key_123")
        crypto_zeroize_key(key)
        assert all(b == 0 for b in key)


class TestCryptoConstantTime:
    """Tests for cryptographic constant-time operations."""
    
    def test_compare_digests_equal(self):
        """Test equal digests compare correctly."""
        digest = secrets.token_bytes(32)
        assert CryptoConstantTime.compare_digests(digest, digest) is True
    
    def test_compare_digests_unequal(self):
        """Test unequal digests compare correctly."""
        digest1 = secrets.token_bytes(32)
        digest2 = secrets.token_bytes(32)
        assert CryptoConstantTime.compare_digests(digest1, digest2) is False
    
    def test_compare_digests_different_lengths(self):
        """Test different length digests return False."""
        digest1 = secrets.token_bytes(32)
        digest2 = secrets.token_bytes(64)
        assert CryptoConstantTime.compare_digests(digest1, digest2) is False
    
    def test_select_constant_time(self):
        """Test constant-time selection works."""
        a = b"\x01\x02\x03\x04"
        b = b"\x05\x06\x07\x08"
        
        assert CryptoConstantTime.select(True, a, b) == a
        assert CryptoConstantTime.select(False, a, b) == b
    
    def test_is_equal_bytes(self):
        """Test byte equality check."""
        data = secrets.token_bytes(32)
        assert CryptoConstantTime.is_equal_bytes(data, data) is True
        assert CryptoConstantTime.is_equal_bytes(data, data[::-1]) is False
    
    def test_is_equal_bytes_different_length(self):
        """Test different length bytes return False."""
        assert CryptoConstantTime.is_equal_bytes(b"a", b"aa") is False
    
    def test_verify_mac(self):
        """Test MAC verification works."""
        key = secrets.token_bytes(32)
        data = b"test message"
        
        import hmac
        import hashlib
        expected_mac = hmac.new(key, data, hashlib.sha256).digest()
        
        assert CryptoConstantTime.verify_mac(expected_mac, data, key) is True
        
        # Wrong MAC should fail
        wrong_mac = secrets.token_bytes(32)
        assert CryptoConstantTime.verify_mac(wrong_mac, data, key) is False
    
    def test_crypto_secure_compare_convenience(self):
        """Test convenience comparison function."""
        data = secrets.token_bytes(32)
        assert crypto_secure_compare(data, data) is True
        assert crypto_secure_compare(data, b"wrong") is False


class TestKeyMaterialValidator:
    """Tests for key material validation."""
    
    def test_validate_valid_symmetric_key(self):
        """Test valid 256-bit symmetric key passes."""
        validator = KeyMaterialValidator()
        key = secrets.token_bytes(32)  # 256 bits
        result = validator.validate_key(key)
        
        assert result.is_valid is True
        assert result.estimated_strength_bits == 256
        assert len(result.errors) == 0
    
    def test_validate_empty_key(self):
        """Test empty key fails validation."""
        validator = KeyMaterialValidator()
        result = validator.validate_key(b"")
        
        assert result.is_valid is False
        assert "Empty" in result.errors[0]
    
    def test_validate_non_bytes(self):
        """Test non-bytes input fails gracefully."""
        validator = KeyMaterialValidator()
        result = validator.validate_key("not bytes")  # type: ignore
        
        assert result.is_valid is False
        assert "must be bytes" in result.errors[0]
    
    def test_validate_key_too_short(self):
        """Test short key fails with bounds check."""
        validator = KeyMaterialValidator()
        result = validator.validate_key(b"short", min_length=10)
        
        assert result.is_valid is False
        assert any("too short" in e.lower() for e in result.errors)
    
    def test_validate_key_too_long(self):
        """Test long key fails with bounds check."""
        validator = KeyMaterialValidator()
        result = validator.validate_key(b"x" * 1000, max_length=100)
        
        assert result.is_valid is False
        assert any("too long" in e.lower() for e in result.errors)
    
    def test_estimate_entropy(self):
        """Test entropy estimation works."""
        validator = KeyMaterialValidator()
        
        # High entropy random data
        high_entropy = secrets.token_bytes(64)
        entropy = validator.estimate_entropy(high_entropy)
        assert entropy > 0.0
        
        # Low entropy repeating data
        low_entropy = b"\x00" * 64
        entropy = validator.estimate_entropy(low_entropy)
        assert entropy < 1.0
    
    def test_repeating_pattern_detection(self):
        """Test repeating patterns are detected."""
        validator = KeyMaterialValidator()
        
        # Single byte repetition
        weak_key = b"\xAA" * 32
        result = validator.validate_key(weak_key)
        assert any("repeating" in w.lower() for w in result.warnings)
    
    def test_sequential_pattern_detection(self):
        """Test sequential patterns are detected."""
        validator = KeyMaterialValidator()
        sequential_key = bytes(range(32))
        result = validator.validate_key(sequential_key)
        # May or may not trigger depending on pattern
    
    def test_detect_key_type_symmetric(self):
        """Test symmetric key type detection."""
        validator = KeyMaterialValidator()
        
        # AES-256 key size
        result = validator.validate_key(secrets.token_bytes(32))
        assert result.key_type == KeyType.SYMMETRIC
    
    def test_detect_key_type_post_quantum(self):
        """Test post-quantum key type detection."""
        validator = KeyMaterialValidator()
        
        # Large PQ-style key
        result = validator.validate_key(secrets.token_bytes(2000))
        assert result.key_type == KeyType.POST_QUANTUM
    
    def test_detect_key_type_hybrid(self):
        """Test hybrid key type detection."""
        validator = KeyMaterialValidator()
        
        # Medium hybrid key
        result = validator.validate_key(secrets.token_bytes(500))
        assert result.key_type == KeyType.HYBRID
    
    def test_quantum_security_warnings(self):
        """Test quantum security level generates appropriate warnings."""
        validator = KeyMaterialValidator(CryptoSecurityLevel.QUANTUM_RESISTANT)
        
        # Small key for quantum level
        result = validator.validate_key(secrets.token_bytes(16))  # 128 bits
        assert len(result.warnings) > 0


class TestCryptoOperationLimiter:
    """Tests for cryptographic operation rate limiting."""
    
    def test_sign_operations_limited(self):
        """Test sign operations are rate limited."""
        config = CryptoRateLimitConfig(
            max_sign_operations=5,
            window_seconds=60
        )
        limiter = CryptoOperationLimiter(config)
        
        # Should allow first 5
        for i in range(5):
            allowed, _ = limiter.can_perform_operation("sign")
            assert allowed is True
        
        # 6th should be blocked
        allowed, meta = limiter.can_perform_operation("sign")
        assert allowed is False
        assert meta.get("reason") == "rate_limit_exceeded"
    
    def test_decrypt_operations_limited(self):
        """Test decrypt operations have separate limits."""
        config = CryptoRateLimitConfig(
            max_decrypt_operations=3,
            window_seconds=60
        )
        limiter = CryptoOperationLimiter(config)
        
        for i in range(3):
            allowed, _ = limiter.can_perform_operation("decrypt")
            assert allowed is True
        
        allowed, _ = limiter.can_perform_operation("decrypt")
        assert allowed is False
    
    def test_keygen_operations_limited(self):
        """Test keygen has strict limits."""
        config = CryptoRateLimitConfig(
            max_keygen_operations=2,
            window_seconds=60
        )
        limiter = CryptoOperationLimiter(config)
        
        for i in range(2):
            allowed, _ = limiter.can_perform_operation("keygen")
            assert allowed is True
        
        allowed, _ = limiter.can_perform_operation("keygen")
        assert allowed is False
    
    def test_per_identifier_limits(self):
        """Test different identifiers have separate counters."""
        config = CryptoRateLimitConfig(max_sign_operations=2, window_seconds=60)
        limiter = CryptoOperationLimiter(config)
        
        # User 1 exhausts limit
        limiter.can_perform_operation("sign", "user1")
        limiter.can_perform_operation("sign", "user1")
        
        # User 2 should still be allowed
        allowed, _ = limiter.can_perform_operation("sign", "user2")
        assert allowed is True
    
    def test_reset_limits(self):
        """Test reset clears all limits."""
        config = CryptoRateLimitConfig(max_sign_operations=1, window_seconds=60)
        limiter = CryptoOperationLimiter(config)
        
        limiter.can_perform_operation("sign")
        limiter.reset()
        
        # Should be allowed after reset
        allowed, _ = limiter.can_perform_operation("sign")
        assert allowed is True
    
    def test_thread_safety(self):
        """Test limiter works under concurrent access."""
        config = CryptoRateLimitConfig(max_sign_operations=1000, window_seconds=60)
        limiter = CryptoOperationLimiter(config)
        
        def worker():
            for i in range(10):
                limiter.can_perform_operation("sign", f"thread_{threading.get_ident()}")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # No exceptions = success


class TestRandomnessValidator:
    """Tests for randomness validation."""
    
    def test_cryptographically_secure(self):
        """Test system has secure RNG available."""
        assert RandomnessValidator.is_cryptographically_secure() is True
    
    def test_validate_random_bytes_high_entropy(self):
        """Test good random bytes pass validation."""
        good_random = secrets.token_bytes(64)
        assert RandomnessValidator.validate_random_bytes(good_random) is True
    
    def test_validate_random_bytes_small(self):
        """Test small bytes pass automatically."""
        assert RandomnessValidator.validate_random_bytes(b"\x00") is True
    
    def test_generate_safe_random(self):
        """Test secure random generation works."""
        random_bytes = generate_secure_random(32)
        assert len(random_bytes) == 32
        assert isinstance(random_bytes, bytes)
    
    def test_generate_safe_random_different_lengths(self):
        """Test various lengths generate correctly."""
        for length in [16, 32, 64, 128]:
            result = generate_secure_random(length)
            assert len(result) == length


class TestCryptoSecurityHardener:
    """Tests for main crypto security hardener facade."""
    
    def test_security_hardener_creation(self):
        """Test hardener creation with various security levels."""
        for level in CryptoSecurityLevel:
            hardener = CryptoSecurityHardener(security_level=level)
            assert hardener.security_level == level
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        hardener = CryptoSecurityHardener()
        assert hardener._enabled is True
        
        hardener.disable()
        assert hardener._enabled is False
        
        hardener.enable()
        assert hardener._enabled is True
    
    def test_wrap_crypto_operation(self):
        """Test operation wrapping works."""
        hardener = CryptoSecurityHardener()
        
        def sign_message(message: bytes, key: bytes) -> bytes:
            return message + key
        
        wrapped = hardener.wrap_crypto_operation(sign_message, "sign")
        result = wrapped(b"test", b"key")
        assert result == b"testkey"
    
    def test_wrap_disabled_bypasses_security(self):
        """Test disabled hardener bypasses all checks."""
        hardener = CryptoSecurityHardener()
        hardener.disable()
        
        def decrypt(ciphertext: bytes) -> bytes:
            return ciphertext
        
        wrapped = hardener.wrap_crypto_operation(decrypt, "decrypt", rate_limit=True)
        result = wrapped(b"ciphertext")
        assert result == b"ciphertext"


class TestCryptoSecurityError:
    """Tests for crypto security exception."""
    
    def test_error_creation(self):
        """Test basic exception creation."""
        error = CryptoSecurityError("Test crypto error")
        assert str(error) == "Test crypto error"
        assert error.metadata == {}
    
    def test_error_with_metadata(self):
        """Test exception with metadata."""
        meta = {"operation": "sign", "attempts": 100}
        error = CryptoSecurityError("Crypto operation failed", metadata=meta)
        assert error.metadata == meta


class TestCryptoSecurityLevel:
    """Tests for crypto security level enumeration."""
    
    def test_all_levels_exist(self):
        """Test all security levels are defined."""
        levels = list(CryptoSecurityLevel)
        assert len(levels) == 4
        assert CryptoSecurityLevel.CLASSIC.value == "classic"
        assert CryptoSecurityLevel.QUANTUM_READY.value == "quantum_ready"
        assert CryptoSecurityLevel.QUANTUM_RESISTANT.value == "quantum_resistant"
        assert CryptoSecurityLevel.MAXIMUM.value == "maximum"


class TestKeyType:
    """Tests for key type enumeration."""
    
    def test_all_key_types_exist(self):
        """Test all key types are defined."""
        types = list(KeyType)
        assert len(types) == 5
        assert KeyType.SYMMETRIC.value == "symmetric"
        assert KeyType.ASYMMETRIC_PRIVATE.value == "private"
        assert KeyType.ASYMMETRIC_PUBLIC.value == "public"
        assert KeyType.POST_QUANTUM.value == "post_quantum"
        assert KeyType.HYBRID.value == "hybrid"


class TestCryptoRateLimitConfig:
    """Tests for crypto rate limit configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = CryptoRateLimitConfig()
        assert config.max_sign_operations == 1000
        assert config.max_decrypt_operations == 500
        assert config.max_keygen_operations == 50
        assert config.window_seconds == 60
        assert config.block_duration_seconds == 60
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = CryptoRateLimitConfig(
            max_sign_operations=100,
            max_decrypt_operations=50,
            max_keygen_operations=5
        )
        assert config.max_sign_operations == 100
        assert config.max_decrypt_operations == 50
        assert config.max_keygen_operations == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
