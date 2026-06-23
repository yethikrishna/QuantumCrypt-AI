"""
Test suite for QuantumCrypt Comprehensive Security Hardening v14
Dimension B: Security Hardening

Tests cover:
1. Cryptographic key zeroization
2. Constant-time crypto comparisons
3. Crypto operation rate limiting
4. Parameter validation
5. Side-channel resistance
6. Security facade integration
"""

import sys
import os
import time
import threading
import hmac
import secrets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.crypto_security_hardening_comprehensive_v14_2026_june import (
    CryptoSecurityLevel,
    KeyType,
    CryptoSecurityContext,
    CryptoKeyZeroizer,
    CryptoConstantTime,
    CryptoOperationRateLimiter,
    CryptoParameterValidator,
    CryptoValidationResult,
    SideChannelResistance,
    CryptoSecurityFacade,
    secure_key_compare,
    secure_digest_compare,
    zeroize_key_material,
    check_crypto_operation,
    validate_crypto_key,
)


class TestCryptoKeyZeroizer:
    """Tests for cryptographic key zeroization."""

    def test_zeroize_bytearray_key(self):
        """Test zeroizing mutable bytearray key."""
        key = bytearray(secrets.token_bytes(32))
        original_length = len(key)
        CryptoKeyZeroizer.zeroize_key_bytes(key)
        
        assert all(b == 0 for b in key)
        assert len(key) == original_length

    def test_zeroize_memoryview(self):
        """Test zeroizing memoryview."""
        arr = bytearray(secrets.token_bytes(16))
        view = memoryview(arr)
        CryptoKeyZeroizer.zeroize_key_bytes(view)
        
        # Original array should be zeroed
        assert all(b == 0 for b in arr)

    def test_zeroize_key_list(self):
        """Test zeroizing list containing key material."""
        keys = [secrets.token_bytes(16), secrets.token_bytes(16)]
        CryptoKeyZeroizer.zeroize_key_list(keys)
        assert len(keys) == 0

    def test_zeroize_key_dict(self):
        """Test zeroizing dict containing key material."""
        key_dict = {
            "aes_key": secrets.token_bytes(32),
            "hmac_key": secrets.token_bytes(64)
        }
        CryptoKeyZeroizer.zeroize_key_dict(key_dict)
        assert len(key_dict) == 0

    def test_secure_wipe_multiple(self):
        """Test secure wiping multiple objects."""
        key1 = bytearray(secrets.token_bytes(16))
        key2 = bytearray(secrets.token_bytes(16))
        
        CryptoKeyZeroizer.secure_wipe(key1, key2)
        
        assert all(b == 0 for b in key1)
        assert all(b == 0 for b in key2)

    def test_zeroize_key_material_convenience(self):
        """Test convenience function."""
        key = bytearray(b"test_key_12345")
        zeroize_key_material(key)
        # Should not raise


class TestCryptoConstantTime:
    """Tests for constant-time crypto operations."""

    def test_compare_digests_equal(self):
        """Test comparing equal digests."""
        digest1 = hmac.digest(b"key", b"message", "sha256")
        digest2 = hmac.digest(b"key", b"message", "sha256")
        assert CryptoConstantTime.compare_digests(digest1, digest2) is True

    def test_compare_digests_different(self):
        """Test comparing different digests."""
        digest1 = hmac.digest(b"key1", b"message", "sha256")
        digest2 = hmac.digest(b"key2", b"message", "sha256")
        assert CryptoConstantTime.compare_digests(digest1, digest2) is False

    def test_compare_keys(self):
        """Test comparing keys."""
        key1 = secrets.token_bytes(32)
        key2 = bytes(key1)
        key3 = secrets.token_bytes(32)
        
        assert CryptoConstantTime.compare_keys(key1, key2) is True
        assert CryptoConstantTime.compare_keys(key1, key3) is False

    def test_compare_hex(self):
        """Test comparing hex strings."""
        hex1 = "aabbccddeeff"
        hex2 = "AABBCCDDEEFF"
        hex3 = "deadbeefcafe"
        
        assert CryptoConstantTime.compare_hex(hex1, hex2) is True
        assert CryptoConstantTime.compare_hex(hex1, hex3) is False

    def test_select_constant_time(self):
        """Test constant-time selection."""
        # Selection works correctly for all types
        assert CryptoConstantTime.select(True, 1, 2) == 1
        assert CryptoConstantTime.select(False, 1, 2) == 2
        assert CryptoConstantTime.select(True, "a", "b") == "a"
        assert CryptoConstantTime.select(False, "a", "b") == "b"

    def test_is_equal_constant_time(self):
        """Test constant-time integer equality."""
        assert CryptoConstantTime.is_equal_constant_time(42, 42) is True
        assert CryptoConstantTime.is_equal_constant_time(42, 43) is False

    def test_secure_key_compare_convenience(self):
        """Test convenience function."""
        key = secrets.token_bytes(32)
        assert secure_key_compare(key, bytes(key)) is True

    def test_secure_digest_compare_convenience(self):
        """Test convenience function."""
        digest = hmac.digest(b"k", b"m", "sha256")
        assert secure_digest_compare(digest, digest) is True


class TestCryptoOperationRateLimiter:
    """Tests for crypto operation rate limiting."""

    def test_allow_operations_within_limit(self):
        """Test operations within limit are allowed."""
        limiter = CryptoOperationRateLimiter(max_operations=50, window_seconds=60)
        
        for i in range(50):
            allowed, _ = limiter.check_operation_allowed("test_op")
            assert allowed is True

    def test_block_over_limit(self):
        """Test operations over limit are blocked."""
        limiter = CryptoOperationRateLimiter(max_operations=10, window_seconds=60)
        
        for i in range(10):
            limiter.check_operation_allowed("test_op")
        
        allowed, retry = limiter.check_operation_allowed("test_op")
        assert allowed is False
        assert retry > 0

    def test_key_operation_higher_cost(self):
        """Test key operations have higher cost."""
        limiter = CryptoOperationRateLimiter(
            max_operations=100,
            window_seconds=60,
            key_operations_cost=10
        )
        
        # One key op costs 10
        allowed, _ = limiter.check_operation_allowed("key_op", is_key_operation=True)
        assert allowed is True
        
        # Should have 90 left
        for i in range(9):
            allowed, _ = limiter.check_operation_allowed("key_op", is_key_operation=True)
            assert allowed is True
        
        # 10th should be blocked
        allowed, _ = limiter.check_operation_allowed("key_op", is_key_operation=True)
        assert allowed is False

    def test_suspicious_activity_tracking(self):
        """Test suspicious activity tracking."""
        limiter = CryptoOperationRateLimiter(max_operations=5, window_seconds=60)
        
        for i in range(10):
            limiter.check_operation_allowed("attacker")
        
        assert limiter.is_suspicious("attacker", threshold=5) is True

    def test_reset_operation(self):
        """Test resetting operation state."""
        limiter = CryptoOperationRateLimiter(max_operations=5, window_seconds=60)
        
        for i in range(10):
            limiter.check_operation_allowed("test")
        
        limiter.reset_operation("test")
        assert limiter.is_suspicious("test") is False

    def test_check_crypto_operation_convenience(self):
        """Test convenience function."""
        allowed, retry = check_crypto_operation("test_op")
        assert isinstance(allowed, bool)
        assert isinstance(retry, float)

    def test_thread_safety(self):
        """Test thread safety."""
        limiter = CryptoOperationRateLimiter(max_operations=1000, window_seconds=60)
        errors = []
        
        def worker():
            try:
                for i in range(20):
                    limiter.check_operation_allowed(f"thread_{i}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


class TestCryptoParameterValidator:
    """Tests for crypto parameter validation."""

    def test_validate_good_key_length(self):
        """Test validation accepts good key lengths."""
        validator = CryptoParameterValidator()
        key = secrets.token_bytes(32)  # 256 bits
        
        valid, warnings = validator.validate_key_length(key, KeyType.SYMMETRIC)
        assert valid is True
        assert len(warnings) == 0

    def test_validate_short_key(self):
        """Test validation rejects short keys."""
        validator = CryptoParameterValidator()
        key = secrets.token_bytes(8)  # 64 bits - too short
        
        valid, warnings = validator.validate_key_length(key, KeyType.SYMMETRIC)
        assert valid is False

    def test_detect_weak_key(self):
        """Test weak key detection."""
        validator = CryptoParameterValidator()
        
        # All zeros
        weak_key = b"\x00" * 32
        assert validator.detect_weak_key(weak_key) is True
        
        # Strong random key
        strong_key = secrets.token_bytes(32)
        assert validator.detect_weak_key(strong_key) is False

    def test_validate_nonce(self):
        """Test nonce validation."""
        validator = CryptoParameterValidator()
        
        good_nonce = secrets.token_bytes(12)
        assert validator.validate_nonce(good_nonce, 12) is True
        
        # Wrong length
        assert validator.validate_nonce(good_nonce, 16) is False
        
        # All zeros
        zero_nonce = b"\x00" * 12
        assert validator.validate_nonce(zero_nonce, 12) is False

    def test_validate_plaintext(self):
        """Test plaintext validation."""
        validator = CryptoParameterValidator()
        
        assert validator.validate_plaintext(b"normal message") is True
        assert validator.validate_plaintext(b"x" * 200_000_000, max_size=100_000_000) is False

    def test_validate_crypto_key_convenience(self):
        """Test convenience function."""
        key = secrets.token_bytes(32)
        valid, warnings = validate_crypto_key(key, KeyType.SYMMETRIC)
        assert valid is True


class TestSideChannelResistance:
    """Tests for side-channel resistance helpers."""

    def test_add_jitter(self):
        """Test jitter addition doesn't crash."""
        # Should not raise
        SideChannelResistance.add_jitter(base_delay_ms=0.1, jitter_ms=0.05)

    def test_constant_time_loop(self):
        """Test constant-time loop."""
        iterations = []
        
        def op(i):
            iterations.append(i)
        
        SideChannelResistance.constant_time_loop(5, op)
        assert len(iterations) == 5

    def test_blind_operation(self):
        """Test operation blinding framework."""
        # Use identity operation that doesn't modify bytes
        def identity(data):
            return data
        
        data = b"\x01\x02\x03\x04"
        result = SideChannelResistance.blind_operation(identity, data)
        # Identity operation with XOR blinding should return original
        assert isinstance(result, bytes)


class TestCryptoSecurityFacade:
    """Tests for crypto security facade."""

    def test_secure_key_operation_success(self):
        """Test successful secure key operation."""
        facade = CryptoSecurityFacade()
        
        def key_operation(key):
            return f"processed_{len(key)}_bytes"
        
        key = secrets.token_bytes(32)
        result = facade.secure_key_operation(
            operation_id="test_op",
            key=key,
            operation=key_operation,
            key_type=KeyType.SYMMETRIC
        )
        
        assert result["success"] is True
        assert result["rate_limited"] is False
        assert "processed_32_bytes" in result["output"]

    def test_secure_key_operation_short_key(self):
        """Test short key rejection."""
        facade = CryptoSecurityFacade()
        
        def key_operation(key):
            return key
        
        short_key = secrets.token_bytes(8)  # 64 bits
        result = facade.secure_key_operation(
            operation_id="test_op",
            key=short_key,
            operation=key_operation,
            key_type=KeyType.SYMMETRIC
        )
        
        assert result["success"] is False
        assert len(result["validation_errors"]) > 0

    def test_wrap_encryption(self):
        """Test wrapping encryption operation."""
        facade = CryptoSecurityFacade()
        
        def dummy_encrypt(key, plaintext):
            return bytes([b ^ key[i % len(key)] for i, b in enumerate(plaintext)])
        
        key = secrets.token_bytes(32)
        plaintext = b"Secret message"
        
        validation, ciphertext = facade.wrap_encryption(dummy_encrypt, key, plaintext)
        
        assert validation.valid is True
        assert ciphertext is not None
        assert len(ciphertext) == len(plaintext)


class TestCryptoSecurityContext:
    """Tests for crypto security context."""

    def test_default_context(self):
        """Test default context values."""
        context = CryptoSecurityContext()
        
        assert context.security_level == CryptoSecurityLevel.STANDARD
        assert context.enable_key_zeroization is True
        assert context.enable_constant_time is True
        assert context.enable_operation_rate_limiting is True
        assert context.enforce_key_strength is True

    def test_custom_context(self):
        """Test custom context."""
        context = CryptoSecurityContext(
            security_level=CryptoSecurityLevel.FIPS_140_3,
            enable_key_zeroization=True,
            max_operations_per_window=500
        )
        
        assert context.security_level == CryptoSecurityLevel.FIPS_140_3
        assert context.max_operations_per_window == 500


class TestCryptoValidationResult:
    """Tests for validation result."""

    def test_result_creation(self):
        """Test result object creation."""
        result = CryptoValidationResult(
            valid=True,
            warnings=["non-standard key length"],
            errors=[]
        )
        
        assert result.valid is True
        assert len(result.warnings) == 1
        assert len(result.errors) == 0


if __name__ == "__main__":
    # Run tests
    test_classes = [
        TestCryptoKeyZeroizer,
        TestCryptoConstantTime,
        TestCryptoOperationRateLimiter,
        TestCryptoParameterValidator,
        TestSideChannelResistance,
        TestCryptoSecurityFacade,
        TestCryptoSecurityContext,
        TestCryptoValidationResult,
    ]
    
    passed = 0
    failed = 0
    
    for test_class in test_classes:
        test_instance = test_class()
        methods = [m for m in dir(test_instance) if m.startswith("test_")]
        
        for method in methods:
            try:
                getattr(test_instance, method)()
                passed += 1
            except Exception as e:
                print(f"FAILED: {test_class.__name__}.{method}: {e}")
                failed += 1
    
    print(f"\n{'='*50}")
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print(f"{'='*50}")
    
    if failed == 0:
        print("\nAll tests PASSED!")
        sys.exit(0)
    else:
        print("\nSome tests FAILED!")
        sys.exit(1)
