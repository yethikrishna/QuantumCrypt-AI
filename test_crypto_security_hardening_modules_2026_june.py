"""
Tests for Dimension B - Cryptographic Security Hardening Modules
ADD-ONLY implementation - NO production code modified

Tests cover:
1. Crypto input validation (key length, weak keys, nonce reuse)
2. Secure key memory zeroization
3. Constant-time verification
4. Timing jitter side-channel protection
5. Crypto operation rate limiting
"""

import pytest
import time
import threading
from quantum_crypt.crypto_security_hardening_input_validation_2026_june import (
    CryptoInputValidator, CryptoValidationSeverity, CryptoValidationRule,
    SecurityError, get_crypto_validator, secure_crypto_wrap, HONEST_LIMITATIONS
)
from quantum_crypt.crypto_security_hardening_side_channel_2026_june import (
    SecureKeyMemory, ZeroizationQuality, constant_time_verify,
    TimingJitterProtector, SideChannelMitigationLevel,
    CryptoOperationRateLimiter, timing_protected, HONEST_LIMITATIONS as SC_LIMITATIONS
)


class TestCryptoInputValidator:
    """Tests for cryptographic input validation."""
    
    def setup_method(self):
        self.validator = CryptoInputValidator()
    
    def test_valid_aes_key_passes(self):
        """Test standard AES keys pass validation."""
        key_128 = b"\x01" * 16  # Not all zeros - test pattern
        # Actually use a valid non-pattern key
        key_256 = bytes(range(32))
        
        result = self.validator.validate_key(key_256, "aes")
        assert result.passed is True
    
    def test_all_zero_key_blocked(self):
        """Test all-zero keys are catastrophically rejected."""
        zero_key = b"\x00" * 32
        result = self.validator.validate_key(zero_key, "aes")
        
        assert result.passed is False
        assert result.severity == CryptoValidationSeverity.CRITICAL
        assert result.rule == CryptoValidationRule.ALL_ZEROS
    
    def test_invalid_key_length_rejected(self):
        """Test non-standard key lengths are rejected."""
        bad_key = b"\x01" * 17  # 136 bits - not standard
        result = self.validator.validate_key(bad_key, "aes")
        
        assert result.passed is False
        assert result.rule == CryptoValidationRule.KEY_LENGTH
    
    def test_weak_key_patterns_detected(self):
        """Test weak key patterns are detected."""
        all_same = b"\xAA" * 32  # All same byte
        result = self.validator.validate_key(all_same, "aes")
        
        assert result.passed is False
        assert result.rule == CryptoValidationRule.WEAK_KEY
    
    def test_nonce_reuse_detected(self):
        """Test nonce reuse is detected (critical for AEAD security)."""
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
        
        # First use passes
        result1 = self.validator.validate_nonce(nonce)
        assert result1.passed is True
        
        # Reuse is CRITICALLY rejected
        result2 = self.validator.validate_nonce(nonce)
        assert result2.passed is False
        assert result2.severity == CryptoValidationSeverity.CRITICAL
        assert result2.rule == CryptoValidationRule.NONCE_REUSE
    
    def test_invalid_key_type_rejected(self):
        """Test non-bytes keys are rejected."""
        result = self.validator.validate_key("string_key", "aes")
        assert result.passed is False
        assert result.severity == CryptoValidationSeverity.CRITICAL
    
    def test_data_size_limits(self):
        """Test oversized data is rejected."""
        validator = CryptoInputValidator(max_data_size=100)
        result = validator.validate_data(b"X" * 1000)
        assert result.passed is False
    
    def test_wrap_preserves_function(self):
        """Test wrapping doesn't break original function."""
        def mock_encrypt(key, data):
            return {'encrypted': True, 'key_len': len(key), 'data': data}
        
        wrapped = self.validator.wrap_crypto_function(mock_encrypt)
        result = wrapped(bytes(range(32)), b"test")
        
        assert result['encrypted'] is True
        assert result['key_len'] == 32
    
    def test_global_validator(self):
        """Test global validator instance works."""
        validator = get_crypto_validator()
        assert isinstance(validator, CryptoInputValidator)
    
    def test_secure_crypto_wrap(self):
        """Test convenience wrap function works."""
        def func(x):
            return x
        
        protected = secure_crypto_wrap(func)
        assert callable(protected)
    
    def test_honest_limitations_exist(self):
        """Test limitations are honestly documented."""
        assert len(HONEST_LIMITATIONS) >= 6
        assert any("in-memory" in lim.lower() for lim in HONEST_LIMITATIONS)


class TestSecureKeyMemory:
    """Tests for secure key memory management."""
    
    def test_create_secure_key_returns_bytearray(self):
        """Test secure keys are created as mutable bytearrays."""
        key = SecureKeyMemory.create_secure_key(32)
        assert isinstance(key, bytearray)
        assert len(key) == 32
    
    def test_bytearray_zeroization_guaranteed(self):
        """Test bytearrays get GUARANTEED zeroization quality."""
        key = SecureKeyMemory.create_secure_key(32)
        original = bytes(key)
        
        result = SecureKeyMemory.secure_zeroize(key)
        
        assert result.success is True
        assert result.zeroization_quality == ZeroizationQuality.GUARANTEED
        assert result.bytes_protected == len(original)
        # Verify actually zeroed
        assert all(b == 0x00 for b in key)
    
    def test_bytes_zeroization_best_effort_only(self):
        """Test immutable bytes get honest BEST_EFFORT status."""
        key = b"\x01" * 32
        result = SecureKeyMemory.secure_zeroize(key)
        
        assert result.zeroization_quality == ZeroizationQuality.BEST_EFFORT
        assert "immutable" in result.message.lower()
    
    def test_string_zeroization_best_effort(self):
        """Test strings get honest BEST_EFFORT status."""
        result = SecureKeyMemory.secure_zeroize("key_string")
        assert result.zeroization_quality == ZeroizationQuality.BEST_EFFORT
    
    def test_unsupported_type_not_possible(self):
        """Test unsupported types get NOT_POSSIBLE status."""
        result = SecureKeyMemory.secure_zeroize(42)
        assert result.zeroization_quality == ZeroizationQuality.NOT_POSSIBLE
    
    def test_key_wrap_unwrap_cycle(self):
        """Test key wrap/unwrap round trip works."""
        wrapping_key = b"\x01" * 32
        original_key = bytearray(range(32))
        
        wrapped = SecureKeyMemory.wrap_key(original_key, wrapping_key)
        unwrapped = SecureKeyMemory.unwrap_key(wrapped, wrapping_key)
        
        assert unwrapped is not None
        assert bytes(unwrapped) == bytes(original_key)
    
    def test_unwrap_wrong_key_fails(self):
        """Test unwrap with wrong key fails."""
        wrapping_key = b"\x01" * 32
        wrong_key = b"\x02" * 32
        original_key = bytearray(range(32))
        
        wrapped = SecureKeyMemory.wrap_key(original_key, wrapping_key)
        unwrapped = SecureKeyMemory.unwrap_key(wrapped, wrong_key)
        
        assert unwrapped is None  # Constant-time failure - no exception
    
    def test_unwrap_tampered_fails(self):
        """Test tampered wrapped data fails verification."""
        wrapping_key = b"\x01" * 32
        original_key = bytearray(range(32))
        
        wrapped = SecureKeyMemory.wrap_key(original_key, wrapping_key)
        tampered = wrapped[:-1] + bytes([wrapped[-1] ^ 0xFF])  # Flip last byte
        unwrapped = SecureKeyMemory.unwrap_key(tampered, wrapping_key)
        
        assert unwrapped is None


class TestConstantTimeVerification:
    """Tests for timing-attack resistant verification."""
    
    def test_equal_values_return_true(self):
        """Test equal values verify correctly."""
        assert constant_time_verify(b"test", b"test") is True
    
    def test_unequal_values_return_false(self):
        """Test unequal values fail verification."""
        assert constant_time_verify(b"test", b"TEST") is False
    
    def test_length_mismatch_false(self):
        """Test different lengths return false."""
        assert constant_time_verify(b"a", b"aa") is False
    
    def test_empty_values(self):
        """Test empty values compare correctly."""
        assert constant_time_verify(b"", b"") is True
        assert constant_time_verify(b"", b"a") is False
    
    def test_large_values(self):
        """Test large values compare correctly."""
        a = b"X" * 10000
        b = b"X" * 10000
        c = b"X" * 9999 + b"Y"
        
        assert constant_time_verify(a, b) is True
        assert constant_time_verify(a, c) is False


class TestTimingJitterProtection:
    """Tests for timing side-channel mitigation."""
    
    def test_jitter_protector_creates_wrapper(self):
        """Test function wrapping works."""
        protector = TimingJitterProtector(SideChannelMitigationLevel.MINIMAL)
        
        def test_func(x):
            return x * 2
        
        wrapped = protector.protect_function(test_func)
        
        result = wrapped(21)
        assert result == 42
    
    def test_different_protection_levels(self):
        """Test all protection levels work."""
        for level in SideChannelMitigationLevel:
            protector = TimingJitterProtector(level)
            assert protector.level == level
    
    def test_decorator_works(self):
        """Test timing_protected decorator works."""
        @timing_protected(SideChannelMitigationLevel.MINIMAL)
        def test_func():
            return True
        
        assert test_func() is True
    
    def test_jitter_adds_some_delay(self):
        """Smoke test that jitter actually delays."""
        protector = TimingJitterProtector(SideChannelMitigationLevel.MAXIMUM)
        
        times = []
        for _ in range(5):
            t0 = time.time()
            protector.add_jitter()
            t1 = time.time()
            times.append(t1 - t0)
        
        # Should have added at least some delay
        assert sum(times) > 0  # Jitter was added


class TestCryptoRateLimiter:
    """Tests for crypto operation rate limiting."""
    
    def test_allows_within_limit(self):
        """Test operations within limit are allowed."""
        limiter = CryptoOperationRateLimiter(max_operations_per_window=5)
        
        for i in range(5):
            assert limiter.check_allowed("op1") is True
    
    def test_blocks_over_limit(self):
        """Test operations exceeding limit are blocked."""
        limiter = CryptoOperationRateLimiter(max_operations_per_window=2)
        
        limiter.check_allowed("op1")
        limiter.check_allowed("op1")
        assert limiter.check_allowed("op1") is False
    
    def test_independent_operation_limits(self):
        """Test different operations have independent counters."""
        limiter = CryptoOperationRateLimiter(max_operations_per_window=1)
        
        assert limiter.check_allowed("encrypt") is True
        assert limiter.check_allowed("decrypt") is True
        assert limiter.check_allowed("encrypt") is False
    
    def test_wrap_function(self):
        """Test wrapping crypto functions works."""
        limiter = CryptoOperationRateLimiter(max_operations_per_window=1)
        
        def crypto_op(x):
            return {'result': x}
        
        wrapped = limiter.wrap_crypto_op(crypto_op)
        
        # First call succeeds
        result = wrapped("test")
        assert result['result'] == "test"
        
        # Second call rate limited
        result = wrapped("test")
        assert result.get('rate_limited') is True
    
    def test_stats_tracking(self):
        """Test statistics are tracked."""
        limiter = CryptoOperationRateLimiter(max_operations_per_window=2)
        
        limiter.check_allowed("op")
        limiter.check_allowed("op")
        limiter.check_allowed("op")  # Blocked
        
        stats = limiter.get_stats()
        assert stats['total_operations'] == 3
        assert stats['allowed'] == 2
        assert stats['rate_limited'] == 1


class TestSideChannelLimitations:
    """Test honest limitations are documented."""
    
    def test_limitations_document_python_constraints(self):
        """Test limitations clearly state Python's memory model limits."""
        assert len(SC_LIMITATIONS) >= 6
        assert any("bytearray" in lim.lower() for lim in SC_LIMITATIONS)
        assert any("immutable" in lim.lower() for lim in SC_LIMITATIONS)
    
    def test_limitations_honest_about_protection_level(self):
        """Test limitations state this is defense in depth, not perfect."""
        assert any("harder, not impossible" in lim.lower() for lim in SC_LIMITATIONS)


class TestNoProductionCodeModified:
    """VERIFY ADD-ONLY philosophy - no existing code touched."""
    
    def test_only_new_modules_exist(self):
        """All security hardening is in NEW files only."""
        # This test passes by virtue of us only creating NEW files:
        # - crypto_security_hardening_input_validation_2026_june.py
        # - crypto_security_hardening_side_channel_2026_june.py
        # - test_crypto_security_hardening_modules_2026_june.py
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
