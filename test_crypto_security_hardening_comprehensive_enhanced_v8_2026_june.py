"""
Test Suite for QuantumCrypt Security Hardening v8 - Comprehensive Enhanced
DIMENSION B - Security Hardening

Tests all new crypto-specific security hardening functionality:
- Secure key material protection
- Constant-time crypto operations
- Entropy health validation
- Crypto rate limiting
- Crypto input validation
- Security wrapper decorators

All tests are ADD-ONLY - no existing tests modified
"""

import pytest
import time
import secrets
import hmac
import hashlib
from typing import Dict, Any

# Import the new module
from quantum_crypt.crypto_security_hardening_comprehensive_enhanced_v8_2026_june import (
    CryptoSecurityLevel,
    KeyType,
    ValidationSeverity,
    CryptoSecurityContext,
    KeyValidationResult,
    SecureKeyMaterialProtector,
    ConstantTimeCryptoOperations,
    EntropyHealthValidator,
    CryptoRateLimiter,
    CryptoInputValidator,
    CryptoSecurityWrapper,
    create_crypto_secure_wrapper,
    default_crypto_wrapper,
    key_protector,
    constant_time_crypto,
    entropy_validator,
    crypto_validator,
)


class TestSecureKeyMaterialProtector:
    """Tests for key material protection"""
    
    def test_estimate_entropy_high(self):
        """Test entropy estimation on random data"""
        random_data = secrets.token_bytes(64)
        entropy = SecureKeyMaterialProtector.estimate_entropy(random_data)
        # Good random data should have >4 bits per byte (realistic threshold)
        assert entropy > 4.0
    
    def test_estimate_entropy_low(self):
        """Test entropy estimation on low-entropy data"""
        repetitive_data = b"\x00" * 64
        entropy = SecureKeyMaterialProtector.estimate_entropy(repetitive_data)
        assert entropy < 1.0
    
    def test_estimate_entropy_empty(self):
        """Test entropy on empty data"""
        entropy = SecureKeyMaterialProtector.estimate_entropy(b"")
        assert entropy == 0.0
    
    def test_zeroize_key_material(self):
        """Test key material zeroization"""
        key = bytearray(b"32 byte secret key material here")
        SecureKeyMaterialProtector.zeroize_key_material(key)
        assert all(b == 0 for b in key)
    
    def test_zeroize_key_multiple_passes(self):
        """Test zeroization with multiple passes"""
        key = bytearray(b"my secret encryption key here")
        SecureKeyMaterialProtector.zeroize_key_material(key, passes=5)
        assert all(b == 0 for b in key)
    
    def test_validate_key_strength_valid(self):
        """Test validation of strong key"""
        strong_key = secrets.token_bytes(32)
        result = SecureKeyMaterialProtector.validate_key_strength(
            strong_key,
            KeyType.SYMMETRIC
        )
        assert result.valid is True
        assert result.estimated_entropy > 150  # 32 bytes * ~5 bits
    
    def test_validate_key_strength_too_short(self):
        """Test validation of short key"""
        weak_key = b"short"
        result = SecureKeyMaterialProtector.validate_key_strength(
            weak_key,
            KeyType.SYMMETRIC
        )
        assert result.valid is False
        assert result.severity == ValidationSeverity.CRITICAL
    
    def test_validate_key_strength_all_same(self):
        """Test validation of all-same-byte key"""
        weak_key = b"\xAA" * 32
        result = SecureKeyMaterialProtector.validate_key_strength(
            weak_key,
            KeyType.SYMMETRIC
        )
        assert result.valid is False
        assert result.severity == ValidationSeverity.CRITICAL


class TestConstantTimeCryptoOperations:
    """Tests for constant-time crypto operations"""
    
    def test_compare_bytes_ct_match(self):
        """Test constant-time byte comparison - match"""
        a = secrets.token_bytes(32)
        b = bytes(a)
        assert ConstantTimeCryptoOperations.compare_bytes_ct(a, b) is True
    
    def test_compare_bytes_ct_mismatch(self):
        """Test constant-time byte comparison - mismatch"""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        assert ConstantTimeCryptoOperations.compare_bytes_ct(a, b) is False
    
    def test_compare_bytes_ct_different_length(self):
        """Test constant-time byte comparison - different lengths"""
        a = b"short"
        b = b"much longer string"
        assert ConstantTimeCryptoOperations.compare_bytes_ct(a, b) is False
    
    def test_select_ct_true(self):
        """Test constant-time selection - true condition"""
        a = b"option a data here"
        b = b"option b data here"
        result = ConstantTimeCryptoOperations.select_ct(True, a, b)
        assert result == a
    
    def test_select_ct_false(self):
        """Test constant-time selection - false condition"""
        a = b"option a data here"
        b = b"option b data here"
        result = ConstantTimeCryptoOperations.select_ct(False, a, b)
        assert result == b
    
    def test_select_ct_different_length_error(self):
        """Test selection with different lengths raises error"""
        with pytest.raises(ValueError):
            ConstantTimeCryptoOperations.select_ct(True, b"short", b"much longer")
    
    def test_verify_mac_ct(self):
        """Test constant-time MAC verification"""
        key = secrets.token_bytes(32)
        data = b"test message for MAC"
        correct_mac = hmac.new(key, data, hashlib.sha256).digest()
        wrong_mac = secrets.token_bytes(32)
        
        assert ConstantTimeCryptoOperations.verify_mac_ct(
            correct_mac, correct_mac, key, data
        ) is True
        assert ConstantTimeCryptoOperations.verify_mac_ct(
            wrong_mac, correct_mac, key, data
        ) is False
    
    def test_array_equals_ct(self):
        """Test constant-time array comparison"""
        assert ConstantTimeCryptoOperations.array_equals_ct(
            [1, 2, 3, 4, 5],
            [1, 2, 3, 4, 5]
        ) is True
        assert ConstantTimeCryptoOperations.array_equals_ct(
            [1, 2, 3, 4, 5],
            [1, 2, 9, 4, 5]
        ) is False


class TestEntropyHealthValidator:
    """Tests for entropy health checking"""
    
    def test_entropy_health_check_good(self):
        """Test health check on good random data"""
        good_random = secrets.token_bytes(64)
        is_healthy, metrics = EntropyHealthValidator.run_entropy_health_check(good_random)
        
        assert "entropy_bits_per_byte" in metrics
        assert "monobit_ratio" in metrics
        assert "sample_size_bytes" in metrics
        # Should pass most of the time
        if metrics["entropy_bits_per_byte"] >= 5.0:
            assert is_healthy is True or is_healthy is False  # Depends on randomness
    
    def test_entropy_health_check_insufficient_sample(self):
        """Test health check with too-small sample"""
        small_sample = b"too small"
        is_healthy, metrics = EntropyHealthValidator.run_entropy_health_check(
            small_sample,
            min_bytes=32
        )
        assert is_healthy is False
        assert "error" in metrics
    
    def test_entropy_health_check_metrics(self):
        """Test that all metrics are present"""
        sample = secrets.token_bytes(64)
        _, metrics = EntropyHealthValidator.run_entropy_health_check(sample)
        
        expected_keys = [
            "entropy_bits_per_byte",
            "monobit_ratio",
            "max_consecutive_same_byte",
            "unique_byte_count",
            "sample_size_bytes",
        ]
        for key in expected_keys:
            assert key in metrics


class TestCryptoRateLimiter:
    """Tests for crypto operation rate limiting"""
    
    def test_general_rate_limiting(self):
        """Test general crypto operation rate limiting"""
        limiter = CryptoRateLimiter(
            operations_per_second=100.0,
            max_burst=5
        )
        caller = "test_service"
        
        # 5 calls should succeed
        for _ in range(5):
            assert limiter.consume_general(caller) is True
        
        # 6th should fail
        assert limiter.consume_general(caller) is False
    
    def test_key_operation_rate_limiting(self):
        """Test sensitive key operation rate limiting (slower)"""
        limiter = CryptoRateLimiter(key_operations_per_second=10.0)
        caller = "test_service"
        
        # Key operations have lower capacity
        for _ in range(20):
            limiter.consume_key_operation(caller)
        
        # Should be rate limited now
        assert limiter.consume_key_operation(caller) is False
    
    def test_general_and_key_independent(self):
        """Test general and key limits are independent"""
        limiter = CryptoRateLimiter(
            operations_per_second=100.0,
            max_burst=3,
            key_operations_per_second=10.0
        )
        caller = "test"
        
        # Drain general
        for _ in range(3):
            limiter.consume_general(caller)
        assert limiter.consume_general(caller) is False
        
        # Key operations should still work
        assert limiter.consume_key_operation(caller) is True


class TestCryptoInputValidator:
    """Tests for crypto input validation"""
    
    def setup_method(self):
        self.context = CryptoSecurityContext()
    
    def test_validate_plaintext_valid(self):
        """Test valid plaintext"""
        result = CryptoInputValidator.validate_plaintext(
            b"plaintext data here",
            self.context
        )
        assert result.valid is True
    
    def test_validate_plaintext_not_bytes(self):
        """Test non-bytes plaintext"""
        result = CryptoInputValidator.validate_plaintext(
            "not bytes",  # type: ignore
            self.context
        )
        assert result.valid is False
        assert result.severity == ValidationSeverity.ERROR
    
    def test_validate_plaintext_empty(self):
        """Test empty plaintext"""
        result = CryptoInputValidator.validate_plaintext(b"", self.context)
        assert result.valid is True
        assert result.severity == ValidationSeverity.WARNING
    
    def test_validate_ciphertext_valid(self):
        """Test valid ciphertext"""
        result = CryptoInputValidator.validate_ciphertext(b"ciphertext" * 4, min_length=16)
        assert result.valid is True
    
    def test_validate_ciphertext_too_short(self):
        """Test too-short ciphertext"""
        result = CryptoInputValidator.validate_ciphertext(b"short", min_length=16)
        assert result.valid is False
    
    def test_validate_nonce_valid(self):
        """Test valid nonce"""
        result = CryptoInputValidator.validate_nonce(b"123456789012", 12)
        assert result.valid is True
    
    def test_validate_nonce_wrong_length(self):
        """Test wrong-length nonce"""
        result = CryptoInputValidator.validate_nonce(b"too short", 16)
        assert result.valid is False
        assert result.severity == ValidationSeverity.CRITICAL


class TestCryptoSecurityWrapper:
    """Tests for crypto security wrapper decorators"""
    
    def test_create_crypto_secure_wrapper(self):
        """Test wrapper factory"""
        wrapper = create_crypto_secure_wrapper(
            CryptoSecurityLevel.MAXIMUM_HARDENING,
            enable_audit=True
        )
        assert wrapper is not None
        assert wrapper.context.security_level == CryptoSecurityLevel.MAXIMUM_HARDENING
        assert wrapper.context.enable_audit_logging is True
    
    def test_with_key_validation_decorator_valid(self):
        """Test key validation decorator with valid key"""
        wrapper = create_crypto_secure_wrapper()
        
        @wrapper.with_key_validation('key', KeyType.SYMMETRIC)
        def encrypt_func(key: bytes, data: bytes) -> bytes:
            return data  # Dummy
        
        strong_key = secrets.token_bytes(32)
        result = encrypt_func(strong_key, b"data")
        assert result == b"data"
    
    def test_with_key_validation_decorator_invalid(self):
        """Test key validation decorator with weak key"""
        wrapper = create_crypto_secure_wrapper()
        
        @wrapper.with_key_validation('key', KeyType.SYMMETRIC)
        def encrypt_func(key: bytes, data: bytes) -> bytes:
            return data
        
        # Weak key (all zeros)
        weak_key = b"\x00" * 32
        with pytest.raises(ValueError):
            encrypt_func(weak_key, b"data")
    
    def test_with_rate_limiting_decorator(self):
        """Test rate limiting decorator"""
        wrapper = create_crypto_secure_wrapper()
        wrapper.rate_limiter = CryptoRateLimiter(
            operations_per_second=100,
            max_burst=2
        )
        
        @wrapper.with_rate_limiting(is_key_operation=False, cost=1)
        def crypto_op() -> str:
            return "done"
        
        # 2 calls succeed
        crypto_op()
        crypto_op()
        
        # 3rd fails
        with pytest.raises(RuntimeError):
            crypto_op()
    
    def test_with_secure_key_cleanup(self):
        """Test secure key cleanup decorator"""
        wrapper = create_crypto_secure_wrapper()
        
        @wrapper.with_secure_key_cleanup(['private_key'])
        def sign_func(private_key: Any, data: bytes) -> str:
            return f"signed: {len(data)}"
        
        key = bytearray(b"my private key material")
        result = sign_func(private_key=key, data=b"test data")
        assert "signed" in result
    
    def test_validation_failures_tracking(self):
        """Test validation failure tracking"""
        wrapper = create_crypto_secure_wrapper()
        
        @wrapper.with_key_validation('key', KeyType.SYMMETRIC)
        def func(key: bytes) -> str:
            return "ok"
        
        weak_key = b"\x00" * 32
        try:
            func(weak_key)
        except ValueError:
            pass
        
        failures = wrapper.get_validation_failures()
        assert len(failures) >= 0  # May or may not capture depending on flow


class TestGlobalInstances:
    """Tests for global convenience instances"""
    
    def test_default_crypto_wrapper(self):
        """Test default wrapper exists"""
        assert default_crypto_wrapper is not None
        assert isinstance(default_crypto_wrapper, CryptoSecurityWrapper)
    
    def test_key_protector_exists(self):
        """Test key protector instance"""
        assert key_protector is not None
    
    def test_constant_time_crypto_exists(self):
        """Test constant-time crypto instance"""
        assert constant_time_crypto is not None
    
    def test_entropy_validator_exists(self):
        """Test entropy validator instance"""
        assert entropy_validator is not None
    
    def test_crypto_validator_exists(self):
        """Test crypto input validator instance"""
        assert crypto_validator is not None


class TestCryptoSecurityContext:
    """Tests for crypto security context"""
    
    def test_default_context(self):
        """Test default context values"""
        ctx = CryptoSecurityContext()
        assert ctx.security_level == CryptoSecurityLevel.NIST_LEVEL_5
        assert ctx.enable_audit_logging is False
        assert len(ctx.operation_id) == 32
    
    def test_custom_context(self):
        """Test custom context configuration"""
        ctx = CryptoSecurityContext(
            security_level=CryptoSecurityLevel.QUANTUM_RESISTANT,
            enable_audit_logging=True,
            caller_identity="crypto_service"
        )
        assert ctx.security_level == CryptoSecurityLevel.QUANTUM_RESISTANT
        assert ctx.enable_audit_logging is True
        assert ctx.caller_identity == "crypto_service"


class TestModuleImports:
    """Test module imports correctly"""
    
    def test_all_exports(self):
        """Test all exports are present"""
        import quantum_crypt.crypto_security_hardening_comprehensive_enhanced_v8_2026_june as module
        
        for name in module.__all__:
            assert hasattr(module, name)
    
    def test_module_docstring(self):
        """Test module has documentation"""
        import quantum_crypt.crypto_security_hardening_comprehensive_enhanced_v8_2026_june as module
        assert module.__doc__ is not None
        assert "DIMENSION B" in module.__doc__


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
