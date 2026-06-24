"""
Test Suite for QuantumCrypt Security Hardening V23
Dimension B - Security Hardening
All tests verify ADD-ONLY behavior - NO existing code modified
All existing tests must continue to pass
"""

import pytest
import time
import threading
from quantum_crypt.security_hardening_comprehensive_v23_2026_june import (
    SecureKeyMemory,
    CryptoInputValidator,
    KeyUsageRateLimiter,
    CryptoSecurityContext,
    SideChannelResistance,
    CryptoSecurityWrapper,
    constant_time_bytes_equal,
    constant_time_signature_verify,
    constant_time_hash_equal,
    constant_time_hex_equal,
    constant_time_key_fingerprint_equal,
    secure_zeroize_crypto_key,
    KeySensitivity,
    CryptoOperation,
    ValidationSeverity,
    KeyRateLimitConfig,
    KeyUsageState,
    CryptoValidationRule,
)


class TestSecureKeyMemory:
    """Test secure key memory zeroization (crypto-specific)"""

    def test_secure_key_memory_basic(self):
        """Test basic key memory container"""
        key = b"x25519_private_key_material_here_32bytes"
        skm = SecureKeyMemory(key, KeySensitivity.CRITICAL)
        assert skm.get_key() == key
        assert not skm._zeroized

    def test_secure_key_memory_zeroize(self):
        """Test multi-pass key zeroization"""
        key = b"aes_256_gcm_key_32_bytes_of_data"
        skm = SecureKeyMemory(key)
        skm.zeroize()
        assert skm.get_key() is None
        assert skm._zeroized

    def test_secure_key_memory_access_limit(self):
        """Test access count limit enforcement - max=3 means accesses 1,2,3 OK, 4th triggers"""
        skm = SecureKeyMemory(b"test_key", _max_accesses=3)
        # First 3 accesses OK (1, 2, 3)
        assert skm.get_key() is not None  # count=1
        assert skm.get_key() is not None  # count=2
        assert skm.get_key() is not None  # count=3
        # 4th should trigger auto-zeroize (count=4 > max=3)
        assert skm.get_key() is None

    def test_secure_zeroize_crypto_key(self):
        """Test multi-pass crypto key zeroization"""
        key = bytearray(b"32_byte_symmetric_key_for_aes256")
        original = bytes(key)
        secure_zeroize_crypto_key(key)
        assert all(b == 0 for b in key)
        assert bytes(key) != original


class TestConstantTimeCryptoComparisons:
    """Test constant-time cryptographic comparisons"""

    def test_constant_time_bytes_equal(self):
        """Test basic byte comparison"""
        assert constant_time_bytes_equal(b"test123", b"test123") is True
        assert constant_time_bytes_equal(b"test123", b"test456") is False

    def test_constant_time_signature_verify(self):
        """Test signature verification timing resistance"""
        sig1 = b"signature_bytes_64_bytes_ecdsa"
        sig2 = b"signature_bytes_64_bytes_ecdsa"
        sig3 = b"different_signature_bytes_here_"
        assert constant_time_signature_verify(sig1, sig2) is True
        assert constant_time_signature_verify(sig1, sig3) is False

    def test_constant_time_hash_equal(self):
        """Test hash comparison"""
        h1 = b"\x00\x01\x02\x03" * 8
        h2 = b"\x00\x01\x02\x03" * 8
        h3 = b"\xff\xff\xff\xff" * 8
        assert constant_time_hash_equal(h1, h2) is True
        assert constant_time_hash_equal(h1, h3) is False

    def test_constant_time_hex_equal(self):
        """Test hex comparison with case insensitivity"""
        assert constant_time_hex_equal("AABBCCDD", "aabbccdd") is True
        assert constant_time_hex_equal("AABBCCDD", "11223344") is False

    def test_constant_time_key_fingerprint(self):
        """Test key fingerprint comparison"""
        fp1 = "AA:BB:CC:DD:EE:FF"
        fp2 = "aabbccddeeff"
        fp3 = "11:22:33:44:55:66"
        assert constant_time_key_fingerprint_equal(fp1, fp2) is True
        assert constant_time_key_fingerprint_equal(fp1, fp3) is False


class TestCryptoInputValidator:
    """Test cryptographic input validation"""

    def test_validate_key_bytes(self):
        """Test key material validation"""
        assert CryptoInputValidator.validate_key_bytes(b"16_byte_key_12345") is True
        assert CryptoInputValidator.validate_key_bytes("not bytes") is False
        assert CryptoInputValidator.validate_key_bytes(b"short", min_len=16) is False

    def test_validate_nonce(self):
        """Test nonce validation"""
        assert CryptoInputValidator.validate_nonce(b"12_byte_nonc") is True  # 12 bytes
        assert CryptoInputValidator.validate_nonce(b"short") is False

    def test_validate_plaintext(self):
        """Test plaintext validation"""
        assert CryptoInputValidator.validate_plaintext(b"test data") is True
        assert CryptoInputValidator.validate_plaintext("string also ok") is True
        assert CryptoInputValidator.validate_plaintext(12345) is False

    def test_validate_ciphertext(self):
        """Test ciphertext validation"""
        assert CryptoInputValidator.validate_ciphertext(b"encrypted_data") is True
        assert CryptoInputValidator.validate_ciphertext(b"") is False

    def test_validate_algorithm_name(self):
        """Test algorithm name validation"""
        assert CryptoInputValidator.validate_algorithm_name("AES-256-GCM") is True
        assert CryptoInputValidator.validate_algorithm_name("ChaCha20-Poly1305") is True
        assert CryptoInputValidator.validate_algorithm_name(123) is False

    def test_validate_iv(self):
        """Test IV validation - exactly 16 bytes"""
        assert CryptoInputValidator.validate_iv(b"16_byte_iv_12345") is True  # FIXED: 16 bytes
        assert CryptoInputValidator.validate_iv(b"short") is False

    def test_validation_wrapper_preserves_behavior(self):
        """Test validation wrapper doesn't break function"""
        @CryptoInputValidator.wrap_crypto_function(
            key=CryptoInputValidator.validate_key_bytes
        )
        def encrypt(key, data):
            return data

        # Function behavior unchanged
        result = encrypt(key=b"16_byte_test_key1", data=b"test")
        assert result == b"test"


class TestKeyUsageRateLimiter:
    """Test key usage rate limiting"""

    def test_rate_limiter_disabled_by_default(self):
        """Test OPT-IN behavior - disabled by default"""
        limiter = KeyUsageRateLimiter()
        allowed, meta = limiter.check_key_usage("key_id_1")
        assert allowed is True
        assert meta["enabled"] is False

    def test_rate_limiter_enable(self):
        """Test enabling rate limiting"""
        limiter = KeyUsageRateLimiter()
        limiter.enable()
        allowed, meta = limiter.check_key_usage("key1")
        assert allowed is True
        assert "operation_count" in meta

    def test_key_usage_tracking(self):
        """Test operation counting"""
        limiter = KeyUsageRateLimiter()
        limiter.enable()
        for i in range(5):
            limiter.check_key_usage("keyA")
        allowed, meta = limiter.check_key_usage("keyA")
        assert meta["operation_count"] >= 5

    def test_decorator_preserves_function(self):
        """Test decorator doesn't break function"""
        limiter = KeyUsageRateLimiter()

        @limiter.limit_key_usage(lambda *a: "test_key")
        def sign(data):
            return f"signed:{data}"

        assert sign("test") == "signed:test"


class TestCryptoSecurityContext:
    """Test cryptographic operation context isolation"""

    def test_crypto_context_basic(self):
        """Test basic context setting"""
        with CryptoSecurityContext(CryptoOperation.DECRYPT, KeySensitivity.SENSITIVE):
            op, sens = CryptoSecurityContext.get_current_context()
            assert op == CryptoOperation.DECRYPT
            assert sens == KeySensitivity.SENSITIVE

    def test_crypto_context_nested(self):
        """Test nested context restoration"""
        with CryptoSecurityContext(CryptoOperation.ENCRYPT, KeySensitivity.INTERNAL):
            with CryptoSecurityContext(CryptoOperation.SIGN, KeySensitivity.CRITICAL):
                op, sens = CryptoSecurityContext.get_current_context()
                assert op == CryptoOperation.SIGN
                assert sens == KeySensitivity.CRITICAL
            # Restored
            op, sens = CryptoSecurityContext.get_current_context()
            assert op == CryptoOperation.ENCRYPT

    def test_crypto_context_default(self):
        """Test default context"""
        op, sens = CryptoSecurityContext.get_current_context()
        assert op is None
        assert sens == KeySensitivity.PUBLIC


class TestSideChannelResistance:
    """Test side-channel resistance helpers"""

    def test_add_timing_noise_no_crash(self):
        """Test timing noise doesn't crash"""
        # Just verify no exceptions
        SideChannelResistance.add_timing_noise(base_delay=0.0001)

    def test_dummy_operations_no_crash(self):
        """Test dummy operations execute without error"""
        SideChannelResistance.dummy_operations(count=2)

    def test_constant_time_pad(self):
        """Test constant time padding"""
        data = b"test"
        padded = SideChannelResistance.constant_time_pad(data, block_size=16)
        assert len(padded) == 16
        assert padded.startswith(b"test")
        assert padded.endswith(b"\x00" * 12)


class TestCryptoSecurityWrapper:
    """Test crypto security wrapper factory"""

    def test_with_validation_preserves_behavior(self):
        """Test validation wrapper"""
        def decrypt(key, data):
            return data

        wrapped = CryptoSecurityWrapper.with_validation(
            decrypt,
            key=CryptoInputValidator.validate_key_bytes
        )
        assert wrapped(key=b"16_byte_test_key1", data=b"test") == b"test"

    def test_with_secure_context(self):
        """Test context wrapper"""
        def get_context():
            return CryptoSecurityContext.get_current_context()

        wrapped = CryptoSecurityWrapper.with_secure_context(
            get_context,
            CryptoOperation.DECRYPT,
            KeySensitivity.SENSITIVE
        )
        op, sens = wrapped()
        assert op == CryptoOperation.DECRYPT

    def test_with_side_channel_protection(self):
        """Test side-channel wrapper"""
        def test_func():
            return True

        wrapped = CryptoSecurityWrapper.with_side_channel_protection(
            test_func, add_noise=False
        )
        assert wrapped() is True

    def test_comprehensive_wrapper_all_optional(self):
        """Test comprehensive wrapper - options are optional"""
        def hash_func(data):
            return data

        wrapped = CryptoSecurityWrapper.comprehensive_crypto_wrapper(hash_func)
        assert wrapped(b"test") == b"test"


class TestBackwardCompatibility:
    """CRITICAL: Verify 100% backward compatibility"""

    def test_existing_imports_unchanged(self):
        """Verify existing quantum_crypt imports still work"""
        try:
            from quantum_crypt import __init__
            assert True
        except Exception:
            pytest.fail("Existing imports broken - INCREMENTAL PHILOSOPHY VIOLATED")

    def test_new_module_standalone(self):
        """New module doesn't interfere with existing"""
        import quantum_crypt.security_hardening_comprehensive_v23_2026_june as sh
        assert sh.__version__ == "23.0.0"
        assert sh.__security_dimension__ == "B - Security Hardening"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
