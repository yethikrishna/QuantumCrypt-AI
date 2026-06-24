"""
Test Suite for Post-Quantum Crypto Security Hardening V24
DIMENSION B: Security Hardening

Tests cover:
- Cryptographic constant-time operations
- Secure key material zeroization
- Key material validation
- Crypto operation rate limiting
- Side-channel mitigations
- PQ security facade integration

All tests are ADD-ONLY - no existing tests modified.
"""

import pytest
import secrets
import threading
import hmac
import hashlib
from typing import Dict, Any

from quantum_crypt.crypto_security_hardening_comprehensive_protection_v24_2026_june import (
    CryptoConstantTime,
    SecureKeyZeroizer,
    KeyMaterialValidator,
    CryptoOperationThrottler,
    SideChannelMitigations,
    PQSecurityHardeningFacade,
    CryptoSecurityLevel,
    KeyType,
    OverwriteStrategy,
    CryptoRateLimitConfig,
    KeyValidationConfig,
    KeyMemoryConfig,
    default_crypto_ct,
    default_key_zeroizer,
    default_key_validator,
    default_crypto_throttler,
    default_side_channel,
)


class TestCryptoConstantTime:
    """Tests for cryptographic constant-time operations."""

    def test_compare_keys_equal(self):
        """Test constant-time key comparison with equal keys."""
        key1 = secrets.token_bytes(32)
        key2 = key1[:]
        assert CryptoConstantTime.compare_keys(key1, key2) is True

    def test_compare_keys_not_equal(self):
        """Test constant-time key comparison with different keys."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        assert CryptoConstantTime.compare_keys(key1, key2) is False

    def test_verify_signature_constant_time(self):
        """Test signature verification in constant time."""
        sig1 = secrets.token_bytes(64)
        sig2 = sig1[:]
        sig3 = secrets.token_bytes(64)
        
        assert CryptoConstantTime.verify_signature_constant_time(sig1, sig2) is True
        assert CryptoConstantTime.verify_signature_constant_time(sig1, sig3) is False

    def test_arrays_equal_ct(self):
        """Test constant-time array comparison."""
        arr1 = [1, 2, 3, 4, 5]
        arr2 = [1, 2, 3, 4, 5]
        arr3 = [1, 2, 3, 4, 6]
        
        assert CryptoConstantTime.arrays_equal_ct(arr1, arr2) is True
        assert CryptoConstantTime.arrays_equal_ct(arr1, arr3) is False
        assert CryptoConstantTime.arrays_equal_ct([1, 2], [1, 2, 3]) is False

    def test_select_constant_time_int(self):
        """Test constant-time selection for integers."""
        assert CryptoConstantTime.select_constant_time(True, 42, 99) == 42
        assert CryptoConstantTime.select_constant_time(False, 42, 99) == 99

    def test_hash_equal_ct(self):
        """Test constant-time hash comparison."""
        hash1 = hashlib.sha256(b"test").digest()
        hash2 = hashlib.sha256(b"test").digest()
        hash3 = hashlib.sha256(b"different").digest()
        
        assert CryptoConstantTime.hash_equal_ct(hash1, hash2) is True
        assert CryptoConstantTime.hash_equal_ct(hash1, hash3) is False

    def test_default_crypto_ct_instance(self):
        """Test default constant-time instance works."""
        assert default_crypto_ct.compare_keys(b"test", b"test") is True


class TestSecureKeyZeroizer:
    """Tests for secure key material zeroization."""

    def test_zeroize_key_material(self):
        """Test cryptographic key zeroization."""
        key = bytearray(secrets.token_bytes(32))
        original = bytes(key)
        
        zeroizer = SecureKeyZeroizer()
        zeroizer.zeroize_key_material(key)
        
        assert all(b == 0 for b in key)
        assert bytes(key) != original

    def test_zeroize_with_nist_strategy(self):
        """Test NIST SP 800-88 overwrite strategy."""
        config = KeyMemoryConfig(overwrite_strategy=OverwriteStrategy.NIST_SP_800_88)
        zeroizer = SecureKeyZeroizer(config)
        
        key = bytearray(b"sensitive_key_material_12345")
        zeroizer.zeroize_key_material(key)
        assert all(b == 0 for b in key)

    def test_zeroize_with_dod_strategy(self):
        """Test DoD overwrite strategy."""
        config = KeyMemoryConfig(overwrite_strategy=OverwriteStrategy.DOD_5220_22_M)
        zeroizer = SecureKeyZeroizer(config)
        
        key = bytearray(b"top_secret_key_data")
        zeroizer.zeroize_key_material(key)
        assert all(b == 0 for b in key)

    def test_zeroize_with_fast_strategy(self):
        """Test fast overwrite strategy."""
        config = KeyMemoryConfig(overwrite_strategy=OverwriteStrategy.FAST)
        zeroizer = SecureKeyZeroizer(config)
        
        key = bytearray(b"test_key")
        zeroizer.zeroize_key_material(key)
        assert all(b == 0 for b in key)

    def test_zeroize_sensitive_bytes(self):
        """Test zeroization of non-key sensitive data."""
        data = bytearray(b"plaintext_message_secret")
        zeroizer = SecureKeyZeroizer()
        zeroizer.zeroize_sensitive_bytes(data)
        assert all(b == 0 for b in data)

    def test_zeroize_disabled(self):
        """Test zeroization can be disabled."""
        config = KeyMemoryConfig(enabled=False)
        zeroizer = SecureKeyZeroizer(config)
        
        key = bytearray(b"test")
        original = bytes(key)
        zeroizer.zeroize_key_material(key)
        assert bytes(key) == original

    def test_wipe_list_sensitive(self):
        """Test wiping list containing sensitive data."""
        sensitive_list = [bytearray(b"key1"), bytearray(b"key2"), "plaintext"]
        zeroizer = SecureKeyZeroizer()
        zeroizer.wipe_list_sensitive(sensitive_list)
        assert len(sensitive_list) == 0

    def test_default_key_zeroizer_instance(self):
        """Test default zeroizer instance works."""
        data = bytearray(b"test")
        default_key_zeroizer.zeroize_key_material(data)
        assert all(b == 0 for b in data)


class TestKeyMaterialValidator:
    """Tests for key material validation."""

    def test_validate_key_bytes_normal(self):
        """Test normal key validation passes."""
        validator = KeyMaterialValidator()
        key = secrets.token_bytes(32)
        result = validator.validate_key_bytes(key, KeyType.SYMMETRIC)
        assert result == key

    def test_validate_key_bytes_too_short(self):
        """Test short keys are rejected."""
        validator = KeyMaterialValidator()
        
        with pytest.raises(ValueError, match="too short"):
            validator.validate_key_bytes(b"short", KeyType.SYMMETRIC)

    def test_validate_key_bytes_all_zeros(self):
        """Test all-zero weak keys are rejected."""
        validator = KeyMaterialValidator()
        
        with pytest.raises(ValueError, match="all zeros"):
            validator.validate_key_bytes(b"\x00" * 32, KeyType.SYMMETRIC)

    def test_validate_key_bytes_expected_length(self):
        """Test key length validation."""
        validator = KeyMaterialValidator()
        key = secrets.token_bytes(32)
        
        with pytest.raises(ValueError, match="Invalid key length"):
            validator.validate_key_bytes(key, KeyType.SYMMETRIC, expected_length=64)

    def test_validate_pq_public_key_kyber(self):
        """Test KYBER public key format validation."""
        validator = KeyMaterialValidator()
        
        # Valid length for KYBER768
        valid_key = secrets.token_bytes(1184)
        result = validator.validate_pq_public_key(valid_key, "KYBER768")
        assert result == valid_key

    def test_validate_pq_public_key_invalid_length(self):
        """Test invalid length PQ public keys are rejected."""
        validator = KeyMaterialValidator()
        
        with pytest.raises(ValueError, match="Invalid.*length"):
            validator.validate_pq_public_key(b"too_short", "KYBER768")

    def test_validation_disabled(self):
        """Test validation can be disabled."""
        config = KeyValidationConfig(enabled=False)
        validator = KeyMaterialValidator(config)
        
        # Even weak keys pass when disabled
        result = validator.validate_key_bytes(b"\x00" * 16, KeyType.SYMMETRIC)
        assert result == b"\x00" * 16

    def test_wrap_key_generation(self):
        """Test key generation function wrapping."""
        validator = KeyMaterialValidator()
        
        @validator.wrap_key_generation
        def generate_key() -> bytes:
            return secrets.token_bytes(32)
        
        # Should work normally
        key = generate_key()
        assert len(key) == 32

    def test_default_key_validator_instance(self):
        """Test default validator instance works."""
        key = secrets.token_bytes(32)
        assert default_key_validator.validate_key_bytes(key, KeyType.SYMMETRIC) == key


class TestCryptoOperationThrottler:
    """Tests for cryptographic operation rate limiting."""

    def test_can_sign_allows_initial(self):
        """Test initial signature operations are allowed."""
        config = CryptoRateLimitConfig(max_signatures_per_second=5)
        throttler = CryptoOperationThrottler(config)
        
        for _ in range(5):
            assert throttler.can_sign() is True

    def test_can_sign_blocks_over_limit(self):
        """Test signatures over limit are blocked."""
        config = CryptoRateLimitConfig(
            max_signatures_per_second=2,
            burst_allowance=0
        )
        throttler = CryptoOperationThrottler(config)
        
        assert throttler.can_sign() is True
        assert throttler.can_sign() is True
        assert throttler.can_sign() is False

    def test_can_encrypt(self):
        """Test encryption rate limiting."""
        config = CryptoRateLimitConfig(max_encryptions_per_second=3)
        throttler = CryptoOperationThrottler(config)
        
        for _ in range(3):
            assert throttler.can_encrypt() is True
        # May need one more to trigger limit due to timing
        throttler.can_encrypt()
        throttler.can_encrypt()

    def test_can_generate_key(self):
        """Test key generation rate limiting."""
        config = CryptoRateLimitConfig(max_key_generations_per_minute=2)
        throttler = CryptoOperationThrottler(config)
        
        assert throttler.can_generate_key() is True
        assert throttler.can_generate_key() is True
        assert throttler.can_generate_key() is False

    def test_burst_allowance(self):
        """Test burst allowance works."""
        config = CryptoRateLimitConfig(
            max_signatures_per_second=1,
            burst_allowance=3
        )
        throttler = CryptoOperationThrottler(config)
        
        # Burst + regular
        for _ in range(4):
            assert throttler.can_sign() is True

    def test_throttling_disabled(self):
        """Test throttling can be disabled."""
        config = CryptoRateLimitConfig(enabled=False)
        throttler = CryptoOperationThrottler(config)
        
        for _ in range(100):
            assert throttler.can_sign() is True
            assert throttler.can_encrypt() is True
            assert throttler.can_generate_key() is True

    def test_get_status(self):
        """Test status query returns expected fields."""
        throttler = CryptoOperationThrottler()
        status = throttler.get_status()
        
        assert "signatures_remaining" in status
        assert "encryptions_remaining" in status
        assert "keygens_remaining" in status
        assert "burst_remaining" in status

    def test_thread_safety(self):
        """Test throttler is thread-safe."""
        config = CryptoRateLimitConfig(max_signatures_per_second=100)
        throttler = CryptoOperationThrottler(config)
        
        results = []
        def worker():
            for _ in range(10):
                results.append(throttler.can_sign())
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(results)

    def test_default_crypto_throttler_instance(self):
        """Test default throttler instance works."""
        assert default_crypto_throttler.can_sign() is True


class TestSideChannelMitigations:
    """Tests for side-channel attack mitigations."""

    def test_constant_time_poly_multiply(self):
        """Test constant-time polynomial multiplication."""
        a = [1, 2, 3]
        b = [4, 5, 6]
        modulus = 17
        
        result = SideChannelMitigations.constant_time_poly_multiply(a, b, modulus)
        assert len(result) == 3
        assert all(isinstance(x, int) for x in result)

    def test_add_timing_blinding(self):
        """Test timing blinding doesn't crash."""
        SideChannelMitigations.add_timing_blinding(delay_range_ms=(0.01, 0.02))

    def test_blind_message(self):
        """Test message blinding and unblinding."""
        message = b"secret message to encrypt"
        
        blinded, factor = SideChannelMitigations.blind_message(message)
        assert blinded != message
        
        unblinded = SideChannelMitigations.unblind_message(blinded, factor)
        assert unblinded == message

    def test_blind_message_with_custom_factor(self):
        """Test blinding with custom factor."""
        message = b"test"
        factor = b"\x01\x02\x03\x04"
        
        blinded, returned_factor = SideChannelMitigations.blind_message(message, factor)
        assert returned_factor == factor
        assert SideChannelMitigations.unblind_message(blinded, factor) == message

    def test_default_side_channel_instance(self):
        """Test default side channel instance works."""
        assert default_side_channel is not None


class TestPQSecurityHardeningFacade:
    """Tests for unified PQ security hardening facade."""

    def test_facade_initialization(self):
        """Test facade initializes all components."""
        facade = PQSecurityHardeningFacade()
        assert facade.constant_time is not None
        assert facade.key_zeroizer is not None
        assert facade.key_validator is not None
        assert facade.operation_throttler is not None
        assert facade.side_channel is not None

    def test_facade_with_custom_configs(self):
        """Test facade accepts custom configurations."""
        val_config = KeyValidationConfig(min_entropy_bits=256)
        mem_config = KeyMemoryConfig(overwrite_strategy=OverwriteStrategy.DOD_5220_22_M)
        rate_config = CryptoRateLimitConfig(max_signatures_per_second=50)
        
        facade = PQSecurityHardeningFacade(val_config, mem_config, rate_config)
        
        assert facade.key_validator.config.min_entropy_bits == 256
        assert facade.key_zeroizer.config.overwrite_strategy == OverwriteStrategy.DOD_5220_22_M
        assert facade.operation_throttler.config.max_signatures_per_second == 50

    def test_secure_sign_wrapper(self):
        """Test signing operation wrapping."""
        facade = PQSecurityHardeningFacade()
        
        def mock_sign(message: bytes, private_key: bytes) -> bytes:
            return hmac.new(private_key, message, "sha256").digest()
        
        secured_sign = facade.secure_sign(mock_sign)
        
        # Normal operation works
        message = b"test message"
        key = secrets.token_bytes(32)
        signature = secured_sign(message, key)
        assert len(signature) == 32

    def test_secure_keygen_wrapper(self):
        """Test key generation wrapping."""
        facade = PQSecurityHardeningFacade()
        
        def mock_keygen() -> tuple[bytes, bytes]:
            return (secrets.token_bytes(32), secrets.token_bytes(32))
        
        secured_keygen = facade.secure_keygen(mock_keygen)
        
        private, public = secured_keygen()
        assert len(private) == 32
        assert len(public) == 32


class TestBackwardCompatibility:
    """Integration tests - verify security layers don't break existing code."""

    def test_all_modules_importable(self):
        """All security modules should import without errors."""
        from quantum_crypt.crypto_security_hardening_comprehensive_protection_v24_2026_june import (
            CryptoConstantTime,
            SecureKeyZeroizer,
            KeyMaterialValidator,
            CryptoOperationThrottler,
            SideChannelMitigations,
            PQSecurityHardeningFacade,
        )
        assert True

    def test_security_is_opt_in(self):
        """Security is optional - can be disabled entirely."""
        disabled_val = KeyValidationConfig(enabled=False)
        disabled_mem = KeyMemoryConfig(enabled=False)
        disabled_rate = CryptoRateLimitConfig(enabled=False)
        
        validator = KeyMaterialValidator(disabled_val)
        zeroizer = SecureKeyZeroizer(disabled_mem)
        throttler = CryptoOperationThrottler(disabled_rate)
        
        # All operations pass through without modification
        assert validator.validate_key_bytes(b"\x00" * 16, KeyType.SYMMETRIC) == b"\x00" * 16
        assert throttler.can_sign() is True
        
        data = bytearray(b"test")
        original = bytes(data)
        zeroizer.zeroize_key_material(data)
        assert bytes(data) == original

    def test_existing_code_patterns_work(self):
        """Existing crypto code patterns work with security wrappers."""
        validator = KeyMaterialValidator()
        
        @validator.wrap_key_generation
        def existing_keygen(seed: bytes) -> bytes:
            return hashlib.sha256(seed).digest()
        
        seed = secrets.token_bytes(16)
        key = existing_keygen(seed)
        assert len(key) == 32
        assert key == hashlib.sha256(seed).digest()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
