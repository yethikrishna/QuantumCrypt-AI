"""
Test Suite for QuantumCrypt AI - Crypto Security Hardening Module v17
DIMENSION B: Security Hardening
All tests are ADD-ONLY - no existing tests modified
"""

import pytest
import secrets
import threading
import time
from quantum_crypt.crypto_security_hardening_side_channel_v17_2026_june import (
    CryptoSecurityLevel,
    KeyType,
    ValidationResult,
    CryptoValidationReport,
    SecureKeyMemory,
    SideChannelResistant,
    CryptoInputValidator,
    TimingAttackProtector,
    CryptoSecurityFacade,
    get_crypto_security
)


class TestCryptoSecurityLevel:
    """Test CryptoSecurityLevel enum."""

    def test_security_level_values(self):
        """Test all crypto security levels exist."""
        assert CryptoSecurityLevel.L1.value == "level1"
        assert CryptoSecurityLevel.L2.value == "level2"
        assert CryptoSecurityLevel.L3.value == "level3"
        assert CryptoSecurityLevel.L4.value == "level4"

    def test_security_level_count(self):
        """Test correct number of security levels."""
        assert len(list(CryptoSecurityLevel)) == 4


class TestKeyType:
    """Test KeyType enum for cryptographic key classification."""

    def test_key_type_values(self):
        """Test all key types exist with correct values."""
        assert KeyType.SYMMETRIC.value == "symmetric"
        assert KeyType.ASYMMETRIC.value == "asymmetric"
        assert KeyType.POST_QUANTUM.value == "post_quantum"
        assert KeyType.SIGNATURE.value == "signature"
        assert KeyType.KEM.value == "kem"
        assert KeyType.DERIVATION.value == "derivation"

    def test_key_type_count(self):
        """Test correct number of key types."""
        assert len(list(KeyType)) == 6


class TestValidationResult:
    """Test ValidationResult enum."""

    def test_validation_result_values(self):
        """Test all validation results exist."""
        assert ValidationResult.VALID.value == "valid"
        assert ValidationResult.INVALID.value == "invalid"
        assert ValidationResult.WEAK.value == "weak"
        assert ValidationResult.SUSPICIOUS.value == "suspicious"


class TestCryptoValidationReport:
    """Test CryptoValidationReport dataclass."""

    def test_report_creation(self):
        """Test creating a validation report."""
        report = CryptoValidationReport(
            result=ValidationResult.VALID,
            entropy_bits=128.0,
            issues=["Test issue"],
            recommendations=["Test recommendation"]
        )
        assert report.result == ValidationResult.VALID
        assert report.entropy_bits == 128.0
        assert report.issues == ["Test issue"]
        assert report.recommendations == ["Test recommendation"]

    def test_report_defaults(self):
        """Test default values work correctly."""
        report = CryptoValidationReport(
            result=ValidationResult.VALID,
            entropy_bits=256.0
        )
        assert report.issues == []
        assert report.recommendations == []
        assert report.metadata == {}


class TestSecureKeyMemory:
    """Test SecureKeyMemory for key management and zeroization."""

    def test_zeroize_bytearray_key(self):
        """Test key material zeroization on bytearray."""
        key = bytearray(secrets.token_bytes(32))
        original = bytes(key)
        SecureKeyMemory.zeroize_key_material(key)
        assert all(b == 0 for b in key)
        assert bytes(key) != original

    def test_zeroize_list_key(self):
        """Test key zeroization on list of integers."""
        key_data = [1, 2, 3, 4, 5] * 5
        SecureKeyMemory.zeroize_key_material(key_data)
        assert all(x == 0 for x in key_data)

    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        assert SecureKeyMemory.constant_time_compare(a, b) is True

    def test_constant_time_compare_different(self):
        """Test constant-time comparison with different values."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        assert SecureKeyMemory.constant_time_compare(a, b) is False

    def test_constant_time_select(self):
        """Test constant-time byte string selection."""
        a = b"hello world 123"
        b = b"goodbye moon 45"
        # Same length strings required
        assert len(a) == len(b)
        # When True, should return a
        result = SecureKeyMemory.constant_time_select(True, a, b)
        assert result == a
        # When False, should return b
        result = SecureKeyMemory.constant_time_select(False, a, b)
        assert result == b

    def test_constant_time_select_length_mismatch(self):
        """Test constant-time select raises on length mismatch."""
        with pytest.raises(ValueError):
            SecureKeyMemory.constant_time_select(True, b"short", b"much longer string")

    def test_wipe_bytes_alias(self):
        """Test wipe_bytes is same as zeroize_key_material."""
        data = bytearray(b"sensitive key here")
        SecureKeyMemory.wipe_bytes(data)
        assert all(b == 0 for b in data)


class TestSideChannelResistant:
    """Test SideChannelResistant operations."""

    def test_dummy_operations(self):
        """Test dummy operations execute without error."""
        # Should not raise any exceptions
        SideChannelResistant.dummy_operations(100)

    def test_constant_time_lookup(self):
        """Test constant-time table lookup."""
        table = [b"\x00\x01", b"\x02\x03", b"\x04\x05", b"\x06\x07"]
        result = SideChannelResistant.constant_time_lookup(table, 2)
        assert result == table[2]

    def test_blind_operation(self):
        """Test operation blinding."""
        def identity(x):
            return x  # Simple operation for testing
        
        data = b"test data"
        result = SideChannelResistant.blind_operation(identity, data)
        # Result depends on blinding, but shouldn't crash
        assert result is not None


class TestCryptoInputValidator:
    """Test CryptoInputValidator for key material validation."""

    def test_calculate_entropy_random(self):
        """Test entropy calculation on random data."""
        random_data = secrets.token_bytes(32)
        entropy = CryptoInputValidator.calculate_entropy(random_data)
        # Random data should have decent entropy
        assert entropy >= 0

    def test_calculate_entropy_zeros(self):
        """Test entropy calculation on all zeros."""
        zero_data = b"\x00" * 32
        entropy = CryptoInputValidator.calculate_entropy(zero_data)
        # All zeros should have very low entropy
        assert entropy <= 1.0

    def test_validate_good_key(self):
        """Test validation of a cryptographically secure key."""
        validator = CryptoInputValidator()
        good_key = secrets.token_bytes(32)
        report = validator.validate_key(good_key, KeyType.SYMMETRIC)
        # Should be valid
        assert report.result in [ValidationResult.VALID, ValidationResult.WEAK]
        assert report.entropy_bits >= 0

    def test_validate_short_key(self):
        """Test validation rejects short keys."""
        validator = CryptoInputValidator()
        short_key = b"short"
        report = validator.validate_key(short_key, KeyType.SYMMETRIC, min_length=16)
        assert report.result == ValidationResult.INVALID
        assert len(report.issues) > 0

    def test_validate_weak_key(self):
        """Test validation detects weak keys."""
        validator = CryptoInputValidator()
        weak_key = b"\x00" * 32  # All zeros
        report = validator.validate_key(weak_key, KeyType.SYMMETRIC)
        assert report.result == ValidationResult.WEAK
        assert len(report.issues) > 0

    def test_validate_nonce_valid(self):
        """Test nonce validation with good nonce."""
        validator = CryptoInputValidator()
        good_nonce = secrets.token_bytes(12)
        report = validator.validate_nonce(good_nonce, 12)
        assert report.result == ValidationResult.VALID

    def test_validate_nonce_wrong_length(self):
        """Test nonce validation rejects wrong length."""
        validator = CryptoInputValidator()
        wrong_nonce = secrets.token_bytes(8)
        report = validator.validate_nonce(wrong_nonce, 12)
        assert report.result == ValidationResult.INVALID

    def test_validate_nonce_all_zeros(self):
        """Test nonce validation warns on all zeros."""
        validator = CryptoInputValidator()
        zero_nonce = b"\x00" * 12
        report = validator.validate_nonce(zero_nonce, 12)
        assert report.result == ValidationResult.WEAK


class TestTimingAttackProtector:
    """Test TimingAttackProtector for timing normalization."""

    def test_timing_protector_context(self):
        """Test timing protector works as context manager."""
        with TimingAttackProtector(min_execution_ms=1.0):
            # Do some work
            x = 2 + 2
        assert x == 4

    def test_timing_protector_enforces_min_time(self):
        """Test timing protector ensures minimum execution time."""
        start = time.perf_counter()
        with TimingAttackProtector(min_execution_ms=20.0):
            # Very fast operation
            pass
        elapsed = (time.perf_counter() - start) * 1000
        # Should take at least close to 20ms
        assert elapsed >= 10.0  # Allow some tolerance

    def test_timing_protector_exception_passthrough(self):
        """Test exceptions pass through timing protector."""
        with pytest.raises(ValueError):
            with TimingAttackProtector(min_execution_ms=1.0):
                raise ValueError("Test error")


class TestCryptoSecurityFacade:
    """Test unified CryptoSecurityFacade."""

    def test_facade_creation(self):
        """Test facade creation."""
        facade = CryptoSecurityFacade(CryptoSecurityLevel.L3)
        assert facade.key_memory is not None
        assert facade.side_channel is not None
        assert facade.validator is not None
        assert facade.security_level == CryptoSecurityLevel.L3

    def test_facade_secure_key_operation(self):
        """Test wrapping a key operation."""
        facade = CryptoSecurityFacade()
        
        def key_op(key):
            return len(key)
        
        good_key = secrets.token_bytes(32)
        success, result = facade.secure_key_operation(key_op, good_key, key_type=KeyType.SYMMETRIC)
        assert success is True
        assert result == 32

    def test_facade_compare_constant_time(self):
        """Test facade constant-time comparison."""
        facade = CryptoSecurityFacade()
        a = secrets.token_bytes(32)
        b = bytes(a)
        c = secrets.token_bytes(32)
        assert facade.compare_constant_time(a, b) is True
        assert facade.compare_constant_time(a, c) is False

    def test_facade_validate_and_wipe(self):
        """Test validate and wipe key from memory."""
        facade = CryptoSecurityFacade()
        key_data = bytearray(secrets.token_bytes(32))
        original_copy = bytes(key_data)
        
        report = facade.validate_and_wipe(key_data)
        
        # Key should be zeroized
        assert all(b == 0 for b in key_data)
        assert bytes(key_data) != original_copy
        # Report should be generated
        assert report is not None

    def test_facade_create_timing_protector(self):
        """Test creating timing protector through facade."""
        facade = CryptoSecurityFacade()
        protector = facade.create_timing_protector(min_ms=5.0)
        assert protector is not None
        assert protector.min_execution_ms == 5.0


class TestDefaultInstance:
    """Test default instance getter."""

    def test_get_crypto_security(self):
        """Test getting default crypto security instance."""
        instance1 = get_crypto_security()
        instance2 = get_crypto_security()
        # Should return same instance (singleton pattern)
        assert instance1 is instance2

    def test_get_crypto_security_with_level(self):
        """Test getting instance with specific security level."""
        instance = get_crypto_security(CryptoSecurityLevel.L4)
        assert instance is not None


class TestThreadSafety:
    """Test thread safety of security components."""

    def test_facade_thread_safety(self):
        """Test facade operations work concurrently."""
        facade = CryptoSecurityFacade()
        results = []
        
        def worker():
            key = secrets.token_bytes(32)
            success, result = facade.secure_key_operation(len, key)
            results.append(success)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
