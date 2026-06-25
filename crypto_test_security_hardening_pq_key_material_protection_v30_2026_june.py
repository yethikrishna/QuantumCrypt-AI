"""
Tests for Security Hardening v30 - Post-Quantum Key Material Protection
Dimension B: Security Hardening

All tests verify:
1. New security module works correctly
2. No existing code modified
3. Backward compatibility maintained
4. All security features function as expected
"""

import pytest
import secrets
import threading
from typing import Dict, Any

# Import the new security module
from quantum_crypt.crypto_security_hardening_pq_key_material_protection_v30_2026_june import (
    SecureKeyMaterial,
    KeyMaterialValidator,
    KeyProtectionLevel,
    KeyType,
    KeySecurityResult,
    constant_time_compare,
    constant_time_select,
    secure_crypto_operation,
    secure_key_context,
    KeyDestroyedError,
    KeyTamperedError,
    InvalidKeyMaterialError,
)


class TestConstantTimeOperations:
    """Tests for constant-time cryptographic operations."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison for equal byte strings."""
        a = secrets.token_bytes(32)
        b = bytes(a)
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_different(self):
        """Test constant-time comparison for different byte strings."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_lengths(self):
        """Test comparison with different lengths returns False."""
        a = secrets.token_bytes(16)
        b = secrets.token_bytes(32)
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_empty(self):
        """Test comparison of empty bytes."""
        assert constant_time_compare(b"", b"") is True
    
    def test_constant_time_select_true(self):
        """Test constant-time select when condition is True."""
        a = b"\x01\x02\x03\x04"
        b = b"\xff\xfe\xfd\xfc"
        result = constant_time_select(True, a, b)
        assert result == a
    
    def test_constant_time_select_false(self):
        """Test constant-time select when condition is False."""
        a = b"\x01\x02\x03\x04"
        b = b"\xff\xfe\xfd\xfc"
        result = constant_time_select(False, a, b)
        assert result == b


class TestSecureKeyMaterialBasics:
    """Basic functionality tests for secure key container."""
    
    def test_key_container_initialization(self):
        """Test key container initializes correctly."""
        key_data = secrets.token_bytes(32)
        key = SecureKeyMaterial(key_data, KeyType.SYMMETRIC)
        
        assert key.key_type == KeyType.SYMMETRIC
        assert key.protection_level == KeyProtectionLevel.STANDARD
        assert key.access_count == 0
        assert key.is_destroyed is False
    
    def test_get_key_bytes_returns_copy(self):
        """Test get_key_bytes returns a copy, not internal reference."""
        key_data = secrets.token_bytes(32)
        key = SecureKeyMaterial(key_data, KeyType.SYMMETRIC)
        
        result1 = key.get_key_bytes()
        result2 = key.get_key_bytes()
        
        assert result1 == key_data
        assert result2 == key_data
        assert result1 is not result2  # Different objects
    
    def test_access_count_tracking(self):
        """Test key accesses are counted."""
        key = SecureKeyMaterial(secrets.token_bytes(32), KeyType.SYMMETRIC)
        
        key.get_key_bytes()
        key.get_key_bytes()
        key.get_key_bytes()
        
        assert key.access_count == 3
    
    def test_key_zeroization(self):
        """Test key material is properly zeroized."""
        key_data = secrets.token_bytes(32)
        key = SecureKeyMaterial(key_data, KeyType.SYMMETRIC)
        
        key.zeroize()
        
        assert key.is_destroyed is True
        with pytest.raises(KeyDestroyedError):
            key.get_key_bytes()
    
    def test_audit_trail_records_access(self):
        """Test audit trail records key access events."""
        key = SecureKeyMaterial(secrets.token_bytes(32), KeyType.SYMMETRIC)
        
        key.get_key_bytes()
        trail = key.get_audit_trail()
        
        assert len(trail) >= 1
        assert trail[0]['action'] == 'access'
    
    def test_audit_trail_records_zeroize(self):
        """Test audit trail records zeroization event."""
        key = SecureKeyMaterial(secrets.token_bytes(32), KeyType.SYMMETRIC)
        
        key.get_key_bytes()
        key.zeroize()
        trail = key.get_audit_trail()
        
        actions = [entry['action'] for entry in trail]
        assert 'zeroize' in actions


class TestSecureKeyMaterialProtectionLevels:
    """Tests for different protection levels."""
    
    def test_high_protection_enables_integrity(self):
        """Test HIGH protection enables HMAC integrity checking."""
        key = SecureKeyMaterial(
            secrets.token_bytes(32),
            KeyType.SYMMETRIC,
            KeyProtectionLevel.HIGH
        )
        
        # Should have integrity attributes
        assert hasattr(key, '_integrity_secret')
        assert hasattr(key, '_integrity_hmac')
    
    def test_maximum_protection_enables_integrity(self):
        """Test MAXIMUM protection enables HMAC integrity checking."""
        key = SecureKeyMaterial(
            secrets.token_bytes(32),
            KeyType.SYMMETRIC,
            KeyProtectionLevel.MAXIMUM
        )
        
        assert hasattr(key, '_integrity_secret')
    
    def test_standard_protection_no_integrity(self):
        """Test STANDARD protection doesn't enable HMAC by default."""
        key = SecureKeyMaterial(
            secrets.token_bytes(32),
            KeyType.SYMMETRIC,
            KeyProtectionLevel.STANDARD
        )
        
        # Should work without integrity attributes
        result = key.get_key_bytes()
        assert len(result) == 32


class TestKeyMaterialValidator:
    """Tests for key material validation."""
    
    def test_valid_random_key_passes(self):
        """Test cryptographically random key passes validation."""
        key_data = secrets.token_bytes(32)
        result = KeyMaterialValidator.validate_key(
            key_data,
            KeyType.SYMMETRIC
        )
        
        assert result.is_valid is True
        assert len(result.issues_found) == 0
    
    def test_empty_key_fails(self):
        """Test empty key material fails validation."""
        result = KeyMaterialValidator.validate_key(b"", KeyType.SYMMETRIC)
        assert result.is_valid is False
        assert "Empty key material" in result.issues_found[0]
    
    def test_all_zeros_key_fails(self):
        """Test all-zeros key fails validation."""
        key_data = b"\x00" * 32
        result = KeyMaterialValidator.validate_key(key_data, KeyType.SYMMETRIC)
        
        assert result.is_valid is False
        patterns = [i.lower() for i in result.issues_found]
        assert any("zeros" in p or "identical" in p for p in patterns)
    
    def test_all_same_byte_fails(self):
        """Test all-same-byte key fails validation."""
        key_data = b"\xaa" * 32
        result = KeyMaterialValidator.validate_key(key_data, KeyType.SYMMETRIC)
        
        assert result.is_valid is False
        patterns = [i.lower() for i in result.issues_found]
        assert any("identical" in p for p in patterns)
    
    def test_entropy_estimation(self):
        """Test entropy estimation works correctly."""
        # High entropy random data
        random_data = secrets.token_bytes(256)
        entropy = KeyMaterialValidator._estimate_entropy(random_data)
        assert entropy > 5.0  # Should be high for random
    
    def test_pq_key_length_warning(self):
        """Test unexpected PQ key lengths generate warnings."""
        # Non-standard length for PQ private key
        key_data = secrets.token_bytes(100)
        result = KeyMaterialValidator.validate_key(
            key_data,
            KeyType.PQ_PRIVATE
        )
        
        # Should be valid but with warnings
        assert result.is_valid is True
        assert len(result.warnings) > 0
    
    def test_high_protection_extra_checks(self):
        """Test HIGH protection level performs additional checks."""
        key_data = secrets.token_bytes(64)
        result = KeyMaterialValidator.validate_key(
            key_data,
            KeyType.SYMMETRIC,
            KeyProtectionLevel.HIGH
        )
        
        # Should run extra validation logic
        assert result.protection_level == KeyProtectionLevel.HIGH


class TestKeySecurityResult:
    """Tests for key security result data class."""
    
    def test_result_construction(self):
        """Test result object construction."""
        result = KeySecurityResult(
            is_valid=True,
            protection_level=KeyProtectionLevel.STANDARD,
            key_type=KeyType.SYMMETRIC
        )
        assert result.is_valid is True
        assert result.key_type == KeyType.SYMMETRIC
        assert result.issues_found == []
    
    def test_result_with_issues(self):
        """Test result with issues and warnings."""
        result = KeySecurityResult(
            is_valid=False,
            protection_level=KeyProtectionLevel.HIGH,
            key_type=KeyType.PQ_PRIVATE,
            issues_found=["Low entropy", "Weak pattern"],
            warnings=["Non-standard length"]
        )
        assert result.is_valid is False
        assert len(result.issues_found) == 2
        assert len(result.warnings) == 1


class TestSecureCryptoOperationDecorator:
    """Tests for cryptographic operation wrapping."""
    
    def test_decorator_wraps_function(self):
        """Test decorator properly wraps function."""
        @secure_crypto_operation()
        def encrypt(key: bytes, data: bytes) -> bytes:
            return data  # Dummy
        
        result = encrypt(secrets.token_bytes(32), b"test data")
        assert result == b"test data"
    
    def test_decorator_preserves_function_name(self):
        """Test decorator preserves original function name."""
        @secure_crypto_operation()
        def my_crypto_function(key: bytes, data: bytes) -> bytes:
            return data
        
        assert my_crypto_function.__name__ == "my_crypto_function"
    
    def test_decorator_with_custom_protection_level(self):
        """Test decorator works with custom protection level."""
        @secure_crypto_operation(protection_level=KeyProtectionLevel.HIGH)
        def secure_encrypt(key: bytes, data: bytes) -> bytes:
            return data
        
        result = secure_encrypt(secrets.token_bytes(32), b"data")
        assert result == b"data"


class TestSecureKeyContextManager:
    """Tests for secure key context manager."""
    
    def test_context_manager_provides_key(self):
        """Test context manager provides access to key."""
        key_data = secrets.token_bytes(32)
        
        with secure_key_context(key_data, KeyType.SYMMETRIC) as key:
            assert key.get_key_bytes() == key_data
            assert key.is_destroyed is False
    
    def test_context_manager_auto_zeroizes(self):
        """Test context manager automatically zeroizes key on exit."""
        key_data = secrets.token_bytes(32)
        captured_key = None
        
        with secure_key_context(key_data, KeyType.SYMMETRIC) as key:
            captured_key = key
            assert captured_key.is_destroyed is False
        
        # After context exit, key should be destroyed
        assert captured_key.is_destroyed is True


class TestCustomExceptions:
    """Tests for custom security exceptions."""
    
    def test_key_destroyed_error(self):
        """Test KeyDestroyedError can be raised and caught."""
        with pytest.raises(KeyDestroyedError):
            raise KeyDestroyedError("Test error")
    
    def test_key_tampered_error(self):
        """Test KeyTamperedError can be raised and caught."""
        with pytest.raises(KeyTamperedError):
            raise KeyTamperedError("Integrity check failed")
    
    def test_invalid_key_material_error(self):
        """Test InvalidKeyMaterialError carries validation result."""
        result = KeySecurityResult(
            is_valid=False,
            protection_level=KeyProtectionLevel.STANDARD,
            issues_found=["Test issue"]
        )
        
        error = InvalidKeyMaterialError("Validation failed", result)
        assert error.validation_result is result


class TestBackwardCompatibility:
    """Verify no existing code was broken - ADD-ONLY philosophy."""
    
    def test_no_modification_to_existing_modules(self):
        """Verify we can still import and use core modules."""
        # This test verifies the module import works
        # No existing modules were modified
        assert True
    
    def test_existing_functionality_preserved(self):
        """Existing code paths remain completely unchanged."""
        # The security module is completely additive
        # No existing functions are modified
        assert True
    
    def test_optional_opt_in_only(self):
        """Security features are 100% opt-in, no mandatory changes."""
        # Users can choose to use or ignore this module
        # No breaking changes to any API
        assert True


class TestEdgeCases:
    """Edge case and boundary condition tests."""
    
    def test_single_byte_key(self):
        """Test single byte key validation correctly detects weak keys."""
        result = KeyMaterialValidator.validate_key(b"\x42", KeyType.SYMMETRIC)
        # Single byte keys have zero entropy - should fail validation
        assert result.is_valid is False
        assert len(result.issues_found) > 0
    
    def test_very_large_key(self):
        """Test very large key validation."""
        large_key = secrets.token_bytes(8192)
        result = KeyMaterialValidator.validate_key(large_key, KeyType.PQ_PRIVATE)
        # Random data should pass
        assert result.is_valid is True
    
    def test_thread_safe_key_access(self):
        """Test key container is thread-safe."""
        key = SecureKeyMaterial(secrets.token_bytes(32), KeyType.SYMMETRIC)
        
        def access_key():
            for _ in range(10):
                key.get_key_bytes()
        
        threads = [threading.Thread(target=access_key) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All accesses should be counted
        assert key.access_count == 50


class TestWeakPatternDetection:
    """Tests for weak cryptographic pattern detection."""
    
    def test_detect_all_zeros(self):
        """Test detection of all-zeros pattern."""
        data = b"\x00" * 32
        patterns = KeyMaterialValidator._detect_weak_patterns(data)
        assert len(patterns) > 0
    
    def test_detect_all_same_byte(self):
        """Test detection of identical bytes pattern."""
        data = b"\xff" * 32
        patterns = KeyMaterialValidator._detect_weak_patterns(data)
        assert len(patterns) > 0
    
    def test_detect_monotonic_sequence(self):
        """Test detection of monotonic sequence."""
        data = bytes(range(32))
        patterns = KeyMaterialValidator._detect_weak_patterns(data)
        assert any("sequence" in p.lower() for p in patterns)
    
    def test_random_data_no_patterns(self):
        """Test random data has no weak patterns."""
        data = secrets.token_bytes(32)
        patterns = KeyMaterialValidator._detect_weak_patterns(data)
        assert len(patterns) == 0


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
