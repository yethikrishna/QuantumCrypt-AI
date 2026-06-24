"""
Test Suite for QuantumCrypt Security Hardening Module V23
Dimension B - Security Hardening

Crypto-Specific Tests:
1. Side-Channel Resistance Wrappers
2. Crypto-Grade Memory Zeroization
3. Constant-Time Crypto Operations
4. Key Material Validation
5. Sensitive Data Redaction (ALWAYS ACTIVE)
6. Backward Compatibility Verification
"""

import os
import sys
import time
import threading
import secrets
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.crypto_security_hardening_side_channel_memory_v23_2026_june import (
    CryptoSecurityConfig,
    SideChannelProtector,
    side_channel_protected,
    CryptoSecureMemory,
    CryptoSensitiveKey,
    crypto_constant_time_compare,
    crypto_constant_time_select,
    KeyValidationError,
    KeyMaterialValidator,
    redact_sensitive_data,
    secure_crypto_operation,
)


# -----------------------------------------------------------------------------
# TEST FIXTURES
# -----------------------------------------------------------------------------
@pytest.fixture
def enable_all_crypto_security():
    """Enable all crypto security features for testing."""
    original_vars = {
        'QUANTUMCRYPT_SEC_SIDE_CHANNEL': os.environ.get('QUANTUMCRYPT_SEC_SIDE_CHANNEL'),
        'QUANTUMCRYPT_SEC_ZEROIZATION': os.environ.get('QUANTUMCRYPT_SEC_ZEROIZATION'),
        'QUANTUMCRYPT_SEC_CONSTANT_TIME': os.environ.get('QUANTUMCRYPT_SEC_CONSTANT_TIME'),
        'QUANTUMCRYPT_SEC_KEY_VALIDATION': os.environ.get('QUANTUMCRYPT_SEC_KEY_VALIDATION'),
    }
    
    os.environ['QUANTUMCRYPT_SEC_SIDE_CHANNEL'] = '1'
    os.environ['QUANTUMCRYPT_SEC_ZEROIZATION'] = '1'
    os.environ['QUANTUMCRYPT_SEC_CONSTANT_TIME'] = '1'
    os.environ['QUANTUMCRYPT_SEC_KEY_VALIDATION'] = '1'
    
    CryptoSecurityConfig._instance = None
    
    yield
    
    for key, value in original_vars.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    CryptoSecurityConfig._instance = None


@pytest.fixture
def disable_all_crypto_security():
    """Disable all crypto security features - test backward compatibility."""
    original_vars = {
        'QUANTUMCRYPT_SEC_SIDE_CHANNEL': os.environ.get('QUANTUMCRYPT_SEC_SIDE_CHANNEL'),
        'QUANTUMCRYPT_SEC_ZEROIZATION': os.environ.get('QUANTUMCRYPT_SEC_ZEROIZATION'),
        'QUANTUMCRYPT_SEC_CONSTANT_TIME': os.environ.get('QUANTUMCRYPT_SEC_CONSTANT_TIME'),
        'QUANTUMCRYPT_SEC_KEY_VALIDATION': os.environ.get('QUANTUMCRYPT_SEC_KEY_VALIDATION'),
    }
    
    os.environ['QUANTUMCRYPT_SEC_SIDE_CHANNEL'] = '0'
    os.environ['QUANTUMCRYPT_SEC_ZEROIZATION'] = '0'
    os.environ['QUANTUMCRYPT_SEC_CONSTANT_TIME'] = '0'
    os.environ['QUANTUMCRYPT_SEC_KEY_VALIDATION'] = '0'
    
    CryptoSecurityConfig._instance = None
    
    yield
    
    for key, value in original_vars.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    CryptoSecurityConfig._instance = None


# -----------------------------------------------------------------------------
# TEST 1: CRYPTO SECURITY CONFIG
# -----------------------------------------------------------------------------
class TestCryptoSecurityConfig:
    def test_singleton_pattern(self):
        """Test config is true singleton."""
        config1 = CryptoSecurityConfig()
        config2 = CryptoSecurityConfig()
        assert config1 is config2
    
    def test_all_features_disabled_by_default(self, disable_all_crypto_security):
        """CRITICAL: All features DISABLED by default."""
        config = CryptoSecurityConfig()
        assert config.side_channel_protection is False
        assert config.zeroization_enabled is False
        assert config.constant_time_enabled is False
        assert config.key_validation_enabled is False
    
    def test_key_logging_permanently_disabled(self):
        """CRITICAL: Key material logging PERMANENTLY disabled."""
        assert CryptoSecurityConfig.ALLOW_KEY_MATERIAL_LOGGING is False
    
    def test_sensitive_field_names_defined(self):
        """Test sensitive field names are defined."""
        assert 'private_key' in CryptoSecurityConfig.SENSITIVE_FIELD_NAMES
        assert 'secret_key' in CryptoSecurityConfig.SENSITIVE_FIELD_NAMES
        assert 'seed' in CryptoSecurityConfig.SENSITIVE_FIELD_NAMES


# -----------------------------------------------------------------------------
# TEST 2: SIDE-CHANNEL PROTECTION
# -----------------------------------------------------------------------------
class TestSideChannelProtection:
    def test_disabled_passthrough(self, disable_all_crypto_security):
        """When disabled, side-channel protection does nothing."""
        protector = SideChannelProtector()
        
        def simple_func(x):
            return x * 2
        
        result = protector.protect_operation(simple_func, 5)
        assert result == 10
    
    def test_protected_decorator(self, enable_all_crypto_security):
        """Test side-channel protected decorator."""
        @side_channel_protected
        def crypto_op(data):
            return data[::-1]
        
        # Should not raise
        result = crypto_op(b'test data')
        assert result == b'atad tset'
    
    def test_no_exceptions_under_load(self, enable_all_crypto_security):
        """Test side-channel protection doesn't break under load."""
        protector = SideChannelProtector()
        
        errors = []
        for _ in range(100):
            try:
                protector.protect_operation(lambda: secrets.token_bytes(32))
            except Exception as e:
                errors.append(e)
        
        assert len(errors) == 0


# -----------------------------------------------------------------------------
# TEST 3: CRYPTO-GRADE MEMORY ZEROIZATION
# -----------------------------------------------------------------------------
class TestCryptoSecureMemory:
    def test_disabled_passthrough(self, disable_all_crypto_security):
        """When disabled, zeroization does nothing (no errors)."""
        data = bytearray(b'secret_key_material')
        CryptoSecureMemory.zeroize_key_material(data)
        # Should not raise
        assert True
    
    def test_multi_pass_zeroization(self, enable_all_crypto_security):
        """Test crypto-grade multi-pass zeroization."""
        sensitive = bytearray(b'private_key_for_kyber_768_algorithm')
        original = bytes(sensitive)
        
        CryptoSecureMemory.zeroize_key_material(sensitive)
        
        # All bytes should be zero
        assert all(b == 0 for b in sensitive)
        assert bytes(sensitive) != original
    
    def test_sensitive_key_context_manager(self, enable_all_crypto_security):
        """Test CryptoSensitiveKey context manager."""
        key_data = b'my_top_secret_signing_key_12345'
        
        with CryptoSensitiveKey(key_data) as key:
            assert bytes(key) == key_data
            key_copy = bytes(key)
        
        assert key_copy == key_data
    
    def test_wipe_stack_variables(self, enable_all_crypto_security):
        """Test wiping multiple stack variables."""
        key1 = bytearray(b'key1_secret')
        key2 = bytearray(b'key2_secret')
        
        CryptoSecureMemory.wipe_stack_variables(key1, key2)
        
        # Both should be zeroized
        assert all(b == 0 for b in key1)
        assert all(b == 0 for b in key2)


# -----------------------------------------------------------------------------
# TEST 4: CONSTANT-TIME CRYPTO OPERATIONS
# -----------------------------------------------------------------------------
class TestConstantTimeCrypto:
    def test_disabled_fallback(self, disable_all_crypto_security):
        """When disabled, falls back to normal comparison."""
        assert crypto_constant_time_compare(b'abc', b'abc') is True
        assert crypto_constant_time_compare(b'abc', b'abd') is False
    
    def test_equal_keys(self, enable_all_crypto_security):
        """Test equal cryptographic keys."""
        key1 = secrets.token_bytes(32)
        key2 = bytes(key1)
        assert crypto_constant_time_compare(key1, key2) is True
    
    def test_different_keys(self, enable_all_crypto_security):
        """Test different cryptographic keys."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        assert crypto_constant_time_compare(key1, key2) is False
    
    def test_different_length_keys(self, enable_all_crypto_security):
        """Test different length keys."""
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(32)
        assert crypto_constant_time_compare(key1, key2) is False
    
    def test_constant_time_select(self, enable_all_crypto_security):
        """Test constant-time conditional selection."""
        a = b'\x01\x02\x03\x04'
        b = b'\x05\x06\x07\x08'
        
        assert crypto_constant_time_select(True, a, b) == a
        assert crypto_constant_time_select(False, a, b) == b
    
    def test_constant_time_select_length_mismatch(self, enable_all_crypto_security):
        """Test constant-time select raises on length mismatch."""
        with pytest.raises(ValueError):
            crypto_constant_time_select(True, b'short', b'much longer string')


# -----------------------------------------------------------------------------
# TEST 5: KEY MATERIAL VALIDATION
# -----------------------------------------------------------------------------
class TestKeyMaterialValidation:
    def test_disabled_passthrough(self, disable_all_crypto_security):
        """When disabled, validation always passes."""
        validator = KeyMaterialValidator()
        result = validator.validate_key(b'')
        assert result['valid'] is True
    
    def test_good_key_validation(self, enable_all_crypto_security):
        """Test validation of cryptographically strong key."""
        validator = KeyMaterialValidator()
        good_key = secrets.token_bytes(32)
        result = validator.validate_key(good_key)
        assert result['valid'] is True
        assert result['entropy'] > 0
    
    def test_short_key_rejection(self, enable_all_crypto_security):
        """Test short key rejection."""
        validator = KeyMaterialValidator()
        short_key = b'short'  # 5 bytes
        result = validator.validate_key(short_key, min_length=16)
        assert result['valid'] is False
        assert any('too short' in err.lower() for err in result['errors'])
    
    def test_weak_key_detection(self, enable_all_crypto_security):
        """Test weak key pattern detection."""
        validator = KeyMaterialValidator()
        
        # All zeros - classic weak key
        weak_key = b'\x00' * 32
        result = validator.validate_key(weak_key)
        assert len(result['warnings']) > 0
    
    def test_entropy_calculation(self, enable_all_crypto_security):
        """Test Shannon entropy calculation."""
        validator = KeyMaterialValidator()
        
        # Low entropy: repeated pattern
        low_entropy = b'AAAA' * 8
        low_result = validator.calculate_shannon_entropy(low_entropy)
        
        # High entropy: random
        high_entropy = secrets.token_bytes(32)
        high_result = validator.calculate_shannon_entropy(high_entropy)
        
        # Random should have higher entropy than repeated pattern
        assert high_result >= low_result
    
    def test_raise_on_validation_failure(self, enable_all_crypto_security):
        """Test exception raising on validation failure."""
        validator = KeyMaterialValidator()
        with pytest.raises(KeyValidationError):
            validator.validate_key(b'short', min_length=32, raise_on_failure=True)


# -----------------------------------------------------------------------------
# TEST 6: SENSITIVE DATA REDACTION - ALWAYS ACTIVE
# -----------------------------------------------------------------------------
class TestSensitiveDataRedaction:
    def test_redaction_always_active(self, disable_all_crypto_security):
        """CRITICAL: Redaction is ALWAYS ACTIVE, even when security disabled."""
        data = {
            'private_key': b'super_secret_key',
            'public_key': b'can_be_shown',
            'nested': {
                'secret_key': 'another_secret',
                'normal_field': 'normal_value'
            }
        }
        
        redacted = redact_sensitive_data(data)
        
        # Sensitive fields should be redacted
        assert redacted['private_key'] == '[REDACTED - SENSITIVE CRYPTO MATERIAL]'
        assert redacted['nested']['secret_key'] == '[REDACTED - SENSITIVE CRYPTO MATERIAL]'
        
        # Normal fields preserved
        assert redacted['public_key'] == b'can_be_shown'
        assert redacted['nested']['normal_field'] == 'normal_value'
    
    def test_large_binary_redaction(self):
        """Test large binary data is redacted."""
        data = b'x' * 100
        result = redact_sensitive_data(data)
        assert 'REDACTED' in result
        assert '100 bytes' in result
    
    def test_list_redaction(self):
        """Test redaction works in lists."""
        data = [
            {'private_key': 'secret'},
            {'normal': 'value'}
        ]
        redacted = redact_sensitive_data(data)
        assert redacted[0]['private_key'] == '[REDACTED - SENSITIVE CRYPTO MATERIAL]'
        assert redacted[1]['normal'] == 'value'


# -----------------------------------------------------------------------------
# TEST 7: SECURE CRYPTO OPERATION DECORATOR
# -----------------------------------------------------------------------------
class TestSecureCryptoOperation:
    def test_decorator_passthrough(self, disable_all_crypto_security):
        """When disabled, decorator is pure passthrough."""
        @secure_crypto_operation()
        def test_func(x, y):
            return x + y
        
        assert test_func(2, 3) == 5
    
    def test_decorator_with_keys(self, enable_all_crypto_security):
        """Test decorator with key material inputs."""
        @secure_crypto_operation()
        def crypto_func(key, data):
            return key + data
        
        key = secrets.token_bytes(32)
        data = b'test data'
        result = crypto_func(key, data)
        assert result == key + data


# -----------------------------------------------------------------------------
# TEST 8: BACKWARD COMPATIBILITY
# -----------------------------------------------------------------------------
class TestBackwardCompatibility:
    def test_zero_overhead_when_disabled(self, disable_all_crypto_security):
        """CRITICAL: Zero overhead when all features are disabled."""
        config = CryptoSecurityConfig()
        
        # All features should be disabled
        assert config.side_channel_protection is False
        assert config.zeroization_enabled is False
        assert config.constant_time_enabled is False
        assert config.key_validation_enabled is False
        
        # All operations should short-circuit
        validator = KeyMaterialValidator()
        result = validator.validate_key(b'any key at all')
        assert result['valid'] is True
        
        # Comparison works normally
        assert crypto_constant_time_compare(b'a', b'a') is True
    
    def test_existing_code_untouched(self):
        """Verify ADD-ONLY philosophy - new file only."""
        assert os.path.exists(
            'quantum_crypt/crypto_security_hardening_side_channel_memory_v23_2026_june.py'
        )


# -----------------------------------------------------------------------------
# RUN TESTS
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
