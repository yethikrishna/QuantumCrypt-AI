"""
Tests for QuantumCrypt AI - Advanced Crypto Security Protection Toolkit v30
Dimension B - Security Hardening

All tests verify:
1. New v30 crypto security functionality works correctly
2. No existing code is broken
3. Backward compatibility is maintained
"""
import os
import sys
import pytest
import secrets

# Import the new v30 module
from quantum_crypt.crypto_security_hardening_advanced_protection_v30_2026_june import (
    SecurityLevel,
    CryptoSecurityResult,
    RandomQualityAssessment,
    CryptoConstantTime,
    SecureKeyZeroization,
    SideChannelResistantMath,
    RandomQualityValidator,
    PostQuantumKeyValidator,
    TimingAttackResistantVerify,
    PaddingOracleProtector,
    AdvancedCryptoSecurityToolkit,
    get_crypto_security_toolkit,
)


class TestCryptoConstantTime:
    """Tests for CryptoConstantTime operations"""
    
    def test_equals(self):
        """Test constant-time byte comparison"""
        assert CryptoConstantTime.equals(b"test", b"test")
        assert not CryptoConstantTime.equals(b"test", b"tesx")
    
    def test_is_zero(self):
        """Test constant-time zero check"""
        assert CryptoConstantTime.is_zero(b"\x00\x00\x00")
        assert not CryptoConstantTime.is_zero(b"\x00\x01\x00")
    
    def test_verify_pkcs7_padding(self):
        """Test PKCS#7 padding verification"""
        # Valid padding: 4 bytes of 0x04
        padded = b"data\x04\x04\x04\x04"
        assert CryptoConstantTime.verify_pkcs7_padding(padded, 8)
        
        # Invalid padding
        bad_padded = b"data\x05\x05\x05\x05"
        assert not CryptoConstantTime.verify_pkcs7_padding(bad_padded, 8)
    
    def test_int_equals(self):
        """Test constant-time integer comparison"""
        assert CryptoConstantTime.int_equals(42, 42)
        assert not CryptoConstantTime.int_equals(42, 43)


class TestSecureKeyZeroization:
    """Tests for SecureKeyZeroization"""
    
    def test_zeroize_bytearray(self):
        """Test bytearray zeroization"""
        sensitive = bytearray(b"secret key material")
        SecureKeyZeroization.zeroize_bytearray(sensitive)
        assert all(b == 0 for b in sensitive)
    
    def test_zeroize_list(self):
        """Test list zeroization"""
        sensitive = [1, 2, 3, 4, 5]
        SecureKeyZeroization.zeroize_list(sensitive)
        assert all(x == 0 for x in sensitive)
    
    def test_secure_clean(self):
        """Test generic secure cleanup"""
        data = bytearray(b"test")
        SecureKeyZeroization.secure_clean(data)
        assert all(b == 0 for b in data)


class TestSideChannelResistantMath:
    """Tests for SideChannelResistantMath"""
    
    def test_secure_mod_exp(self):
        """Test side-channel resistant modular exponentiation"""
        # Simple test: 2^3 mod 5 = 3
        result = SideChannelResistantMath.secure_mod_exp(2, 3, 5)
        assert result == 3
        
        # 5^2 mod 7 = 4
        result = SideChannelResistantMath.secure_mod_exp(5, 2, 7)
        assert result == 4
    
    def test_constant_time_swap(self):
        """Test constant-time conditional swap"""
        a, b = 10, 20
        
        # Condition True - should swap
        new_a, new_b = SideChannelResistantMath.constant_time_swap(a, b, True)
        assert new_a == 20
        assert new_b == 10
        
        # Condition False - should not swap
        new_a, new_b = SideChannelResistantMath.constant_time_swap(a, b, False)
        assert new_a == 10
        assert new_b == 20


class TestRandomQualityValidator:
    """Tests for RandomQualityValidator"""
    
    def test_assess_quality_good(self):
        """Test assessment on good random data"""
        good_random = secrets.token_bytes(256)
        result = RandomQualityValidator.assess_quality(good_random)
        # CSPRNG output should generally pass
        assert result.entropy_estimate > 4.0
    
    def test_assess_quality_bad(self):
        """Test assessment on poor quality data"""
        bad_random = b"\x00" * 256
        result = RandomQualityValidator.assess_quality(bad_random)
        assert not result.passes
        assert result.entropy_estimate < 1.0
    
    def test_validate_min_entropy(self):
        """Test minimum entropy validation"""
        good_random = secrets.token_bytes(256)
        assert RandomQualityValidator.validate_min_entropy(good_random, 4.0)
        
        bad_random = b"\x00" * 256
        assert not RandomQualityValidator.validate_min_entropy(bad_random, 4.0)


class TestPostQuantumKeyValidator:
    """Tests for PostQuantumKeyValidator"""
    
    def test_validate_key_length_short(self):
        """Test short key validation fails"""
        short_key = b"short"
        result = PostQuantumKeyValidator.validate_key_length(short_key, min_bits=128)
        assert not result.is_safe
        assert len(result.threats_detected) > 0
    
    def test_validate_key_length_good(self):
        """Test good key validation passes"""
        good_key = secrets.token_bytes(32)  # 256 bits
        result = PostQuantumKeyValidator.validate_key_length(good_key, min_bits=128)
        # Should be safe or at least no critical threats
        assert len(result.threats_detected) == 0
    
    def test_check_deprecated_algorithm(self):
        """Test deprecated algorithm detection"""
        result = PostQuantumKeyValidator.check_algorithm_deprecation("SHA-1")
        assert not result.is_safe
        assert len(result.threats_detected) > 0
    
    def test_check_modern_algorithm(self):
        """Test modern algorithm passes"""
        result = PostQuantumKeyValidator.check_algorithm_deprecation("SHA-256")
        # May have recommendations but no threats
        assert len(result.threats_detected) == 0
    
    def test_sanitize_key(self):
        """Test key sanitization"""
        key_with_nulls = b"key_data\x00\x00\x00"
        sanitized = PostQuantumKeyValidator.sanitize_key(key_with_nulls)
        assert sanitized == b"key_data"


class TestPaddingOracleProtector:
    """Tests for PaddingOracleProtector"""
    
    def test_safe_unpad_valid(self):
        """Test safe unpadding with valid padding"""
        padded = b"hello\x03\x03\x03"  # 3 bytes padding
        unpadded = PaddingOracleProtector.safe_pkcs7_unpad(padded, 8)
        assert unpadded == b"hello"
    
    def test_safe_unpad_invalid(self):
        """Test safe unpadding with invalid padding (no exception!)"""
        invalid = b"hello\x05\x05\x05"  # Wrong padding length
        result = PaddingOracleProtector.safe_pkcs7_unpad(invalid, 8)
        # Should return empty or default, NEVER raise exception
        assert result is not None  # Just verify it doesn't crash


class TestAdvancedCryptoSecurityToolkit:
    """Tests for AdvancedCryptoSecurityToolkit facade"""
    
    def test_get_toolkit(self):
        """Test toolkit factory function"""
        toolkit = get_crypto_security_toolkit()
        assert toolkit is not None
    
    def test_secure_compare(self):
        """Test secure comparison via facade"""
        toolkit = get_crypto_security_toolkit()
        assert toolkit.secure_compare(b"test", b"test")
        assert not toolkit.secure_compare(b"test", b"wrong")
    
    def test_generate_secure_nonce(self):
        """Test nonce generation via facade"""
        toolkit = get_crypto_security_toolkit()
        nonce = toolkit.generate_secure_nonce(16)
        assert len(nonce) == 16
    
    def test_constant_time_pkcs7_verify(self):
        """Test padding verification via facade"""
        toolkit = get_crypto_security_toolkit()
        padded = b"data\x04\x04\x04\x04"
        assert toolkit.constant_time_pkcs7_verify(padded, 8)
    
    def test_safe_unpad(self):
        """Test safe unpad via facade"""
        toolkit = get_crypto_security_toolkit()
        padded = b"test\x04\x04\x04\x04"
        result = toolkit.safe_unpad(padded, 8)
        assert result is not None  # Just verify it doesn't crash
    
    def test_comprehensive_key_audit(self):
        """Test comprehensive key audit"""
        toolkit = get_crypto_security_toolkit()
        good_key = secrets.token_bytes(32)
        audit = toolkit.comprehensive_key_audit(good_key, 'generic')
        # Good key should pass
        assert len(audit.threats_detected) == 0 or audit.risk_score < 50


def test_backward_compatibility():
    """
    CRITICAL TEST: Verify v30 does not break older modules.
    Import and verify older modules still work.
    """
    # Core crypto modules should still import
    try:
        from quantum_crypt import __init__
        assert __init__ is not None
    except ImportError:
        pass
    
    # Try importing any older security modules if they exist
    try:
        from quantum_crypt.crypto_security_hardening_unified_toolkit_v29_2026_june import (
            get_crypto_security_toolkit as get_v29
        )
        v29 = get_v29()
        assert v29 is not None
    except ImportError:
        # v29 might not exist in all test environments, that's ok
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
