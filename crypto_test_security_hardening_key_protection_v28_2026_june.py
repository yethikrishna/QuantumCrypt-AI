"""
Test Suite: Security Hardening v28 - Cryptographic Key Protection
QuantumCrypt-AI
API Stability: STABLE

Tests for secure key memory management, constant-time crypto operations,
cryptographic input validation, and rate limiting.

All tests are ADD-ONLY - no modifications to existing tests.
"""

import pytest
import secrets
import threading
import time
from typing import Any

# Import security hardening modules
from quantum_crypt.crypto_security_hardening_key_protection_v28_2026_june import (
    SecureKeyMemory,
    ConstantTimeCrypto,
    CryptoInputValidator,
    CryptoRateLimiter,
    HardenedCryptoWrapper,
    KeySensitivityLevel,
    CryptoValidationResult,
)


class TestSecureKeyMemory:
    """Tests for secure key memory management"""
    
    def test_zeroize_bytearray_key(self):
        """Test bytearray key material is properly zeroized"""
        # Create sensitive key data
        key_data = bytearray(secrets.token_bytes(32))  # AES-256 key
        original = bytes(key_data)
        
        SecureKeyMemory.zeroize_key_material(key_data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in key_data)
        assert bytes(key_data) != original
    
    def test_zeroize_rejects_immutable_bytes(self):
        """Test immutable bytes cannot be zeroized"""
        key_bytes = secrets.token_bytes(32)
        with pytest.raises(TypeError):
            SecureKeyMemory.zeroize_key_material(key_bytes)  # type: ignore
    
    def test_wrap_sensitive_key_creates_copy(self):
        """Test wrapping creates mutable copy"""
        original = secrets.token_bytes(32)
        wrapped = SecureKeyMemory.wrap_sensitive_key(original)
        
        assert isinstance(wrapped, bytearray)
        assert bytes(wrapped) == original
        assert wrapped is not original  # Different object
    
    def test_secure_delete_key(self):
        """Test secure deletion attempts cleanup"""
        key_data = bytearray(secrets.token_bytes(16))
        # Should not raise
        SecureKeyMemory.secure_delete_key(key_data)


class TestConstantTimeCrypto:
    """Tests for constant-time cryptographic operations"""
    
    def test_verify_signature_equal(self):
        """Test identical signatures verify correctly"""
        sig1 = secrets.token_bytes(64)
        sig2 = bytes(sig1)
        
        assert ConstantTimeCrypto.verify_signature(sig1, sig2) is True
    
    def test_verify_signature_not_equal(self):
        """Test different signatures fail verification"""
        sig1 = secrets.token_bytes(64)
        sig2 = secrets.token_bytes(64)
        
        assert ConstantTimeCrypto.verify_signature(sig1, sig2) is False
    
    def test_verify_signature_different_length(self):
        """Test different length signatures always fail"""
        sig1 = secrets.token_bytes(64)
        sig2 = secrets.token_bytes(32)
        
        assert ConstantTimeCrypto.verify_signature(sig1, sig2) is False
    
    def test_verify_mac_equal(self):
        """Test MAC verification works"""
        mac1 = secrets.token_bytes(32)
        mac2 = bytes(mac1)
        
        assert ConstantTimeCrypto.verify_mac(mac1, mac2) is True
    
    def test_verify_mac_not_equal(self):
        """Test different MACs fail"""
        mac1 = secrets.token_bytes(32)
        mac2 = secrets.token_bytes(32)
        
        assert ConstantTimeCrypto.verify_mac(mac1, mac2) is False
    
    def test_compare_hashes(self):
        """Test hash comparison"""
        hash1 = b'\x00' * 32
        hash2 = b'\x00' * 32
        hash3 = b'\x01' * 32
        
        assert ConstantTimeCrypto.compare_hashes(hash1, hash2) is True
        assert ConstantTimeCrypto.compare_hashes(hash1, hash3) is False
    
    def test_compare_key_fingerprints(self):
        """Test key fingerprint comparison"""
        fp1 = "SHA256:abcdef1234567890"
        fp2 = "SHA256:abcdef1234567890"
        fp3 = "SHA256:differentfingerprint"
        
        assert ConstantTimeCrypto.compare_key_fingerprints(fp1, fp2) is True
        assert ConstantTimeCrypto.compare_key_fingerprints(fp1, fp3) is False
    
    def test_secure_select_same_length(self):
        """Test secure selection with same length inputs"""
        true_val = b'\xFF' * 16
        false_val = b'\x00' * 16
        
        result_true = ConstantTimeCrypto.secure_select(True, true_val, false_val)
        result_false = ConstantTimeCrypto.secure_select(False, true_val, false_val)
        
        assert result_true == true_val
        assert result_false == false_val
    
    def test_secure_select_different_length_raises(self):
        """Test secure select with different lengths raises"""
        with pytest.raises(ValueError):
            ConstantTimeCrypto.secure_select(True, b'\x00', b'\x00\x00')


class TestCryptoInputValidator:
    """Tests for cryptographic input validation"""
    
    def test_valid_aes_256_key(self):
        """Test valid AES-256 key passes"""
        key = secrets.token_bytes(32)  # 256 bits
        result = CryptoInputValidator.validate_symmetric_key(key)
        assert result.passed is True
        assert "256 bits" in result.message
    
    def test_valid_aes_128_key(self):
        """Test valid AES-128 key passes"""
        key = secrets.token_bytes(16)  # 128 bits
        result = CryptoInputValidator.validate_symmetric_key(key)
        assert result.passed is True
    
    def test_invalid_key_size(self):
        """Test invalid key size is rejected"""
        key = secrets.token_bytes(24)  # 192 bits is valid, test with 7 bytes
        key = secrets.token_bytes(7)  # 56 bits - invalid
        result = CryptoInputValidator.validate_symmetric_key(key)
        assert result.passed is False
        assert result.error_code == "INVALID_KEY_SIZE"
    
    def test_valid_nonce(self):
        """Test valid nonce passes"""
        nonce = secrets.token_bytes(12)  # GCM nonce size
        result = CryptoInputValidator.validate_nonce(nonce, 12)
        assert result.passed is True
    
    def test_all_zero_nonce_rejected(self):
        """Test all-zero nonce is rejected (security critical)"""
        nonce = b'\x00' * 12
        result = CryptoInputValidator.validate_nonce(nonce, 12)
        assert result.passed is False
        assert result.error_code == "ALL_ZERO_NONCE"
        assert result.severity == "CRITICAL"
    
    def test_wrong_length_nonce(self):
        """Test wrong length nonce is rejected"""
        nonce = secrets.token_bytes(16)
        result = CryptoInputValidator.validate_nonce(nonce, 12)
        assert result.passed is False
        assert result.error_code == "INVALID_NONCE_LENGTH"
    
    def test_valid_hex_string(self):
        """Test valid hex string passes"""
        result = CryptoInputValidator.validate_hex_string("deadBEEF1234")
        assert result.passed is True
    
    def test_invalid_hex_string(self):
        """Test invalid hex string is rejected"""
        result = CryptoInputValidator.validate_hex_string("not hex!")
        assert result.passed is False
        assert result.error_code == "INVALID_HEX"
    
    def test_odd_length_hex(self):
        """Test odd-length hex is rejected"""
        result = CryptoInputValidator.validate_hex_string("abc")  # 3 chars = odd
        assert result.passed is False
        assert result.error_code == "ODD_LENGTH_HEX"
    
    def test_plaintext_size_ok(self):
        """Test reasonable plaintext size passes"""
        data = b'x' * 1024
        result = CryptoInputValidator.validate_plaintext_size(data)
        assert result.passed is True
    
    def test_oversized_plaintext_rejected(self):
        """Test oversized plaintext is rejected"""
        data = b'x' * (20 * 1024 * 1024)  # 20MB
        result = CryptoInputValidator.validate_plaintext_size(data, max_size=10*1024*1024)
        assert result.passed is False
        assert result.error_code == "PLAINTEXT_TOO_LARGE"


class TestCryptoRateLimiter:
    """Tests for cryptographic operation rate limiting"""
    
    def test_signature_ops_within_limit(self):
        """Test signature ops within limit are allowed"""
        limiter = CryptoRateLimiter(max_sign_ops_per_minute=5)
        
        for _ in range(5):
            assert limiter.check_signature_operation() is True
    
    def test_signature_ops_over_limit(self):
        """Test signature ops over limit are rejected"""
        limiter = CryptoRateLimiter(max_sign_ops_per_minute=3)
        
        for _ in range(3):
            limiter.check_signature_operation()
        
        # Over limit
        assert limiter.check_signature_operation() is False
    
    def test_keygen_rate_limit(self):
        """Test key generation rate limiting"""
        limiter = CryptoRateLimiter(max_keygen_per_minute=2)
        
        assert limiter.check_key_generation() is True
        assert limiter.check_key_generation() is True
        assert limiter.check_key_generation() is False  # Over limit
    
    def test_encryption_rate_limit(self):
        """Test encryption rate limiting"""
        limiter = CryptoRateLimiter(max_encrypt_per_minute=10)
        
        for _ in range(10):
            assert limiter.check_encryption() is True
        
        assert limiter.check_encryption() is False
    
    def test_thread_safety(self):
        """Test rate limiter is thread-safe"""
        limiter = CryptoRateLimiter(max_sign_ops_per_minute=100)
        
        results = []
        lock = threading.Lock()
        
        def worker():
            for _ in range(10):
                r = limiter.check_signature_operation()
                with lock:
                    results.append(r)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(results) == 100
        assert all(results)


class TestHardenedCryptoWrapper:
    """Tests for hardened crypto wrapper"""
    
    class MockCryptoModule:
        """Mock crypto module for testing"""
        def sign(self, data: bytes) -> bytes:
            return b'signature:' + data
        
        def verify(self, signature: bytes, data: bytes) -> bool:
            return signature == b'signature:' + data
        
        def encrypt(self, plaintext: bytes) -> bytes:
            return plaintext[::-1]
        
        def generate_key(self) -> bytes:
            return secrets.token_bytes(32)
    
    def test_wrapper_passes_method_calls(self):
        """Test wrapper passes through method calls"""
        mock = self.MockCryptoModule()
        wrapper = HardenedCryptoWrapper(mock, enable_rate_limiting=False)
        
        result = wrapper.encrypt(b"test data")
        assert result == mock.encrypt(b"test data")
    
    def test_wrapper_rate_limits_sign_ops(self):
        """Test wrapper rate limits signature operations"""
        mock = self.MockCryptoModule()
        wrapper = HardenedCryptoWrapper(
            mock,
            enable_rate_limiting=True,
            enable_validation=False
        )
        
        # Should work
        result = wrapper.sign(b"test")
        assert b"signature" in result
    
    def test_secure_cleanup_available(self):
        """Test secure cleanup method is available"""
        mock = self.MockCryptoModule()
        wrapper = HardenedCryptoWrapper(mock)
        
        key_data = bytearray(b"sensitive key material")
        wrapper.secure_cleanup_key(key_data)
        
        # Should be zeroized
        assert all(b == 0 for b in key_data)
    
    def test_constant_time_verify_method(self):
        """Test constant time verify is available"""
        mock = self.MockCryptoModule()
        wrapper = HardenedCryptoWrapper(mock)
        
        sig1 = b"test_signature"
        sig2 = b"test_signature"
        sig3 = b"different_sig"
        
        assert wrapper.constant_time_verify(sig1, sig2) is True
        assert wrapper.constant_time_verify(sig1, sig3) is False
    
    def test_get_original_returns_unwrapped(self):
        """Test get_original returns unwrapped module"""
        mock = self.MockCryptoModule()
        wrapper = HardenedCryptoWrapper(mock)
        
        original = wrapper.get_original()
        assert isinstance(original, self.MockCryptoModule)
        assert original is mock


class TestKeySensitivityLevel:
    """Tests for key sensitivity enumeration"""
    
    def test_sensitivity_levels_exist(self):
        """Test all sensitivity levels are defined"""
        assert KeySensitivityLevel.PUBLIC.value == "public"
        assert KeySensitivityLevel.INTERNAL.value == "internal"
        assert KeySensitivityLevel.SECRET.value == "secret"
        assert KeySensitivityLevel.CRITICAL.value == "critical"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
