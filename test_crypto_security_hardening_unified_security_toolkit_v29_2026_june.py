"""
Tests for Unified Crypto Security Toolkit (Dimension B - Security Hardening)
============================================================================
ADD-ONLY tests - no modifications to existing production code.
Verifies all cryptographic security utilities work correctly.
"""

import pytest
import time
import threading
import secrets
from quantum_crypt.crypto_security_hardening_unified_security_toolkit_v29_2026_june import (
    SecureKeyMemory,
    ConstantTimeCrypto,
    CryptoInputValidator,
    KeyOperationRateLimiter,
    UnifiedCryptoSecurityToolkit,
    CryptoSecurityLevel,
    CryptoValidationResult,
    get_crypto_security_toolkit
)


class TestSecureKeyMemory:
    """Tests for secure key memory zeroization"""

    def test_zeroize_key_material(self):
        """Test FIPS-compliant key zeroization"""
        key_data = bytearray(secrets.token_bytes(32))  # 256-bit key
        original = bytes(key_data)
        
        SecureKeyMemory.zeroize_key_material(key_data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in key_data)
        assert bytes(key_data) != original

    def test_zeroize_memoryview(self):
        """Test zeroizing memoryview buffers"""
        key_data = bytearray(secrets.token_bytes(16))
        view = memoryview(key_data)
        
        SecureKeyMemory.zeroize_sensitive_buffer(view)
        
        assert all(b == 0 for b in key_data)

    def test_secure_wipe_list_of_keys(self):
        """Test wiping multiple keys in a list"""
        key1 = bytearray(secrets.token_bytes(16))
        key2 = bytearray(secrets.token_bytes(16))
        key_list = [key1, key2, "not sensitive"]
        
        SecureKeyMemory.secure_wipe_object(key_list)
        
        assert all(b == 0 for b in key1)
        assert all(b == 0 for b in key2)


class TestConstantTimeCrypto:
    """Tests for constant-time cryptographic operations"""

    def test_compare_keys_equal(self):
        """Test constant-time key comparison"""
        key_a = secrets.token_bytes(32)
        key_b = bytes(key_a)
        key_c = secrets.token_bytes(32)
        
        assert ConstantTimeCrypto.compare_keys(key_a, key_b) is True
        assert ConstantTimeCrypto.compare_keys(key_a, key_c) is False

    def test_compare_keys_different_lengths(self):
        """Test comparing keys of different lengths returns False"""
        key_short = secrets.token_bytes(16)
        key_long = secrets.token_bytes(32)
        
        assert ConstantTimeCrypto.compare_keys(key_short, key_long) is False

    def test_compare_signatures(self):
        """Test signature comparison"""
        sig_a = secrets.token_bytes(64)
        sig_b = bytes(sig_a)
        sig_c = secrets.token_bytes(64)
        
        assert ConstantTimeCrypto.compare_signatures(sig_a, sig_b) is True
        assert ConstantTimeCrypto.compare_signatures(sig_a, sig_c) is False

    def test_compare_hashes(self):
        """Test hash comparison"""
        import hashlib
        hash_a = hashlib.sha256(b"test").digest()
        hash_b = hashlib.sha256(b"test").digest()
        hash_c = hashlib.sha256(b"different").digest()
        
        assert ConstantTimeCrypto.compare_hashes(hash_a, hash_b) is True
        assert ConstantTimeCrypto.compare_hashes(hash_a, hash_c) is False

    def test_array_equals(self):
        """Test integer array comparison"""
        assert ConstantTimeCrypto.array_equals([1, 2, 3], [1, 2, 3]) is True
        assert ConstantTimeCrypto.array_equals([1, 2, 3], [1, 2, 4]) is False
        assert ConstantTimeCrypto.array_equals([1], [1, 2]) is False


class TestCryptoInputValidator:
    """Tests for cryptographic input validation"""

    def test_validate_aes_key_128(self):
        """Test validating 128-bit AES key"""
        validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)
        key = secrets.token_bytes(16)
        result = validator.validate_key_length(key, required_length=16)
        
        assert result.is_valid is True
        assert result.security_score > 0

    def test_validate_aes_key_wrong_length(self):
        """Test validating AES key with wrong length"""
        validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)
        key = secrets.token_bytes(15)  # Wrong length
        result = validator.validate_key_length(key, required_length=16)
        
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_nonce(self):
        """Test nonce validation"""
        validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)
        nonce = secrets.token_bytes(12)  # AES-GCM nonce
        result = validator.validate_nonce(nonce, required_length=12)
        
        assert result.is_valid is True

    def test_validate_all_zero_nonce_warning(self):
        """Test all-zero nonce generates warning"""
        validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)
        nonce = bytes(12)  # All zeros
        result = validator.validate_nonce(nonce, required_length=12)
        
        assert len(result.warnings) > 0
        assert "All-zero nonce" in result.warnings[0]

    def test_entropy_estimation(self):
        """Test entropy estimation works"""
        validator = CryptoInputValidator(CryptoSecurityLevel.STANDARD)
        # High entropy random data
        high_entropy = secrets.token_bytes(32)
        result = validator.validate_key_length(high_entropy, min_length=16)
        assert result.security_score > 50  # Random data should have good entropy
        
        # Low entropy data
        low_entropy = b"\x00" * 32
        result_low = validator.validate_key_length(low_entropy, min_length=16)
        assert result_low.security_score < result.security_score


class TestKeyOperationRateLimiter:
    """Tests for key operation rate limiting"""

    def test_basic_key_rate_limiting(self):
        """Test basic rate limiting for key operations"""
        limiter = KeyOperationRateLimiter(max_operations_per_second=10)
        
        # Should allow 10 operations
        for _ in range(10):
            assert limiter.try_key_operation() is True
        
        # 11th should be rate limited
        assert limiter.try_key_operation() is False

    def test_rate_limit_refill(self):
        """Test rate limit tokens refill"""
        limiter = KeyOperationRateLimiter(max_operations_per_second=1000)
        
        # Consume all
        for _ in range(1000):
            limiter.try_key_operation()
        
        time.sleep(0.002)
        
        # Should have refilled some tokens
        assert limiter.try_key_operation() is True


class TestUnifiedCryptoSecurityToolkit:
    """Tests for the main crypto toolkit facade"""

    def test_get_crypto_toolkit(self):
        """Test getting toolkit instance"""
        toolkit = get_crypto_security_toolkit()
        assert toolkit is not None
        assert isinstance(toolkit, UnifiedCryptoSecurityToolkit)

    def test_secure_compare_keys_facade(self):
        """Test key comparison through facade"""
        toolkit = get_crypto_security_toolkit()
        key = secrets.token_bytes(32)
        
        assert toolkit.secure_compare_keys(key, bytes(key)) is True
        assert toolkit.secure_compare_keys(key, secrets.token_bytes(32)) is False

    def test_secure_compare_signatures_facade(self):
        """Test signature comparison through facade"""
        toolkit = get_crypto_security_toolkit()
        sig = secrets.token_bytes(64)
        
        assert toolkit.secure_compare_signatures(sig, bytes(sig)) is True

    def test_zeroize_key_facade(self):
        """Test key zeroization through facade"""
        toolkit = get_crypto_security_toolkit()
        key_data = bytearray(secrets.token_bytes(32))
        
        toolkit.zeroize_key(key_data)
        
        assert all(b == 0 for b in key_data)

    def test_validate_aes_key_facade(self):
        """Test AES key validation through facade"""
        toolkit = get_crypto_security_toolkit()
        
        # Valid AES keys
        assert toolkit.validate_aes_key(secrets.token_bytes(16)).is_valid is True  # 128-bit
        assert toolkit.validate_aes_key(secrets.token_bytes(24)).is_valid is True  # 192-bit
        assert toolkit.validate_aes_key(secrets.token_bytes(32)).is_valid is True  # 256-bit
        
        # Invalid AES key
        assert toolkit.validate_aes_key(secrets.token_bytes(20)).is_valid is False

    def test_validate_post_quantum_key_facade(self):
        """Test post-quantum key validation"""
        toolkit = get_crypto_security_toolkit()
        key = secrets.token_bytes(64)
        result = toolkit.validate_post_quantum_key(key)
        
        assert result.is_valid is True

    def test_get_named_rate_limiter(self):
        """Test getting named rate limiter"""
        toolkit = get_crypto_security_toolkit()
        limiter1 = toolkit.get_key_rate_limiter("hsm_operations")
        limiter2 = toolkit.get_key_rate_limiter("hsm_operations")
        
        # Same instance
        assert limiter1 is limiter2


class TestThreadSafety:
    """Tests for thread safety"""

    def test_key_rate_limiter_thread_safety(self):
        """Test rate limiter under concurrent access"""
        limiter = KeyOperationRateLimiter(max_operations_per_second=200)
        successes = [0]
        lock = threading.Lock()
        
        def worker():
            for _ in range(20):
                if limiter.try_key_operation():
                    with lock:
                        successes[0] += 1
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have successful operations
        assert successes[0] > 0
        # Should not exceed max
        assert successes[0] <= 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
