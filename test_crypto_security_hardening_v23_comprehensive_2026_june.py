"""
Test Suite for QuantumCrypt AI Security Hardening v23
Dimension B - Security Hardening
Tests for:
- Crypto Key Zeroization
- Constant-Time Crypto Operations
- Crypto Input Validation
- Crypto Operation Rate Limiting

All tests are ADD-ONLY - no modification to existing tests.
"""

import pytest
import time
import os
import sys

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_security_hardening_key_zeroization_v23_2026_june import (
    CryptoKeyZeroizer,
    CryptoConstantTimeOps,
    zeroize_crypto_key,
    constant_time_verify,
    SensitiveCryptoContext
)

from crypto_security_hardening_input_validation_rate_limit_v23_2026_june import (
    CryptoInputValidator,
    CryptoValidationResult,
    CryptoOperationRateLimiter,
    validate_crypto_input,
    rate_limited_crypto
)


class TestCryptoKeyZeroization:
    """Tests for cryptographic key material zeroization."""
    
    def test_zeroizer_initialization(self):
        """Test crypto zeroizer initializes with NIST-compliant defaults."""
        zeroizer = CryptoKeyZeroizer()
        assert zeroizer.overwrite_passes == 4
        stats = zeroizer.get_zeroization_stats()
        assert stats['keys_zeroized'] == 0
        assert stats['nist_compliant'] is True  # 4 passes >= 3
    
    def test_zeroize_key_bytes(self):
        """Test cryptographic key material is actually zeroized."""
        zeroizer = CryptoKeyZeroizer()
        key = bytearray(b"x" * 32)  # 256-bit key
        original = bytes(key)
        
        zeroizer.zeroize_key_bytes(key)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in key)
        assert bytes(key) != original
        stats = zeroizer.get_zeroization_stats()
        assert stats['keys_zeroized'] == 1
        assert stats['total_bytes_zeroized'] == 32
    
    def test_zeroize_session_key(self):
        """Test ephemeral session key zeroization."""
        zeroizer = CryptoKeyZeroizer()
        session_key = bytearray(os.urandom(16))
        
        zeroizer.zeroize_session_key(session_key)
        
        assert all(b == 0 for b in session_key)
    
    def test_zeroize_derivation_material(self):
        """Test KDF intermediate material zeroization."""
        zeroizer = CryptoKeyZeroizer()
        kdf_material = [
            bytearray(b"intermediate1"),
            bytearray(b"intermediate2"),
            bytearray(b"salt_value")
        ]
        
        zeroizer.zeroize_derivation_material(kdf_material)
        
        assert len(kdf_material) == 0
    
    def test_zeroize_plaintext(self):
        """Test plaintext zeroization after encryption."""
        zeroizer = CryptoKeyZeroizer()
        plaintext = bytearray(b"Secret message to encrypt")
        
        zeroizer.zeroize_plaintext(plaintext)
        
        assert all(b == 0 for b in plaintext)
    
    def test_zeroize_crypto_key_convenience(self):
        """Test convenience zeroization function."""
        key = bytearray(b"test_key_material")
        zeroize_crypto_key(key)
        assert all(b == 0 for b in key)
    
    def test_sensitive_crypto_context(self):
        """Test context manager automatically zeroizes crypto material."""
        tracked_key = None
        
        with SensitiveCryptoContext() as ctx:
            private_key = ctx.track(bytearray(b"private_key_data_here_12345"))
            tracked_key = private_key
            assert len(private_key) > 0
        
        # Should be zeroized after context exit
        assert all(b == 0 for b in tracked_key)
    
    def test_custom_overwrite_passes(self):
        """Test custom overwrite pass configuration."""
        zeroizer = CryptoKeyZeroizer(overwrite_passes=7)
        assert zeroizer.overwrite_passes == 7
        stats = zeroizer.get_zeroization_stats()
        assert stats['overwrite_passes'] == 7


class TestCryptoConstantTimeOps:
    """Tests for constant-time cryptographic operations."""
    
    def test_constant_time_initialization(self):
        """Test constant-time ops initializes."""
        ct_ops = CryptoConstantTimeOps()
        assert ct_ops is not None
    
    def test_verify_mac_equal(self):
        """Test MAC verification for matching tags."""
        mac1 = b"\x01\x02\x03\x04" * 8
        mac2 = b"\x01\x02\x03\x04" * 8
        
        result = CryptoConstantTimeOps.verify_mac(mac1, mac2)
        assert result is True
    
    def test_verify_mac_not_equal(self):
        """Test MAC verification for non-matching tags."""
        mac1 = b"\x01\x02\x03\x04" * 8
        mac2 = b"\xff\xee\xdd\xcc" * 8
        
        result = CryptoConstantTimeOps.verify_mac(mac1, mac2)
        assert result is False
    
    def test_verify_signature(self):
        """Test signature verification."""
        sig_a = b"signature_bytes_here"
        sig_b = b"signature_bytes_here"
        sig_c = b"different_signature"
        
        assert CryptoConstantTimeOps.verify_signature(sig_a, sig_b) is True
        assert CryptoConstantTimeOps.verify_signature(sig_a, sig_c) is False
    
    def test_compare_keys_equal(self):
        """Test key comparison for equal keys."""
        ct_ops = CryptoConstantTimeOps()
        key_a = b"x" * 32
        key_b = b"x" * 32
        
        assert ct_ops.compare_keys(key_a, key_b) is True
    
    def test_compare_keys_length_mismatch(self):
        """Test key comparison detects length mismatch."""
        ct_ops = CryptoConstantTimeOps()
        key_a = b"x" * 16
        key_b = b"x" * 32
        
        assert ct_ops.compare_keys(key_a, key_b) is False
    
    def test_compare_keys_not_equal(self):
        """Test key comparison for different keys."""
        ct_ops = CryptoConstantTimeOps()
        key_a = b"a" * 32
        key_b = b"b" * 32
        
        assert ct_ops.compare_keys(key_a, key_b) is False
    
    def test_compare_hashes(self):
        """Test hash comparison."""
        ct_ops = CryptoConstantTimeOps()
        hash1 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        hash2 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        hash3 = "ffffffffffffffffffffffffffffffff"
        
        assert ct_ops.compare_hashes(hash1, hash2) is True
        assert ct_ops.compare_hashes(hash1, hash3) is False
    
    def test_constant_time_select(self):
        """Test constant-time conditional selection."""
        ct_ops = CryptoConstantTimeOps()
        a = b"\x01\x02\x03\x04"
        b = b"\xff\xee\xdd\xcc"
        
        result_true = ct_ops.constant_time_select(True, a, b)
        result_false = ct_ops.constant_time_select(False, a, b)
        
        assert result_true == a
        assert result_false == b
    
    def test_constant_time_verify_convenience(self):
        """Test convenience verification function."""
        assert constant_time_verify(b"test", b"test") is True
        assert constant_time_verify(b"test", b"fail") is False


class TestCryptoInputValidation:
    """Tests for cryptographic input validation."""
    
    def test_validator_initialization(self):
        """Test crypto validator initializes."""
        validator = CryptoInputValidator()
        assert validator is not None
    
    def test_validate_aes_key_size(self):
        """Test AES-256 key size validation."""
        validator = CryptoInputValidator()
        key_256 = b"x" * 32  # 256 bits
        
        result = validator.validate_key_size(key_256, 'AES-256')
        assert result.is_valid is True
    
    def test_validate_aes_key_size_wrong(self):
        """Test wrong AES key size is rejected."""
        validator = CryptoInputValidator()
        wrong_key = b"x" * 16  # 128 bits for AES-256 (wrong!)
        
        result = validator.validate_key_size(wrong_key, 'AES-256')
        assert result.is_valid is False
        assert '256' in result.error_message
    
    def test_validate_rsa_minimum_size(self):
        """Test RSA minimum key size enforcement."""
        validator = CryptoInputValidator()
        small_key = b"x" * 128  # 1024 bits (too small!)
        
        result = validator.validate_key_size(small_key, 'RSA')
        assert result.is_valid is False
        assert 'too small' in result.error_message.lower()
    
    def test_validate_nonce_length(self):
        """Test nonce/IV length validation."""
        validator = CryptoInputValidator()
        good_nonce = b"x" * 12
        bad_nonce = b"x" * 8
        
        assert validator.validate_nonce(good_nonce, 12).is_valid is True
        assert validator.validate_nonce(bad_nonce, 12).is_valid is False
    
    def test_validate_plaintext_length(self):
        """Test plaintext length bounds."""
        validator = CryptoInputValidator()
        small_data = b"Hello, World!"
        huge_data = b"x" * 100_000_000  # 100MB
        
        assert validator.validate_plaintext_length(small_data).is_valid is True
        assert validator.validate_plaintext_length(huge_data).is_valid is False
    
    def test_validate_algorithm_allowed(self):
        """Test algorithm whitelist validation."""
        validator = CryptoInputValidator()
        allowed = ['AES-256', 'RSA-4096', 'ECDSA-P256']
        
        assert validator.validate_algorithm_name('AES-256', allowed).is_valid is True
        assert validator.validate_algorithm_name('BROKEN-CIPHER', allowed).is_valid is False
    
    def test_validate_all_encryption_params(self):
        """Test complete encryption parameter validation."""
        validator = CryptoInputValidator()
        key = b"x" * 32  # AES-256
        nonce = b"x" * 12  # GCM standard
        plaintext = b"Secret message"
        
        result = validator.validate_all_encryption_params(key, nonce, plaintext, 'AES-256')
        assert result.is_valid is True
        assert result.validation_type == "complete_encryption"
    
    def test_validation_stats(self):
        """Test validation statistics."""
        validator = CryptoInputValidator()
        validator.validate_key_size(b"x" * 32, 'AES-256')
        validator.validate_key_size(b"x" * 32, 'AES-256')
        
        stats = validator.get_validation_stats()
        assert stats['total_validations'] == 2
        assert stats['total_rejections'] == 0
    
    def test_validate_crypto_input_decorator(self):
        """Test validation decorator."""
        @validate_crypto_input()
        def encrypt_func(key: bytes, nonce: bytes, plaintext: bytes):
            return b"encrypted"
        
        # Valid params
        key = b"x" * 32
        nonce = b"x" * 12
        result = encrypt_func(key, nonce, b"test")
        assert result == b"encrypted"


class TestCryptoOperationRateLimiting:
    """Tests for cryptographic operation rate limiting."""
    
    def test_rate_limiter_initialization(self):
        """Test crypto rate limiter initializes."""
        limiter = CryptoOperationRateLimiter(max_cost_per_minute=100)
        assert limiter.max_cost == 100
    
    def test_check_operation_allowed(self):
        """Test operations under limit are allowed."""
        limiter = CryptoOperationRateLimiter(max_cost_per_minute=1000)  # Higher limit
        
        # Cheap operations should be allowed
        for _ in range(5):
            assert limiter.check_operation('encrypt_symmetric', 'client1') is True
    
    def test_expensive_operations_limited(self):
        """Test expensive operations are properly rate limited."""
        limiter = CryptoOperationRateLimiter(max_cost_per_minute=10)
        # key_gen_pq costs 2 per operation
        
        # 5 operations = 10 cost
        for _ in range(5):
            assert limiter.check_operation('key_gen_pq', 'client2') is True
        
        # 6th should exceed limit
        assert limiter.check_operation('key_gen_pq', 'client2') is False
    
    def test_remaining_capacity(self):
        """Test remaining capacity calculation."""
        limiter = CryptoOperationRateLimiter(max_cost_per_minute=100)
        limiter.check_operation('key_gen_rsa', 'client3')  # cost = 5
        
        remaining = limiter.get_remaining_capacity('client3')
        assert remaining == 95
    
    def test_different_clients_independent(self):
        """Test different clients have independent limits."""
        limiter = CryptoOperationRateLimiter(max_cost_per_minute=10)
        
        # Client A uses all capacity
        for _ in range(5):
            limiter.check_operation('key_gen_pq', 'clientA')
        
        # Client B should still have capacity
        assert limiter.get_remaining_capacity('clientB') == 10
        assert limiter.check_operation('key_gen_pq', 'clientB') is True
    
    def test_rate_limited_decorator(self):
        """Test rate limiting decorator for crypto functions."""
        @rate_limited_crypto()
        def generate_key(operation_type: str = 'key_gen_rsa', client_id: str = 'test'):
            return "key_generated"
        
        result = generate_key(operation_type='key_gen_rsa', client_id='test_user')
        assert result == "key_generated"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
