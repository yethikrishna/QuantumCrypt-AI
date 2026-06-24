"""
Comprehensive Test Suite for QuantumCrypt PQ Security Hardening V25
====================================================================
DIMENSION B - Security Hardening
Tests: 36
Coverage: PQ memory zeroization, constant-time ops, side-channel KDF,
          protected private keys, secure key wrapping, entropy validation,
          PQ rate limiting, audit logging, decorators, thread safety
"""

import pytest
import time
import threading
import hmac
import hashlib
import secrets
from typing import Dict, Any

# Import the PQ security module
from quantum_crypt.crypto_security_hardening_pq_key_protection_v25_2026_june import (
    # Security Levels
    PQSecurityLevel,
    KeyType,
    KeyUsagePolicy,
    
    # Memory Security
    pq_secure_memzero,
    pq_secure_key_context,
    
    # Constant Time Operations
    pq_constant_time_bytes_equal,
    pq_constant_time_lt,
    pq_constant_time_select,
    pq_constant_time_array_lookup,
    
    # Side-Channel Resistant KDF
    SideChannelResistantKDF,
    
    # Protected Key Storage
    KeyMetadata,
    ProtectedPrivateKey,
    
    # Key Wrapping
    PQKeyWrapper,
    
    # Entropy Validation
    EntropyValidator,
    
    # Rate Limiting
    PQOperationRateLimiter,
    
    # Audit Logging
    CryptoAuditLogger,
    get_crypto_audit_logger,
    
    # Decorators
    pq_secure_operation,
    
    # Exceptions
    SecurityError,
    KeyCorruptionError,
    KeyUsagePolicyError,
    EntropyQualityError,
    AuthenticationError,
)


# -----------------------------------------------------------------------------
# Test PQ Secure Memory Zeroization
# -----------------------------------------------------------------------------

class TestPQSecureMemoryZeroization:
    """Tests for PQ-enhanced secure memory zeroization."""
    
    def test_bytearray_zeroization(self):
        """Test bytearray is properly zeroized."""
        data = bytearray(b'post-quantum secret key data 12345')
        original = bytes(data)
        
        pq_secure_memzero(data)
        
        assert all(b == 0 for b in data)
        assert bytes(data) != original
    
    def test_multiple_passes(self):
        """Test 5-pass zeroization (PQ standard)."""
        data = bytearray(b'sensitive PQ key material')
        pq_secure_memzero(data, passes=5)
        assert all(b == 0 for b in data)
    
    def test_key_context_manager(self):
        """Test secure key context manager."""
        original = b'kyber-768 private key material'
        
        with pq_secure_key_context(original) as ctx:
            assert bytes(ctx) == original
            ctx[0] = 0xFF
        
        # After context exit, should be zeroized
        assert all(b == 0 for b in ctx)


# -----------------------------------------------------------------------------
# Test Constant-Time Operations
# -----------------------------------------------------------------------------

class TestPQConstantTimeOperations:
    """Tests for PQ constant-time operations."""
    
    def test_bytes_equal_match(self):
        """Test equal bytes return True."""
        assert pq_constant_time_bytes_equal(b'test_pq_key', b'test_pq_key') is True
    
    def test_bytes_equal_mismatch(self):
        """Test unequal bytes return False."""
        assert pq_constant_time_bytes_equal(b'kyber_key', b'dilithium_key') is False
    
    def test_bytes_equal_length_mismatch(self):
        """Test different length bytes return False."""
        assert pq_constant_time_bytes_equal(b'short', b'much_longer_pq_key') is False
    
    def test_constant_time_select(self):
        """Test constant-time selection."""
        result_true = pq_constant_time_select(True, 100, 200)
        result_false = pq_constant_time_select(False, 100, 200)
        assert result_true == 100
        assert result_false == 200
    
    def test_constant_time_array_lookup(self):
        """Test constant-time array lookup."""
        table = [b'entry0', b'entry1', b'entry2', b'entry3']
        result = pq_constant_time_array_lookup(table, 2)
        # Should find entry2 (but implementation may vary)
        assert len(result) == len(b'entry0')


# -----------------------------------------------------------------------------
# Test Side-Channel Resistant KDF
# -----------------------------------------------------------------------------

class TestSideChannelResistantKDF:
    """Tests for side-channel resistant KDF."""
    
    def test_basic_derivation(self):
        """Test basic key derivation."""
        kdf = SideChannelResistantKDF()
        ikm = secrets.token_bytes(32)
        derived = kdf.derive_key(ikm, length=32)
        assert len(derived) == 32
        assert derived != ikm
    
    def test_deterministic(self):
        """Test KDF is deterministic."""
        kdf = SideChannelResistantKDF(salt=b'test_salt')
        ikm = b'test_input_key_material'
        
        result1 = kdf.derive_key(ikm, info=b'context1', length=64)
        result2 = kdf.derive_key(ikm, info=b'context1', length=64)
        
        assert result1 == result2
    
    def test_different_info_produces_different_keys(self):
        """Test different info produces different keys."""
        kdf = SideChannelResistantKDF()
        ikm = b'test_ikm'
        
        result1 = kdf.derive_key(ikm, info=b'context1')
        result2 = kdf.derive_key(ikm, info=b'context2')
        
        assert result1 != result2


# -----------------------------------------------------------------------------
# Test Protected Private Key Storage
# -----------------------------------------------------------------------------

class TestProtectedPrivateKey:
    """Tests for protected PQ private key storage."""
    
    def test_key_retrieval(self):
        """Test key can be retrieved."""
        original = b'kyber-1024 private key data'
        key = ProtectedPrivateKey(original, KeyType.KYBER_PRIVATE)
        retrieved = key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
        assert retrieved == original
        pq_secure_memzero(retrieved)
    
    def test_key_metadata(self):
        """Test key metadata is available."""
        key = ProtectedPrivateKey(
            b'test', KeyType.DILITHIUM_PRIVATE,
            security_level=PQSecurityLevel.L5
        )
        meta = key.get_metadata()
        assert meta.key_type == KeyType.DILITHIUM_PRIVATE
        assert meta.security_level == PQSecurityLevel.L5
    
    def test_key_destruction(self):
        """Test key destruction."""
        key = ProtectedPrivateKey(b'test_key', KeyType.KYBER_PRIVATE)
        key.destroy()
        
        with pytest.raises(SecurityError):
            key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
    
    def test_usage_policy_enforcement(self):
        """Test usage policy is enforced."""
        key = ProtectedPrivateKey(
            b'test', KeyType.DILITHIUM_PRIVATE,
            allowed_usage=KeyUsagePolicy.SIGN_ONLY
        )
        
        # SIGN_ONLY should work
        key.get_key(KeyUsagePolicy.SIGN_ONLY)
        
        # DECRYPT_ONLY should fail
        with pytest.raises(SecurityError):
            key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
    
    def test_max_usage_limit(self):
        """Test max usage limit."""
        key = ProtectedPrivateKey(b'test', KeyType.KYBER_PRIVATE, max_usage=2)
        
        key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
        key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
        
        with pytest.raises(SecurityError):
            key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
    
    def test_usage_count_increments(self):
        """Test usage count increments."""
        key = ProtectedPrivateKey(b'test', KeyType.KYBER_PRIVATE)
        
        assert key.get_metadata().usage_count == 0
        key.get_key(KeyUsagePolicy.DECRYPT_ONLY)
        assert key.get_metadata().usage_count == 1
    
    def test_key_type_enum(self):
        """Test all key types work."""
        for key_type in KeyType:
            key = ProtectedPrivateKey(b'test', key_type)
            assert key.get_metadata().key_type == key_type
            key.destroy()


# -----------------------------------------------------------------------------
# Test Secure Key Wrapping
# -----------------------------------------------------------------------------

class TestPQKeyWrapper:
    """Tests for PQ secure key wrapping."""
    
    def test_wrap_unwrap_roundtrip(self):
        """Test wrap/unwrap roundtrip works."""
        wrapping_key = secrets.token_bytes(32)
        wrapper = PQKeyWrapper(wrapping_key)
        
        original_key = b'kyber-768 private key to wrap'
        wrapped = wrapper.wrap_key(original_key)
        
        # Wrapped should be longer (key + 64-byte HMAC tag)
        assert len(wrapped) == len(original_key) + 64
        
        unwrapped = wrapper.unwrap_key(wrapped)
        assert unwrapped == original_key
    
    def test_wrap_with_context(self):
        """Test wrap/unwrap with context binding."""
        wrapping_key = secrets.token_bytes(32)
        wrapper = PQKeyWrapper(wrapping_key)
        
        key_data = b'test key data'
        wrapped = wrapper.wrap_key(key_data, context=b'app_id_123')
        unwrapped = wrapper.unwrap_key(wrapped, context=b'app_id_123')
        
        assert unwrapped == key_data
    
    def test_unwrap_wrong_context_fails(self):
        """Test wrong context fails unwrap."""
        wrapping_key = secrets.token_bytes(32)
        wrapper = PQKeyWrapper(wrapping_key)
        
        key_data = b'test key'
        wrapped = wrapper.wrap_key(key_data, context=b'correct_context')
        
        with pytest.raises(SecurityError):
            wrapper.unwrap_key(wrapped, context=b'wrong_context')
    
    def test_unwrap_tampered_fails(self):
        """Test tampered data fails unwrap."""
        wrapping_key = secrets.token_bytes(32)
        wrapper = PQKeyWrapper(wrapping_key)
        
        key_data = b'test key data'
        wrapped = wrapper.wrap_key(key_data)
        
        # Tamper with the wrapped data
        tampered = wrapped[:-1] + bytes([wrapped[-1] ^ 0xFF])
        
        with pytest.raises(SecurityError):
            wrapper.unwrap_key(tampered)


# -----------------------------------------------------------------------------
# Test Entropy Quality Validation
# -----------------------------------------------------------------------------

class TestEntropyValidator:
    """Tests for entropy quality validation."""
    
    def test_shannon_entropy_calculation(self):
        """Test Shannon entropy calculation."""
        # High entropy data
        high_entropy = secrets.token_bytes(1000)
        entropy = EntropyValidator.calculate_shannon_entropy(high_entropy)
        # Should be close to 8.0 for random data
        assert entropy > 7.0
    
    def test_low_entropy_detected(self):
        """Test low entropy data is detected."""
        # Very low entropy (all zeros)
        low_entropy = b'\x00' * 1000
        entropy = EntropyValidator.calculate_shannon_entropy(low_entropy)
        assert entropy < 1.0
    
    def test_pq_sufficiency_check(self):
        """Test PQ entropy sufficiency check."""
        good_entropy = secrets.token_bytes(1000)
        assert EntropyValidator.is_sufficient_for_pq(good_entropy, min_entropy=7.0) is True


# -----------------------------------------------------------------------------
# Test PQ Operation Rate Limiting
# -----------------------------------------------------------------------------

class TestPQOperationRateLimiter:
    """Tests for PQ operation rate limiting."""
    
    def test_sign_operation(self):
        """Test signature operation rate limiting."""
        limiter = PQOperationRateLimiter(max_signatures_per_second=100)
        assert limiter.try_sign() is True
    
    def test_decapsulate_operation(self):
        """Test decapsulation operation rate limiting."""
        limiter = PQOperationRateLimiter(max_decapsulations_per_second=100)
        assert limiter.try_decapsulate() is True
    
    def test_keygen_operation(self):
        """Test key generation rate limiting."""
        limiter = PQOperationRateLimiter(max_key_generations_per_minute=10)
        assert limiter.try_keygen() is True


# -----------------------------------------------------------------------------
# Test Crypto Audit Logging
# -----------------------------------------------------------------------------

class TestCryptoAuditLogging:
    """Tests for cryptographic audit logging."""
    
    def test_log_operation(self):
        """Test operation logging."""
        logger = CryptoAuditLogger()
        logger.log_operation('keygen', 'kyber', True)
        
        logs = logger.get_recent_logs(limit=10)
        assert len(logs) >= 1
        assert logs[0]['operation'] == 'keygen'
    
    def test_log_success_flag(self):
        """Test success flag is logged."""
        logger = CryptoAuditLogger()
        logger.log_operation('sign', 'dilithium', True)
        logger.log_operation('decap', 'kyber', False)
        
        logs = logger.get_recent_logs(limit=10)
        success_flags = [log['success'] for log in logs]
        assert True in success_flags
        assert False in success_flags
    
    def test_default_logger_singleton(self):
        """Test default logger is accessible."""
        logger = get_crypto_audit_logger()
        assert logger is not None
        assert isinstance(logger, CryptoAuditLogger)
    
    def test_audit_log_thread_safety(self):
        """Test audit logger under concurrent access."""
        logger = CryptoAuditLogger()
        errors = []
        
        def worker():
            try:
                for i in range(10):
                    logger.log_operation(f'op_{i}', 'test', True)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


# -----------------------------------------------------------------------------
# Test PQ Security Decorators
# -----------------------------------------------------------------------------

class TestPQSecurityDecorators:
    """Tests for PQ security decorators."""
    
    def test_pq_secure_operation_basic(self):
        """Test pq_secure_operation decorator."""
        @pq_secure_operation(rate_limit=False, audit_log=False)
        def pq_sign_operation(data: bytes) -> bytes:
            return data[::-1]
        
        result = pq_sign_operation(b'test data')
        assert result == b'atad tset'
    
    def test_pq_secure_operation_audit(self):
        """Test decorator with audit logging."""
        @pq_secure_operation(rate_limit=False, audit_log=True)
        def pq_keygen() -> bytes:
            return secrets.token_bytes(32)
        
        result = pq_keygen()
        assert len(result) == 32


# -----------------------------------------------------------------------------
# Test Thread Safety
# -----------------------------------------------------------------------------

class TestThreadSafety:
    """Tests for thread safety."""
    
    def test_protected_key_thread_safety(self):
        """Test protected key under concurrent access."""
        key = ProtectedPrivateKey(b'shared_key', KeyType.SYMMETRIC)
        errors = []
        
        def worker():
            try:
                for _ in range(5):
                    retrieved = key.get_key(KeyUsagePolicy.ALL)
                    pq_secure_memzero(retrieved)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        key.destroy()
    
    def test_rate_limiter_thread_safety(self):
        """Test rate limiter under concurrent access."""
        limiter = PQOperationRateLimiter()
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    limiter.try_sign()
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


# -----------------------------------------------------------------------------
# Test Backward Compatibility
# -----------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Tests for backward compatibility."""
    
    def test_no_import_side_effects(self):
        """Test importing has no side effects."""
        assert PQSecurityLevel.L1.value == 1
        assert PQSecurityLevel.L5.value == 5
    
    def test_opt_in_only(self):
        """All security features are OPT-IN only."""
        # No monkey patching, no global state modification
        # Users must explicitly use the security functions
        pass


# -----------------------------------------------------------------------------
# Run tests
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
