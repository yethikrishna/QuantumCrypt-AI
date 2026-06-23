"""
Test Suite: QuantumCrypt Error Resilience v21
DIMENSION E - Error Resilience
June 2026

Tests for crypto-specific exception hierarchy, retry, backoff,
timeout, circuit breaker, bulkhead, algorithm downgrade fallbacks,
and constant-time security helpers.

All tests must pass - no existing code modifications.
"""

import pytest
import time
import secrets

# Import the new module
from quantum_crypt.crypto_error_resilience_comprehensive_exception_hierarchy_v21_2026_june import (
    # Enums
    CryptoExceptionSeverity,
    CryptoExceptionCategory,
    CryptoBackoffStrategy,
    
    # Exceptions
    QuantumCryptBaseError,
    QuantumCryptTransientError,
    QuantumCryptTimeoutError,
    QuantumCryptNetworkError,
    QuantumCryptKeyError,
    QuantumCryptKeyNotFoundError,
    QuantumCryptKeyExpiredError,
    QuantumCryptKeyRotationRequiredError,
    QuantumCryptOperationError,
    QuantumCryptDecryptionError,
    QuantumCryptSignatureVerificationError,
    QuantumCryptRandomnessError,
    QuantumCryptValidationError,
    QuantumCryptAlgorithmNotSupportedError,
    QuantumCryptCertificateError,
    QuantumCryptCertificateExpiredError,
    QuantumCryptCertificateRevokedError,
    QuantumCryptHardwareSecurityError,
    
    # Constant-time helpers
    constant_time_compare,
    constant_time_equals,
    secure_wipe,
    
    # Retry
    CryptoRetryConfig,
    CryptoRetryManager,
    crypto_retry,
    
    # Timeout
    CryptoTimeoutManager,
    crypto_timeout,
    
    # Circuit Breaker
    CryptoCircuitBreakerConfig,
    CryptoCircuitBreaker,
    get_crypto_circuit_breaker,
    
    # Fallback
    CryptoFallbackResult,
    crypto_algorithm_fallback,
    
    # Bulkhead
    CryptoBulkhead,
    get_crypto_bulkhead,
)


# ============================================================================
# CONSTANT-TIME SECURITY TESTS (CRITICAL)
# ============================================================================

class TestConstantTimeSecurity:
    """Test constant-time security critical functions."""
    
    def test_constant_time_compare_equal(self):
        """Equal byte strings compare equal."""
        a = b"hello world"
        b = b"hello world"
        assert constant_time_compare(a, b) is True
        
    def test_constant_time_compare_not_equal(self):
        """Different byte strings compare not equal."""
        a = b"hello world"
        b = b"hello worlx"
        assert constant_time_compare(a, b) is False
        
    def test_constant_time_compare_length_mismatch(self):
        """Different length strings always fail."""
        a = b"short"
        b = b"longer string"
        assert constant_time_compare(a, b) is False
        
    def test_constant_time_equals_strings(self):
        """String comparison works."""
        assert constant_time_equals("test", "test") is True
        assert constant_time_equals("test", "tesx") is False
        
    def test_secure_wipe(self):
        """Secure wipe overwrites bytearray."""
        data = bytearray(b"sensitive key material 12345")
        original = bytes(data)
        
        secure_wipe(data)
        
        # Data should be all zeros now
        assert all(b == 0 for b in data)
        assert bytes(data) != original


# ============================================================================
# CRYPTO EXCEPTION HIERARCHY TESTS
# ============================================================================

class TestCryptoExceptionHierarchy:
    """Test crypto-specific exception hierarchy."""
    
    def test_base_exception_security_safe(self):
        """Base exceptions mark themselves safe for logging."""
        err = QuantumCryptBaseError("Test error")
        assert err.safe_for_logging is True
        d = err.to_dict()
        assert "safe_for_logging" in d
        
    def test_transient_crypto_errors_retry_eligible(self):
        """Transient crypto errors are retry-eligible."""
        assert QuantumCryptTransientError("Test").retry_eligible is True
        assert QuantumCryptTimeoutError("Test").retry_eligible is True
        assert QuantumCryptNetworkError("Test").retry_eligible is True
        
    def test_key_errors_not_retry_eligible(self):
        """Key management errors are NOT retry-eligible."""
        assert QuantumCryptKeyError("Test").retry_eligible is False
        assert QuantumCryptKeyNotFoundError("Test").retry_eligible is False
        
    def test_key_rotation_retry_eligible(self):
        """Key rotation warning IS retry-eligible."""
        assert QuantumCryptKeyRotationRequiredError("Test").retry_eligible is True
        
    def test_crypto_operation_errors_severe(self):
        """Crypto failures are ERROR severity."""
        assert QuantumCryptOperationError("Test").severity == CryptoExceptionSeverity.ERROR
        
    def test_randomness_errors_critical(self):
        """Randomness failures are CRITICAL (security issue)."""
        assert QuantumCryptRandomnessError("Test").severity == CryptoExceptionSeverity.CRITICAL
        
    def test_certificate_revoked_critical(self):
        """Revoked certificates are CRITICAL."""
        assert QuantumCryptCertificateRevokedError("Test").severity == CryptoExceptionSeverity.CRITICAL
        
    def test_key_id_hashed_for_security(self):
        """Key IDs are hashed, not logged directly."""
        err = QuantumCryptKeyNotFoundError("Missing", key_id="secret-key-12345")
        assert "key_id_hash" in err.details
        # Hash is numeric, not the raw key ID
        assert isinstance(err.details["key_id_hash"], int)


# ============================================================================
# CRYPTO RETRY TESTS
# ============================================================================

class TestCryptoRetry:
    """Test crypto-optimized retry logic."""
    
    def test_crypto_backoff_faster_default(self):
        """Crypto retry uses faster default delays."""
        config = CryptoRetryConfig()
        # Crypto uses 0.1s initial delay vs 1.0s general
        assert config.initial_delay == 0.1
        assert config.max_delay == 5.0
        
    def test_crypto_retry_only_transient(self):
        """Crypto retry ONLY retries transient errors."""
        manager = CryptoRetryManager()
        
        # Transient errors should retry
        assert manager.should_retry(QuantumCryptTransientError("Temp")) is True
        
        # Security errors should NEVER retry
        assert manager.should_retry(QuantumCryptOperationError("Security")) is False
        assert manager.should_retry(QuantumCryptDecryptionError("MAC fail")) is False
        
    def test_crypto_retry_decorator(self):
        """@crypto_retry decorator works."""
        call_count = 0
        
        @crypto_retry(max_attempts=5)
        def flaky_crypto_op():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise QuantumCryptTransientError("HSM busy")
            return "signature_ok"
            
        result = flaky_crypto_op()
        assert result == "signature_ok"
        assert call_count == 3


# ============================================================================
# CRYPTO TIMEOUT TESTS
# ============================================================================

class TestCryptoTimeout:
    """Test crypto timeout wrappers."""
    
    def test_crypto_timeout_completes(self):
        """Fast crypto ops complete normally."""
        manager = CryptoTimeoutManager(5.0)
        result = manager.execute(lambda: "hash_ok")
        assert result == "hash_ok"
        
    def test_crypto_timeout_decorator(self):
        """@crypto_timeout decorator works."""
        @crypto_timeout(seconds=1.0)
        def fast_hash():
            return "sha256_ok"
            
        assert fast_hash() == "sha256_ok"


# ============================================================================
# CRYPTO CIRCUIT BREAKER TESTS
# ============================================================================

class TestCryptoCircuitBreaker:
    """Test HSM/TPM protection circuit breaker."""
    
    def test_crypto_circuit_breaker_higher_threshold(self):
        """Crypto circuit breaker has higher default threshold."""
        config = CryptoCircuitBreakerConfig()
        assert config.failure_threshold == 10  # Higher for HSM protection
        
    def test_crypto_circuit_breaker_protects_hsm(self):
        """Circuit breaker prevents HSM DoS."""
        cb = CryptoCircuitBreaker(CryptoCircuitBreakerConfig(
            failure_threshold=3,
            reset_timeout=0.01
        ))
        
        # Simulate HSM failures
        cb.on_failure()
        cb.on_failure()
        cb.on_failure()
        
        assert cb.allow_call() is False
        
    def test_named_crypto_circuit_breaker(self):
        """Named circuit breakers are singletons."""
        cb1 = get_crypto_circuit_breaker("hsm_main")
        cb2 = get_crypto_circuit_breaker("hsm_main")
        assert cb1 is cb2


# ============================================================================
# ALGORITHM DOWNGRADE FALLBACK TESTS
# ============================================================================

class TestAlgorithmDowngrade:
    """Test graceful algorithm downgrade fallbacks."""
    
    def test_crypto_fallback_algorithm_downgrade(self):
        """Fallback to classic crypto when PQ fails."""
        def classic_rsa(*args, **kwargs):
            return "rsa_2048_signature"
            
        @crypto_algorithm_fallback(fallback_algorithm=classic_rsa)
        def post_quantum_crystals(should_fail=False):
            if should_fail:
                raise QuantumCryptTimeoutError("PQ too slow")
            return "crystals_kyber_768"
            
        # Happy path - PQ works
        assert post_quantum_crystals(False) == "crystals_kyber_768"
        
        # Failure path - graceful downgrade
        result = post_quantum_crystals(True)
        assert isinstance(result, CryptoFallbackResult)
        assert result.value == "rsa_2048_signature"
        assert result.algorithm_downgraded is True
        assert result.original_algorithm == "post_quantum_crystals"
        assert result.fallback_algorithm == "classic_rsa"


# ============================================================================
# CRYPTO BULKHEAD TESTS
# ============================================================================

class TestCryptoBulkhead:
    """Test HSM resource isolation bulkhead."""
    
    def test_crypto_bulkhead_lower_concurrency(self):
        """Crypto bulkhead has lower default concurrency."""
        bh = CryptoBulkhead()
        assert bh.max_concurrent == 5  # Lower for HSM protection
        
    def test_crypto_bulkhead_executes(self):
        """Bulkhead allows normal execution."""
        bh = CryptoBulkhead(max_concurrent=2)
        result = bh.execute(lambda: "aes_gcm_ok")
        assert result == "aes_gcm_ok"
        
    def test_named_crypto_bulkhead(self):
        """Named bulkheads are singletons."""
        bh1 = get_crypto_bulkhead("tpm_0", max_concurrent=3)
        bh2 = get_crypto_bulkhead("tpm_0")
        assert bh1 is bh2


# ============================================================================
# HAPPY PATH PRESERVATION TEST (CRITICAL)
# ============================================================================

def test_crypto_happy_path_100_percent_preserved():
    """
    CRITICAL VERIFICATION:
    Happy path behavior 100% preserved - no modifications to existing flow.
    
    All resilience features are purely additive wrappers.
    """
    # Pure crypto function (simulated)
    def pure_aes_encrypt(plaintext, key):
        return f"encrypted_{plaintext}_{key}"
        
    # Same function with full resilience wrapping
    @crypto_retry()
    @crypto_timeout(seconds=10.0)
    def wrapped_aes_encrypt(plaintext, key):
        return f"encrypted_{plaintext}_{key}"
        
    # Results are IDENTICAL
    test_cases = [
        ("hello", "key123"),
        ("secret", "key456"),
        ("data", "key789"),
    ]
    
    for plaintext, key in test_cases:
        pure = pure_aes_encrypt(plaintext, key)
        wrapped = wrapped_aes_encrypt(plaintext, key)
        assert pure == wrapped, "Happy path must be identical"


def test_crypto_exception_categories_complete():
    """All crypto exception categories are defined."""
    categories = [
        CryptoExceptionCategory.TRANSIENT,
        CryptoExceptionCategory.KEY_MANAGEMENT,
        CryptoExceptionCategory.CRYPTOGRAPHIC,
        CryptoExceptionCategory.VALIDATION,
        CryptoExceptionCategory.RANDOMNESS,
        CryptoExceptionCategory.TIMEOUT,
        CryptoExceptionCategory.RESOURCE,
        CryptoExceptionCategory.NETWORK,
        CryptoExceptionCategory.INTEGRITY,
        CryptoExceptionCategory.CERTIFICATE,
        CryptoExceptionCategory.COMPATIBILITY,
        CryptoExceptionCategory.HARDWARE,
        CryptoExceptionCategory.SIDE_CHANNEL,
        CryptoExceptionCategory.UNKNOWN,
    ]
    
    for cat in categories:
        assert cat.value is not None
        assert cat.name is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
