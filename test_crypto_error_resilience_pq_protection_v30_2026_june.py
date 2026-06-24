"""
Test Suite for QuantumCrypt Error Resilience Module v30
Dimension E - Error Resilience

Tests cover:
- Custom crypto exception hierarchy
- Secure memory zeroization
- Crypto circuit breaker pattern
- Smart retry for crypto operations
- Crypto timeout with secure cleanup
- Algorithm fallback graceful degradation
- Crypto bulkhead isolation
- Crypto error context with auto-zeroization

All tests verify that:
1. Happy path behavior is 100% preserved
2. Error paths are handled correctly
3. No existing code is broken
4. Security properties are maintained
"""

import pytest
import time
import threading
from datetime import datetime, timedelta

# Import the module to test
from quantum_crypt.crypto_error_resilience_pq_protection_v30_2026_june import (
    # Exceptions
    QuantumCryptError,
    CryptoOperationError,
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    SignatureError,
    HashError,
    RandomnessError,
    HSMConnectError,
    PostQuantumError,
    PQKeyExchangeError,
    PQSignatureError,
    SecurityError,
    ValidationError,
    SideChannelRiskError,
    TimeoutError,
    CircuitBreakerOpenError,
    FallbackActivatedError,
    InsecureFallbackWarning,
    
    # Secure memory
    secure_zeroize,
    SecureContext,
    
    # Circuit Breaker
    CryptoCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    get_crypto_circuit_breaker,
    
    # Retry
    CryptoRetryConfig,
    crypto_retry,
    
    # Timeout
    crypto_timeout,
    
    # Fallbacks
    with_algorithm_fallback,
    CryptoFallbackResult,
    
    # Bulkhead
    CryptoBulkhead,
    get_crypto_bulkhead,
    
    # Combined
    resilient_crypto_op,
    
    # Context
    CryptoErrorContext,
)


# -----------------------------------------------------------------------------
# TEST CRYPTO EXCEPTION HIERARCHY
# -----------------------------------------------------------------------------

class TestCryptoExceptionHierarchy:
    """Test custom crypto exception hierarchy"""
    
    def test_base_exception_creation(self):
        """Test base QuantumCryptError creation"""
        exc = QuantumCryptError("Test crypto error", "QC-TEST-001", {"key": "value"})
        assert str(exc) == "Test crypto error"
        assert exc.error_code == "QC-TEST-001"
        assert exc.details["key"] == "value"
        assert "timestamp" in exc.to_dict()
    
    def test_exception_to_dict(self):
        """Test exception serialization to dict"""
        exc = QuantumCryptError("Test", "QC-001")
        result = exc.to_dict()
        assert result["error_type"] == "QuantumCryptError"
        assert result["message"] == "Test"
        assert result["error_code"] == "QC-001"
    
    def test_crypto_operation_exception_hierarchy(self):
        """Test crypto operation exception hierarchy"""
        assert issubclass(CryptoOperationError, QuantumCryptError)
        assert issubclass(KeyGenerationError, CryptoOperationError)
        assert issubclass(EncryptionError, CryptoOperationError)
        assert issubclass(DecryptionError, CryptoOperationError)
        assert issubclass(SignatureError, CryptoOperationError)
        assert issubclass(HashError, CryptoOperationError)
    
    def test_key_generation_error_with_details(self):
        """Test KeyGenerationError with algorithm and key size"""
        exc = KeyGenerationError("Key gen failed", "CRYSTALS-Kyber", 1024)
        assert exc.details["algorithm"] == "CRYSTALS-Kyber"
        assert exc.details["key_size"] == 1024
    
    def test_post_quantum_exception_hierarchy(self):
        """Test post-quantum exception hierarchy"""
        assert issubclass(PostQuantumError, QuantumCryptError)
        assert issubclass(PQKeyExchangeError, PostQuantumError)
        assert issubclass(PQSignatureError, PostQuantumError)
    
    def test_security_exception_hierarchy(self):
        """Test security exception hierarchy"""
        assert issubclass(SecurityError, QuantumCryptError)
        assert issubclass(ValidationError, SecurityError)
        assert issubclass(SideChannelRiskError, SecurityError)
    
    def test_hsm_connect_error(self):
        """Test HSMConnectError with HSM ID"""
        exc = HSMConnectError("HSM connection failed", "hsm-prod-01")
        assert exc.details["hsm_id"] == "hsm-prod-01"
    
    def test_timeout_error(self):
        """Test TimeoutError with details"""
        exc = TimeoutError("Key gen timed out", 30.0, "key_generation")
        assert exc.details["timeout_seconds"] == 30.0
        assert exc.details["operation"] == "key_generation"


# -----------------------------------------------------------------------------
# TEST SECURE MEMORY ZEROIZATION
# -----------------------------------------------------------------------------

class TestSecureMemory:
    """Test secure memory zeroization"""
    
    def test_secure_zeroize_modifies_data(self):
        """Test secure_zeroize actually overwrites data"""
        sensitive = bytearray(b"secret_key_material_12345")
        original = bytes(sensitive)
        secure_zeroize(sensitive)
        # Should be all zeros
        assert all(b == 0 for b in sensitive)
        assert bytes(sensitive) != original
    
    def test_secure_zeroize_empty(self):
        """Test secure_zeroize handles empty bytearray"""
        empty = bytearray()
        secure_zeroize(empty)
        assert len(empty) == 0
    
    def test_secure_context_zeroizes_on_exit(self):
        """Test SecureContext zeroizes on exit"""
        sensitive = bytearray(b"my_secret_key")
        original = bytes(sensitive)
        
        with SecureContext(sensitive) as data:
            assert bytes(data) == original
        
        # Should be zeroized after context exit
        assert all(b == 0 for b in sensitive)
    
    def test_secure_context_zeroizes_on_exception(self):
        """Test SecureContext zeroizes even on exception"""
        sensitive = bytearray(b"my_secret_key")
        
        try:
            with SecureContext(sensitive):
                raise RuntimeError("Test error")
        except RuntimeError:
            pass
        
        # Should still be zeroized
        assert all(b == 0 for b in sensitive)


# -----------------------------------------------------------------------------
# TEST CRYPTO CIRCUIT BREAKER
# -----------------------------------------------------------------------------

class TestCryptoCircuitBreaker:
    """Test Crypto Circuit Breaker pattern"""
    
    def test_circuit_breaker_initial_state(self):
        """Test circuit breaker starts in CLOSED state"""
        cb = CryptoCircuitBreaker("test_hsm")
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_call() is True
    
    def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker opens after threshold failures"""
        config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout_seconds=1.0)
        cb = CryptoCircuitBreaker("test", config)
        
        @cb
        def failing_hsm_call():
            raise HSMConnectError("HSM down")
        
        for _ in range(3):
            try:
                failing_hsm_call()
            except HSMConnectError:
                pass
        
        assert cb.state == CircuitState.OPEN
        assert cb.allow_call() is False
    
    def test_circuit_breaker_rejects_when_open(self):
        """Test circuit breaker raises when open"""
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=10.0)
        cb = CryptoCircuitBreaker("test", config)
        
        @cb
        def failing():
            raise HSMConnectError("Fail")
        
        for _ in range(2):
            try:
                failing()
            except HSMConnectError:
                pass
        
        with pytest.raises(CircuitBreakerOpenError):
            failing()
    
    def test_circuit_breaker_transitions_to_half_open(self):
        """Test circuit breaker transitions after recovery timeout"""
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=0.1)
        cb = CryptoCircuitBreaker("test", config)
        
        @cb
        def failing():
            raise HSMConnectError("Fail")
        
        for _ in range(2):
            try:
                failing()
            except HSMConnectError:
                pass
        
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_circuit_breaker_stats(self):
        """Test circuit breaker stats tracking"""
        cb = CryptoCircuitBreaker("test")
        stats = cb.stats
        assert stats.success_count == 0
        assert stats.failure_count == 0
        assert stats.rejected_count == 0
    
    def test_get_circuit_breaker_singleton(self):
        """Test get_crypto_circuit_breaker returns same instance"""
        cb1 = get_crypto_circuit_breaker("test_singleton")
        cb2 = get_crypto_circuit_breaker("test_singleton")
        assert cb1 is cb2
    
    def test_circuit_breaker_excluded_exceptions(self):
        """Test excluded exceptions don't count as failures"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            excluded_exceptions=(ValueError,)
        )
        cb = CryptoCircuitBreaker("test", config)
        
        cb._on_failure(ValueError("test"))
        cb._on_failure(ValueError("test"))
        
        assert cb.stats.failure_count == 0
        assert cb.state == CircuitState.CLOSED


# -----------------------------------------------------------------------------
# TEST CRYPTO RETRY
# -----------------------------------------------------------------------------

class TestCryptoRetry:
    """Test smart crypto retry"""
    
    def test_retry_succeeds_on_second_attempt(self):
        """Test retry succeeds on second attempt"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def flaky_hsm_call():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectError("Temporary HSM issue")
            return "success"
        
        result = flaky_hsm_call()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_retry_eventually_fails(self):
        """Test retry eventually fails"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def always_fails():
            call_count[0] += 1
            raise HSMConnectError("Always fails")
        
        with pytest.raises(HSMConnectError):
            always_fails()
        
        assert call_count[0] == 3
    
    def test_retry_never_retries_security_errors(self):
        """Test security errors are NEVER retried"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def raises_security_error():
            call_count[0] += 1
            raise ValidationError("Invalid input")
        
        with pytest.raises(ValidationError):
            raises_security_error()
        
        # Should only be called once - security errors are never retried
        assert call_count[0] == 1
    
    def test_retry_only_transient_errors(self):
        """Test only transient errors are retried"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def raises_timeout():
            call_count[0] += 1
            if call_count[0] < 2:
                raise TimeoutError("Timeout")
            return "ok"
        
        result = raises_timeout()
        assert result == "ok"
        assert call_count[0] == 2  # Timeout should be retried


# -----------------------------------------------------------------------------
# TEST CRYPTO TIMEOUT
# -----------------------------------------------------------------------------

class TestCryptoTimeout:
    """Test crypto timeout with cleanup"""
    
    def test_timeout_completes_normally(self):
        """Test function completes within timeout"""
        @crypto_timeout(seconds=1.0)
        def quick_encrypt():
            return "encrypted_data"
        
        result = quick_encrypt()
        assert result == "encrypted_data"
    
    def test_timeout_raises_exception(self):
        """Test timeout raises on slow function"""
        @crypto_timeout(seconds=0.1)
        def slow_key_gen():
            time.sleep(0.5)
            return "key"
        
        with pytest.raises(TimeoutError):
            slow_key_gen()
    
    def test_timeout_with_fallback(self):
        """Test timeout activates fallback"""
        fallback_called = [False]
        
        def fallback():
            fallback_called[0] = True
            return "fallback_result"
        
        @crypto_timeout(seconds=0.1, fallback=fallback)
        def slow():
            time.sleep(0.5)
            return "done"
        
        result = slow()
        assert fallback_called[0] is True
        assert result == "fallback_result"
    
    def test_timeout_with_cleanup(self):
        """Test timeout runs cleanup function"""
        cleanup_called = [False]
        
        def cleanup():
            cleanup_called[0] = True
        
        @crypto_timeout(seconds=0.1, secure_cleanup=cleanup)
        def slow():
            time.sleep(0.5)
            return "done"
        
        try:
            slow()
        except TimeoutError:
            pass
        
        assert cleanup_called[0] is True


# -----------------------------------------------------------------------------
# TEST ALGORITHM FALLBACKS
# -----------------------------------------------------------------------------

class TestAlgorithmFallbacks:
    """Test graceful algorithm degradation"""
    
    def test_primary_succeeds_no_fallback(self):
        """Test primary succeeds - no fallback activated"""
        def fallback():
            return "fallback"
        
        @with_algorithm_fallback(fallback, "Kyber", "RSA")
        def primary():
            return "primary_result"
        
        result = primary()
        assert result.value == "primary_result"
        assert result.was_fallback is False
        assert result.is_quantum_safe is True
    
    def test_fallback_activates_on_error(self):
        """Test fallback activates on primary failure"""
        def fallback():
            return "fallback_result"
        
        @with_algorithm_fallback(fallback, "Kyber", "RSA")
        def failing():
            raise RuntimeError("PQ algorithm failed")
        
        result = failing()
        assert result.value == "fallback_result"
        assert result.was_fallback is True
        assert result.primary_algorithm == "Kyber"
        assert result.fallback_algorithm == "RSA"
        assert result.primary_error is not None
    
    def test_insecure_fallback_warning(self):
        """Test insecure fallback is flagged"""
        def fallback():
            return "non_pq_result"
        
        @with_algorithm_fallback(fallback, "Kyber", "RSA", fallback_is_quantum_safe=False)
        def failing():
            raise RuntimeError("PQ failed")
        
        result = failing()
        assert result.is_quantum_safe is False


# -----------------------------------------------------------------------------
# TEST CRYPTO BULKHEAD
# -----------------------------------------------------------------------------

class TestCryptoBulkhead:
    """Test Crypto Bulkhead isolation"""
    
    def test_bulkhead_allows_call_within_limit(self):
        """Test bulkhead allows calls within limit"""
        bulkhead = CryptoBulkhead("key_gen", max_concurrent=5)
        
        @bulkhead
        def generate_key():
            return "key_material"
        
        result = generate_key()
        assert result == "key_material"
    
    def test_bulkhead_stats(self):
        """Test bulkhead stats tracking"""
        bulkhead = CryptoBulkhead("test", max_concurrent=5)
        stats = bulkhead.stats
        assert stats["max_concurrent"] == 5
        assert stats["active"] == 0
    
    def test_get_bulkhead_singleton(self):
        """Test get_crypto_bulkhead returns same instance"""
        bh1 = get_crypto_bulkhead("test_singleton", max_concurrent=5)
        bh2 = get_crypto_bulkhead("test_singleton", max_concurrent=5)
        assert bh1 is bh2


# -----------------------------------------------------------------------------
# TEST COMBINED RESILIENT CRYPTO OP
# -----------------------------------------------------------------------------

class TestResilientCryptoOp:
    """Test combined resilient crypto operation"""
    
    def test_resilient_op_basic(self):
        """Test basic resilient crypto wrapper"""
        @resilient_crypto_op(timeout_seconds=5.0, max_retries=0)
        def encrypt():
            return "ciphertext"
        
        result = encrypt()
        assert result == "ciphertext"
    
    def test_resilient_op_full_stack(self):
        """Test full resilience stack"""
        @resilient_crypto_op(
            timeout_seconds=30.0,
            max_retries=1,
            circuit_breaker="hsm_ops",
            bulkhead="key_gen_pool"
        )
        def generate_pq_key():
            return {"key": "kyber-1024-key", "type": "KEM"}
        
        result = generate_pq_key()
        assert result["key"] == "kyber-1024-key"


# -----------------------------------------------------------------------------
# TEST CRYPTO ERROR CONTEXT
# -----------------------------------------------------------------------------

class TestCryptoErrorContext:
    """Test CryptoErrorContext manager"""
    
    def test_context_no_exception(self):
        """Test context with no exception"""
        with CryptoErrorContext("key_generation") as ctx:
            assert ctx.operation == "key_generation"
    
    def test_context_enriches_exception(self):
        """Test context enriches exceptions"""
        try:
            with CryptoErrorContext("encryption"):
                raise EncryptionError("Failed", "Kyber")
        except EncryptionError as e:
            assert e.details["operation"] == "encryption"
            assert "duration_seconds" in e.details
    
    def test_context_zeroizes_sensitive_data(self):
        """Test context zeroizes sensitive data on exit"""
        sensitive = bytearray(b"private_key")
        
        with CryptoErrorContext("sign", sensitive_data=sensitive):
            pass
        
        # Should be zeroized even without exception
        assert all(b == 0 for b in sensitive)


# -----------------------------------------------------------------------------
# HAPPY PATH VERIFICATION
# -----------------------------------------------------------------------------

class TestHappyPathPreservation:
    """Verify happy path behavior is 100% preserved"""
    
    def test_decorators_preserve_metadata(self):
        """Test decorators preserve function metadata"""
        def original():
            """Original docstring"""
            pass
        
        decorated = crypto_retry()(original)
        assert decorated.__name__ == "original"
        assert decorated.__doc__ == "Original docstring"
    
    def test_no_side_effects_on_success(self):
        """Test no side effects when function succeeds"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3)
        @crypto_timeout(seconds=5.0)
        def succeeds():
            call_count[0] += 1
            return "ok"
        
        result = succeeds()
        assert result == "ok"
        assert call_count[0] == 1  # Called exactly once
    
    def test_module_imports_cleanly(self):
        """Test module imports without errors"""
        import quantum_crypt.crypto_error_resilience_pq_protection_v30_2026_june as module
        assert module.__version__ == "30.0.0"
        assert module.__dimension__ == "E - Error Resilience"
        assert module.__stable__ is True


# -----------------------------------------------------------------------------
# INTEGRATION TESTS
# -----------------------------------------------------------------------------

class TestIntegration:
    """Integration tests"""
    
    def test_full_resilience_stack(self):
        """Test full resilience stack working together"""
        call_count = [0]
        
        @resilient_crypto_op(
            timeout_seconds=10.0,
            max_retries=2,
            circuit_breaker="integration_test"
        )
        def flaky_key_exchange():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectError("Temporary HSM issue")
            return {"shared_secret": "abc123", "algorithm": "Kyber"}
        
        result = flaky_key_exchange()
        assert result["shared_secret"] == "abc123"
        assert call_count[0] == 2
    
    def test_exception_hierarchy_catching(self):
        """Test catching exceptions at different hierarchy levels"""
        try:
            raise PQKeyExchangeError("KEM failed", "Kyber")
        except PostQuantumError:
            caught_pq = True
        except CryptoOperationError:
            caught_pq = False
        
        assert caught_pq is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
