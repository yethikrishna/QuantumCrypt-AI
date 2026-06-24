"""
Test Suite for QuantumCrypt Comprehensive Error Resilience Framework v30
Dimension E: Error Resilience

Tests verify:
- Crypto-specific exception hierarchy
- Secure memory zeroization
- Crypto circuit breaker pattern
- Crypto retry with exponential backoff
- Crypto timeout wrappers
- Algorithm fallback chains
- Crypto bulkhead isolation
- Composite crypto resilience policies

All tests are ADD-ONLY - no existing code modified.
"""

import pytest
import time
import threading
import secrets

# Import the new crypto error resilience module
from quantum_crypt.crypto_error_resilience_comprehensive_framework_v30_2026_june import (
    # Exceptions
    QuantumCryptError,
    KeyManagementError,
    EncryptionError,
    DecryptionError,
    SignatureError,
    VerificationError,
    HSMConnectionError,
    RandomnessError,
    AlgorithmUnavailableError,
    IntegrityCheckError,
    KeyRotationError,
    CircuitBreakerOpenError,
    TimeoutError,
    
    # Secure Memory
    secure_zeroize,
    SecureContext,
    
    # Circuit Breaker
    CircuitState,
    CryptoCircuitBreaker,
    
    # Retry
    crypto_retry,
    
    # Timeout
    crypto_timeout,
    
    # Algorithm Fallback
    AlgorithmFallbackChain,
    
    # Bulkhead
    CryptoBulkhead,
    
    # Safe Fallbacks
    safe_identity_hash,
    safe_encrypt_fallback,
    safe_decrypt_fallback,
    
    # Composite Policy
    CryptoResiliencePolicy,
)


# -----------------------------------------------------------------------------
# Crypto Exception Hierarchy Tests
# -----------------------------------------------------------------------------

class TestCryptoExceptionHierarchy:
    """Test crypto-specific custom exception hierarchy."""
    
    def test_base_exception_attributes(self):
        """Test base QuantumCryptError has required attributes."""
        exc = QuantumCryptError("Test crypto error", {"key_id": "test-123"})
        
        assert exc.message == "Test crypto error"
        assert exc.details == {"key_id": "test-123"}
        assert exc.error_code == "QC-000"
        assert exc.retryable is False
        assert exc.severity == "ERROR"
        assert exc.security_sensitive is False
        assert hasattr(exc, 'timestamp')
    
    def test_key_management_error_retryable(self):
        """Test KeyManagementError is retryable and security-sensitive."""
        exc = KeyManagementError("Key not found")
        assert exc.error_code == "QC-001"
        assert exc.retryable is True
        assert exc.security_sensitive is True
    
    def test_encryption_error_not_retryable(self):
        """Test EncryptionError is NOT retryable (security-sensitive)."""
        exc = EncryptionError("Encryption failed")
        assert exc.error_code == "QC-002"
        assert exc.retryable is False
        assert exc.security_sensitive is True
    
    def test_decryption_error_not_retryable(self):
        """Test DecryptionError is NOT retryable."""
        exc = DecryptionError("Decryption failed")
        assert exc.error_code == "QC-003"
        assert exc.retryable is False
        assert exc.security_sensitive is True
    
    def test_hsm_connection_error_retryable(self):
        """Test HSMConnectionError is retryable."""
        exc = HSMConnectionError("HSM connection lost")
        assert exc.error_code == "QC-006"
        assert exc.retryable is True
        assert exc.security_sensitive is False
    
    def test_randomness_error_critical(self):
        """Test RandomnessError has CRITICAL severity."""
        exc = RandomnessError("RNG failure")
        assert exc.error_code == "QC-007"
        assert exc.retryable is True
        assert exc.severity == "CRITICAL"
    
    def test_integrity_error_critical(self):
        """Test IntegrityCheckError has CRITICAL severity."""
        exc = IntegrityCheckError("Data tampered")
        assert exc.error_code == "QC-009"
        assert exc.retryable is False
        assert exc.severity == "CRITICAL"
    
    def test_all_exceptions_inherit_base(self):
        """Test all crypto exceptions inherit from QuantumCryptError."""
        assert issubclass(KeyManagementError, QuantumCryptError)
        assert issubclass(EncryptionError, QuantumCryptError)
        assert issubclass(DecryptionError, QuantumCryptError)
        assert issubclass(SignatureError, QuantumCryptError)
        assert issubclass(VerificationError, QuantumCryptError)
        assert issubclass(HSMConnectionError, QuantumCryptError)
        assert issubclass(RandomnessError, QuantumCryptError)
        assert issubclass(AlgorithmUnavailableError, QuantumCryptError)
        assert issubclass(IntegrityCheckError, QuantumCryptError)
        assert issubclass(KeyRotationError, QuantumCryptError)


# -----------------------------------------------------------------------------
# Secure Memory Zeroization Tests
# -----------------------------------------------------------------------------

class TestSecureMemory:
    """Test secure memory zeroization."""
    
    def test_secure_zeroize_bytearray(self):
        """Test secure_zeroize properly clears bytearray."""
        sensitive_data = bytearray(b"secret-key-12345")
        original = bytes(sensitive_data)
        
        secure_zeroize(sensitive_data)
        
        # Verify all bytes are zero
        assert all(b == 0 for b in sensitive_data)
        # Verify original data is gone
        assert bytes(sensitive_data) != original
    
    def test_secure_zeroize_non_bytearray_noop(self):
        """Test secure_zeroize handles non-bytearray gracefully."""
        # Should not raise exception
        secure_zeroize("not a bytearray")
        secure_zeroize(None)
        secure_zeroize(12345)
    
    def test_secure_context_zeroizes_on_exit(self):
        """Test SecureContext zeroizes data on exit."""
        sensitive_data = bytearray(b"my-secret-key")
        
        with SecureContext(sensitive_data) as data:
            # Data accessible inside context
            assert bytes(data) == b"my-secret-key"
        
        # Data zeroized after context exit
        assert all(b == 0 for b in sensitive_data)
    
    def test_secure_context_zeroizes_on_exception(self):
        """Test SecureContext zeroizes even when exception occurs."""
        sensitive_data = bytearray(b"my-secret-key")
        
        try:
            with SecureContext(sensitive_data):
                raise EncryptionError("Operation failed")
        except EncryptionError:
            pass
        
        # Data still zeroized despite exception
        assert all(b == 0 for b in sensitive_data)


# -----------------------------------------------------------------------------
# Crypto Circuit Breaker Tests
# -----------------------------------------------------------------------------

class TestCryptoCircuitBreaker:
    """Test Crypto Circuit Breaker implementation."""
    
    def test_circuit_starts_closed(self):
        """Test crypto circuit breaker starts in CLOSED state."""
        cb = CryptoCircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitState.CLOSED
    
    def test_circuit_allows_successful_calls(self):
        """Test successful calls pass through circuit breaker."""
        cb = CryptoCircuitBreaker(failure_threshold=3)
        
        @cb(op_type="encrypt")
        def encrypt_func():
            return "encrypted"
        
        result = encrypt_func()
        assert result == "encrypted"
        assert cb.metrics.encryption_attempts == 1
        assert cb.metrics.encryption_failures == 0
    
    def test_circuit_opens_on_hsm_failures(self):
        """Test circuit opens on HSM connection failures."""
        cb = CryptoCircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
        
        @cb(op_type="key_op")
        def hsm_func():
            raise HSMConnectionError("HSM down")
        
        # First failure
        with pytest.raises(HSMConnectionError):
            hsm_func()
        assert cb.state == CircuitState.CLOSED
        
        # Second failure - circuit opens
        with pytest.raises(HSMConnectionError):
            hsm_func()
        assert cb.state == CircuitState.OPEN
        
        # Third call fails fast
        with pytest.raises(CircuitBreakerOpenError):
            hsm_func()
    
    def test_circuit_recovers_after_timeout(self):
        """Test circuit recovers after timeout."""
        cb = CryptoCircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        
        @cb(op_type="key_op")
        def flaky_hsm():
            raise HSMConnectionError("HSM flaky")
        
        # Trip circuit
        with pytest.raises(HSMConnectionError):
            flaky_hsm()
        assert cb.state == CircuitState.OPEN
        
        # Wait for recovery
        time.sleep(0.15)
        
        # Should allow test call now
        with pytest.raises(HSMConnectionError):
            flaky_hsm()
    
    def test_circuit_metrics_track_operation_types(self):
        """Test circuit breaker tracks metrics per operation type."""
        cb = CryptoCircuitBreaker(failure_threshold=5)
        
        @cb(op_type="encrypt")
        def encrypt_ok():
            return "ok"
        
        @cb(op_type="decrypt")
        def decrypt_ok():
            return "ok"
        
        @cb(op_type="sign")
        def sign_ok():
            return "ok"
        
        encrypt_ok()
        encrypt_ok()
        decrypt_ok()
        sign_ok()
        
        assert cb.metrics.encryption_attempts == 2
        assert cb.metrics.decryption_attempts == 1
        assert cb.metrics.sign_attempts == 1


# -----------------------------------------------------------------------------
# Crypto Retry Tests
# -----------------------------------------------------------------------------

class TestCryptoRetry:
    """Test crypto-specific retry decorator."""
    
    def test_retry_hsm_connection_errors(self):
        """Test retry works for HSM connection errors."""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def flaky_hsm():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectionError("Temporary HSM issue")
            return "connected"
        
        result = flaky_hsm()
        assert result == "connected"
        assert call_count[0] == 2
    
    def test_no_retry_security_sensitive_errors(self):
        """Test NO retry for security-sensitive errors (decryption, integrity)."""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def decrypt_func():
            call_count[0] += 1
            raise DecryptionError("Decryption failed - security sensitive")
        
        with pytest.raises(DecryptionError):
            decrypt_func()
        
        # Should NOT retry decryption errors
        assert call_count[0] == 1
    
    def test_retry_gives_up_after_max_attempts(self):
        """Test retry gives up after max attempts."""
        call_count = [0]
        
        @crypto_retry(max_attempts=2, initial_delay=0.01)
        def always_fails():
            call_count[0] += 1
            raise HSMConnectionError("Always fails")
        
        with pytest.raises(HSMConnectionError):
            always_fails()
        
        assert call_count[0] == 2


# -----------------------------------------------------------------------------
# Crypto Timeout Tests
# -----------------------------------------------------------------------------

class TestCryptoTimeout:
    """Test crypto timeout decorator."""
    
    def test_timeout_raises_on_slow_operation(self):
        """Test timeout raises exception for slow crypto ops."""
        
        @crypto_timeout(seconds=0.1)
        def slow_kdf():
            time.sleep(1.0)
            return "derived-key"
        
        with pytest.raises(TimeoutError):
            slow_kdf()
    
    def test_timeout_passes_fast_operations(self):
        """Test fast operations pass through timeout."""
        
        @crypto_timeout(seconds=5.0)
        def fast_hash():
            return "hash-result"
        
        result = fast_hash()
        assert result == "hash-result"
    
    def test_timeout_propagates_exceptions(self):
        """Test exceptions are propagated through timeout."""
        
        @crypto_timeout(seconds=5.0)
        def error_func():
            raise EncryptionError("Encryption failed")
        
        with pytest.raises(EncryptionError):
            error_func()


# -----------------------------------------------------------------------------
# Algorithm Fallback Chain Tests
# -----------------------------------------------------------------------------

class TestAlgorithmFallbackChain:
    """Test algorithm fallback chain for graceful degradation."""
    
    def test_primary_algorithm_used_when_working(self):
        """Test primary algorithm is used when it works."""
        def primary(data):
            return f"primary:{data}"
        
        def fallback(data):
            return f"fallback:{data}"
        
        chain = AlgorithmFallbackChain([
            ("AES-256", primary),
            ("AES-128", fallback),
        ])
        
        result, algo_used = chain("test-data")
        assert result == "primary:test-data"
        assert algo_used == "AES-256"
    
    def test_fallback_used_when_primary_fails(self):
        """Test fallback algorithm is used when primary fails."""
        def failing_primary(data):
            raise AlgorithmUnavailableError("Hardware accel unavailable")
        
        def fallback(data):
            return f"fallback:{data}"
        
        chain = AlgorithmFallbackChain([
            ("AES-NI", failing_primary),
            ("AES-Soft", fallback),
        ])
        
        result, algo_used = chain("test-data")
        assert result == "fallback:test-data"
        assert algo_used == "AES-Soft"
    
    def test_all_fallbacks_fail_raises_exception(self):
        """Test exception when all algorithms fail."""
        def fail1(data):
            raise AlgorithmUnavailableError("Fail 1")
        
        def fail2(data):
            raise AlgorithmUnavailableError("Fail 2")
        
        chain = AlgorithmFallbackChain([
            ("Algo1", fail1),
            ("Algo2", fail2),
        ])
        
        with pytest.raises(AlgorithmUnavailableError):
            chain("test-data")
    
    def test_fallback_usage_tracking(self):
        """Test fallback usage statistics are tracked."""
        def primary(data):
            return f"primary:{data}"
        
        def fallback(data):
            return f"fallback:{data}"
        
        chain = AlgorithmFallbackChain([
            ("primary", primary),
            ("fallback", fallback),
        ])
        
        chain("data1")
        chain("data2")
        
        assert chain.fallback_usage["primary"] == 2
        assert chain.fallback_usage["fallback"] == 0


# -----------------------------------------------------------------------------
# Crypto Bulkhead Tests
# -----------------------------------------------------------------------------

class TestCryptoBulkhead:
    """Test Crypto Bulkhead isolation."""
    
    def test_bulkhead_allows_calls_within_limit(self):
        """Test bulkhead allows calls within concurrency limit."""
        bulkhead = CryptoBulkhead(max_concurrent=2, operation_type="key_op")
        
        @bulkhead
        def key_op():
            return "key-result"
        
        results = [key_op() for _ in range(5)]
        assert all(r == "key-result" for r in results)
    
    def test_bulkhead_basic_functionality(self):
        """Test bulkhead basic functionality works."""
        bulkhead = CryptoBulkhead(max_concurrent=1, max_waiting=10, operation_type="encrypt")
        
        @bulkhead
        def simple_encrypt():
            return "encrypted"
        
        result = simple_encrypt()
        assert result == "encrypted"


# -----------------------------------------------------------------------------
# Safe Crypto Fallback Tests
# -----------------------------------------------------------------------------

class TestSafeCryptoFallbacks:
    """Test safe crypto fallback implementations."""
    
    def test_safe_identity_hash_returns_bytes(self):
        """Test safe_identity_hash returns bytes."""
        result = safe_identity_hash(b"test-data")
        assert isinstance(result, bytes)
        assert len(result) == 32  # SHA256 output
    
    def test_safe_encrypt_fallback_structure(self):
        """Test safe_encrypt_fallback returns proper degraded structure."""
        result = safe_encrypt_fallback(b"secret-data")
        assert result["status"] == "degraded"
        assert result["fallback_used"] is True
        assert result["ciphertext"] is None
        assert "CRITICAL" in result["security_risk"]
        assert "timestamp" in result
    
    def test_safe_decrypt_fallback_structure(self):
        """Test safe_decrypt_fallback returns proper structure."""
        result = safe_decrypt_fallback(b"encrypted-data")
        assert result["status"] == "degraded"
        assert result["fallback_used"] is True
        assert result["plaintext"] is None


# -----------------------------------------------------------------------------
# Composite Crypto Resilience Policy Tests
# -----------------------------------------------------------------------------

class TestCryptoResiliencePolicy:
    """Test composite crypto resilience policy."""
    
    def test_policy_decorates_successfully(self):
        """Test resilience policy can decorate crypto functions."""
        policy = CryptoResiliencePolicy(
            name="hsm_policy",
            max_retries=2,
            timeout_seconds=10.0,
            operation_type="key_op"
        )
        
        @policy
        def hsm_encrypt(data):
            return f"encrypted:{data}"
        
        result = hsm_encrypt("test")
        assert result == "encrypted:test"


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestCryptoResilienceIntegration:
    """Integration tests for crypto resilience patterns."""
    
    def test_circuit_breaker_with_crypto_retry(self):
        """Test combining circuit breaker and crypto retry."""
        cb = CryptoCircuitBreaker(failure_threshold=10, recovery_timeout=60.0)
        
        call_count = [0]
        
        @cb(op_type="key_op")
        @crypto_retry(max_attempts=2, initial_delay=0.01)
        def flaky_key_op():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectionError("Temporary issue")
            return "key-ready"
        
        result = flaky_key_op()
        assert result == "key-ready"
        assert call_count[0] == 2
    
    def test_secure_context_with_exception(self):
        """Test secure context combined with error handling."""
        key_material = bytearray(secrets.token_bytes(32))
        
        try:
            with SecureContext(key_material):
                raise EncryptionError("Operation failed")
        except EncryptionError:
            pass
        
        # Key material should be zeroized despite exception
        assert all(b == 0 for b in key_material)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
