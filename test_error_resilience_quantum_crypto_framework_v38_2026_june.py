"""
Tests for Error Resilience Quantum Crypto Framework v38
Dimension E: Error Resilience - June 2026

All tests verify happy path behavior is 100% preserved.
No existing tests are modified - only new tests added.
"""

import pytest
import time
import threading
import secrets

from quantum_crypt.error_resilience_quantum_crypto_framework_v38_2026_june import (
    # Utilities
    secure_zeroize,
    sensitive_data_scope,
    
    # Exceptions
    QuantumCryptError,
    QuantumCryptWarning,
    QuantumCryptCritical,
    KeyManagementError,
    KeyNotFoundError,
    KeyRotationInProgress,
    KeyExpiredError,
    KeyCompromisedError,
    CryptoOperationError,
    CryptoTimeoutError,
    CryptoTemporaryFailure,
    CryptoPermanentFailure,
    IntegrityVerificationFailed,
    QuantumCryptoError,
    QuantumChannelNoise,
    EntropyDepletionError,
    PostQuantumAlgorithmError,
    
    # Retry
    CryptoRetryStrategy,
    CryptoRetryConfig,
    CryptoRetryManager,
    
    # Timeout
    CryptoOperationContext,
    CryptoTimeoutManager,
    
    # Fallback
    CryptoFallbackStrategy,
    CryptoFallbackConfig,
    CryptoGracefulDegradation,
    
    # Composite
    QuantumCryptoResilienceManager,
)


# -----------------------------------------------------------------------------
# Secure Memory Utilities Tests
# -----------------------------------------------------------------------------

class TestSecureMemoryUtilities:
    """Test secure memory zeroization utilities."""
    
    def test_secure_zeroize_clears_data(self):
        """Test secure_zeroize actually clears the bytearray."""
        sensitive = bytearray(b"secret key material 12345")
        original = bytes(sensitive)
        
        secure_zeroize(sensitive)
        
        # All bytes should be zero
        assert all(b == 0 for b in sensitive)
        # Original data is gone
        assert bytes(sensitive) != original
    
    def test_secure_zeroize_empty(self):
        """Test zeroize handles empty data gracefully."""
        sensitive = bytearray()
        secure_zeroize(sensitive)
        assert len(sensitive) == 0
    
    def test_sensitive_data_scope_context_manager(self):
        """Test sensitive_data_scope zeroizes after use."""
        sensitive = bytearray(b"test secret")
        
        with sensitive_data_scope(sensitive) as data:
            # Data is accessible inside context
            assert bytes(data) == b"test secret"
        
        # Data is zeroized after context exits
        assert all(b == 0 for b in sensitive)


# -----------------------------------------------------------------------------
# Exception Hierarchy Tests
# -----------------------------------------------------------------------------

class TestExceptionHierarchy:
    """Test custom crypto exception hierarchy."""
    
    def test_base_exception_attributes(self):
        """Test base exception has required attributes."""
        exc = QuantumCryptError("Test message", details={"key_id": "xxx"})
        assert exc.error_code == "QUANTUMCRYPT_ERROR"
        assert exc.severity == "ERROR"
        assert exc.details == {"key_id": "xxx"}
        assert exc.timestamp is not None
    
    def test_safe_message_hides_sensitive_details(self):
        """Test safe_message doesn't expose sensitive data."""
        exc = QuantumCryptError("Internal error with secret data")
        safe_msg = exc.safe_message()
        assert "secret" not in safe_msg
        assert "QUANTUMCRYPT_ERROR" in safe_msg
    
    def test_warning_exception(self):
        """Test warning exception inheritance."""
        exc = QuantumCryptWarning("Test")
        assert isinstance(exc, QuantumCryptError)
        assert exc.severity == "WARNING"
    
    def test_critical_exception(self):
        """Test critical exception inheritance."""
        exc = QuantumCryptCritical("Test")
        assert isinstance(exc, QuantumCryptError)
        assert exc.severity == "CRITICAL"
    
    def test_key_management_exceptions(self):
        """Test key management exception hierarchy."""
        assert issubclass(KeyRotationInProgress, KeyManagementError)
        assert issubclass(KeyRotationInProgress, QuantumCryptWarning)
        assert issubclass(KeyCompromisedError, QuantumCryptCritical)
        assert KeyCompromisedError.sensitive is True
    
    def test_crypto_operation_exceptions(self):
        """Test crypto operation exception hierarchy."""
        assert issubclass(CryptoTimeoutError, CryptoOperationError)
        assert issubclass(CryptoTimeoutError, QuantumCryptWarning)
        assert issubclass(CryptoPermanentFailure, QuantumCryptCritical)
        assert issubclass(IntegrityVerificationFailed, QuantumCryptCritical)
    
    def test_quantum_specific_exceptions(self):
        """Test quantum crypto exception hierarchy."""
        assert issubclass(QuantumChannelNoise, QuantumCryptoError)
        assert issubclass(QuantumChannelNoise, QuantumCryptWarning)
        assert issubclass(EntropyDepletionError, QuantumCryptWarning)
        assert issubclass(PostQuantumAlgorithmError, QuantumCryptCritical)


# -----------------------------------------------------------------------------
# Crypto Retry Manager Tests
# -----------------------------------------------------------------------------

class TestCryptoRetryManager:
    """Test crypto retry manager functionality."""
    
    def test_retry_happy_path_no_error(self):
        """Happy path: crypto function succeeds on first try."""
        retry_manager = CryptoRetryManager(CryptoRetryConfig(max_attempts=3))
        
        call_count = [0]
        
        @retry_manager
        def successful_signing():
            call_count[0] += 1
            return "signature_verified"
        
        result = successful_signing()
        assert result == "signature_verified"
        assert call_count[0] == 1  # Only called once
    
    def test_retry_with_crypto_jitter(self):
        """Test retry with cryptographic jitter backoff."""
        retry_manager = CryptoRetryManager(CryptoRetryConfig(
            max_attempts=3,
            initial_delay=0.001,
            strategy=CryptoRetryStrategy.CRYPTO_JITTER_BACKOFF
        ))
        
        call_count = [0]
        
        @retry_manager
        def flaky_hsm():
            call_count[0] += 1
            if call_count[0] < 3:
                raise CryptoTemporaryFailure("HSM busy")
            return "hsm_success"
        
        result = flaky_hsm()
        assert result == "hsm_success"
        assert call_count[0] == 3
    
    def test_retry_exhausted_raises(self):
        """Test exception raised when all crypto retries fail."""
        retry_manager = CryptoRetryManager(CryptoRetryConfig(
            max_attempts=2,
            initial_delay=0.001
        ))
        
        call_count = [0]
        
        @retry_manager
        def always_fails():
            call_count[0] += 1
            raise CryptoTemporaryFailure("HSM unavailable")
        
        with pytest.raises(CryptoTemporaryFailure):
            always_fails()
        
        assert call_count[0] == 2
    
    def test_non_retryable_exception_passthrough(self):
        """Non-retryable crypto exceptions pass through immediately."""
        retry_manager = CryptoRetryManager(CryptoRetryConfig(max_attempts=3))
        
        call_count = [0]
        
        @retry_manager
        def integrity_failure():
            call_count[0] += 1
            raise IntegrityVerificationFailed("Data tampered")
        
        with pytest.raises(IntegrityVerificationFailed):
            integrity_failure()
        
        assert call_count[0] == 1  # No retries for critical failures
    
    def test_retry_stats_tracking(self):
        """Test crypto retry statistics are tracked."""
        retry_manager = CryptoRetryManager(CryptoRetryConfig(
            max_attempts=2,
            initial_delay=0.001
        ))
        
        @retry_manager
        def flaky_op():
            raise CryptoTemporaryFailure("Error")
        
        with pytest.raises(CryptoTemporaryFailure):
            flaky_op()
        
        stats = retry_manager.get_retry_stats()
        assert len(stats) > 0


# -----------------------------------------------------------------------------
# Crypto Timeout Manager Tests
# -----------------------------------------------------------------------------

class TestCryptoTimeoutManager:
    """Test crypto timeout manager functionality."""
    
    def test_timeout_happy_path_no_timeout(self):
        """Happy path: crypto operation completes within timeout."""
        timeout_manager = CryptoTimeoutManager(default_timeout=5.0)
        
        @timeout_manager.with_crypto_timeout(1.0, "aes_encrypt")
        def fast_encrypt():
            return "encrypted_data"
        
        result = fast_encrypt()
        assert result == "encrypted_data"
    
    def test_timeout_context_propagation(self):
        """Test crypto timeout context propagates to nested calls."""
        timeout_manager = CryptoTimeoutManager()
        
        @timeout_manager.with_crypto_timeout(2.0, "key_derivation")
        def outer_op():
            ctx = timeout_manager._get_current_context()
            return ctx
        
        ctx = outer_op()
        assert ctx is not None
        assert ctx.operation_type == "key_derivation"
        assert ctx.remaining_time() > 0
        assert ctx.sensitive is True
    
    def test_timeout_check_raises_when_expired(self):
        """Test timeout check raises when crypto deadline expired."""
        timeout_manager = CryptoTimeoutManager()
        
        @timeout_manager.with_crypto_timeout(0.001, "slow_kdf")
        def slow_kdf():
            time.sleep(0.01)
            timeout_manager.check_crypto_timeout()
        
        with pytest.raises(CryptoTimeoutError):
            slow_kdf()
    
    def test_timeout_context_thread_safety(self):
        """Test crypto timeout context is thread-local."""
        timeout_manager = CryptoTimeoutManager()
        contexts = []
        
        def worker(op_type):
            @timeout_manager.with_crypto_timeout(1.0, op_type)
            def func():
                time.sleep(0.01)
                return timeout_manager._get_current_context()
            contexts.append(func())
        
        t1 = threading.Thread(target=worker, args=("sign",))
        t2 = threading.Thread(target=worker, args=("encrypt",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        assert len(contexts) == 2
        assert contexts[0].operation_type != contexts[1].operation_type


# -----------------------------------------------------------------------------
# Crypto Graceful Degradation Tests
# -----------------------------------------------------------------------------

class TestCryptoGracefulDegradation:
    """Test crypto graceful degradation functionality."""
    
    def test_happy_path_no_fallback(self):
        """Happy path: no fallback needed, crypto succeeds normally."""
        fallback_manager = CryptoGracefulDegradation()
        
        @fallback_manager.with_crypto_fallback(CryptoFallbackConfig(
            safe_default="degraded_hash"
        ))
        def normal_hash():
            return "sha256_hash"
        
        result = normal_hash()
        assert result == "sha256_hash"  # No fallback activated
    
    def test_fallback_returns_safe_default(self):
        """Test fallback returns safe default when crypto fails."""
        fallback_manager = CryptoGracefulDegradation()
        
        @fallback_manager.with_crypto_fallback(CryptoFallbackConfig(
            strategy=CryptoFallbackStrategy.SAFE_DEFAULT,
            safe_default="safe_fallback_result",
            log_audit=False
        ))
        def failing_hsm():
            raise CryptoPermanentFailure("HSM failure")
        
        result = failing_hsm()
        assert result == "safe_fallback_result"
    
    def test_fallback_algorithm_invoked(self):
        """Test fallback algorithm is invoked when primary fails."""
        fallback_manager = CryptoGracefulDegradation()
        
        def fallback_aes():
            return "aes_fallback_result"
        
        @fallback_manager.with_crypto_fallback(CryptoFallbackConfig(
            strategy=CryptoFallbackStrategy.FALLBACK_ALGORITHM,
            fallback_algorithm=fallback_aes,
            log_audit=False
        ))
        def failing_post_quantum():
            raise PostQuantumAlgorithmError("PQ algorithm failed")
        
        result = failing_post_quantum()
        assert result == "aes_fallback_result"
    
    def test_audit_logging(self):
        """Test fallback events are audited."""
        fallback_manager = CryptoGracefulDegradation()
        
        @fallback_manager.with_crypto_fallback(CryptoFallbackConfig(
            safe_default="default",
            log_audit=True
        ))
        def failing_op():
            raise ValueError("Error")
        
        failing_op()
        failing_op()
        
        audit_log = fallback_manager.get_audit_log()
        assert len(audit_log) == 2
        assert "event_id" in audit_log[0]
        assert "timestamp" in audit_log[0]


# -----------------------------------------------------------------------------
# Composite Manager Tests
# -----------------------------------------------------------------------------

class TestQuantumCryptoResilienceManager:
    """Test composite quantum crypto resilience manager."""
    
    def test_happy_path_all_features(self):
        """Happy path: all features wrap function without breaking behavior."""
        resilience = QuantumCryptoResilienceManager()
        
        @resilience.secure_crypto_operation(timeout=5.0, retry=True, fallback=True)
        def secure_sign(data: bytes) -> str:
            return f"signature_{data.hex()[:8]}"
        
        result = secure_sign(b"test data")
        assert "signature_" in result  # Normal behavior preserved
    
    def test_security_metrics_available(self):
        """Test security metrics are available."""
        resilience = QuantumCryptoResilienceManager()
        metrics = resilience.get_security_metrics()
        
        assert "retry_stats" in metrics
        assert "fallback_stats" in metrics
        assert "timestamp" in metrics
        assert metrics["version"] == "v38_2026_june"


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestCryptoResilienceIntegration:
    """Integration tests for crypto error resilience features."""
    
    def test_full_crypto_pipeline_resilience(self):
        """Test full crypto pipeline with all resilience features."""
        resilience = QuantumCryptoResilienceManager(default_timeout=10.0)
        
        operations = []
        
        @resilience.secure_crypto_operation(timeout=2.0, retry=True, fallback=True)
        def encrypt_data(plaintext: str, key_id: str) -> dict:
            operations.append((plaintext, key_id))
            return {
                "ciphertext": f"enc_{plaintext}",
                "key_id": key_id,
                "algorithm": "AES-256-GCM",
                "authenticated": True
            }
        
        # Happy path - normal operation
        result = encrypt_data("secret message", "key_001")
        assert result["authenticated"] is True
        assert result["algorithm"] == "AES-256-GCM"
        assert len(operations) == 1
    
    def test_exception_chaining_preserved(self):
        """Test exception chaining is properly preserved."""
        retry_manager = CryptoRetryManager(CryptoRetryConfig(
            max_attempts=1,
            initial_delay=0.001
        ))
        
        original_error = ValueError("HSM internal error")
        
        @retry_manager
        def failing_func():
            raise CryptoTemporaryFailure("Wrapper") from original_error
        
        try:
            failing_func()
        except CryptoTemporaryFailure as e:
            assert e.__cause__ is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
