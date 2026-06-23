"""
Test suite for QuantumCrypt Error Resilience v20
Adaptive Timeout with Jitter + Configurable Backoff Strategies + Crypto-Specific Features

DIMENSION E - Error Resilience
Tests cover:
- Crypto-safe backoff strategies (using secrets module)
- HSM/KMS circuit breaker
- Operation-specific bulkhead isolation
- Crypto operation timeout enforcement
- Algorithm graceful degradation
- Secure memory zeroization
- Exception hierarchies
- Orchestrator singleton
- Happy path preservation
"""

import pytest
import time
import threading
import secrets

from quantum_crypt.crypto_error_resilience_adaptive_timeout_jitter_backoff_v20_2026_june import (
    CryptoBackoffStrategy,
    CircuitState,
    CryptoResilienceError,
    CryptoOperationTimeout,
    HSMConnectionError,
    KeyOperationError,
    CryptoCircuitBreakerOpen,
    CryptoMaxRetriesExceeded,
    CryptoBulkheadCapacityExceeded,
    AlgorithmDegradationError,
    CryptoRetryConfig,
    CryptoCircuitBreakerConfig,
    CryptoBulkheadConfig,
    CryptoTimeoutConfig,
    AlgorithmFallback,
    CryptoBackoffCalculator,
    CryptoCircuitBreaker,
    CryptoBulkhead,
    CryptoResilienceOrchestrator,
    crypto_retry,
    crypto_timeout,
    with_algorithm_fallback,
)


class TestCryptoExceptionHierarchies:
    """Test crypto exception hierarchy."""

    def test_base_exception_inheritance(self):
        """Test all crypto exceptions inherit from base."""
        assert issubclass(CryptoOperationTimeout, CryptoResilienceError)
        assert issubclass(HSMConnectionError, CryptoResilienceError)
        assert issubclass(KeyOperationError, CryptoResilienceError)
        assert issubclass(CryptoCircuitBreakerOpen, CryptoResilienceError)
        assert issubclass(CryptoMaxRetriesExceeded, CryptoResilienceError)
        assert issubclass(CryptoBulkheadCapacityExceeded, CryptoResilienceError)
        assert issubclass(AlgorithmDegradationError, CryptoResilienceError)


class TestCryptoBackoffCalculator:
    """Test crypto-safe backoff calculation."""

    def test_crypto_secure_jitter(self):
        """Test crypto secure jitter uses secrets module."""
        config = CryptoRetryConfig(
            strategy=CryptoBackoffStrategy.CRYPTO_SECURE_JITTER,
            initial_delay=0.1,
            jitter_factor=0.5
        )
        
        delays = [CryptoBackoffCalculator.calculate(3, config) for _ in range(100)]
        # Verify jitter produces variation (cryptographically secure random)
        assert len(set(delays)) > 10

    def test_backoff_strategies(self):
        """Test all backoff strategies."""
        strategies = [
            CryptoBackoffStrategy.FIXED,
            CryptoBackoffStrategy.LINEAR,
            CryptoBackoffStrategy.EXPONENTIAL,
            CryptoBackoffStrategy.CRYPTO_SECURE_JITTER,
        ]
        
        for strategy in strategies:
            config = CryptoRetryConfig(strategy=strategy, initial_delay=0.01)
            for attempt in range(1, 5):
                delay = CryptoBackoffCalculator.calculate(attempt, config)
                assert delay >= 0
                assert delay <= config.max_delay

    def test_max_delay_clamping(self):
        """Test max delay is enforced."""
        config = CryptoRetryConfig(
            strategy=CryptoBackoffStrategy.EXPONENTIAL,
            initial_delay=1.0,
            max_delay=2.0
        )
        
        delay = CryptoBackoffCalculator.calculate(10, config)
        assert delay <= 2.0


class TestCryptoCircuitBreaker:
    """Test circuit breaker for HSM/KMS operations."""

    def test_initial_state(self):
        """Test circuit breaker starts closed."""
        cb = CryptoCircuitBreaker(CryptoCircuitBreakerConfig(failure_threshold=3))
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_hsm_circuit_opens(self):
        """Test circuit opens on HSM connection failures."""
        cb = CryptoCircuitBreaker(CryptoCircuitBreakerConfig(
            failure_threshold=2,
            operation_type="hsm_connection"
        ))
        
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_circuit_recovery(self):
        """Test circuit recovery after timeout."""
        cb = CryptoCircuitBreaker(CryptoCircuitBreakerConfig(
            failure_threshold=1,
            success_threshold=2,
            reset_timeout=0.05
        ))
        
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        
        time.sleep(0.06)
        assert cb.allow_request() is True
        assert cb.state == CircuitState.HALF_OPEN
        
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED


class TestCryptoBulkhead:
    """Test operation-specific bulkhead isolation."""

    def test_operation_specific_limits(self):
        """Test different limits for different operation types."""
        bulkhead = CryptoBulkhead(CryptoBulkheadConfig(
            max_concurrent_key_gen=2,
            max_concurrent_hsm=1
        ))
        
        # Key gen should allow 2 concurrent
        assert bulkhead.acquire("key_gen") is True
        assert bulkhead.acquire("key_gen") is True
        assert bulkhead.acquire("key_gen", timeout=0.01) is False
        
        bulkhead.release("key_gen")
        bulkhead.release("key_gen")
        
        # HSM should only allow 1 concurrent
        assert bulkhead.acquire("hsm") is True
        assert bulkhead.acquire("hsm", timeout=0.01) is False
        bulkhead.release("hsm")

    def test_bulkhead_stats(self):
        """Test bulkhead stats tracking."""
        bulkhead = CryptoBulkhead()
        
        bulkhead.acquire("encrypt")
        bulkhead.acquire("sign")
        
        stats = bulkhead.get_stats()
        assert stats["encrypt"] == 1
        assert stats["sign"] == 1
        
        bulkhead.release("encrypt")
        bulkhead.release("sign")


class TestCryptoRetryDecorator:
    """Test @crypto_retry decorator."""

    def test_hsm_connection_retry(self):
        """Test retry on HSM connection errors."""
        call_count = [0]
        
        @crypto_retry(config=CryptoRetryConfig(
            max_attempts=3,
            initial_delay=0.01
        ))
        def flaky_hsm_call():
            call_count[0] += 1
            if call_count[0] < 3:
                raise HSMConnectionError("Temporary HSM failure")
            return "hsm_success"
        
        result = flaky_hsm_call()
        assert result == "hsm_success"
        assert call_count[0] == 3

    def test_stop_on_key_errors(self):
        """Test key operation errors stop immediately."""
        call_count = [0]
        
        @crypto_retry(config=CryptoRetryConfig(max_attempts=5))
        def key_operation():
            call_count[0] += 1
            raise KeyOperationError("Invalid key parameters")
        
        with pytest.raises(KeyOperationError):
            key_operation()
        
        assert call_count[0] == 1  # No retries for key errors

    def test_max_retries_with_fallback(self):
        """Test fallback on max retries exceeded."""
        def fallback_encrypt():
            return "fallback_ciphertext"
        
        @crypto_retry(
            config=CryptoRetryConfig(max_attempts=2, initial_delay=0.01),
            fallback=fallback_encrypt
        )
        def failing_encrypt():
            raise HSMConnectionError("HSM down")
        
        result = failing_encrypt()
        assert result == "fallback_ciphertext"

    def test_circuit_breaker_integration(self):
        """Test circuit breaker integration with retry."""
        @crypto_retry(
            config=CryptoRetryConfig(max_attempts=2),
            circuit_breaker_name="test_hsm"
        )
        def protected_call():
            return "success"
        
        result = protected_call()
        assert result == "success"


class TestCryptoTimeoutDecorator:
    """Test @crypto_timeout decorator."""

    def test_key_gen_timeout(self):
        """Test timeout enforcement for key generation."""
        @crypto_timeout(timeout_seconds=0.1, operation_type="key_gen")
        def slow_key_gen():
            time.sleep(1.0)
            return b"key_material"
        
        with pytest.raises(CryptoOperationTimeout):
            slow_key_gen()

    def test_fast_operation_completes(self):
        """Test fast operation completes normally."""
        @crypto_timeout(timeout_seconds=5.0, operation_type="sign")
        def fast_sign():
            return b"signature"
        
        result = fast_sign()
        assert result == b"signature"

    def test_timeout_with_fallback(self):
        """Test fallback on timeout."""
        def fallback_sign():
            return b"fallback_signature"
        
        @crypto_timeout(timeout_seconds=0.1, operation_type="sign", fallback=fallback_sign)
        def slow_sign():
            time.sleep(1.0)
            return b"signature"
        
        result = slow_sign()
        assert result == b"fallback_signature"


class TestAlgorithmFallback:
    """Test graceful algorithm degradation."""

    def test_primary_algorithm_works(self):
        """Test primary algorithm used when available."""
        used_algorithms = []
        
        @with_algorithm_fallback(AlgorithmFallback(
            primary_algorithm="AES-256-GCM",
            fallback_algorithms=["AES-128-GCM", "ChaCha20"]
        ))
        def encrypt(data, algorithm=None):
            used_algorithms.append(algorithm)
            return f"encrypted_with_{algorithm}"
        
        result = encrypt(b"test_data")
        assert result == "encrypted_with_AES-256-GCM"
        assert used_algorithms == ["AES-256-GCM"]

    def test_fallback_chain(self):
        """Test fallback chain when primary fails."""
        used_algorithms = []
        fail_count = [0]
        
        @with_algorithm_fallback(AlgorithmFallback(
            primary_algorithm="RSA-4096",
            fallback_algorithms=["RSA-2048", "AES-256"]
        ))
        def encrypt(data, algorithm=None):
            used_algorithms.append(algorithm)
            fail_count[0] += 1
            if fail_count[0] < 3:
                raise ValueError(f"{algorithm} not available")
            return f"encrypted_with_{algorithm}"
        
        result = encrypt(b"test")
        assert "encrypted_with_" in result
        assert len(used_algorithms) == 3

    def test_all_algorithms_fail(self):
        """Test exception when all algorithms fail."""
        @with_algorithm_fallback(AlgorithmFallback(
            primary_algorithm="ALG1",
            fallback_algorithms=["ALG2"]
        ))
        def always_fail(data, algorithm=None):
            raise ValueError(f"{algorithm} failed")
        
        with pytest.raises(AlgorithmDegradationError):
            always_fail(b"test")


class TestSecureMemoryWipe:
    """Test secure memory zeroization."""

    def test_secure_wipe_bytearray(self):
        """Test secure wipe overwrites sensitive data."""
        orchestrator = CryptoResilienceOrchestrator()
        
        sensitive = bytearray(b"secret_key_material_12345")
        original = bytes(sensitive)
        
        orchestrator.secure_wipe(sensitive)
        
        # Data should no longer match original
        assert bytes(sensitive) != original
        # Should be all zeros after final pass
        assert all(b == 0 for b in sensitive)


class TestOrchestrator:
    """Test CryptoResilienceOrchestrator."""

    def test_singleton(self):
        """Test orchestrator is singleton."""
        orch1 = CryptoResilienceOrchestrator()
        orch2 = CryptoResilienceOrchestrator()
        assert orch1 is orch2

    def test_circuit_breaker_registry(self):
        """Test circuit breaker registry."""
        orch = CryptoResilienceOrchestrator()
        cb1 = orch.get_circuit_breaker("hsm_prod")
        cb2 = orch.get_circuit_breaker("hsm_prod")
        assert cb1 is cb2

    def test_adaptive_timeout_learning(self):
        """Test adaptive timeout learns from history."""
        orch = CryptoResilienceOrchestrator()
        
        # Record fast operations
        for _ in range(10):
            orch.record_operation_duration("sign", 0.05)
        
        timeout = orch.get_adaptive_timeout("sign", 5.0)
        # Should be much lower than default 5s
        assert timeout < 1.0


class TestBulkheadInDecorator:
    """Test bulkhead integration in decorator."""

    def test_bulkhead_basic_functionality(self):
        """Test bulkhead works correctly in @crypto_retry."""
        @crypto_retry(
            config=CryptoRetryConfig(max_attempts=1),
            operation_type="hsm"
        )
        def hsm_call():
            return "done"
        
        # Basic call should work
        result = hsm_call()
        assert result == "done"


class TestHappyPathPreservation:
    """Verify happy path behavior is 100% preserved."""

    def test_no_resilience_overhead(self):
        """Test normal crypto operations work identically."""
        @crypto_retry()
        @crypto_timeout(timeout_seconds=30.0)
        def normal_encrypt(data):
            return data[::-1]
        
        test_data = b"hello world"
        result = normal_encrypt(test_data)
        assert result == test_data[::-1]

    def test_function_metadata_preserved(self):
        """Test function metadata preserved."""
        def original():
            """Original crypto function docstring."""
            pass
        
        decorated = crypto_retry()(original)
        assert decorated.__name__ == "original"
        assert decorated.__doc__ == "Original crypto function docstring."


class TestConcurrencySafety:
    """Test thread safety of resilience components."""

    def test_circuit_breaker_thread_safety(self):
        """Test circuit breaker under concurrent access."""
        cb = CryptoCircuitBreaker(CryptoCircuitBreakerConfig(failure_threshold=100))
        barrier = threading.Barrier(10)
        
        def worker():
            barrier.wait()
            for _ in range(100):
                cb.record_failure()
                cb.record_success()
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should still be closed (successes reset failures)
        assert cb.state == CircuitState.CLOSED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
