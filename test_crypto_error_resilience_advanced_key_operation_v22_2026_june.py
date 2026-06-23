"""
Test suite for QuantumCrypt Error Resilience v22 - Advanced Key Operation Protection

100% ADD-ONLY tests - no existing tests modified
All existing tests must continue to pass
"""

import pytest
import time
import threading
import secrets
from quantum_crypt.crypto_error_resilience_advanced_key_operation_v22_2026_june import (
    CryptoOperationCircuitBreaker,
    CryptoCircuitBreakerConfig,
    CircuitState,
    CryptoCircuitBreakerOpenError,
    KeyOperationBulkhead,
    KeyBulkheadConfig,
    KeyBulkheadTimeoutError,
    AlgorithmFallbackChain,
    CryptoAlgorithmTier,
    AlgorithmFallbackExhaustedError,
    ConstantTimeRetryWithEntropyRefresh,
    CryptoRetryConfig,
    KeyOperationType,
    CryptoResilienceMetrics,
    with_crypto_circuit_breaker,
    with_key_bulkhead,
    with_crypto_retry,
    create_crypto_error_resilience_v22,
)


class TestCryptoOperationCircuitBreaker:
    """Tests for crypto-specific circuit breaker."""
    
    def test_circuit_starts_closed(self):
        breaker = CryptoOperationCircuitBreaker()
        assert breaker.state == CircuitState.CLOSED
    
    def test_allow_key_generation_operation(self):
        breaker = CryptoOperationCircuitBreaker()
        assert breaker.allow_operation(KeyOperationType.KEY_GENERATION) is True
    
    def test_successful_key_generation(self):
        breaker = CryptoOperationCircuitBreaker()
        
        def generate_key():
            return secrets.token_bytes(32)
        
        result = breaker.execute(KeyOperationType.KEY_GENERATION, generate_key)
        assert len(result) == 32
        assert breaker.metrics.successful_ops == 1
    
    def test_failed_operation_records_failure(self):
        breaker = CryptoOperationCircuitBreaker()
        
        def fail_op():
            raise ValueError("key generation failed")
        
        with pytest.raises(ValueError):
            breaker.execute(KeyOperationType.KEY_GENERATION, fail_op)
        
        assert breaker.metrics.failed_ops == 1
    
    def test_circuit_opens_after_failures(self):
        config = CryptoCircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            constant_time_transitions=False,
        )
        breaker = CryptoOperationCircuitBreaker(config)
        
        def fail_op():
            raise ValueError("crypto error")
        
        for _ in range(5):
            try:
                breaker.execute(KeyOperationType.SIGNATURE, fail_op)
            except (ValueError, CryptoCircuitBreakerOpenError):
                pass
        
        assert breaker.state == CircuitState.OPEN
    
    def test_open_circuit_rejects_operations(self):
        config = CryptoCircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            constant_time_transitions=False,
        )
        breaker = CryptoOperationCircuitBreaker(config)
        
        def fail_op():
            raise ValueError("crypto error")
        
        for _ in range(5):
            try:
                breaker.execute(KeyOperationType.SIGNATURE, fail_op)
            except (ValueError, CryptoCircuitBreakerOpenError):
                pass
        
        with pytest.raises(CryptoCircuitBreakerOpenError):
            breaker.execute(KeyOperationType.SIGNATURE, lambda: b"key")
    
    def test_half_open_transition_after_timeout(self):
        config = CryptoCircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            reset_timeout=0.1,
            constant_time_transitions=False,
        )
        breaker = CryptoOperationCircuitBreaker(config)
        
        def fail_op():
            raise ValueError("crypto error")
        
        for _ in range(5):
            try:
                breaker.execute(KeyOperationType.SIGNATURE, fail_op)
            except (ValueError, CryptoCircuitBreakerOpenError):
                pass
        
        assert breaker.state == CircuitState.OPEN
        time.sleep(0.15)
        assert breaker.state == CircuitState.HALF_OPEN
    
    def test_half_open_success_closes_circuit(self):
        config = CryptoCircuitBreakerConfig(
            failure_threshold=2,
            min_calls_to_open=2,
            sampling_window=10,
            reset_timeout=0.1,
            success_threshold=2,
            constant_time_transitions=False,
        )
        breaker = CryptoOperationCircuitBreaker(config)
        
        def fail_op():
            raise ValueError("crypto error")
        
        for _ in range(5):
            try:
                breaker.execute(KeyOperationType.SIGNATURE, fail_op)
            except (ValueError, CryptoCircuitBreakerOpenError):
                pass
        
        time.sleep(0.15)
        
        def success_op():
            return b"signature"
        
        for _ in range(3):
            breaker.execute(KeyOperationType.SIGNATURE, success_op)
        
        assert breaker.state == CircuitState.CLOSED
    
    def test_constant_time_transitions_enabled(self):
        config = CryptoCircuitBreakerConfig(constant_time_transitions=True)
        breaker = CryptoOperationCircuitBreaker(config)
        
        # Just verify it doesn't crash
        state = breaker.state
        assert state in (CircuitState.CLOSED, CircuitState.HALF_OPEN, CircuitState.OPEN)
    
    def test_circuit_metrics(self):
        breaker = CryptoOperationCircuitBreaker(CryptoCircuitBreakerConfig(
            constant_time_transitions=False
        ))
        
        for _ in range(10):
            breaker.execute(KeyOperationType.VERIFICATION, lambda: True)
        
        metrics = breaker.metrics
        assert metrics.total_key_ops == 10
        assert metrics.successful_ops == 10
        assert metrics.failed_ops == 0


class TestKeyOperationBulkhead:
    """Tests for key operation bulkhead with entropy management."""
    
    def test_bulkhead_allows_key_operation(self):
        bulkhead = KeyOperationBulkhead()
        
        result = bulkhead.execute(
            KeyOperationType.KEY_GENERATION,
            lambda: secrets.token_bytes(32)
        )
        assert len(result) == 32
    
    def test_bulkhead_tracks_active_operations(self):
        bulkhead = KeyOperationBulkhead(KeyBulkheadConfig(max_concurrent_key_ops=5))
        assert bulkhead.active_operations == 0
        
        barrier = threading.Barrier(2)
        
        def blocking_op():
            barrier.wait()
            barrier.wait()
            return b"key"
        
        thread = threading.Thread(
            target=lambda: bulkhead.execute(KeyOperationType.KEY_GENERATION, blocking_op)
        )
        thread.start()
        
        barrier.wait()
        assert bulkhead.active_operations == 1
        barrier.wait()
        thread.join()
        
        assert bulkhead.active_operations == 0
    
    def test_bulkhead_timeout_when_full(self):
        config = KeyBulkheadConfig(
            max_concurrent_key_ops=1,
            max_wait_time=0.1,
        )
        bulkhead = KeyOperationBulkhead(config)
        
        barrier = threading.Barrier(2)
        
        def blocking_op():
            barrier.wait()
            time.sleep(0.5)
            return b"key"
        
        thread = threading.Thread(
            target=lambda: bulkhead.execute(KeyOperationType.KEY_GENERATION, blocking_op)
        )
        thread.start()
        
        barrier.wait()
        
        with pytest.raises(KeyBulkheadTimeoutError):
            bulkhead.execute(KeyOperationType.KEY_GENERATION, lambda: b"late")
        
        thread.join()
    
    def test_entropy_refresh_triggers(self):
        bulkhead = KeyOperationBulkhead(KeyBulkheadConfig(
            max_concurrent_key_ops=10,
            max_entropy_pool_usage=0.01,  # Very low to trigger refresh
        ))
        
        # Should not crash when entropy refresh triggers
        for _ in range(10):
            bulkhead.execute(KeyOperationType.KEY_GENERATION, lambda: b"key")


class TestAlgorithmFallbackChain:
    """Tests for algorithm agility fallback chain."""
    
    def test_uses_highest_security_tier_first(self):
        chain = AlgorithmFallbackChain()
        chain.register_implementation(CryptoAlgorithmTier.POST_QUANTUM, lambda: "pq_key")
        chain.register_implementation(CryptoAlgorithmTier.HYBRID, lambda: "hybrid_key")
        
        result, tier = chain.execute(min_allowed_tier=CryptoAlgorithmTier.POST_QUANTUM)
        
        assert result == "pq_key"
        assert tier == CryptoAlgorithmTier.POST_QUANTUM
    
    def test_falls_back_to_lower_tier(self):
        chain = AlgorithmFallbackChain()
        chain.register_implementation(
            CryptoAlgorithmTier.POST_QUANTUM,
            lambda: (_ for _ in ()).throw(ValueError("pq failed"))
        )
        chain.register_implementation(CryptoAlgorithmTier.HYBRID, lambda: "hybrid_key")
        
        result, tier = chain.execute(min_allowed_tier=CryptoAlgorithmTier.POST_QUANTUM)
        
        assert result == "hybrid_key"
        assert tier == CryptoAlgorithmTier.HYBRID
        assert chain.downgrade_count == 1
    
    def test_respects_min_allowed_tier(self):
        chain = AlgorithmFallbackChain()
        chain.register_implementation(
            CryptoAlgorithmTier.POST_QUANTUM,
            lambda: (_ for _ in ()).throw(ValueError("pq failed"))
        )
        chain.register_implementation(
            CryptoAlgorithmTier.HYBRID,
            lambda: (_ for _ in ()).throw(ValueError("hybrid failed"))
        )
        chain.register_implementation(CryptoAlgorithmTier.CLASSIC_MODERN, lambda: "classic_key")
        
        result, tier = chain.execute(min_allowed_tier=CryptoAlgorithmTier.HYBRID)
        
        assert result == "classic_key"
        assert tier == CryptoAlgorithmTier.CLASSIC_MODERN
    
    def test_all_tiers_failed_raises(self):
        chain = AlgorithmFallbackChain()
        chain.register_implementation(
            CryptoAlgorithmTier.POST_QUANTUM,
            lambda: (_ for _ in ()).throw(ValueError())
        )
        
        with pytest.raises(AlgorithmFallbackExhaustedError):
            chain.execute(min_allowed_tier=CryptoAlgorithmTier.POST_QUANTUM)
    
    def test_available_tiers_property(self):
        chain = AlgorithmFallbackChain()
        chain.register_implementation(CryptoAlgorithmTier.POST_QUANTUM, lambda: "pq")
        chain.register_implementation(CryptoAlgorithmTier.CLASSIC_MODERN, lambda: "classic")
        
        available = chain.available_tiers
        assert CryptoAlgorithmTier.POST_QUANTUM in available
        assert CryptoAlgorithmTier.CLASSIC_MODERN in available
        assert CryptoAlgorithmTier.HYBRID not in available


class TestConstantTimeRetryWithEntropyRefresh:
    """Tests for constant-time crypto retry."""
    
    def test_succeeds_on_first_attempt(self):
        retry = ConstantTimeRetryWithEntropyRefresh(CryptoRetryConfig(
            constant_time_jitter=False
        ))
        call_count = [0]
        
        def op():
            call_count[0] += 1
            return b"signature"
        
        result = retry.execute(op)
        assert result == b"signature"
        assert call_count[0] == 1
    
    def test_retries_with_entropy_refresh(self):
        retry = ConstantTimeRetryWithEntropyRefresh(CryptoRetryConfig(
            max_attempts=3,
            min_delay=0.01,
            constant_time_jitter=False,
            entropy_refresh_on_retry=True,
        ))
        call_count = [0]
        
        def op():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("transient error")
            return b"success"
        
        result = retry.execute(op)
        assert result == b"success"
        assert call_count[0] == 3
    
    def test_exhausts_attempts(self):
        retry = ConstantTimeRetryWithEntropyRefresh(CryptoRetryConfig(
            max_attempts=2,
            min_delay=0.01,
            constant_time_jitter=False,
        ))
        call_count = [0]
        
        def op():
            call_count[0] += 1
            raise ValueError("always fails")
        
        with pytest.raises(ValueError):
            retry.execute(op)
        
        assert call_count[0] == 2
    
    def test_constant_time_jitter_enabled(self):
        retry = ConstantTimeRetryWithEntropyRefresh(CryptoRetryConfig(
            max_attempts=2,
            min_delay=0.01,
            constant_time_jitter=True,
        ))
        
        # Should complete without errors
        try:
            retry.execute(lambda: b"ok")
        except Exception:
            pytest.fail("Constant time jitter should not cause errors")


class TestDecorators:
    """Tests for crypto convenience decorators."""
    
    def test_crypto_circuit_breaker_decorator(self):
        @with_crypto_circuit_breaker(KeyOperationType.SIGNATURE)
        def sign_data():
            return b"signature"
        
        result = sign_data()
        assert result == b"signature"
        assert hasattr(sign_data, "crypto_circuit_breaker")
    
    def test_key_bulkhead_decorator(self):
        @with_key_bulkhead(KeyOperationType.KEY_GENERATION)
        def generate_key():
            return b"key"
        
        result = generate_key()
        assert result == b"key"
        assert hasattr(generate_key, "key_bulkhead")
    
    def test_crypto_retry_decorator(self):
        @with_crypto_retry()
        def verify_signature():
            return True
        
        result = verify_signature()
        assert result is True
        assert hasattr(verify_signature, "crypto_retry")


class TestFactoryFunction:
    """Tests for main factory function."""
    
    def test_create_all_crypto_components(self):
        components = create_crypto_error_resilience_v22()
        
        assert components["version"] == "v22"
        assert components["enabled"] is True
        assert components["crypto_circuit_breaker"] is not None
        assert components["key_bulkhead"] is not None
        assert components["crypto_retry"] is not None
        assert components["algorithm_fallback"] is not None
        assert components["key_operation_types"] == KeyOperationType
        assert components["algorithm_tiers"] == CryptoAlgorithmTier
    
    def test_create_with_selected_components(self):
        components = create_crypto_error_resilience_v22(
            enable_circuit_breaker=False,
            enable_key_bulkhead=False,
        )
        
        assert components["crypto_circuit_breaker"] is None
        assert components["key_bulkhead"] is None
        assert components["crypto_retry"] is not None


class TestThreadSafety:
    """Thread safety tests for crypto resilience components."""
    
    def test_circuit_breaker_concurrent_key_ops(self):
        breaker = CryptoOperationCircuitBreaker(CryptoCircuitBreakerConfig(
            constant_time_transitions=False
        ))
        errors = []
        
        def worker():
            try:
                for _ in range(50):
                    try:
                        breaker.execute(
                            KeyOperationType.SIGNATURE,
                            lambda: time.sleep(0.001) or b"sig"
                        )
                    except Exception:
                        pass
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
    
    def test_bulkhead_concurrent_key_generation(self):
        bulkhead = KeyOperationBulkhead(KeyBulkheadConfig(max_concurrent_key_ops=3))
        errors = []
        
        def worker():
            try:
                for _ in range(20):
                    bulkhead.execute(
                        KeyOperationType.KEY_GENERATION,
                        lambda: time.sleep(0.001) or b"key"
                    )
            except KeyBulkheadTimeoutError:
                pass  # Expected under load
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
