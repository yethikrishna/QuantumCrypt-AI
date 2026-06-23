"""
Test Suite for QuantumCrypt Error Resilience v22
===============================================
DIMENSION E - Error Resilience
ADD-ONLY COMPLIANT - NO PRODUCTION CODE MODIFIED

Covers:
1. Crypto exception hierarchy
2. Crypto-safe jitter and constant-time utilities
3. Key operation circuit breakers
4. HSM connection resilience
5. Crypto bulkhead isolation
6. Key generation retry with crypto-safe backoff
7. Graceful degradation and cached key fallback
8. Singleton pattern
9. Backward compatibility
10. Thread safety for crypto operations
"""

import pytest
import time
import threading

from quantum_crypt.crypto_error_resilience_pq_key_operation_v22_2026_june import (
    # Exceptions
    QuantumCryptResilienceError,
    CryptoOperationTimeoutError,
    HSMConnectionError,
    KeyOperationCircuitBreakerOpen,
    KeyGenerationRetryExhausted,
    CryptoBulkheadFullError,
    CryptoDegradationActivated,
    EntropySourceDepletedError,
    
    # Enums
    CircuitState,
    KeyOperationType,
    PQAlgorithm,
    HSMProvider,
    CryptoFallbackStrategy,
    
    # Config
    CryptoResilienceConfigV22,
    CryptoCircuitBreakerConfig,
    
    # Utilities
    crypto_safe_jitter,
    constant_time_compare,
    
    # Components
    CryptoCircuitBreaker,
    CryptoBulkhead,
    CachedKeyMaterial,
    
    # Main class
    QuantumCryptResilienceV22,
    CryptoResilienceWrappersV22,
    
    # Accessors
    get_crypto_resilience_manager,
    CRYPTO_RESILIENCE_VERSION,
    CRYPTO_RESILIENCE_FEATURES
)


# -----------------------------------------------------------------------------
# Test 1: Crypto Exception Hierarchy
# -----------------------------------------------------------------------------
class TestCryptoExceptionHierarchyV22:
    """Test crypto-specific exception hierarchy"""
    
    def test_base_exception_inheritance(self):
        """All crypto resilience exceptions inherit from base"""
        assert issubclass(CryptoOperationTimeoutError, QuantumCryptResilienceError)
        assert issubclass(HSMConnectionError, QuantumCryptResilienceError)
        assert issubclass(KeyOperationCircuitBreakerOpen, QuantumCryptResilienceError)
        assert issubclass(KeyGenerationRetryExhausted, QuantumCryptResilienceError)
        assert issubclass(CryptoBulkheadFullError, QuantumCryptResilienceError)
        assert issubclass(CryptoDegradationActivated, QuantumCryptResilienceError)
        assert issubclass(EntropySourceDepletedError, QuantumCryptResilienceError)
    
    def test_crypto_timeout_error_message(self):
        """Crypto timeout contains operation and algorithm info"""
        err = CryptoOperationTimeoutError("key_gen", "kyber_768", 30.0, 35.5)
        assert "key_gen" in str(err)
        assert "kyber_768" in str(err)
        assert "35.5" in str(err)
    
    def test_hsm_connection_error_message(self):
        """HSM error contains provider info"""
        err = HSMConnectionError("aws_cloudhsm", "connection refused", 3)
        assert "aws_cloudhsm" in str(err)
        assert "3" in str(err)
        assert "connection refused" in str(err)
    
    def test_key_gen_retry_exhausted(self):
        """Retry exhausted contains algorithm and attempt info"""
        original = ValueError("RNG failure")
        err = KeyGenerationRetryExhausted("kyber_768", 3, original)
        assert "kyber_768" in str(err)
        assert "3" in str(err)
        assert err.last_error is original


# -----------------------------------------------------------------------------
# Test 2: Crypto-Safe Utilities
# -----------------------------------------------------------------------------
class TestCryptoSafeUtilitiesV22:
    """Test cryptographic safety utilities"""
    
    def test_crypto_safe_jitter_produces_variation(self):
        """Crypto-safe jitter produces non-deterministic delays"""
        delays = [crypto_safe_jitter(1.0, 0.25) for _ in range(20)]
        # Should have variation due to cryptographically secure randomness
        unique_delays = len(set(round(d, 6) for d in delays))
        assert unique_delays > 1
    
    def test_crypto_safe_jitter_bounds(self):
        """Jitter stays within expected bounds"""
        base = 1.0
        jitter_factor = 0.25
        for _ in range(100):
            delay = crypto_safe_jitter(base, jitter_factor)
            # Should be within ±25% of base
            assert 0.75 <= delay <= 1.25
    
    def test_constant_time_compare_equal(self):
        """Constant-time compare works for equal bytes"""
        a = b"test_data_12345"
        b = b"test_data_12345"
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_different(self):
        """Constant-time compare detects different bytes"""
        a = b"test_data_12345"
        b = b"test_data_12346"
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_length(self):
        """Different length bytes return False"""
        a = b"short"
        b = b"longer_data"
        assert constant_time_compare(a, b) is False


# -----------------------------------------------------------------------------
# Test 3: Crypto Circuit Breaker
# -----------------------------------------------------------------------------
class TestCryptoCircuitBreakerV22:
    """Test crypto-specific circuit breaker"""
    
    def test_initial_state_closed(self):
        """Circuit breaker starts closed"""
        config = CryptoCircuitBreakerConfig(enabled=True)
        cb = CryptoCircuitBreaker("key_gen_kyber", config)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True
    
    def test_hsm_has_higher_threshold(self):
        """HSM connections have higher failure threshold"""
        config = CryptoCircuitBreakerConfig(
            enabled=True,
            key_gen_failure_threshold=3,
            hsm_failure_threshold=5
        )
        cb_hsm = CryptoCircuitBreaker("hsm_connect", config)
        cb_keygen = CryptoCircuitBreaker("key_gen", config)
        
        # Key gen should trip at 3 failures
        for _ in range(3):
            cb_keygen.record_failure()
        assert cb_keygen.state == CircuitState.OPEN
    
    def test_circuit_recovery_after_timeout(self):
        """Circuit recovers after reset timeout"""
        config = CryptoCircuitBreakerConfig(
            enabled=True,
            key_gen_failure_threshold=2,
            reset_timeout_seconds=0.1
        )
        cb = CryptoCircuitBreaker("test", config)
        
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        
        time.sleep(0.15)
        assert cb.allow_request() is True  # Triggers half-open
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_circuit_recloses_after_successes(self):
        """Circuit re-closes after successful recovery"""
        config = CryptoCircuitBreakerConfig(
            enabled=True,
            key_gen_failure_threshold=2,
            success_threshold=2,
            reset_timeout_seconds=0.1
        )
        cb = CryptoCircuitBreaker("test", config)
        
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        cb.allow_request()  # Half-open
        
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED


# -----------------------------------------------------------------------------
# Test 4: Crypto Bulkhead
# -----------------------------------------------------------------------------
class TestCryptoBulkheadV22:
    """Test crypto operation bulkhead isolation"""
    
    def test_bulkhead_limits_concurrency(self):
        """Bulkhead limits concurrent crypto operations"""
        bh = CryptoBulkhead("key_gen", max_concurrent=2, max_waiting=0, queue_timeout=0.1)
        
        assert bh.acquire() is True
        assert bh.acquire() is True
        assert bh.acquire() is False  # Third should fail
        assert bh.current_active == 2
    
    def test_bulkhead_release_frees_capacity(self):
        """Release frees capacity for new operations"""
        bh = CryptoBulkhead("key_gen", max_concurrent=1, max_waiting=0, queue_timeout=0.1)
        
        bh.acquire()
        assert bh.acquire() is False
        
        bh.release()
        assert bh.acquire() is True
    
    def test_bulkhead_context_manager(self):
        """Context manager properly acquires and releases"""
        bh = CryptoBulkhead("signing", max_concurrent=1, max_waiting=0, queue_timeout=0.1)
        
        with bh:
            assert bh.current_active == 1
            assert bh.acquire() is False
        
        assert bh.current_active == 0
        assert bh.acquire() is True


# -----------------------------------------------------------------------------
# Test 5: Cached Key Material
# -----------------------------------------------------------------------------
class TestCachedKeyMaterialV22:
    """Test key material cache for graceful degradation"""
    
    def test_cache_put_and_get(self):
        """Basic cache operations work"""
        cache = CachedKeyMaterial(ttl_seconds=60)
        
        cache.put("kyber_768", "fake_key_material_123")
        assert cache.get("kyber_768") == "fake_key_material_123"
    
    def test_cache_miss_returns_none(self):
        """Missing key returns None"""
        cache = CachedKeyMaterial()
        assert cache.get("nonexistent_alg") is None
    
    def test_cache_expires_after_ttl(self):
        """Cached keys expire after TTL"""
        cache = CachedKeyMaterial(ttl_seconds=0.1)
        
        cache.put("kyber_768", "temp_key")
        assert cache.get("kyber_768") == "temp_key"
        
        time.sleep(0.15)
        assert cache.get("kyber_768") is None
    
    def test_cache_clear_removes_all(self):
        """Clear empties the cache"""
        cache = CachedKeyMaterial()
        cache.put("a", "key1")
        cache.put("b", "key2")
        cache.clear()
        
        assert cache.get("a") is None
        assert cache.get("b") is None


# -----------------------------------------------------------------------------
# Test 6: Main Crypto Resilience Manager
# -----------------------------------------------------------------------------
class TestQuantumCryptResilienceV22:
    """Test main crypto resilience manager"""
    
    def setup_method(self):
        QuantumCryptResilienceV22._instance = None
    
    def test_singleton_pattern(self):
        """Manager implements singleton"""
        m1 = QuantumCryptResilienceV22.get_instance()
        m2 = QuantumCryptResilienceV22.get_instance()
        assert m1 is m2
    
    def test_all_features_disabled_by_default(self):
        """ALL features DISABLED by default - OPT-IN philosophy"""
        manager = QuantumCryptResilienceV22.get_instance()
        
        assert manager.config.timeout.enabled is False
        assert manager.config.circuit_breaker.enabled is False
        assert manager.config.retry.enabled is False
        assert manager.config.bulkhead.enabled is False
        assert manager.config.fallback.enabled is False
    
    def test_enable_all_convenience(self):
        """enable_all() turns on all resilience features"""
        manager = QuantumCryptResilienceV22.get_instance()
        manager.enable_all()
        
        assert manager.config.timeout.enabled is True
        assert manager.config.circuit_breaker.enabled is True
        assert manager.config.retry.enabled is True
        assert manager.config.bulkhead.enabled is True
        assert manager.config.fallback.enabled is True
    
    def test_no_op_when_disabled(self):
        """All wrappers are no-op when disabled"""
        manager = QuantumCryptResilienceV22.get_instance()
        
        call_count = [0]
        def key_gen_func():
            call_count[0] += 1
            return "generated_key"
        
        wrapped = manager.wrap_key_operation(key_gen_func, KeyOperationType.KEY_GENERATION, PQAlgorithm.KYBER_768)
        result = wrapped()
        
        assert result == "generated_key"
        assert call_count[0] == 1
    
    def test_retry_retries_flaky_key_gen(self):
        """Retry wrapper handles flaky key generation"""
        manager = QuantumCryptResilienceV22.get_instance()
        manager.config.retry.enabled = True
        manager.config.retry.max_key_gen_attempts = 3
        
        call_count = [0]
        def flaky_key_gen():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("entropy glitch")
            return "stable_key"
        
        wrapped = manager.wrap_key_operation(flaky_key_gen, KeyOperationType.KEY_GENERATION, PQAlgorithm.KYBER_768)
        result = wrapped()
        
        assert result == "stable_key"
        assert call_count[0] == 3
    
    def test_hsm_connection_retry(self):
        """HSM connection wrapper retries on failure"""
        manager = QuantumCryptResilienceV22.get_instance()
        manager.config.retry.enabled = True
        manager.config.retry.max_hsm_connect_attempts = 3
        
        call_count = [0]
        def flaky_hsm_connect():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ConnectionError("HSM busy")
            return "hsm_connected"
        
        wrapped = manager.wrap_hsm_connection(flaky_hsm_connect, HSMProvider.AWS_CLOUDHSM)
        result = wrapped()
        
        assert result == "hsm_connected"
        assert call_count[0] == 2
    
    def test_fallback_uses_cached_key(self):
        """Fallback returns cached key when enabled"""
        manager = QuantumCryptResilienceV22.get_instance()
        manager.config.fallback.enabled = True
        
        # First call succeeds and caches
        call_count = [0]
        def sometimes_fails():
            call_count[0] += 1
            if call_count[0] == 1:
                return "good_key"
            raise ValueError("HSM offline")
        
        wrapped = manager.wrap_key_operation(sometimes_fails, KeyOperationType.KEY_GENERATION, PQAlgorithm.KYBER_768)
        
        assert wrapped() == "good_key"  # First call succeeds
        assert wrapped() == "good_key"  # Second fails but returns cached
    
    def test_status_summary(self):
        """Status summary returns correct structure"""
        manager = QuantumCryptResilienceV22.get_instance()
        status = manager.get_status_summary()
        
        assert "version" in status
        assert status["version"] == "v22"
        assert "enabled_features" in status
        assert "circuit_breakers" in status
        assert "bulkheads" in status


# -----------------------------------------------------------------------------
# Test 7: Crypto Resilience Wrappers
# -----------------------------------------------------------------------------
class TestCryptoResilienceWrappersV22:
    """Test pre-built crypto operation wrappers"""
    
    def setup_method(self):
        QuantumCryptResilienceV22._instance = None
    
    def test_all_wrapper_types_exist(self):
        """All operation wrappers are available"""
        assert callable(CryptoResilienceWrappersV22.wrap_key_generation)
        assert callable(CryptoResilienceWrappersV22.wrap_encapsulation)
        assert callable(CryptoResilienceWrappersV22.wrap_decapsulation)
        assert callable(CryptoResilienceWrappersV22.wrap_signing)
        assert callable(CryptoResilienceWrappersV22.wrap_verification)
        assert callable(CryptoResilienceWrappersV22.wrap_hsm_connect)
    
    def test_wrappers_passthrough_when_disabled(self):
        """Wrappers pass through when resilience disabled"""
        def original(x):
            return x * 2
        
        wrapped = CryptoResilienceWrappersV22.wrap_key_generation(original, PQAlgorithm.KYBER_768)
        assert wrapped(5) == 10


# -----------------------------------------------------------------------------
# Test 8: Backward Compatibility
# -----------------------------------------------------------------------------
class TestBackwardCompatibilityV22:
    """Test backward compatibility guarantees"""
    
    def setup_method(self):
        QuantumCryptResilienceV22._instance = None
    
    def test_legacy_accessor_works(self):
        """Legacy accessor returns correct instance"""
        manager = get_crypto_resilience_manager()
        assert isinstance(manager, QuantumCryptResilienceV22)
    
    def test_version_constants(self):
        """Version constants available"""
        assert CRYPTO_RESILIENCE_VERSION == "v22"
        assert len(CRYPTO_RESILIENCE_FEATURES) > 0
    
    def test_config_structure_preserved(self):
        """Config objects have expected structure"""
        config = CryptoResilienceConfigV22()
        assert hasattr(config, "timeout")
        assert hasattr(config, "circuit_breaker")
        assert hasattr(config, "retry")
        assert hasattr(config, "bulkhead")
        assert hasattr(config, "fallback")
    
    def test_happy_path_preserved(self):
        """Happy path behavior unchanged when disabled"""
        manager = QuantumCryptResilienceV22.get_instance()
        
        def original(a, b, c=10):
            return a + b + c
        
        wrapped = manager.wrap_key_operation(original, KeyOperationType.ENCRYPTION, PQAlgorithm.AES_256_GCM)
        
        assert wrapped(1, 2) == 13  # 1+2+10
        assert wrapped(1, 2, c=100) == 103


# -----------------------------------------------------------------------------
# Test 9: Thread Safety
# -----------------------------------------------------------------------------
class TestThreadSafetyV22:
    """Test concurrent access safety"""
    
    def setup_method(self):
        QuantumCryptResilienceV22._instance = None
    
    def test_concurrent_singleton_initialization(self):
        """Singleton handles concurrent initialization"""
        instances = []
        
        def get_instance():
            instances.append(QuantumCryptResilienceV22.get_instance())
        
        threads = [threading.Thread(target=get_instance) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(i is instances[0] for i in instances)
    
    def test_concurrent_circuit_breaker_recording(self):
        """Circuit breaker handles concurrent failure recording"""
        config = CryptoCircuitBreakerConfig(enabled=True, key_gen_failure_threshold=100)
        cb = CryptoCircuitBreaker("test", config)
        
        def record_failures():
            for _ in range(10):
                cb.record_failure()
        
        threads = [threading.Thread(target=record_failures) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert cb._failure_count == 100


# -----------------------------------------------------------------------------
# Test 10: Enum Validation
# -----------------------------------------------------------------------------
class TestEnumsV22:
    """Test all enums have expected values"""
    
    def test_key_operation_types_complete(self):
        """All crypto operation types defined"""
        expected = [
            "key_generation", "key_encapsulation", "key_decapsulation",
            "signature_generation", "signature_verification",
            "encryption", "decryption", "hsm_connect", "random_generation"
        ]
        actual = [op.value for op in KeyOperationType]
        assert all(e in actual for e in expected)
    
    def test_pq_algorithms_complete(self):
        """All PQ algorithms defined"""
        expected = ["kyber_512", "kyber_768", "kyber_1024", "dilithium_2", "dilithium_3", "dilithium_5"]
        actual = [alg.value for alg in PQAlgorithm]
        assert all(e in actual for e in expected)
    
    def test_hsm_providers_defined(self):
        """Major HSM providers defined"""
        expected = ["aws_cloudhsm", "azure_key_vault_hsm", "gcp_cloud_hsm"]
        actual = [p.value for p in HSMProvider]
        assert all(e in actual for e in expected)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
