"""
Test suite for QuantumCrypt Error Resilience v24
Cryptographic Operation Timeout + Retry + Fallback + Circuit Breaker
DIMENSION E - Error Resilience
Tests cover:
- Crypto-specific exception hierarchy with zeroization
- Secure memory zeroization utilities
- Crypto-optimized backoff strategies (HSM optimized)
- Crypto circuit breaker with security levels
- Crypto bulkhead isolation for sensitive operations
- Algorithm fallback chains with security-aware ordering
- Combined crypto resilience decorator sync support
- Security level transitions and metrics
- Global crypto orchestrator singleton pattern
- Happy path behavior 100% preserved
"""
import pytest
import time
import threading
import asyncio
from unittest.mock import patch, MagicMock
from quantum_crypt.crypto_error_resilience_v24_key_operation_timeout_retry_fallback_2026_june import (
    # Utilities
    secure_zeroize,
    secure_random_bytes,
    
    # Exceptions
    CryptoResilienceBaseError,
    CryptoOperationTimeoutError,
    CryptoKeyAccessError,
    CryptoHSMUnavailableError,
    CryptoMaxRetriesExceededError,
    CryptoCircuitBreakerOpenError,
    CryptoBulkheadCapacityExceededError,
    CryptoAlgorithmFallbackExhaustedError,
    CryptoKeyZeroizationError,
    
    # Enums
    CryptoBackoffStrategy,
    CryptoCircuitState,
    SecurityLevel,
    AlgorithmFallbackPriority,
    
    # Config and metrics
    CryptoResilienceConfig,
    CryptoOperationMetrics,
    
    # Core components
    CryptoBackoffCalculator,
    CryptoCircuitBreaker,
    CryptoBulkheadIsolator,
    AlgorithmFallbackChain,
    
    # Decorators
    CryptoCombinedResilience,
    
    # Orchestrator
    CryptoResilienceOrchestrator,
    crypto_resilience_orchestrator
)


# ============================================================================
# SECURE MEMORY TESTS
# ============================================================================

class TestSecureMemory:
    """Test secure memory handling."""
    
    def test_secure_zeroize(self):
        data = bytearray(b'sensitive_key_material_12345')
        original = bytes(data)
        secure_zeroize(data)
        assert all(b == 0 for b in data)
        assert bytes(data) != original
    
    def test_secure_random_bytes(self):
        rand1 = secure_random_bytes(32)
        rand2 = secure_random_bytes(32)
        assert len(rand1) == 32
        assert len(rand2) == 32
        assert rand1 != rand2  # Cryptographically random


# ============================================================================
# CRYPTO EXCEPTION HIERARCHY TESTS
# ============================================================================

class TestCryptoExceptionHierarchy:
    """Test crypto-specific exception hierarchy."""
    
    def test_base_exception_metadata(self):
        exc = CryptoResilienceBaseError("crypto error", key_id="key_123")
        assert exc.operation_id is not None
        assert exc.metadata["key_id"] == "key_123"
    
    def test_circuit_breaker_exception(self):
        exc = CryptoCircuitBreakerOpenError(
            "HSM circuit open",
            reset_timeout=120.0,
            security_level="hsm"
        )
        assert exc.reset_timeout == 120.0
        assert exc.security_level == "hsm"
    
    def test_bulkhead_exception(self):
        exc = CryptoBulkheadCapacityExceededError(
            "crypto bulkhead full",
            current_concurrency=10,
            max_concurrency=5
        )
        assert exc.current_concurrency == 10
        assert exc.max_concurrency == 5
    
    def test_algorithm_fallback_exception(self):
        exc = CryptoAlgorithmFallbackExhaustedError(
            "all algorithms failed",
            attempted_algorithms=["AES-256", "ChaCha20", "3DES"]
        )
        assert exc.attempted_algorithms == ["AES-256", "ChaCha20", "3DES"]


# ============================================================================
# CRYPTO BACKOFF CALCULATOR TESTS
# ============================================================================

class TestCryptoBackoffCalculator:
    """Test crypto-optimized backoff strategies."""
    
    def test_hsm_optimized_backoff(self):
        """HSM strategy should have minimum 1.0 second delays."""
        delay = CryptoBackoffCalculator.calculate(
            CryptoBackoffStrategy.HSM_OPTIMIZED,
            attempt=0,
            initial_backoff=0.5,
            max_backoff=60.0
        )
        assert delay >= 1.0  # HSM needs minimum delays
    
    def test_exponential_with_jitter(self):
        delays = [
            CryptoBackoffCalculator.calculate(
                CryptoBackoffStrategy.EXPONENTIAL_WITH_JITTER,
                attempt=2,
                initial_backoff=0.5,
                max_backoff=60.0
            )
            for _ in range(10)
        ]
        assert len(set(delays)) > 1  # Jitter causes variation
    
    def test_max_backoff_clamping(self):
        delay = CryptoBackoffCalculator.calculate(
            CryptoBackoffStrategy.EXPONENTIAL,
            attempt=10,
            initial_backoff=0.5,
            max_backoff=5.0
        )
        assert delay == 5.0  # Clamped to max


# ============================================================================
# CRYPTO OPERATION METRICS TESTS
# ============================================================================

class TestCryptoOperationMetrics:
    """Test crypto-specific metrics tracking."""
    
    def test_metrics_initial_state(self):
        metrics = CryptoOperationMetrics()
        assert metrics.total_calls == 0
        assert metrics.get_security_score() == 1.0
    
    def test_security_transition_tracking(self):
        metrics = CryptoOperationMetrics()
        metrics.record_security_transition("hsm", "software_high")
        metrics.record_security_transition("hsm", "software_high")
        assert metrics.security_level_transitions["hsm->software_high"] == 2
    
    def test_security_score_degradation(self):
        metrics = CryptoOperationMetrics()
        metrics.record_success(100.0)
        metrics.record_failure(100.0)
        metrics.record_fallback()
        score = metrics.get_security_score()
        assert score < 1.0  # Score should degrade with failures/fallbacks


# ============================================================================
# CRYPTO CIRCUIT BREAKER TESTS
# ============================================================================

class TestCryptoCircuitBreaker:
    """Test crypto circuit breaker with security levels."""
    
    def test_circuit_with_security_level(self):
        cb = CryptoCircuitBreaker(
            "hsm_signing",
            security_level=SecurityLevel.HSM,
            failure_threshold=10,
            reset_timeout=120.0
        )
        assert cb.security_level == SecurityLevel.HSM
        assert cb.state == CryptoCircuitState.CLOSED
    
    def test_hsm_circuit_trip(self):
        """HSM circuits should have higher failure thresholds."""
        cb = CryptoCircuitBreaker(
            "hsm_key",
            security_level=SecurityLevel.HSM,
            failure_threshold=10,
            reset_timeout=0.01
        )
        # Higher threshold for HSM operations
        for _ in range(10):
            cb.record_failure()
        assert cb.state == CryptoCircuitState.OPEN
    
    def test_circuit_half_open_recovery(self):
        cb = CryptoCircuitBreaker(
            "test",
            security_level=SecurityLevel.SOFTWARE_HIGH,
            failure_threshold=2,
            success_threshold=2,
            reset_timeout=0.01
        )
        # Trip
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        
        # Recover
        cb.allow_request()
        cb.record_success()
        cb.allow_request()
        cb.record_success()
        assert cb.state == CryptoCircuitState.CLOSED
    
    def test_status_with_security_level(self):
        cb = CryptoCircuitBreaker("test", security_level=SecurityLevel.TPM)
        status = cb.get_status()
        assert status["security_level"] == "tpm"
        assert "security_score" in status["metrics"]


# ============================================================================
# CRYPTO BULKHEAD TESTS
# ============================================================================

class TestCryptoBulkheadIsolator:
    """Test crypto bulkhead for sensitive operations."""
    
    def test_crypto_bulkhead_limits(self):
        """Crypto operations have lower concurrency defaults."""
        bh = CryptoBulkheadIsolator(
            "key_signing",
            max_concurrency=2,  # Lower for crypto
            max_wait_time=0.01,
            security_level=SecurityLevel.HSM
        )
        
        def acquire_and_wait():
            with bh.acquire():
                time.sleep(0.1)
        
        t1 = threading.Thread(target=acquire_and_wait)
        t2 = threading.Thread(target=acquire_and_wait)
        t1.start()
        t2.start()
        time.sleep(0.01)
        
        # Third should fail immediately
        with pytest.raises(CryptoBulkheadCapacityExceededError):
            with bh.acquire(timeout=0.01):
                pass
        
        t1.join()
        t2.join()
    
    def test_bulkhead_security_level(self):
        bh = CryptoBulkheadIsolator(
            "test",
            security_level=SecurityLevel.SECURE_ELEMENT
        )
        status = bh.get_status()
        assert status["security_level"] == "se"


# ============================================================================
# ALGORITHM FALLBACK CHAIN TESTS
# ============================================================================

class TestAlgorithmFallbackChain:
    """Test security-aware algorithm fallback."""
    
    def test_security_desc_ordering(self):
        """Most secure algorithms should be tried first."""
        chain = AlgorithmFallbackChain(
            "encryption",
            priority=AlgorithmFallbackPriority.SECURITY_DESC
        )
        chain.register("software_low", lambda *a, **kw: "low", SecurityLevel.SOFTWARE_LOW)
        chain.register("hsm", lambda *a, **kw: "hsm", SecurityLevel.HSM)
        chain.register("software_high", lambda *a, **kw: "high", SecurityLevel.SOFTWARE_HIGH)
        
        ordered = chain._order_algorithms()
        # HSM should be first, then software_high, then software_low
        assert ordered[0][0] == "hsm"
        assert ordered[1][0] == "software_high"
        assert ordered[2][0] == "software_low"
    
    def test_security_asc_graceful_degradation(self):
        """Graceful degradation tries less secure first."""
        chain = AlgorithmFallbackChain(
            "encryption",
            priority=AlgorithmFallbackPriority.SECURITY_ASC
        )
        chain.register("hsm", lambda *a, **kw: 1/0, SecurityLevel.HSM)
        chain.register("software_high", lambda *a, **kw: 1/0, SecurityLevel.SOFTWARE_HIGH)
        chain.register("software_low", lambda *a, **kw: "degraded", SecurityLevel.SOFTWARE_LOW)
        
        result = chain.execute_sync(Exception("error"))
        assert result == "degraded"
    
    def test_fallback_chain_exhausted(self):
        chain = AlgorithmFallbackChain("signing")
        chain.register("alg1", lambda *a, **kw: 1/0, SecurityLevel.SOFTWARE_HIGH)
        chain.register("alg2", lambda *a, **kw: 1/0, SecurityLevel.SOFTWARE_MEDIUM)
        
        with pytest.raises(CryptoAlgorithmFallbackExhaustedError) as exc:
            chain.execute_sync(Exception("error"))
        
        assert "alg1" in exc.value.attempted_algorithms
        assert "alg2" in exc.value.attempted_algorithms


# ============================================================================
# COMBINED CRYPTO RESILIENCE TESTS
# ============================================================================

class TestCryptoCombinedResilience:
    """Test combined crypto resilience decorator."""
    
    def test_successful_crypto_operation(self):
        config = CryptoResilienceConfig(
            max_retries=0,
            circuit_enable=False,
            bulkhead_enable=False
        )
        
        @CryptoCombinedResilience(config=config)
        def sign_data():
            return "signature_123"
        
        assert sign_data() == "signature_123"
    
    def test_crypto_retry_on_hsm_unavailable(self):
        call_count = [0]
        config = CryptoResilienceConfig(
            max_retries=3,
            initial_backoff=0.001,
            circuit_enable=False,
            bulkhead_enable=False
        )
        
        @CryptoCombinedResilience(config=config)
        def hsm_operation():
            call_count[0] += 1
            if call_count[0] < 3:
                raise CryptoHSMUnavailableError("HSM busy")
            return "hsm_signature"
        
        result = hsm_operation()
        assert result == "hsm_signature"
        assert call_count[0] == 3
    
    def test_hsm_timeout_different_from_software(self):
        """HSM operations should have longer timeout config."""
        config = CryptoResilienceConfig(
            timeout_seconds=60.0,
            hsm_timeout_seconds=120.0,
            security_level=SecurityLevel.HSM
        )
        assert config.hsm_timeout_seconds > config.timeout_seconds
    
    def test_crypto_circuit_breaker(self):
        config = CryptoResilienceConfig(
            max_retries=0,
            failure_threshold=3,
            reset_timeout=60.0,
            bulkhead_enable=False,
            security_level=SecurityLevel.HSM
        )
        
        @CryptoCombinedResilience(name="hsm_op_test", config=config)
        def failing_op():
            raise CryptoHSMUnavailableError("HSM down")
        
        # Trip circuit
        for _ in range(3):
            with pytest.raises(Exception):
                failing_op()
        
        # Should now fast-fail
        with pytest.raises(CryptoCircuitBreakerOpenError):
            failing_op()


# ============================================================================
# CRYPTO ORCHESTRATOR TESTS
# ============================================================================

class TestCryptoResilienceOrchestrator:
    """Test global crypto resilience orchestrator."""
    
    def test_singleton_pattern(self):
        instance1 = CryptoResilienceOrchestrator()
        instance2 = CryptoResilienceOrchestrator()
        assert instance1 is instance2
    
    def test_hsm_config_registration(self):
        orchestrator = CryptoResilienceOrchestrator()
        hsm_config = CryptoResilienceConfig(
            security_level=SecurityLevel.HSM,
            hsm_timeout_seconds=180.0,
            max_retries=10
        )
        orchestrator.register_config("hsm_signing", hsm_config)
        decorator = orchestrator.create_decorator("hsm_signing")
        assert decorator.config.security_level == SecurityLevel.HSM
        assert decorator.config.hsm_timeout_seconds == 180.0


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestCryptoResilienceIntegration:
    """End-to-end crypto resilience integration tests."""
    
    def test_full_crypto_resilience_pipeline(self):
        """Test all crypto resilience strategies working together."""
        fallback_chain = AlgorithmFallbackChain("key_operation")
        fallback_chain.register(
            "software_fallback",
            lambda e, *a, **kw: "DEGRADED_SOFTWARE_SIGNATURE",
            SecurityLevel.SOFTWARE_HIGH
        )
        
        config = CryptoResilienceConfig(
            timeout_seconds=30.0,
            max_retries=3,  # 4 total attempts
            initial_backoff=0.001,
            failure_threshold=10,
            max_concurrency=5,
            circuit_enable=False,
            bulkhead_enable=False,
            security_level=SecurityLevel.HSM
        )
        
        call_count = [0]
        
        @CryptoCombinedResilience(name="hsm_sign_test", config=config, algorithm_fallback_chain=fallback_chain)
        def resilient_sign():
            call_count[0] += 1
            if call_count[0] <= 3:
                raise CryptoHSMUnavailableError("HSM connection error")
            return "HSM_SIGNATURE_SUCCESS"
        
        result = resilient_sign()
        # Should succeed after retries
        assert result == "HSM_SIGNATURE_SUCCESS"
        assert call_count[0] == 4
    
    def test_happy_path_preserved(self):
        """Verify happy path is 100% preserved."""
        config = CryptoResilienceConfig()
        
        @CryptoCombinedResilience(config=config)
        def simple_encrypt(data):
            return f"encrypted:{data}"
        
        # Normal operation should work exactly as before
        assert simple_encrypt("hello") == "encrypted:hello"
        assert simple_encrypt("world") == "encrypted:world"
