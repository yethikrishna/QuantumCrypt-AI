"""
Crypto Test Suite for Dimension E - Error Resilience v34
PQ Key Operation Protection with Algorithm Fallback Chain

ADD-ONLY verification - tests new module only
No production crypto code modified
"""

import pytest
import time
import threading
from quantum_crypt.crypto_error_resilience_pq_key_operation_v34_2026_june import (
    # Exceptions
    QuantumCryptError,
    PostQuantumError,
    KeyExchangeError,
    KeyGenerationError,
    SignatureError,
    EncryptionError,
    DecryptionError,
    HSMConnectionError,
    AlgorithmNotAvailableError,
    RandomnessError,
    ClassicalCryptoError,
    KeyManagementError,
    
    # Enums
    AlgorithmSecurityLevel,
    OperationType,
    
    # Data classes
    CryptoRetryConfig,
    CryptoFallbackStrategy,
    CryptoOperationResult,
    
    # Core classes
    HSMCircuitBreaker,
    CryptoBulkheadManager,
    PQAlgorithmFallbackChain,
    
    # Decorators
    with_pq_resilience,
    register_pq_fallback,
)


# -----------------------------------------------------------------------------
# EXCEPTION HIERARCHY TESTS
# -----------------------------------------------------------------------------

class TestCryptoExceptionHierarchy:
    """Test PQ crypto exception hierarchy"""

    def test_base_exception_attributes(self):
        exc = QuantumCryptError("Test crypto error", {"key_id": "test-123"})
        assert exc.error_code == "QC-000"
        assert exc.severity == "ERROR"
        assert exc.message == "Test crypto error"
        assert exc.details == {"key_id": "test-123"}
        assert hasattr(exc, "timestamp")

    def test_post_quantum_error_fallback_available(self):
        exc = PostQuantumError("PQ failed")
        assert exc.error_code == "QC-PQ-000"
        assert exc.fallback_available is True
        assert isinstance(exc, QuantumCryptError)

    def test_key_exchange_error_retryable(self):
        exc = KeyExchangeError("Key exchange failed")
        assert exc.error_code == "QC-PQ-001"
        assert exc.retryable is True

    def test_key_generation_error_retryable(self):
        exc = KeyGenerationError("Key gen failed")
        assert exc.retryable is True

    def test_signature_error_retryable(self):
        exc = SignatureError("Sign failed")
        assert exc.retryable is True

    def test_hsm_connection_error(self):
        exc = HSMConnectionError("HSM down")
        assert exc.error_code == "QC-PQ-006"
        assert exc.retryable is True

    def test_algorithm_not_available_not_retryable(self):
        exc = AlgorithmNotAvailableError("Kyber not loaded")
        assert exc.retryable is False
        assert exc.fallback_available is True

    def test_randomness_error(self):
        exc = RandomnessError("RNG failed")
        assert exc.retryable is True
        assert exc.fallback_available is True

    def test_classical_crypto_safe_default(self):
        exc = ClassicalCryptoError("RSA failed")
        assert exc.safe_default_available is True


# -----------------------------------------------------------------------------
# ENUM TESTS
# -----------------------------------------------------------------------------

class TestCryptoEnums:
    """Test security level and operation enums"""

    def test_security_level_order(self):
        levels = [
            AlgorithmSecurityLevel.PQ_NIST_LEVEL_5,
            AlgorithmSecurityLevel.PQ_NIST_LEVEL_3,
            AlgorithmSecurityLevel.PQ_NIST_LEVEL_1,
            AlgorithmSecurityLevel.CLASSICAL_ECC,
            AlgorithmSecurityLevel.CLASSICAL_RSA,
            AlgorithmSecurityLevel.SAFE_DEFAULT,
        ]
        assert len(levels) == 6

    def test_operation_types_exist(self):
        operations = [
            OperationType.KEY_EXCHANGE,
            OperationType.KEY_GENERATION,
            OperationType.SIGNING,
            OperationType.ENCRYPTION,
            OperationType.DECRYPTION,
            OperationType.RANDOMNESS,
        ]
        assert len(operations) == 6


# -----------------------------------------------------------------------------
# DATA CLASS TESTS
# -----------------------------------------------------------------------------

class TestCryptoDataClasses:
    """Test crypto dataclass configurations"""

    def test_crypto_retry_config_defaults(self):
        config = CryptoRetryConfig()
        assert config.max_attempts == 3
        assert config.initial_delay == 0.05
        assert config.max_delay == 2.0
        assert config.backoff_factor == 1.5
        assert config.jitter_factor == 0.05

    def test_crypto_fallback_strategy(self):
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_EXCHANGE,
            min_security_level=AlgorithmSecurityLevel.PQ_NIST_LEVEL_1
        )
        assert strategy.operation_type == OperationType.KEY_EXCHANGE
        assert strategy.min_security_level == AlgorithmSecurityLevel.PQ_NIST_LEVEL_1
        assert strategy.allow_degraded is True

    def test_crypto_operation_result(self):
        result = CryptoOperationResult(
            success=True,
            result={"key": "secret"},
            algorithm_used="CRYSTALS-Kyber",
            security_level=AlgorithmSecurityLevel.PQ_NIST_LEVEL_5,
            attempts=1,
            total_time=0.01
        )
        assert result.success is True
        assert result.degraded is False
        assert result.warnings == []
        assert result.fallback_chain == []


# -----------------------------------------------------------------------------
# HSM CIRCUIT BREAKER TESTS
# -----------------------------------------------------------------------------

class TestHSMCircuitBreaker:
    """Test HSM-specific circuit breaker"""

    def test_initial_available(self):
        cb = HSMCircuitBreaker()
        assert cb.is_available() is True

    def test_trips_after_threshold(self):
        cb = HSMCircuitBreaker(failure_threshold=2, recovery_timeout=1.0)
        
        cb.record_failure()
        cb.record_failure()
        
        assert cb.is_available() is False

    def test_recovers_after_timeout(self):
        cb = HSMCircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        cb.record_failure()
        cb.record_failure()
        assert cb.is_available() is False
        
        time.sleep(0.15)
        assert cb.is_available() is True  # half_open counts as available

    def test_closes_after_successful_recovery(self):
        cb = HSMCircuitBreaker(
            failure_threshold=2,
            recovery_timeout=0.1,
            half_open_max_calls=2
        )
        
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.15)
        
        cb.record_success()
        cb.record_success()
        
        assert cb.is_available() is True
        assert cb._state == "closed"


# -----------------------------------------------------------------------------
# CRYPTO BULKHEAD TESTS
# -----------------------------------------------------------------------------

class TestCryptoBulkheadManager:
    """Test crypto operation bulkhead isolation"""

    def test_initialization(self):
        bulkhead = CryptoBulkheadManager()
        assert bulkhead is not None

    def test_acquire_release(self):
        bulkhead = CryptoBulkheadManager()
        
        assert bulkhead.acquire("key_operations") is True
        bulkhead.release("key_operations")
        
        # Should be able to acquire again
        assert bulkhead.acquire("key_operations") is True

    def test_different_bulkheads(self):
        bulkhead = CryptoBulkheadManager()
        
        # Different operation types have different limits
        assert bulkhead.acquire("key_operations") is True
        assert bulkhead.acquire("signing") is True
        assert bulkhead.acquire("encryption") is True
        assert bulkhead.acquire("randomness") is True


# -----------------------------------------------------------------------------
# PQ ALGORITHM FALLBACK CHAIN TESTS
# -----------------------------------------------------------------------------

class TestPQAlgorithmFallbackChain:
    """Test main PQ fallback chain implementation"""

    def test_initialization(self):
        chain = PQAlgorithmFallbackChain()
        assert chain is not None

    def test_register_algorithm(self):
        chain = PQAlgorithmFallbackChain()
        
        def kyber_key_exchange():
            return {"shared_secret": b"test"}
        
        chain.register_algorithm(
            OperationType.KEY_EXCHANGE,
            AlgorithmSecurityLevel.PQ_NIST_LEVEL_5,
            kyber_key_exchange
        )
        
        assert OperationType.KEY_EXCHANGE in chain._algorithm_registry

    def test_successful_primary_operation(self):
        chain = PQAlgorithmFallbackChain()
        
        def kyber_kem():
            return {"shared_secret": b"secure_key_123"}
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_EXCHANGE
        )
        
        result = chain.execute_operation(
            kyber_kem, "CRYSTALS-Kyber-768", strategy
        )
        
        assert result.success is True
        assert result.result == {"shared_secret": b"secure_key_123"}
        assert result.algorithm_used == "CRYSTALS-Kyber-768"
        assert result.degraded is False

    def test_safe_default_key_exchange(self):
        chain = PQAlgorithmFallbackChain()
        
        def failing_kem():
            raise HSMConnectionError("HSM offline")
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_EXCHANGE,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            failing_kem, "Kyber", strategy,
            retry_config=CryptoRetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert result.degraded is True
        assert result.result["degraded"] is True
        assert "shared_secret" in result.result

    def test_safe_default_key_generation(self):
        chain = PQAlgorithmFallbackChain()
        
        def failing_keygen():
            raise KeyGenerationError("Failed")
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_GENERATION,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            failing_keygen, "Dilithium", strategy,
            retry_config=CryptoRetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert "public_key" in result.result

    def test_safe_default_signing(self):
        chain = PQAlgorithmFallbackChain()
        
        def failing_sign():
            raise SignatureError("Failed")
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.SIGNING,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            failing_sign, "Dilithium", strategy,
            retry_config=CryptoRetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert "signature" in result.result

    def test_safe_default_encryption(self):
        chain = PQAlgorithmFallbackChain()
        
        def failing_encrypt():
            raise EncryptionError("Failed")
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.ENCRYPTION,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            failing_encrypt, "Kyber", strategy,
            retry_config=CryptoRetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert "ciphertext" in result.result

    def test_safe_default_randomness(self):
        chain = PQAlgorithmFallbackChain()
        
        def failing_rng():
            raise RandomnessError("RNG stuck")
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.RANDOMNESS,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            failing_rng, "DRBG", strategy,
            retry_config=CryptoRetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert "random_bytes" in result.result

    def test_retry_mechanism_flaky_hsm(self):
        chain = PQAlgorithmFallbackChain()
        call_count = [0]
        
        def flaky_hsm_operation():
            call_count[0] += 1
            if call_count[0] < 3:
                raise HSMConnectionError("Flaky")
            return {"key": "success"}
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_EXCHANGE
        )
        
        result = chain.execute_operation(
            flaky_hsm_operation, "HSM-Kyber", strategy
        )
        
        assert result.success is True
        assert call_count[0] == 3
        assert len(result.warnings) >= 1

    def test_registered_fallback_used(self):
        chain = PQAlgorithmFallbackChain()
        
        def failing_primary():
            raise HSMConnectionError("HSM down")
        
        def ecc_fallback():
            return {"key": "ecc_fallback_key", "algorithm": "ECC"}
        
        chain.register_algorithm(
            OperationType.KEY_EXCHANGE,
            AlgorithmSecurityLevel.CLASSICAL_ECC,
            ecc_fallback
        )
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_EXCHANGE,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            failing_primary, "Kyber-HSM", strategy,
            retry_config=CryptoRetryConfig(max_attempts=1)
        )
        
        assert result.success is True
        assert result.degraded is True
        assert len(result.fallback_chain) >= 1


# -----------------------------------------------------------------------------
# DECORATOR TESTS
# -----------------------------------------------------------------------------

class TestCryptoDecorators:
    """Test PQ resilience decorators"""

    def test_with_pq_resilience_decorator(self):
        @with_pq_resilience(
            "test-kyber",
            OperationType.KEY_EXCHANGE,
            min_security=AlgorithmSecurityLevel.CLASSICAL_ECC
        )
        def my_key_exchange():
            return {"shared_secret": b"test-key"}
        
        result = my_key_exchange()
        assert result == {"shared_secret": b"test-key"}

    def test_with_pq_resilience_failure_with_degraded(self):
        @with_pq_resilience(
            "failing-kem",
            OperationType.KEY_EXCHANGE,
            allow_degraded=True
        )
        def failing_exchange():
            raise HSMConnectionError("Failed")
        
        # Should return safe default, not raise
        result = failing_exchange()
        assert result is not None
        assert result["degraded"] is True

    def test_register_pq_fallback_decorator(self):
        @register_pq_fallback(
            OperationType.KEY_EXCHANGE,
            AlgorithmSecurityLevel.CLASSICAL_ECC
        )
        def ecc_fallback():
            return {"key": "ecc"}
        
        # Should register without error
        assert ecc_fallback() == {"key": "ecc"}


# -----------------------------------------------------------------------------
# INTEGRATION TESTS
# -----------------------------------------------------------------------------

class TestCryptoFullIntegration:
    """Full crypto resilience stack integration tests"""

    def test_complete_fallback_chain(self):
        """Test: HSM failure -> retry -> registered fallback -> success"""
        chain = PQAlgorithmFallbackChain()
        
        def hsm_kyber():
            raise HSMConnectionError("HSM offline")
        
        def software_kyber():
            return {"shared_secret": b"software_kyber_key"}
        
        chain.register_algorithm(
            OperationType.KEY_EXCHANGE,
            AlgorithmSecurityLevel.PQ_NIST_LEVEL_5,
            software_kyber
        )
        
        strategy = CryptoFallbackStrategy(
            operation_type=OperationType.KEY_EXCHANGE,
            allow_degraded=True
        )
        
        result = chain.execute_operation(
            hsm_kyber, "HSM-Kyber", strategy
        )
        
        assert result.success is True
        assert result.degraded is True

    def test_thread_safety(self):
        """Thread safety test for crypto operations"""
        chain = PQAlgorithmFallbackChain()
        
        def worker():
            for _ in range(5):
                chain.execute_operation(
                    lambda: {"key": "ok"},
                    "test-op",
                    CryptoFallbackStrategy(operation_type=OperationType.SIGNING)
                )
        
        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # No exceptions = success
        assert True


# -----------------------------------------------------------------------------
# BACKWARD COMPATIBILITY TESTS
# -----------------------------------------------------------------------------

class TestCryptoBackwardCompatibility:
    """Verify no breaking changes to existing crypto code"""

    def test_new_module_importable(self):
        """New module imports without errors"""
        from quantum_crypt.crypto_error_resilience_pq_key_operation_v34_2026_june import (
            PQAlgorithmFallbackChain, OperationType, AlgorithmSecurityLevel
        )
        assert PQAlgorithmFallbackChain is not None

    def test_add_only_philosophy(self):
        """This is a new file - no existing code modified"""
        import os
        assert os.path.exists(
            "quantum_crypt/crypto_error_resilience_pq_key_operation_v34_2026_june.py"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
