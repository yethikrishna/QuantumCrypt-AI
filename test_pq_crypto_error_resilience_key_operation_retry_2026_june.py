"""
Tests for Post-Quantum Crypto Error Resilience Module - Dimension E
Crypto-specific retry, timeout, circuit breaker, and fallback mechanisms
"""

import pytest
import time
import threading

from quantum_crypt.pq_crypto_error_resilience_key_operation_retry_2026_june import (
    CryptoErrorCategory,
    CryptoResilienceError,
    CryptoOperationTimeoutError,
    CryptoMaxRetriesExceededError,
    CryptoAlgorithmFallbackError,
    KeyRotationRecoveryError,
    CryptoRetryConfig,
    CryptoOperationResult,
    CryptoExponentialBackoff,
    CryptoOperationCircuitBreaker,
    AlgorithmFallbackChain,
    KeyRotationRecoveryManager,
    with_crypto_retry,
    with_crypto_timeout,
    get_crypto_circuit_breaker,
    get_key_rotation_manager,
    get_crypto_resilience_metrics,
)


class TestCryptoExponentialBackoff:
    """Tests for crypto-optimized backoff."""
    
    def test_initial_delay(self):
        backoff = CryptoExponentialBackoff(initial_delay=0.05)
        delay = backoff.calculate_delay(0)
        assert 0.0375 <= delay <= 0.0625  # With secure jitter
    
    def test_no_jitter(self):
        backoff = CryptoExponentialBackoff(initial_delay=0.05, secure_jitter=False)
        delay = backoff.calculate_delay(0)
        assert delay == 0.05
    
    def test_max_delay_enforced(self):
        backoff = CryptoExponentialBackoff(initial_delay=0.05, max_delay=1.0, secure_jitter=False)
        delay = backoff.calculate_delay(10)
        assert delay == 1.0


class TestCryptoOperationCircuitBreaker:
    """Tests for crypto-specific circuit breaker."""
    
    def test_initial_state_closed(self):
        cb = CryptoOperationCircuitBreaker()
        assert cb.get_state() == "closed"
        assert cb.allow_request() is True
    
    def test_transition_to_open(self):
        cb = CryptoOperationCircuitBreaker(failure_threshold=3)
        
        cb.record_failure()
        cb.record_failure()
        assert cb.get_state() == "closed"
        
        cb.record_failure()
        assert cb.get_state() == "open"
        assert cb.allow_request() is False
    
    def test_half_open_recovery(self):
        cb = CryptoOperationCircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1
        )
        
        cb.record_failure()
        assert cb.get_state() == "open"
        
        time.sleep(0.15)
        assert cb.get_state() == "half_open"
        assert cb.allow_request() is True
    
    def test_success_closes_circuit(self):
        cb = CryptoOperationCircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1
        )
        
        cb.record_failure()
        time.sleep(0.15)
        
        # First allow a request to trigger state transition to half-open
        cb.allow_request()
        cb.record_success()
        cb.record_success()  # Need 2 successes
        assert cb.get_state() == "closed"
    
    def test_per_algorithm_tracking(self):
        cb = CryptoOperationCircuitBreaker()
        cb.record_failure(algorithm="CRYSTALS-Kyber")
        cb.record_failure(algorithm="CRYSTALS-Kyber")
        
        metrics = cb.get_metrics()
        assert "CRYSTALS-Kyber" in metrics["algorithm_failures"]
        assert metrics["algorithm_failures"]["CRYSTALS-Kyber"] == 2
    
    def test_get_metrics(self):
        cb = CryptoOperationCircuitBreaker()
        metrics = cb.get_metrics()
        assert "state" in metrics
        assert "global_failure_count" in metrics
        assert "algorithm_failures" in metrics


class TestCryptoRetryDecorator:
    """Tests for @with_crypto_retry decorator."""
    
    def test_succeeds_immediately(self):
        call_count = [0]
        
        @with_crypto_retry(category=CryptoErrorCategory.ENCRYPTION)
        def encrypt():
            call_count[0] += 1
            return "ciphertext"
        
        result = encrypt()
        assert result == "ciphertext"
        assert call_count[0] == 1
    
    def test_retries_temporary_failures(self):
        call_count = [0]
        
        @with_crypto_retry(category=CryptoErrorCategory.KEY_GENERATION)
        def generate_key():
            call_count[0] += 1
            if call_count[0] < 3:
                raise RuntimeError("RNG busy")
            return "keypair"
        
        result = generate_key()
        assert result == "keypair"
        assert call_count[0] == 3
    
    def test_max_retries_exceeded(self):
        call_count = [0]
        
        @with_crypto_retry(
            config=CryptoRetryConfig(max_attempts=2),
            category=CryptoErrorCategory.ENCRYPTION
        )
        def always_fails():
            call_count[0] += 1
            raise RuntimeError("HSM error")
        
        with pytest.raises(CryptoMaxRetriesExceededError):
            always_fails()
        
        assert call_count[0] == 2
    
    def test_no_retry_for_signing(self):
        """Signing/verification should NOT be retried - deterministic operations."""
        call_count = [0]
        
        @with_crypto_retry(category=CryptoErrorCategory.SIGNING)
        def sign():
            call_count[0] += 1
            raise RuntimeError("signing error")
        
        with pytest.raises(CryptoResilienceError):
            sign()
        
        assert call_count[0] == 1  # Only called once, no retries


class TestCryptoTimeoutDecorator:
    """Tests for @with_crypto_timeout decorator."""
    
    def test_fast_operation_succeeds(self):
        @with_crypto_timeout(1.0, category=CryptoErrorCategory.ENCRYPTION)
        def fast_encrypt():
            return "fast"
        
        result = fast_encrypt()
        assert result == "fast"
    
    def test_slow_operation_times_out(self):
        @with_crypto_timeout(0.1, category=CryptoErrorCategory.KEY_GENERATION)
        def slow_keygen():
            time.sleep(1.0)
            return "key"
        
        with pytest.raises(CryptoOperationTimeoutError):
            slow_keygen()
    
    def test_timeout_with_fallback(self):
        def fallback():
            return "fallback_key"
        
        @with_crypto_timeout(0.1, category=CryptoErrorCategory.KEY_GENERATION, fallback=fallback)
        def slow_keygen():
            time.sleep(1.0)
            return "key"
        
        result = slow_keygen()
        assert result == "fallback_key"


class TestAlgorithmFallbackChain:
    """Tests for algorithm fallback chain."""
    
    def test_primary_succeeds(self):
        def primary():
            return "pq_encrypted"
        
        chain = AlgorithmFallbackChain("CRYSTALS-Kyber", primary)
        result = chain()
        
        assert result.success is True
        assert result.result == "pq_encrypted"
        assert result.algorithm == "CRYSTALS-Kyber"
        assert result.used_fallback is False
    
    def test_fallback_used_when_primary_fails(self):
        def primary():
            raise RuntimeError("PQ algorithm failed")
        
        def fallback():
            return "classic_encrypted"
        
        chain = AlgorithmFallbackChain(
            "CRYSTALS-Kyber",
            primary,
            ("RSA-OAEP", fallback)
        )
        
        result = chain()
        assert result.success is True
        assert result.result == "classic_encrypted"
        assert result.algorithm == "RSA-OAEP"
        assert result.used_fallback is True
    
    def test_multiple_fallbacks(self):
        def primary():
            raise RuntimeError("fail1")
        
        def fallback1():
            raise RuntimeError("fail2")
        
        def fallback2():
            return "success"
        
        chain = AlgorithmFallbackChain(
            "ALGO1", primary,
            ("ALGO2", fallback1),
            ("ALGO3", fallback2)
        )
        
        result = chain()
        assert result.success is True
        assert result.algorithm == "ALGO3"
    
    def test_all_fallbacks_fail(self):
        def primary():
            raise RuntimeError("fail1")
        
        def fallback():
            raise RuntimeError("fail2")
        
        chain = AlgorithmFallbackChain("ALGO1", primary, ("ALGO2", fallback))
        
        with pytest.raises(CryptoAlgorithmFallbackError):
            chain()


class TestKeyRotationRecoveryManager:
    """Tests for key rotation recovery manager."""
    
    def test_backup_and_retrieve(self):
        manager = KeyRotationRecoveryManager()
        manager.backup_key("key-001", "old_key_data")
        
        backup = manager.get_backup("key-001")
        assert backup == "old_key_data"
    
    def test_commit_removes_backup(self):
        manager = KeyRotationRecoveryManager()
        manager.backup_key("key-001", "old_key_data")
        manager.commit_rotation("key-001")
        
        backup = manager.get_backup("key-001")
        assert backup is None
    
    def test_rollback_restores_key(self):
        manager = KeyRotationRecoveryManager()
        manager.backup_key("key-001", "old_key_data")
        
        restored = manager.rollback_key("key-001")
        assert restored == "old_key_data"
    
    def test_rollback_no_backup(self):
        manager = KeyRotationRecoveryManager()
        
        with pytest.raises(KeyRotationRecoveryError):
            manager.rollback_key("nonexistent")
    
    def test_backup_expires(self):
        manager = KeyRotationRecoveryManager()
        manager.backup_key("key-001", "data", ttl_seconds=0.1)
        
        time.sleep(0.15)
        backup = manager.get_backup("key-001")
        assert backup is None
    
    def test_cleanup_expired(self):
        manager = KeyRotationRecoveryManager()
        manager.backup_key("key-001", "data1", ttl_seconds=0.1)
        manager.backup_key("key-002", "data2", ttl_seconds=3600)
        
        time.sleep(0.15)
        cleaned = manager.cleanup_expired()
        assert cleaned == 1


class TestSharedInstances:
    """Tests for shared resilience components."""
    
    def test_shared_circuit_breaker(self):
        cb1 = get_crypto_circuit_breaker("hsm_connections")
        cb2 = get_crypto_circuit_breaker("hsm_connections")
        assert cb1 is cb2
    
    def test_shared_key_rotation_manager(self):
        mgr1 = get_key_rotation_manager()
        mgr2 = get_key_rotation_manager()
        assert mgr1 is mgr2
    
    def test_get_metrics(self):
        get_crypto_circuit_breaker("test_metrics")
        
        metrics = get_crypto_resilience_metrics()
        assert "circuit_breakers" in metrics
        assert "key_rotation_backups" in metrics


class TestIntegration:
    """Integration tests for full crypto resilience stack."""
    
    def test_retry_with_timeout(self):
        """Combine retry and timeout protection."""
        
        @with_crypto_timeout(5.0, category=CryptoErrorCategory.KEY_GENERATION)
        @with_crypto_retry(category=CryptoErrorCategory.KEY_GENERATION)
        def robust_keygen():
            return "keypair"
        
        result = robust_keygen()
        assert result == "keypair"
    
    def test_fallback_chain_with_circuit_breaker(self):
        """Fallback chain protected by circuit breaker."""
        cb = get_crypto_circuit_breaker("pq_algorithms")
        
        def primary():
            return "kyber_key"
        
        chain = AlgorithmFallbackChain("Kyber", primary)
        
        # Should work when circuit is closed
        assert cb.allow_request("Kyber") is True
        result = chain()
        assert result.success is True


class TestExceptionHierarchy:
    """Tests for custom exception hierarchy."""
    
    def test_crypto_resilience_error_metadata(self):
        err = CryptoResilienceError(
            "test message",
            category=CryptoErrorCategory.ENCRYPTION,
            algorithm="Kyber",
            retry_attempts=3
        )
        
        assert err.category == CryptoErrorCategory.ENCRYPTION
        assert err.algorithm == "Kyber"
        assert err.retry_attempts == 3
    
    def test_exception_inheritance(self):
        assert issubclass(CryptoOperationTimeoutError, CryptoResilienceError)
        assert issubclass(CryptoMaxRetriesExceededError, CryptoResilienceError)
        assert issubclass(CryptoAlgorithmFallbackError, CryptoResilienceError)
        assert issubclass(KeyRotationRecoveryError, CryptoResilienceError)


class TestErrorCategories:
    """Tests for crypto error categories."""
    
    def test_all_categories_defined(self):
        categories = list(CryptoErrorCategory)
        assert len(categories) >= 8
        assert CryptoErrorCategory.KEY_GENERATION in categories
        assert CryptoErrorCategory.ENCRYPTION in categories
        assert CryptoErrorCategory.DECRYPTION in categories
        assert CryptoErrorCategory.SIGNING in categories
        assert CryptoErrorCategory.VERIFICATION in categories
    
    def test_category_values(self):
        assert CryptoErrorCategory.KEY_GENERATION.value == "key_generation"
        assert CryptoErrorCategory.ENCRYPTION.value == "encryption"


def test_module_imports():
    """Test all public exports are available."""
    from quantum_crypt import pq_crypto_error_resilience_key_operation_retry_2026_june
    
    assert hasattr(pq_crypto_error_resilience_key_operation_retry_2026_june, "CryptoErrorCategory")
    assert hasattr(pq_crypto_error_resilience_key_operation_retry_2026_june, "with_crypto_retry")
    assert hasattr(pq_crypto_error_resilience_key_operation_retry_2026_june, "with_crypto_timeout")
    assert hasattr(pq_crypto_error_resilience_key_operation_retry_2026_june, "AlgorithmFallbackChain")
    assert hasattr(pq_crypto_error_resilience_key_operation_retry_2026_june, "KeyRotationRecoveryManager")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
