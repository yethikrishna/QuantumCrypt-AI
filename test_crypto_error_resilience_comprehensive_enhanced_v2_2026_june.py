"""
Test Suite for QuantumCrypt Crypto Error Resilience Framework v2
DIMENSION E: Error Resilience
45 comprehensive tests - ALL must pass

Tests cover:
1. Crypto Custom Exception Hierarchy (10 tests)
2. Crypto Operation Enums (2 tests)
3. Side-Channel Safe Timeout Wrappers (5 tests)
4. Crypto Retry Policies (6 tests)
5. Algorithm Fallback Chains (4 tests)
6. Crypto Bulkhead - HSM Resource Isolation (5 tests)
7. Key Operation Error Recovery (3 tests)
8. Entropy Health Monitor (5 tests)
9. Comprehensive Crypto Resilient Decorator (5 tests)
"""

import pytest
import time
import threading

# Import the module to test
from quantum_crypt.crypto_error_resilience_comprehensive_enhanced_v2_2026_june import (
    # Crypto Exceptions
    QuantumCryptError,
    KeyError,
    KeyGenerationError,
    KeyLoadError,
    KeyRotationError,
    KeyDerivationError,
    KeyCompromiseDetectedError,
    CryptoOperationError,
    EncryptionError,
    DecryptionError,
    SignatureError,
    VerificationError,
    KEMEncapError,
    KEMDecapError,
    EntropyError,
    EntropyDepletedError,
    EntropyQualityError,
    HardwareSecurityModuleError,
    HSMConnectionError,
    HSMLoadError,
    SideChannelRiskDetectedError,
    CertificateError,
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateValidationError,
    ProtocolError,
    HandshakeError,
    SessionKeyError,
    ForwardSecrecyError,
    
    # Enums
    CryptoOperation,
    CryptoAlgorithm,
    
    # Timeout
    CryptoTimeout,
    crypto_timeout,
    
    # Retry
    CryptoRetryConfig,
    CryptoRetryPolicy,
    crypto_retry,
    
    # Fallback Chains
    AlgorithmFallbackChain,
    
    # Bulkhead
    CryptoBulkhead,
    
    # Key Recovery
    KeyOperationRecovery,
    
    # Entropy Monitoring
    EntropyHealthMonitor,
    
    # Comprehensive
    crypto_resilient,
)


# -----------------------------------------------------------------------------
# 1. CRYPTO CUSTOM EXCEPTION HIERARCHY TESTS
# -----------------------------------------------------------------------------

class TestCryptoExceptionHierarchy:
    """Test crypto-specific exception hierarchy"""
    
    def test_base_crypto_exception_properties(self):
        exc = QuantumCryptError("Crypto error", context={"algorithm": "kyber"})
        assert exc.error_code == "QUANTUMCRYPT_ERROR"
        assert exc.severity == "ERROR"
        assert exc.security_sensitive is True
        assert exc.context["algorithm"] == "kyber"
    
    def test_exception_sanitizes_sensitive_data(self):
        exc = QuantumCryptError(
            "Key error",
            context={"private_key": "SECRET_MATERIAL", "key_size": 2048}
        )
        assert "REDACTED" in exc.context["private_key"]
        assert exc.context["key_size"] == 2048  # Non-sensitive preserved
    
    def test_exception_to_dict(self):
        exc = KeyGenerationError("Key gen failed", context={"key_size": 4096})
        d = exc.to_dict()
        assert d["error_code"] == "KEY_GENERATION_ERROR"
        assert d["retryable"] is True
        assert d["security_sensitive"] is True
        assert "timestamp" in d
    
    def test_key_error_critical_severity(self):
        exc = KeyError("Key failure")
        assert exc.severity == "CRITICAL"
    
    def test_key_generation_retryable(self):
        exc = KeyGenerationError("Temporary key gen failure")
        assert exc.retryable is True
    
    def test_decryption_not_retryable(self):
        # Decryption failures usually mean bad key/data, don't retry
        exc = DecryptionError("Decryption failed")
        assert exc.retryable is False
    
    def test_verification_not_retryable(self):
        # Signature verification failures are security-critical
        exc = VerificationError("Signature invalid")
        assert exc.retryable is False
    
    def test_certificate_revoked_critical(self):
        exc = CertificateRevokedError("Certificate revoked")
        assert exc.severity == "CRITICAL"
        assert exc.retryable is False
    
    def test_entropy_error_critical(self):
        exc = EntropyQualityError("Entropy quality insufficient")
        assert exc.severity == "CRITICAL"
    
    def test_exception_inheritance_chains(self):
        # Test multiple inheritance levels
        assert isinstance(KeyGenerationError("test"), KeyError)
        assert isinstance(KeyGenerationError("test"), QuantumCryptError)
        assert isinstance(HSMConnectionError("test"), HardwareSecurityModuleError)
        assert isinstance(HSMConnectionError("test"), QuantumCryptError)
        assert isinstance(HandshakeError("test"), ProtocolError)
        assert isinstance(HandshakeError("test"), QuantumCryptError)


# -----------------------------------------------------------------------------
# 2. CRYPTO OPERATION ENUMERATIONS TESTS
# -----------------------------------------------------------------------------

class TestCryptoEnumerations:
    """Test crypto operation and algorithm enums"""
    
    def test_crypto_operation_enum_complete(self):
        operations = list(CryptoOperation)
        # Verify key operations exist
        assert CryptoOperation.KEY_GENERATION in operations
        assert CryptoOperation.ENCRYPT in operations
        assert CryptoOperation.DECRYPT in operations
        assert CryptoOperation.SIGN in operations
        assert CryptoOperation.VERIFY in operations
        assert CryptoOperation.KEM_ENCAPS in operations
        assert CryptoOperation.KEM_DECAPS in operations
        assert CryptoOperation.RANDOM_GEN in operations
        assert CryptoOperation.HANDSHAKE in operations
    
    def test_crypto_algorithm_enum_complete(self):
        algorithms = list(CryptoAlgorithm)
        # Post-quantum algorithms
        assert CryptoAlgorithm.KYBER_512 in algorithms
        assert CryptoAlgorithm.KYBER_768 in algorithms
        assert CryptoAlgorithm.KYBER_1024 in algorithms
        assert CryptoAlgorithm.DILITHIUM_2 in algorithms
        assert CryptoAlgorithm.DILITHIUM_3 in algorithms
        assert CryptoAlgorithm.DILITHIUM_5 in algorithms
        # Classic algorithms
        assert CryptoAlgorithm.AES_GCM in algorithms
        assert CryptoAlgorithm.CHACHA20_POLY1305 in algorithms
        assert CryptoAlgorithm.SHA2_256 in algorithms
        assert CryptoAlgorithm.HKDF in algorithms
        assert CryptoAlgorithm.ARGON2ID in algorithms


# -----------------------------------------------------------------------------
# 3. SIDE-CHANNEL SAFE TIMEOUT WRAPPER TESTS
# -----------------------------------------------------------------------------

class TestCryptoTimeoutWrappers:
    """Test side-channel safe timeout wrappers"""
    
    def test_crypto_timeout_triggers(self):
        @crypto_timeout(0.1)
        def slow_key_gen():
            time.sleep(1.0)
            return "key_material"
        
        with pytest.raises(KeyGenerationError):
            slow_key_gen()
    
    def test_crypto_timeout_no_trigger_fast_function(self):
        @crypto_timeout(1.0)
        def fast_key_gen():
            return "key_material"
        
        result = fast_key_gen()
        assert result == "key_material"
    
    def test_crypto_timeout_with_fallback(self):
        @crypto_timeout(0.1, fallback="degraded_key")
        def slow_key_gen():
            time.sleep(1.0)
            return "key_material"
        
        result = slow_key_gen()
        assert result == "degraded_key"
    
    def test_crypto_timeout_preserves_exceptions(self):
        @crypto_timeout(1.0)
        def raising_func():
            raise ValueError("Test crypto error")
        
        with pytest.raises(ValueError):
            raising_func()
    
    def test_crypto_timeout_class(self):
        wrapper = CryptoTimeout(0.1)
        
        @wrapper
        def slow_func():
            time.sleep(1.0)
        
        with pytest.raises(KeyGenerationError):
            slow_func()


# -----------------------------------------------------------------------------
# 4. CRYPTO RETRY POLICY TESTS
# -----------------------------------------------------------------------------

class TestCryptoRetryPolicies:
    """Test crypto-specific retry policies"""
    
    def test_crypto_retry_succeeds_eventually(self):
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def flaky_hsm_call():
            call_count[0] += 1
            if call_count[0] < 3:
                raise HSMConnectionError("Temporary HSM issue")
            return "hsm_key"
        
        result = flaky_hsm_call()
        assert result == "hsm_key"
        assert call_count[0] == 3
    
    def test_crypto_retry_exhausted_raises(self):
        call_count = [0]
        
        @crypto_retry(max_attempts=2, initial_delay=0.01)
        def always_fails():
            call_count[0] += 1
            raise HSMConnectionError("HSM down")
        
        with pytest.raises(HSMConnectionError):
            always_fails()
        assert call_count[0] == 2
    
    def test_crypto_retry_never_retries_verification_failures(self):
        """Security-critical: NEVER retry verification failures"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def verification_fails():
            call_count[0] += 1
            raise VerificationError("Signature invalid")
        
        with pytest.raises(VerificationError):
            verification_fails()
        assert call_count[0] == 1  # Should NOT retry!
    
    def test_crypto_retry_never_retries_decryption_failures(self):
        """Security-critical: NEVER retry decryption failures"""
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def decryption_fails():
            call_count[0] += 1
            raise DecryptionError("Decryption failed")
        
        with pytest.raises(DecryptionError):
            decryption_fails()
        assert call_count[0] == 1  # Should NOT retry!
    
    def test_crypto_retry_backoff_calculation(self):
        config = CryptoRetryConfig(
            max_attempts=4,
            initial_delay=0.1,
            exponential_backoff=True
        )
        policy = CryptoRetryPolicy(config)
        
        delay1 = policy._calculate_delay(1)
        delay2 = policy._calculate_delay(2)
        delay3 = policy._calculate_delay(3)
        
        # Exponential backoff should increase
        assert delay2 >= delay1
        assert delay3 >= delay2
    
    def test_crypto_retry_policy_class(self):
        config = CryptoRetryConfig(max_attempts=2, initial_delay=0.01)
        policy = CryptoRetryPolicy(config)
        
        call_count = [0]
        @policy
        def test_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise EntropyDepletedError("Low entropy")
            return "ok"
        
        result = test_func()
        assert result == "ok"


# -----------------------------------------------------------------------------
# 5. ALGORITHM FALLBACK CHAIN TESTS
# -----------------------------------------------------------------------------

class TestAlgorithmFallbackChains:
    """Test graceful degradation algorithm fallback chains"""
    
    def test_kem_fallback_chain_defined(self):
        chain = AlgorithmFallbackChain(
            AlgorithmFallbackChain.KEM_FALLBACK_CHAIN,
            CryptoOperation.KEM_ENCAPS
        )
        assert len(chain.algorithm_chain) >= 3
        assert CryptoAlgorithm.KYBER_1024 in chain.algorithm_chain
        assert CryptoAlgorithm.KYBER_768 in chain.algorithm_chain
    
    def test_signature_fallback_chain_defined(self):
        chain = AlgorithmFallbackChain(
            AlgorithmFallbackChain.SIGNATURE_FALLBACK_CHAIN,
            CryptoOperation.SIGN
        )
        assert len(chain.algorithm_chain) >= 3
        assert CryptoAlgorithm.DILITHIUM_5 in chain.algorithm_chain
        assert CryptoAlgorithm.DILITHIUM_3 in chain.algorithm_chain
    
    def test_get_fallback_algorithm(self):
        chain = AlgorithmFallbackChain(
            AlgorithmFallbackChain.KEM_FALLBACK_CHAIN,
            CryptoOperation.KEM_ENCAPS
        )
        
        fallback = chain.get_fallback_algorithm(CryptoAlgorithm.KYBER_1024)
        assert fallback == CryptoAlgorithm.KYBER_768
        
        fallback2 = chain.get_fallback_algorithm(CryptoAlgorithm.KYBER_768)
        assert fallback2 == CryptoAlgorithm.KYBER_512
    
    def test_fallback_stats_tracking(self):
        chain = AlgorithmFallbackChain(
            AlgorithmFallbackChain.KEM_FALLBACK_CHAIN,
            CryptoOperation.KEM_ENCAPS
        )
        
        chain.get_fallback_algorithm(CryptoAlgorithm.KYBER_1024)
        chain.get_fallback_algorithm(CryptoAlgorithm.KYBER_1024)
        
        stats = chain.get_stats()
        assert stats["fallback_counts"]["kyber_1024"] == 2


# -----------------------------------------------------------------------------
# 6. CRYPTO BULKHEAD - HSM RESOURCE ISOLATION
# -----------------------------------------------------------------------------

class TestCryptoBulkhead:
    """Test HSM resource isolation bulkhead pattern"""
    
    def test_crypto_bulkhead_normal_operation(self):
        bulkhead = CryptoBulkhead(
            max_concurrent=4,
            operation=CryptoOperation.KEY_GENERATION
        )
        
        @bulkhead
        def hsm_key_gen():
            return "generated_key"
        
        result = hsm_key_gen()
        assert result == "generated_key"
    
    def test_crypto_bulkhead_tracking(self):
        bulkhead = CryptoBulkhead(max_concurrent=4, operation=CryptoOperation.ENCRYPT)
        
        assert bulkhead.active_count == 0
        assert bulkhead.utilization == 0.0
        
        @bulkhead
        def track_func():
            assert bulkhead.active_count == 1
            assert bulkhead.utilization == 0.25
            return "ok"
        
        track_func()
        assert bulkhead.active_count == 0
    
    def test_crypto_bulkhead_rejects_when_full(self):
        bulkhead = CryptoBulkhead(
            max_concurrent=1,
            acquire_timeout=0.05,
            operation=CryptoOperation.SIGN
        )
        
        barrier = threading.Barrier(2)
        
        @bulkhead
        def slow_hsm_call():
            barrier.wait(timeout=1.0)
            time.sleep(0.1)
            return "done"
        
        # Start first call - holds bulkhead
        t = threading.Thread(target=slow_hsm_call)
        t.start()
        
        # Wait for first call to acquire
        barrier.wait(timeout=1.0)
        
        # Second call should timeout
        with pytest.raises(HSMConnectionError):
            slow_hsm_call()
        
        t.join()
    
    def test_crypto_bulkhead_releases_on_exception(self):
        bulkhead = CryptoBulkhead(max_concurrent=1, operation=CryptoOperation.DECRYPT)
        
        @bulkhead
        def raising_func():
            raise ValueError("HSM error")
        
        try:
            raising_func()
        except ValueError:
            pass
        
        assert bulkhead.active_count == 0  # Released!
    
    def test_crypto_bulkhead_rejection_tracking(self):
        bulkhead = CryptoBulkhead(
            max_concurrent=1,
            acquire_timeout=0.01,
            operation=CryptoOperation.KEY_GENERATION
        )
        
        barrier = threading.Barrier(2)
        
        @bulkhead
        def wait_func():
            barrier.wait(timeout=1.0)
            time.sleep(0.1)
        
        t = threading.Thread(target=wait_func)
        t.start()
        barrier.wait(timeout=1.0)
        
        try:
            wait_func()
        except HSMConnectionError:
            pass
        
        t.join()
        
        assert bulkhead.rejected_count >= 1


# -----------------------------------------------------------------------------
# 7. KEY OPERATION ERROR RECOVERY
# -----------------------------------------------------------------------------

class TestKeyOperationRecovery:
    """Test key operation error recovery"""
    
    def test_key_recovery_retries(self):
        call_count = [0]
        
        @KeyOperationRecovery(max_retries=2)
        def flaky_key_gen(**kwargs):
            call_count[0] += 1
            if call_count[0] < 3:
                raise KeyGenerationError("Temporary failure")
            return "key"
        
        result = flaky_key_gen()
        assert result == "key"
        assert call_count[0] == 3
    
    def test_key_recovery_passes_fresh_entropy(self):
        entropy_flag = [False]
        
        @KeyOperationRecovery(max_retries=1, fresh_entropy_on_retry=True)
        def key_gen(**kwargs):
            if 'fresh_entropy' in kwargs and kwargs['fresh_entropy']:
                entropy_flag[0] = True
            if not entropy_flag[0]:
                raise KeyGenerationError("First attempt fails")
            return "key"
        
        result = key_gen()
        assert result == "key"
        assert entropy_flag[0] is True  # Should pass fresh_entropy=True on retry
    
    def test_key_recovery_exhausted_raises(self):
        call_count = [0]
        
        @KeyOperationRecovery(max_retries=1)
        def always_fails():
            call_count[0] += 1
            raise KeyGenerationError("Always fails")
        
        with pytest.raises(KeyGenerationError):
            always_fails()
        assert call_count[0] == 2  # 1 initial + 1 retry


# -----------------------------------------------------------------------------
# 8. ENTROPY HEALTH MONITOR TESTS
# -----------------------------------------------------------------------------

class TestEntropyHealthMonitor:
    """Test entropy quality and availability monitoring"""
    
    def test_entropy_monitor_records_failures(self):
        monitor = EntropyHealthMonitor(failure_threshold=3)
        monitor.record_failure()
        monitor.record_failure()
        assert monitor.get_recent_failures() == 2
    
    def test_entropy_monitor_records_successes(self):
        monitor = EntropyHealthMonitor()
        monitor.record_success()
        monitor.record_success()
        status = monitor.get_health_status()
        assert status["total_successes"] == 2
    
    def test_entropy_at_risk_when_threshold_exceeded(self):
        monitor = EntropyHealthMonitor(failure_threshold=2, window_seconds=60)
        monitor.record_failure()
        monitor.record_failure()
        monitor.record_failure()
        assert monitor.is_entropy_at_risk() is True
    
    def test_entropy_health_score(self):
        monitor = EntropyHealthMonitor(failure_threshold=5)
        status = monitor.get_health_status()
        assert status["health_score"] == 100  # Perfect health
        
        monitor.record_failure()
        monitor.record_failure()
        status = monitor.get_health_status()
        assert status["health_score"] == 60  # 2 failures = -40
    
    def test_entropy_window_cleanup(self):
        monitor = EntropyHealthMonitor(failure_threshold=5, window_seconds=0.1)
        monitor.record_failure()
        monitor.record_failure()
        assert monitor.get_recent_failures() == 2
        
        time.sleep(0.15)  # Wait for window to expire
        
        # Old failures should be cleaned up
        assert monitor.get_recent_failures() == 0


# -----------------------------------------------------------------------------
# 9. COMPREHENSIVE CRYPTO RESILIENT DECORATOR
# -----------------------------------------------------------------------------

class TestComprehensiveCryptoResilientDecorator:
    """Test the all-in-one crypto resilient decorator"""
    
    def test_crypto_resilient_basic(self):
        @crypto_resilient()
        def normal_crypto_op():
            return "crypto_result"
        
        result = normal_crypto_op()
        assert result == "crypto_result"
    
    def test_crypto_resilient_with_timeout(self):
        @crypto_resilient(timeout_seconds=0.1)
        def slow_op():
            time.sleep(1.0)
            return "done"
        
        with pytest.raises(KeyGenerationError):
            slow_op()
    
    def test_crypto_resilient_with_retry(self):
        call_count = [0]
        
        @crypto_resilient(max_retries=2)
        def flaky_op():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectionError("Temporary")
            return "success"
        
        result = flaky_op()
        assert result == "success"
        assert call_count[0] == 2
    
    def test_crypto_resilient_with_bulkhead(self):
        @crypto_resilient(
            bulkhead_max_concurrent=2,
            operation=CryptoOperation.KEY_GENERATION
        )
        def protected_op():
            return "protected"
        
        result = protected_op()
        assert result == "protected"
    
    def test_crypto_resilient_full_stack(self):
        call_count = [0]
        
        @crypto_resilient(
            timeout_seconds=5.0,
            max_retries=2,
            bulkhead_max_concurrent=4,
            operation=CryptoOperation.SIGN
        )
        def full_stack_op():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectionError("Temp HSM issue")
            return "signed_data"
        
        result = full_stack_op()
        assert result == "signed_data"
        assert call_count[0] == 2


# -----------------------------------------------------------------------------
# RUN TESTS
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
