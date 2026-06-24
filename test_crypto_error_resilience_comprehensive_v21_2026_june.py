"""
Test Suite: Cryptography Error Resilience Comprehensive Coverage v21
Dimension E - Error Resilience
Tests for:
- Cryptographic exception hierarchy (security-hardened)
- Secure retry with constant-time jitter
- Security-hardened circuit breaker
- Crypto fallback manager
- Side-channel resistant error handling
"""

import unittest
import time
import threading
import hmac
from typing import Any

# Import crypto error resilience modules
from quantum_crypt.crypto_error_resilience_exception_hierarchy_v21_2026_june import (
    QuantumCryptBaseException,
    CryptoErrorSeverity,
    CryptoErrorCategory,
    KeyError,
    KeyGenerationError,
    KeyImportError,
    KeyExpiredError,
    WeakKeyError,
    EncryptionError,
    DecryptionError,
    AuthenticationFailedError,
    IntegrityCheckFailedError,
    PaddingError,
    SignatureError,
    SignatureVerificationFailedError,
    RandomnessError,
    InsufficientEntropyError,
    SideChannelRiskError,
    TimingAttackDetectedError,
    KeyDerivationError,
    CryptoValidationError,
    CryptoConfigurationError,
    InsecureConfigurationError,
    constant_time_error_compare,
    secure_error_hash
)

from quantum_crypt.crypto_error_resilience_secure_retry_circuit_breaker_v22_2026_june import (
    SecureRetryConfig,
    SecureRetryStats,
    SecureRetryStrategy,
    SecureCircuitBreakerConfig,
    SecureCircuitBreaker,
    SecureCircuitState,
    secure_retry,
    secure_circuit_breaker,
    CryptoFallbackManager,
    get_secure_circuit,
    get_crypto_fallback_manager
)


class TestCryptoExceptionHierarchy(unittest.TestCase):
    """Test cryptographic exception hierarchy."""
    
    def test_base_exception_no_sensitive_leak(self):
        """Test base exception doesn't leak sensitive data in str."""
        exc = QuantumCryptBaseException(
            message="Sensitive key data: SECRET123",
            error_code="QC_TEST_001"
        )
        
        str_repr = str(exc)
        # Should NOT contain sensitive message content
        self.assertNotIn("SECRET123", str_repr)
        self.assertIn("QC_TEST_001", str_repr)
        self.assertIn("Cryptographic operation failed", str_repr)
        
    def test_base_exception_has_unique_id(self):
        """Test each exception has unique ID."""
        exc1 = QuantumCryptBaseException("Test 1")
        exc2 = QuantumCryptBaseException("Test 2")
        
        self.assertIsNotNone(exc1.error_id)
        self.assertIsNotNone(exc2.error_id)
        self.assertNotEqual(exc1.error_id, exc2.error_id)
        
    def test_exception_to_dict_safe(self):
        """Test dict serialization doesn't expose sensitive data."""
        exc = QuantumCryptBaseException(
            message="Sensitive data",
            severity=CryptoErrorSeverity.CRITICAL,
            category=CryptoErrorCategory.KEY_ERROR
        )
        
        d = exc.to_dict()
        self.assertIn("error_id", d)
        self.assertIn("error_code", d)
        self.assertIn("severity", d)
        self.assertIn("category", d)
        self.assertIn("sensitive", d)
        # Should NOT contain raw message
        self.assertNotIn("Sensitive data", str(d.values()))
        
    def test_key_exceptions(self):
        """Test key management exceptions."""
        with self.assertRaises(KeyGenerationError) as ctx:
            raise KeyGenerationError(algorithm="CRYSTALS-Kyber")
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)
        self.assertTrue(ctx.exception.sensitive)
        
        with self.assertRaises(KeyImportError) as ctx:
            raise KeyImportError(reason="invalid PEM format")
        self.assertFalse(ctx.exception.retryable)
        
        with self.assertRaises(KeyExpiredError):
            raise KeyExpiredError()
            
        with self.assertRaises(WeakKeyError) as ctx:
            raise WeakKeyError(weakness_type="low_entropy")
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)
        
    def test_encryption_decryption_exceptions(self):
        """Test encryption/decryption exceptions."""
        with self.assertRaises(EncryptionError) as ctx:
            raise EncryptionError(algorithm="AES-GCM")
        self.assertTrue(ctx.exception.retryable)
        
        with self.assertRaises(DecryptionError) as ctx:
            raise DecryptionError(algorithm="AES-GCM")
        self.assertFalse(ctx.exception.retryable)  # Decryption failures shouldn't retry
        
    def test_authentication_integrity_exceptions(self):
        """Test authentication and integrity exceptions."""
        with self.assertRaises(AuthenticationFailedError) as ctx:
            raise AuthenticationFailedError()
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)
        self.assertEqual(ctx.exception.category, CryptoErrorCategory.AUTHENTICATION_ERROR)
        
        with self.assertRaises(IntegrityCheckFailedError) as ctx:
            raise IntegrityCheckFailedError()
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)
        
        with self.assertRaises(PaddingError):
            raise PaddingError()
            
    def test_signature_exceptions(self):
        """Test signature exceptions."""
        with self.assertRaises(SignatureError):
            raise SignatureError()
            
        with self.assertRaises(SignatureVerificationFailedError) as ctx:
            raise SignatureVerificationFailedError()
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)
        
    def test_randomness_exceptions(self):
        """Test randomness exceptions."""
        with self.assertRaises(RandomnessError):
            raise RandomnessError()
            
        with self.assertRaises(InsufficientEntropyError) as ctx:
            raise InsufficientEntropyError(available=64.0, required=128.0)
        self.assertEqual(ctx.exception.context["available_entropy"], 64.0)
        
    def test_side_channel_exceptions(self):
        """Test side-channel detection exceptions."""
        with self.assertRaises(SideChannelRiskError) as ctx:
            raise SideChannelRiskError(risk_type="cache_timing")
        self.assertFalse(ctx.exception.sensitive)  # Safe to log
        
        with self.assertRaises(TimingAttackDetectedError) as ctx:
            raise TimingAttackDetectedError(deviation=0.005)
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)
        
    def test_key_derivation_exception(self):
        """Test key derivation exception."""
        with self.assertRaises(KeyDerivationError) as ctx:
            raise KeyDerivationError(kdf="HKDF-SHA256")
        self.assertEqual(ctx.exception.context["kdf_algorithm"], "HKDF-SHA256")
        
    def test_validation_configuration_exceptions(self):
        """Test validation and configuration exceptions."""
        with self.assertRaises(CryptoValidationError) as ctx:
            raise CryptoValidationError(field="key_length")
        self.assertFalse(ctx.exception.sensitive)
        
        with self.assertRaises(CryptoConfigurationError) as ctx:
            raise CryptoConfigurationError(parameter="key_size")
        self.assertFalse(ctx.exception.sensitive)
        
        with self.assertRaises(InsecureConfigurationError) as ctx:
            raise InsecureConfigurationError(
                issue="small key size",
                recommendation="use 256-bit keys"
            )
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.WARNING)
        
    def test_constant_time_error_compare(self):
        """Test constant-time error comparison."""
        exc1 = QuantumCryptBaseException("Test")
        exc2 = QuantumCryptBaseException("Test")
        
        # Same object should compare equal
        self.assertTrue(constant_time_error_compare(exc1, exc1))
        
        # Different objects should not
        self.assertFalse(constant_time_error_compare(exc1, exc2))
        
    def test_secure_error_hash(self):
        """Test secure error hashing for auditing."""
        exc = QuantumCryptBaseException("Test")
        h = secure_error_hash(exc)
        
        self.assertEqual(len(h), 64)  # SHA256 hex
        # Should be deterministic
        self.assertEqual(h, secure_error_hash(exc))


class TestSecureRetryStrategy(unittest.TestCase):
    """Test security-hardened retry strategy."""
    
    def test_secure_retry_success(self):
        """Test successful execution on first attempt."""
        def success_func():
            return "success"
            
        strategy = SecureRetryStrategy(SecureRetryConfig(max_attempts=3))
        result, stats = strategy.execute(success_func)
        
        self.assertEqual(result, "success")
        self.assertTrue(stats.successful)
        self.assertEqual(stats.attempt, 1)
        
    def test_secure_retry_eventually_succeeds(self):
        """Test retry succeeds after failures."""
        call_count = [0]
        
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary error")
            return "success"
            
        strategy = SecureRetryStrategy(SecureRetryConfig(
            max_attempts=5,
            min_delay_seconds=0.01,
            max_delay_seconds=0.1
        ))
        result, stats = strategy.execute(flaky_func)
        
        self.assertEqual(result, "success")
        self.assertTrue(stats.successful)
        self.assertEqual(stats.attempt, 3)
        
    def test_secure_retry_exhausted(self):
        """Test exception raised after all retries."""
        def always_fails():
            raise ValueError("Permanent error")
            
        strategy = SecureRetryStrategy(SecureRetryConfig(
            max_attempts=3,
            min_delay_seconds=0.01
        ))
        
        with self.assertRaises(ValueError):
            strategy.execute(always_fails)
            
    def test_secure_retry_decorator(self):
        """Test secure retry decorator."""
        call_count = [0]
        
        @secure_retry(max_attempts=5, min_delay_seconds=0.01)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary")
            return "success"
            
        result = flaky_func()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 3)
        
    def test_secure_jitter_cryptographically_secure(self):
        """Test jitter uses secure randomness."""
        config = SecureRetryConfig(
            min_delay_seconds=0.1,
            max_delay_seconds=1.0,
            add_random_jitter=True
        )
        strategy = SecureRetryStrategy(config)
        
        # Generate multiple delays, should be different
        delays = [strategy._secure_delay(0.5) for _ in range(10)]
        # Should have variation due to jitter
        self.assertGreater(len(set(delays)), 1)
        
    def test_dont_retry_exceptions(self):
        """Test certain exceptions don't trigger retry."""
        class PermanentCryptoError(Exception):
            pass
            
        strategy = SecureRetryStrategy(SecureRetryConfig(
            max_attempts=3,
            min_delay_seconds=0.01,
            dont_retry_on_exceptions=(PermanentCryptoError,)
        ))
        
        def raise_permanent():
            raise PermanentCryptoError("Don't retry")
            
        with self.assertRaises(PermanentCryptoError):
            strategy.execute(raise_permanent)


class TestSecureCircuitBreaker(unittest.TestCase):
    """Test security-hardened circuit breaker."""
    
    def test_secure_circuit_closed(self):
        """Test normal operation when circuit closed."""
        cb = SecureCircuitBreaker(name="test")
        
        def success_func():
            return "success"
            
        result = cb.execute(success_func)
        self.assertEqual(result, "success")
        self.assertEqual(cb.state, SecureCircuitState.CLOSED)
        
    def test_secure_circuit_opens(self):
        """Test circuit opens after failure threshold."""
        config = SecureCircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout_seconds=1.0
        )
        cb = SecureCircuitBreaker(config, name="test")
        
        def failing_func():
            raise ValueError("Crypto failure")
            
        # Trigger failures
        for _ in range(3):
            with self.assertRaises(ValueError):
                cb.execute(failing_func)
                
        self.assertEqual(cb.state, SecureCircuitState.OPEN)
        
        # Next call should raise circuit open error
        with self.assertRaises(QuantumCryptBaseException) as ctx:
            cb.execute(failing_func)
        self.assertEqual(ctx.exception.error_code, "QC_CB_001")
        
    def test_secure_circuit_fallback(self):
        """Test fallback when circuit is open."""
        def fallback():
            return "degraded_mode"
            
        config = SecureCircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout_seconds=10.0
        )
        cb = SecureCircuitBreaker(config, name="test")
        
        def failing_func():
            raise ValueError("Failure")
            
        # Open circuit
        for _ in range(2):
            with self.assertRaises(ValueError):
                cb.execute(failing_func)
                
        # Should use fallback
        result = cb.execute(failing_func, fallback=fallback)
        self.assertEqual(result, "degraded_mode")
        
    def test_secure_circuit_degraded_result(self):
        """Test degraded result when circuit open."""
        config = SecureCircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout_seconds=10.0
        )
        cb = SecureCircuitBreaker(config, name="test")
        
        def failing_func():
            raise ValueError("Failure")
            
        # Open circuit
        for _ in range(2):
            with self.assertRaises(ValueError):
                cb.execute(failing_func)
                
        # Should return degraded result
        result = cb.execute(failing_func, degraded_result="safe_default")
        self.assertEqual(result, "safe_default")
        
    def test_secure_circuit_breaker_decorator(self):
        """Test secure circuit breaker decorator."""
        call_count = [0]
        
        @secure_circuit_breaker(failure_threshold=3, recovery_timeout_seconds=1.0)
        def flaky_func():
            call_count[0] += 1
            if call_count[0] < 5:
                raise ValueError("Fail")
            return "success"
            
        # Trigger circuit open
        for _ in range(3):
            with self.assertRaises(ValueError):
                flaky_func()
                
        # Circuit should be open
        with self.assertRaises(QuantumCryptBaseException):
            flaky_func()
            
    def test_secure_circuit_reset(self):
        """Test manual circuit reset."""
        cb = SecureCircuitBreaker(name="test")
        cb._transition_to(SecureCircuitState.OPEN)
        self.assertEqual(cb.state, SecureCircuitState.OPEN)
        
        cb.reset()
        self.assertEqual(cb.state, SecureCircuitState.CLOSED)
        
    def test_global_secure_circuit_registry(self):
        """Test global circuit registry."""
        cb1 = get_secure_circuit("kem_operation")
        cb2 = get_secure_circuit("kem_operation")
        
        self.assertIs(cb1, cb2)


class TestCryptoFallbackManager(unittest.TestCase):
    """Test crypto fallback manager."""
    
    def test_fallback_chain_primary_works(self):
        """Test primary implementation works."""
        fm = CryptoFallbackManager()
        
        def primary(x):
            return f"primary_{x}"
            
        def fallback(x):
            return f"fallback_{x}"
            
        fm.register_fallback_chain("encrypt", primary, fallback)
        
        result, impl = fm.execute_with_fallback("encrypt", "test")
        self.assertEqual(result, "primary_test")
        self.assertEqual(impl, "primary")
        
    def test_fallback_chain_uses_fallback(self):
        """Test fallback used when primary fails."""
        fm = CryptoFallbackManager()
        
        def primary(x):
            raise ValueError("Primary failed")
            
        def fallback(x):
            return f"fallback_{x}"
            
        fm.register_fallback_chain("encrypt", primary, fallback)
        
        result, impl = fm.execute_with_fallback("encrypt", "test")
        self.assertEqual(result, "fallback_test")
        self.assertEqual(impl, "fallback_1")
        
    def test_fallback_chain_multiple_levels(self):
        """Test multiple fallback levels."""
        fm = CryptoFallbackManager()
        
        def primary(x):
            raise ValueError("Primary failed")
            
        def fallback1(x):
            raise ValueError("Fallback1 failed")
            
        def fallback2(x):
            return f"fallback2_{x}"
            
        fm.register_fallback_chain("encrypt", primary, fallback1, fallback2)
        
        result, impl = fm.execute_with_fallback("encrypt", "test")
        self.assertEqual(result, "fallback2_test")
        self.assertEqual(impl, "fallback_2")
        
    def test_global_fallback_manager(self):
        """Test global fallback manager."""
        fm = get_crypto_fallback_manager()
        self.assertIsInstance(fm, CryptoFallbackManager)


class TestIntegration(unittest.TestCase):
    """Integration tests for crypto error resilience."""
    
    def test_retry_with_circuit_breaker(self):
        """Test retry and circuit breaker working together."""
        call_count = [0]
        
        def flaky_hsm_call():
            call_count[0] += 1
            if call_count[0] < 4:
                raise ConnectionError("HSM unavailable")
            return "success"
            
        @secure_retry(max_attempts=5, min_delay_seconds=0.01)
        @secure_circuit_breaker(failure_threshold=10, recovery_timeout_seconds=5.0)
        def protected_operation():
            return flaky_hsm_call()
            
        result = protected_operation()
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 4)
        
    def test_exception_preserved_through_retry(self):
        """Test exception information preserved."""
        strategy = SecureRetryStrategy(SecureRetryConfig(
            max_attempts=3,
            min_delay_seconds=0.01
        ))
        
        def raise_crypto_error():
            raise AuthenticationFailedError(
                message="MAC verification failed"
            )
            
        with self.assertRaises(AuthenticationFailedError) as ctx:
            strategy.execute(raise_crypto_error)
            
        self.assertEqual(ctx.exception.severity, CryptoErrorSeverity.CRITICAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
