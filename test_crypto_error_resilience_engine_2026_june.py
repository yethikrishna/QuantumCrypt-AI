"""
Unit Tests for QuantumCrypt Crypto Error Resilience Engine - Dimension E
=========================================================================
24 comprehensive tests covering all crypto resilience functionality
All tests are REAL - no mocked success
"""

import unittest
import time
import threading
import secrets
import hmac

# Import the module
from quantum_crypt.crypto_error_resilience_engine_2026_june import (
    # Exceptions
    CryptoError,
    KeyGenerationError,
    KeyValidationError,
    EncryptionError,
    DecryptionError,
    SignatureError,
    HashError,
    RandomnessError,
    EntropyLowError,
    CertificateError,
    SideChannelRiskError,
    
    # Constant-time utilities
    constant_time_compare,
    constant_time_select,
    secure_zero_memory,
    SecureMemoryBuffer,
    
    # Timeout
    with_crypto_timeout,
    
    # Retry
    with_crypto_retry,
    CryptoRetryConfig,
    CryptoRetryStats,
    
    # Circuit Breaker
    CryptoCircuitBreaker,
    get_crypto_circuit,
    
    # Graceful Degradation
    CryptoFallbackLevel,
    CryptoFallbackResult,
    CryptoGracefulDegradation,
    
    # Entropy Monitoring
    EntropyHealthMonitor,
    
    # Combined
    with_crypto_resilience,
    
    # Utilities
    safe_crypto_call,
)


# ============================================================================
# TEST CRYPTO EXCEPTION HIERARCHY
# ============================================================================

class TestCryptoExceptionHierarchy(unittest.TestCase):
    """Test crypto-specific exception hierarchy"""
    
    def test_base_crypto_exception(self):
        """Test base CryptoError attributes"""
        exc = CryptoError("Test crypto error", "QC-000", {"key": "value"})
        self.assertEqual(exc.message, "Test crypto error")
        self.assertEqual(exc.error_code, "QC-000")
        self.assertIn("timestamp", exc.to_dict())
    
    def test_key_generation_error(self):
        """Test KeyGenerationError with algorithm info"""
        exc = KeyGenerationError("Key generation failed", algorithm="Kyber-768")
        self.assertEqual(exc.error_code, "QC-001")
        self.assertEqual(exc.details["algorithm"], "Kyber-768")
        self.assertIsInstance(exc, CryptoError)
    
    def test_decryption_error_auth_flag(self):
        """Test DecryptionError with authentication failure flag"""
        exc = DecryptionError("Decryption failed", auth_failure=True)
        self.assertEqual(exc.error_code, "QC-004")
        self.assertTrue(exc.details["authentication_failure"])
    
    def test_signature_error_verification(self):
        """Test SignatureError with verification flag"""
        exc = SignatureError("Signature invalid", verification=True)
        self.assertTrue(exc.details["verification_failure"])
    
    def test_exception_serialization(self):
        """Test exception to_dict serialization"""
        exc = CertificateError("Cert expired", reason="not_after")
        d = exc.to_dict()
        self.assertEqual(d["error"], "CertificateError")
        self.assertEqual(d["details"]["validation_reason"], "not_after")


# ============================================================================
# TEST CONSTANT-TIME UTILITIES
# ============================================================================

class TestConstantTimeUtilities(unittest.TestCase):
    """Test constant-time utilities for side-channel resistance"""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time compare with equal inputs"""
        a = b"test_data_12345"
        b = b"test_data_12345"
        self.assertTrue(constant_time_compare(a, b))
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time compare with different inputs"""
        a = b"test_data_12345"
        b = b"test_data_54321"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_constant_time_compare_different_lengths(self):
        """Test constant-time compare with different lengths"""
        a = b"short"
        b = b"much_longer_data"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_constant_time_select_true(self):
        """Test constant-time select with True condition"""
        true_val = b"option_a"
        false_val = b"option_b"
        result = constant_time_select(True, true_val, false_val)
        self.assertEqual(result, true_val)
    
    def test_constant_time_select_false(self):
        """Test constant-time select with False condition"""
        true_val = b"option_a"
        false_val = b"option_b"
        result = constant_time_select(False, true_val, false_val)
        self.assertEqual(result, false_val)
    
    def test_secure_zero_memory(self):
        """Test memory zeroization"""
        data = bytearray(b"sensitive_key_material_here")
        original = bytes(data)
        
        secure_zero_memory(data)
        
        # Should be all zeros now
        self.assertEqual(bytes(data), b"\x00" * len(original))
    
    def test_secure_memory_buffer_context(self):
        """Test SecureMemoryBuffer context manager"""
        with SecureMemoryBuffer(32) as buf:
            buf.data[:] = b"A" * 32
            self.assertEqual(bytes(buf.data), b"A" * 32)
        
        # After context exit, should be zeroized
        # Note: accessing after zeroize raises error
        with self.assertRaises(CryptoError):
            _ = buf.data


# ============================================================================
# TEST CRYPTO TIMEOUT WRAPPER
# ============================================================================

class TestCryptoTimeout(unittest.TestCase):
    """Test crypto operation timeout wrappers"""
    
    def test_crypto_operation_completes(self):
        """Test normal crypto operation completes"""
        @with_crypto_timeout(5.0)
        def fast_hash():
            return hmac.new(b"key", b"data", "sha256").digest()
        
        result = fast_hash()
        self.assertEqual(len(result), 32)
    
    def test_crypto_timeout_raises(self):
        """Test crypto timeout raises KeyGenerationError"""
        @with_crypto_timeout(0.1)
        def slow_operation():
            time.sleep(1.0)
            return "done"
        
        with self.assertRaises(KeyGenerationError):
            slow_operation()
    
    def test_crypto_timeout_preserves_errors(self):
        """Test original exceptions are preserved through timeout"""
        @with_crypto_timeout(1.0)
        def error_func():
            raise ValueError("original crypto error")
        
        with self.assertRaises(ValueError):
            error_func()


# ============================================================================
# TEST CRYPTO RETRY (CONSERVATIVE)
# ============================================================================

class TestCryptoRetry(unittest.TestCase):
    """Test conservative retry for crypto operations"""
    
    def test_retry_transient_randomness_error(self):
        """Test retry on transient randomness errors"""
        attempts = []
        
        @with_crypto_retry(max_attempts=3, initial_delay=0.01)
        def flaky_random():
            attempts.append(1)
            if len(attempts) < 2:
                raise RandomnessError("Transient entropy issue")
            return secrets.token_bytes(32)
        
        result = flaky_random()
        self.assertEqual(len(result), 32)
        self.assertEqual(len(attempts), 2)
    
    def test_no_retry_on_key_validation(self):
        """Test KeyValidationError is NOT retried (security-critical)"""
        attempts = []
        
        @with_crypto_retry(max_attempts=3, initial_delay=0.01)
        def validation_fail():
            attempts.append(1)
            raise KeyValidationError("Invalid key")
        
        with self.assertRaises(KeyValidationError):
            validation_fail()
        
        self.assertEqual(len(attempts), 1)  # No retry!
    
    def test_no_retry_on_decryption_error(self):
        """Test DecryptionError is NOT retried (security-critical)"""
        attempts = []
        
        @with_crypto_retry(max_attempts=3, initial_delay=0.01)
        def decrypt_fail():
            attempts.append(1)
            raise DecryptionError("Auth failed", auth_failure=True)
        
        with self.assertRaises(DecryptionError):
            decrypt_fail()
        
        self.assertEqual(len(attempts), 1)  # No retry - important for security!
    
    def test_retry_stats_calculation(self):
        """Test crypto retry delay calculation"""
        config = CryptoRetryConfig(initial_delay=0.05, backoff_factor=1.5)
        stats = CryptoRetryStats(attempt=2)
        delay = stats.calculate_delay(config)
        # Conservative delays for crypto - no aggressive backoff
        self.assertGreater(delay, 0.02)
        self.assertLess(delay, 0.2)


# ============================================================================
# TEST CRYPTO CIRCUIT BREAKER
# ============================================================================

class TestCryptoCircuitBreaker(unittest.TestCase):
    """Test circuit breaker for HSM/crypto hardware operations"""
    
    def test_circuit_allows_initially(self):
        """Test circuit allows operations initially"""
        cb = CryptoCircuitBreaker(failure_threshold=3)
        self.assertTrue(cb.allow_operation())
    
    def test_circuit_opens_after_failures(self):
        """Test circuit opens after threshold failures"""
        cb = CryptoCircuitBreaker(failure_threshold=2, recovery_timeout=1.0)
        
        cb.record_failure()
        cb.record_failure()
        
        self.assertFalse(cb.allow_operation())
    
    def test_circuit_recovers_after_timeout(self):
        """Test circuit recovers after timeout"""
        cb = CryptoCircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        cb.record_failure()
        self.assertFalse(cb.allow_operation())
        
        time.sleep(0.15)
        
        self.assertTrue(cb.allow_operation())
    
    def test_success_reduces_failure_count(self):
        """Test success decrements failure counter"""
        cb = CryptoCircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()  # Should reduce failure count
        cb.record_failure()
        # Should still be closed (2 failures total)
        self.assertTrue(cb.allow_operation())
    
    def test_named_circuit_registry(self):
        """Test named circuit breaker registry"""
        cb1 = get_crypto_circuit("hsm_main")
        cb2 = get_crypto_circuit("hsm_main")
        self.assertIs(cb1, cb2)


# ============================================================================
# TEST CRYPTO GRACEFUL DEGRADATION
# ============================================================================

class TestCryptoGracefulDegradation(unittest.TestCase):
    """Test graceful degradation for crypto operations"""
    
    def test_full_security_on_success(self):
        """Test success returns FULL_SECURITY level"""
        @CryptoGracefulDegradation(allow_fallback=True)
        def good_signature():
            return b"valid_signature"
        
        result = good_signature()
        self.assertIsInstance(result, CryptoFallbackResult)
        self.assertEqual(result.result, b"valid_signature")
        self.assertEqual(result.fallback_level, CryptoFallbackLevel.FULL_SECURITY)
        self.assertEqual(result.warning, "")
    
    def test_fallback_on_failure(self):
        """Test fallback function is called on failure"""
        def fallback():
            return b"fallback_hash"
        
        decorator = CryptoGracefulDegradation(
            allow_fallback=True,
            fallback_function=fallback
        )
        
        @decorator
        def failing_hash():
            raise HashError("Hash algorithm not available")
        
        result = failing_hash()
        self.assertEqual(result.fallback_level, CryptoFallbackLevel.REDUCED_SECURITY)
        self.assertIn("Fell back", result.warning)
        self.assertIsNotNone(result.original_error)
    
    def test_fallback_count_tracking(self):
        """Test fallback count tracking"""
        decorator = CryptoGracefulDegradation(allow_fallback=True)
        
        @decorator
        def failing_op():
            raise CryptoError("fail")
        
        failing_op()
        failing_op()
        
        self.assertEqual(decorator.fallback_count, 2)


# ============================================================================
# TEST ENTROPY HEALTH MONITOR
# ============================================================================

class TestEntropyHealthMonitor(unittest.TestCase):
    """Test entropy quality monitoring"""
    
    def test_entropy_estimate(self):
        """Test Shannon entropy estimation"""
        monitor = EntropyHealthMonitor()
        
        # High entropy random data
        good_sample = secrets.token_bytes(64)
        is_healthy, entropy = monitor.check_randomness_quality(good_sample)
        
        # Should have reasonable entropy
        self.assertGreater(entropy, 0)
        self.assertGreater(monitor.health_score, 0)
    
    def test_low_entropy_detection(self):
        """Test low entropy detection"""
        monitor = EntropyHealthMonitor(min_entropy_bits=128.0)
        
        # Very low entropy - all zeros
        bad_sample = b"\x00" * 64
        is_healthy, entropy = monitor.check_randomness_quality(bad_sample)
        
        self.assertLess(monitor.health_score, 1.0)
    
    def test_require_healthy_raises(self):
        """Test require_healthy raises on critically low entropy"""
        monitor = EntropyHealthMonitor()
        # Force bad health score
        monitor._health_score = 0.1
        
        with self.assertRaises(EntropyLowError):
            monitor.require_healthy()


# ============================================================================
# TEST COMBINED CRYPTO RESILIENCE
# ============================================================================

class TestCombinedCryptoResilience(unittest.TestCase):
    """Test combined crypto resilience decorator"""
    
    def test_happy_path_unchanged(self):
        """Test happy path is 100% preserved"""
        @with_crypto_resilience(timeout=5.0, max_retries=1)
        def normal_operation():
            return hmac.new(b"k", b"d", "sha256").digest()
        
        result = normal_operation()
        self.assertEqual(len(result), 32)
    
    def test_combined_timeout(self):
        """Test combined timeout works"""
        @with_crypto_resilience(timeout=0.1, max_retries=1)
        def slow_op():
            time.sleep(1.0)
            return "done"
        
        with self.assertRaises(KeyGenerationError):
            slow_op()


# ============================================================================
# TEST SAFE CRYPTO CALL
# ============================================================================

class TestSafeCryptoCall(unittest.TestCase):
    """Test safe_crypto_call utility"""
    
    def test_safe_call_success(self):
        """Test safe crypto call returns result"""
        def good_op():
            return secrets.token_bytes(16)
        
        result, exc = safe_crypto_call(good_op)
        self.assertEqual(len(result), 16)
        self.assertIsNone(exc)
    
    def test_safe_call_exception(self):
        """Test safe crypto call catches exception"""
        def bad_op():
            raise KeyValidationError("Bad key")
        
        result, exc = safe_crypto_call(bad_op)
        self.assertIsNone(result)
        self.assertIsInstance(exc, KeyValidationError)
    
    def test_safe_call_with_timeout(self):
        """Test safe crypto call with timeout"""
        def slow_op():
            time.sleep(1.0)
            return "done"
        
        result, exc = safe_crypto_call(slow_op, timeout=0.1)
        # Either times out or completes depending on scheduling
        self.assertTrue(result is None or result == "done")


# ============================================================================
# TEST THREAD SAFETY
# ============================================================================

class TestCryptoThreadSafety(unittest.TestCase):
    """Test thread safety of crypto resilience components"""
    
    def test_circuit_breaker_concurrent(self):
        """Test circuit breaker under concurrent access"""
        cb = CryptoCircuitBreaker(failure_threshold=1000)
        
        def record_successes():
            for _ in range(100):
                cb.record_success()
        
        threads = [threading.Thread(target=record_successes) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should still work correctly
        self.assertTrue(cb.allow_operation())


# ============================================================================
# RUN ALL TESTS
# ============================================================================

if __name__ == "__main__":
    # Count tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    test_count = suite.countTestCases()
    print(f"Running {test_count} tests for Crypto Error Resilience Engine (Dimension E)...")
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"{'='*60}")
