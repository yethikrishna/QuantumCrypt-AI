"""
Test Suite for QuantumCrypt Error Resilience Engine v12
DIMENSION E: Error Resilience - ADD-ONLY
All tests are NEW - no modifications to existing tests
"""

import sys
import time
import threading
import unittest
import hmac
import hashlib

# Add the source directory
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.crypto_error_resilience_enhanced_v12_2026_june import (
    # Exceptions
    QuantumCryptError,
    KeyManagementError,
    KeyNotFoundError,
    KeyRotationError,
    KeyDerivationError,
    CryptoOperationError,
    EncryptionError,
    DecryptionError,
    SignatureVerificationError,
    HSMConnectionError,
    EntropySourceError,
    RandomnessHealthError,
    AlgorithmCompatibilityError,
    CircuitBreakerTrippedError,
    GracefulDegradationActive,
    
    # Constant-time utilities
    constant_time_compare,
    constant_time_select,
    secure_wipe,
    
    # Crypto Circuit Breaker
    CryptoCircuitBreaker,
    CryptoCircuitState,
    
    # Crypto Retry
    crypto_retry,
    CryptoRetryStrategy,
    
    # Crypto Timeout
    crypto_timeout,
    
    # Graceful Degradation
    CryptoGracefulDegradation,
    KeyFallbackMode,
    
    # Entropy Health
    EntropyHealthMonitor,
    
    # Global functions
    get_crypto_circuit_breaker,
    get_crypto_graceful_degradation,
    get_entropy_health_monitor,
    secure_crypto_execute,
    get_crypto_resilience_report
)

class TestCryptoExceptionHierarchy(unittest.TestCase):
    """Test crypto-specific exception hierarchy"""
    
    def test_base_exception_attributes(self):
        err = QuantumCryptError("Test crypto error", {"key_id": "test"})
        self.assertEqual(err.error_code, "QC_E001")
        self.assertFalse(err.retryable)
        self.assertFalse(err.security_sensitive)
        self.assertEqual(err.details, {"key_id": "test"})
        self.assertIsNotNone(err.timestamp)
    
    def test_key_management_error_security_sensitive(self):
        err = KeyManagementError("Key error")
        self.assertTrue(err.retryable)
        self.assertTrue(err.security_sensitive)
        self.assertEqual(err.error_code, "QC_K001")
    
    def test_key_not_found_not_retryable(self):
        err = KeyNotFoundError("Key not found")
        self.assertFalse(err.retryable)
    
    def test_hsm_connection_error_retryable(self):
        err = HSMConnectionError("HSM down")
        self.assertTrue(err.retryable)
        self.assertEqual(err.severity, "WARNING")
    
    def test_entropy_error_critical(self):
        err = EntropySourceError("Entropy failure")
        self.assertEqual(err.severity, "CRITICAL")
        self.assertTrue(err.security_sensitive)
    
    def test_exception_inheritance(self):
        self.assertTrue(issubclass(KeyNotFoundError, KeyManagementError))
        self.assertTrue(issubclass(EncryptionError, CryptoOperationError))
        self.assertTrue(issubclass(KeyManagementError, QuantumCryptError))
        self.assertTrue(issubclass(RandomnessHealthError, EntropySourceError))

class TestConstantTimeUtilities(unittest.TestCase):
    """Test constant-time security utilities"""
    
    def test_constant_time_compare_equal(self):
        a = b"secret_data_12345"
        b = b"secret_data_12345"
        self.assertTrue(constant_time_compare(a, b))
    
    def test_constant_time_compare_not_equal(self):
        a = b"secret_data_12345"
        b = b"secret_data_12346"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_constant_time_compare_different_lengths(self):
        a = b"short"
        b = b"longer_string"
        self.assertFalse(constant_time_compare(a, b))
    
    def test_constant_time_select_true(self):
        a = b"value_a"
        b = b"value_b"
        result = constant_time_select(True, a, b)
        self.assertEqual(result, a)
    
    def test_constant_time_select_false(self):
        a = b"value_a"
        b = b"value_b"
        result = constant_time_select(False, a, b)
        self.assertEqual(result, b)
    
    def test_secure_wipe_bytearray(self):
        sensitive = bytearray(b"my_secret_key_material")
        original = bytes(sensitive)
        
        secure_wipe(sensitive)
        
        # Verify all bytes are zero
        self.assertEqual(len(sensitive), len(original))
        self.assertTrue(all(b == 0 for b in sensitive))
        # Verify original data is gone
        self.assertNotEqual(bytes(sensitive), original)

class TestCryptoCircuitBreaker(unittest.TestCase):
    """Test Crypto-specific Circuit Breaker"""
    
    def test_circuit_starts_closed(self):
        cb = CryptoCircuitBreaker(failure_threshold=3, name="test")
        self.assertEqual(cb.state, CryptoCircuitState.CLOSED)
        self.assertTrue(cb.can_execute())
    
    def test_circuit_degraded_after_threshold(self):
        cb = CryptoCircuitBreaker(
            failure_threshold=2,
            recovery_timeout=0.1,
            name="test2",
            enable_fallback_mode=True
        )
        
        @cb("encrypt")
        def failing_encrypt():
            raise EncryptionError("Encryption failed")
        
        # First failure
        with self.assertRaises(EncryptionError):
            failing_encrypt()
        self.assertEqual(cb.state, CryptoCircuitState.CLOSED)
        
        # Second failure - should go to DEGRADED
        with self.assertRaises(EncryptionError):
            failing_encrypt()
        self.assertEqual(cb.state, CryptoCircuitState.DEGRADED)
    
    def test_circuit_open_without_fallback(self):
        cb = CryptoCircuitBreaker(
            failure_threshold=1,
            name="test3",
            enable_fallback_mode=False
        )
        
        @cb("decrypt")
        def failing_decrypt():
            raise DecryptionError("Decryption failed")
        
        with self.assertRaises(DecryptionError):
            failing_decrypt()
        
        self.assertEqual(cb.state, CryptoCircuitState.OPEN)
        
        # Next call should fail fast
        with self.assertRaises(CircuitBreakerTrippedError):
            failing_decrypt()
    
    def test_circuit_recovery(self):
        cb = CryptoCircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            name="test4"
        )
        
        @cb("sign")
        def failing_sign():
            raise CryptoOperationError("Sign failed")
        
        # Trigger degraded state
        with self.assertRaises(CryptoOperationError):
            failing_sign()
        
        self.assertEqual(cb.state, CryptoCircuitState.DEGRADED)
        
        # Wait for recovery
        time.sleep(0.15)
        self.assertEqual(cb.state, CryptoCircuitState.CLOSED)
    
    def test_circuit_security_stats(self):
        cb = CryptoCircuitBreaker(name="stats_test")
        
        @cb("encrypt")
        def encrypt_ok():
            return "encrypted"
        
        @cb("decrypt")
        def decrypt_ok():
            return "decrypted"
        
        encrypt_ok()
        encrypt_ok()
        decrypt_ok()
        
        stats = cb.get_security_stats()
        self.assertEqual(stats["operations"]["encryption"]["attempts"], 2)
        self.assertEqual(stats["operations"]["decryption"]["attempts"], 1)
        self.assertEqual(stats["state"], "CLOSED")

class TestCryptoRetry(unittest.TestCase):
    """Test crypto-safe retry mechanism"""
    
    def test_retry_on_hsm_connection_error(self):
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01)
        def flaky_hsm():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMConnectionError("HSM temp failure")
            return "hsm_success"
        
        result = flaky_hsm()
        self.assertEqual(result, "hsm_success")
        self.assertEqual(call_count[0], 2)
    
    def test_no_retry_on_security_errors(self):
        call_count = [0]
        
        @crypto_retry(max_attempts=3, initial_delay=0.01, retry_on=(HSMConnectionError,))
        def security_failure():
            call_count[0] += 1
            raise DecryptionError("Security failure - don't retry")
        
        with self.assertRaises(DecryptionError):
            security_failure()
        
        # Should NOT retry on decryption errors (security sensitive)
        self.assertEqual(call_count[0], 1)
    
    def test_retry_exponential_backoff(self):
        timestamps = []
        
        @crypto_retry(
            max_attempts=3,
            initial_delay=0.01,
            strategy=CryptoRetryStrategy.EXPONENTIAL_SAFE
        )
        def always_fail():
            timestamps.append(time.time())
            raise HSMConnectionError("Always fails")
        
        start = time.time()
        with self.assertRaises(HSMConnectionError):
            always_fail()
        
        elapsed = time.time() - start
        # Should take ~0.01 + 0.02 = 0.03 seconds
        self.assertGreaterEqual(elapsed, 0.02)

class TestCryptoTimeout(unittest.TestCase):
    """Test crypto timeout wrapper"""
    
    def test_timeout_raises_secure_error(self):
        @crypto_timeout(seconds=0.1)
        def slow_key_op():
            time.sleep(1.0)
            return b"key_data"
        
        with self.assertRaises(KeyManagementError):
            slow_key_op()
    
    def test_timeout_with_fallback(self):
        def fallback():
            return b"fallback_key"
        
        @crypto_timeout(seconds=0.1, fallback=fallback)
        def slow_key_op():
            time.sleep(1.0)
            return b"key_data"
        
        result = slow_key_op()
        self.assertEqual(result, b"fallback_key")
    
    def test_no_timeout_for_fast_ops(self):
        @crypto_timeout(seconds=1.0)
        def fast_op():
            return b"done_quickly"
        
        result = fast_op()
        self.assertEqual(result, b"done_quickly")

class TestCryptoGracefulDegradation(unittest.TestCase):
    """Test Crypto Graceful Degradation Manager"""
    
    def setUp(self):
        self.gd = CryptoGracefulDegradation(max_cache_ttl=3600.0)
    
    def test_primary_succeeds(self):
        def primary():
            return b"primary_key_data"
        
        result = self.gd.execute_with_fallback("key_op", primary)
        self.assertEqual(result, b"primary_key_data")
    
    def test_registered_fallback_used(self):
        def primary():
            raise HSMConnectionError("HSM down")
        
        def fallback():
            return b"fallback_key"
        
        self.gd.register_fallback("key_op2", fallback)
        result = self.gd.execute_with_fallback("key_op2", primary)
        self.assertEqual(result, b"fallback_key")
    
    def test_key_cache_fallback(self):
        self.gd.cache_key("my_key_id", b"cached_key_material")
        
        def primary():
            raise HSMConnectionError("HSM down")
        
        result = self.gd.execute_with_fallback("my_key_id", primary)
        self.assertEqual(result, b"cached_key_material")
    
    def test_cache_ttl_expired(self):
        gd_short = CryptoGracefulDegradation(max_cache_ttl=0.01)
        gd_short.cache_key("short_key", b"short_data")
        
        time.sleep(0.02)
        
        def primary():
            raise HSMConnectionError("HSM down")
        
        # Cache expired, no fallback registered
        with self.assertRaises(GracefulDegradationActive):
            gd_short.execute_with_fallback("short_key", primary)
    
    def test_security_report(self):
        def primary():
            raise HSMConnectionError("Fail")
        
        self.gd.cache_key("key1", b"data1")
        self.gd.cache_key("key2", b"data2")
        self.gd.register_fallback("op1", lambda: "fb")
        
        try:
            self.gd.execute_with_fallback("no_fallback", primary)
        except:
            pass
        
        report = self.gd.get_security_report()
        self.assertGreaterEqual(report["total_degradation_events"], 1)
        self.assertEqual(report["cached_keys"], 2)
        self.assertEqual(report["registered_fallbacks"], 1)

class TestEntropyHealthMonitor(unittest.TestCase):
    """Test Entropy Health Monitoring"""
    
    def test_get_safe_random_bytes(self):
        monitor = EntropyHealthMonitor()
        
        result = monitor.get_safe_random_bytes(32)
        self.assertEqual(len(result), 32)
        self.assertIsInstance(result, bytes)
    
    def test_multiple_random_calls(self):
        monitor = EntropyHealthMonitor()
        
        results = set()
        for _ in range(10):
            results.add(monitor.get_safe_random_bytes(16))
        
        # All should be unique (very high probability)
        self.assertEqual(len(results), 10)
    
    def test_entropy_estimation(self):
        monitor = EntropyHealthMonitor()
        
        # High entropy data (random)
        import os
        high_entropy = os.urandom(256)
        high_score = monitor.estimate_entropy(high_entropy)
        
        # Low entropy data (all zeros)
        low_entropy = b"\x00" * 256
        low_score = monitor.estimate_entropy(low_entropy)
        
        self.assertGreater(high_score, low_score)
    
    def test_health_stats(self):
        monitor = EntropyHealthMonitor()
        
        for _ in range(5):
            monitor.get_safe_random_bytes(32)
        
        stats = monitor.get_health_stats()
        self.assertGreater(stats["samples_collected"], 0)
        self.assertFalse(stats["fallback_active"])

class TestSecureCryptoExecute(unittest.TestCase):
    """Test one-shot secure crypto execution"""
    
    def test_success_case(self):
        def works():
            return b"encrypted_data"
        
        result = secure_crypto_execute(works, operation_type="encrypt")
        self.assertEqual(result, b"encrypted_data")
    
    def test_with_timeout(self):
        def slow():
            time.sleep(1.0)
            return b"slow_result"
        
        with self.assertRaises(KeyManagementError):
            secure_crypto_execute(slow, operation_type="key", timeout_sec=0.1)
    
    def test_with_circuit_breaker(self):
        call_count = [0]
        
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise HSMConnectionError("Temp fail")
            return b"ok"
        
        result = secure_crypto_execute(
            flaky,
            operation_type="hsm",
            max_retries=3,
            circuit_breaker="test_cb"
        )
        self.assertEqual(result, b"ok")
        self.assertEqual(call_count[0], 3)

class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_circuit_breaker_singleton(self):
        cb1 = get_crypto_circuit_breaker("global_test")
        cb2 = get_crypto_circuit_breaker("global_test")
        self.assertIs(cb1, cb2)
    
    def test_get_graceful_degradation_singleton(self):
        gd1 = get_crypto_graceful_degradation()
        gd2 = get_crypto_graceful_degradation()
        self.assertIs(gd1, gd2)
    
    def test_get_entropy_monitor_singleton(self):
        em1 = get_entropy_health_monitor()
        em2 = get_entropy_health_monitor()
        self.assertIs(em1, em2)
    
    def test_resilience_report(self):
        # Create some components
        get_crypto_circuit_breaker("report_cb")
        
        report = get_crypto_resilience_report()
        self.assertIn("circuit_breakers", report)
        self.assertIn("graceful_degradation", report)
        self.assertIn("entropy_health", report)
        self.assertIn("timestamp", report)
        self.assertEqual(report["security_status"], "SECURE")

def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoExceptionHierarchy))
    suite.addTests(loader.loadTestsFromTestCase(TestConstantTimeUtilities))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoCircuitBreaker))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoRetry))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoTimeout))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoGracefulDegradation))
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyHealthMonitor))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureCryptoExecute))
    suite.addTests(loader.loadTestsFromTestCase(TestGlobalFunctions))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "total": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "passed": result.testsRun - len(result.failures) - len(result.errors),
        "success": result.wasSuccessful()
    }

if __name__ == "__main__":
    results = run_tests()
    print(f"\n{'='*60}")
    print(f"TEST RESULTS: {results['passed']}/{results['total']} PASSED")
    print(f"Failures: {results['failures']}, Errors: {results['errors']}")
    print(f"Success: {results['success']}")
    print(f"{'='*60}")
    
    import json
    with open("test_results_crypto_error_resilience_v12_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
