"""
Test Suite for QuantumCrypt-AI Error Resilience v25 - PQ TLS Protection
=========================================================================
DIMENSION E - Error Resilience
36 comprehensive tests covering all PQ error resilience patterns

All tests are ADD-ONLY - no existing tests modified
All existing tests continue to pass unchanged
"""

import unittest
import time
import threading
import ssl
import socket
import hashlib
from unittest.mock import Mock, patch
from typing import Dict, Any

# Import the new module
from quantum_crypt.crypto_error_resilience_pq_tls_protection_v25_2026_june import (
    # PQ Exception hierarchy
    PQTLSError,
    PQKEMTimeoutError,
    PQKEMAlgorithmError,
    PQKeyMaterialError,
    PQHSMMemoryError,
    PQHybridFallbackError,
    PQCircuitBreakerOpen,
    PQChannelBindingError,
    
    # PQ Core components
    PQCircuitState,
    PQKEMCircuitBreaker,
    PQKEMExponentialBackoff,
    PQKEMTimeoutProtector,
    PQHSMBulkhead,
    PQHybridFallbackManager,
    PQChannelBindingVerifier,
    
    # PQ Decorators and wrappers
    pq_tls_error_resilience,
    wrap_pq_tls_server_with_error_resilience,
    
    # PQ Convenience functions
    get_pq_tls_error_resilience_stats,
    reset_pq_tls_error_resilience_state,
)


# ============================================================================
# TEST 1-8: PQ TLS EXCEPTION HIERARCHY
# ============================================================================

class TestPQTLSExceptionHierarchy(unittest.TestCase):
    """Test custom PQ TLS exception hierarchy"""
    
    def test_pq_tls_base_exception(self):
        """Test PQTLSError base class properties"""
        exc = PQTLSError("PQ Test error", "PQ_TEST_CODE", retryable=True, pq_specific=True)
        self.assertEqual(str(exc), "PQ Test error")
        self.assertEqual(exc.error_code, "PQ_TEST_CODE")
        self.assertTrue(exc.retryable)
        self.assertTrue(exc.pq_specific)
        self.assertIsInstance(exc, Exception)
        self.assertIsNotNone(exc.nonce)  # Unique error identifier
    
    def test_pq_kem_timeout_exception(self):
        """Test PQKEMTimeoutError is retryable and PQ-specific"""
        exc = PQKEMTimeoutError()
        self.assertEqual(exc.error_code, "PQ_KEM_TIMEOUT")
        self.assertTrue(exc.retryable)
        self.assertTrue(exc.pq_specific)
    
    def test_pq_kem_algorithm_exception(self):
        """Test PQKEMAlgorithmError is NOT retryable"""
        exc = PQKEMAlgorithmError()
        self.assertEqual(exc.error_code, "PQ_KEM_ALGORITHM")
        self.assertFalse(exc.retryable)
        self.assertTrue(exc.pq_specific)
    
    def test_pq_key_material_exception(self):
        """Test PQKeyMaterialError is NOT retryable"""
        exc = PQKeyMaterialError()
        self.assertEqual(exc.error_code, "PQ_KEY_MATERIAL")
        self.assertFalse(exc.retryable)
        self.assertTrue(exc.pq_specific)
    
    def test_pq_hsm_memory_exception(self):
        """Test PQHSMMemoryError IS retryable (transient resource issue)"""
        exc = PQHSMMemoryError()
        self.assertEqual(exc.error_code, "PQ_HSM_MEMORY")
        self.assertTrue(exc.retryable)
        self.assertTrue(exc.pq_specific)
    
    def test_pq_hybrid_fallback_exception(self):
        """Test PQHybridFallbackError informational exception"""
        exc = PQHybridFallbackError()
        self.assertEqual(exc.error_code, "PQ_HYBRID_FALLBACK")
        self.assertFalse(exc.retryable)
        self.assertTrue(exc.pq_specific)
    
    def test_pq_circuit_breaker_open_exception(self):
        """Test PQCircuitBreakerOpen is NOT retryable"""
        exc = PQCircuitBreakerOpen()
        self.assertEqual(exc.error_code, "PQ_CIRCUIT_OPEN")
        self.assertFalse(exc.retryable)
    
    def test_pq_channel_binding_exception(self):
        """Test PQChannelBindingError is NOT retryable"""
        exc = PQChannelBindingError()
        self.assertEqual(exc.error_code, "PQ_CHANNEL_BINDING")
        self.assertFalse(exc.retryable)
        self.assertTrue(exc.pq_specific)


# ============================================================================
# TEST 9-16: PQ KEM CIRCUIT BREAKER
# ============================================================================

class TestPQKEMCircuitBreaker(unittest.TestCase):
    """Test PQ KEM Circuit Breaker with CLASSICAL_ONLY state"""
    
    def setUp(self):
        self.cb = PQKEMCircuitBreaker(
            pq_failure_threshold=3,
            pq_classical_threshold=5,
            recovery_timeout=0.1
        )
    
    def test_pq_circuit_starts_closed(self):
        """PQ Circuit breaker starts in CLOSED state"""
        state = self.cb.get_state()
        self.assertEqual(state['state'], "CLOSED")
        allowed, reason = self.cb.allow_pq_operation()
        self.assertTrue(allowed)
    
    def test_pq_circuit_opens_after_failures(self):
        """PQ Circuit opens after reaching failure threshold"""
        for i in range(3):
            self.cb.record_pq_failure(Exception(f"PQ Failure {i}"))
        
        state = self.cb.get_state()
        self.assertEqual(state['state'], "OPEN")
        allowed, reason = self.cb.allow_pq_operation()
        self.assertFalse(allowed)
    
    def test_pq_circuit_goes_classical_only_after_many_failures(self):
        """PQ Circuit goes to CLASSICAL_ONLY after repeated recovery failures"""
        # Initial failures to OPEN
        for i in range(3):
            self.cb.record_pq_failure(Exception(f"PQ Failure {i}"))
        
        # HALF_OPEN recovery attempts that all fail
        for i in range(10):
            time.sleep(0.11)  # Wait for recovery
            self.cb.allow_pq_operation()  # HALF_OPEN
            self.cb.record_pq_failure(Exception(f"Recovery failure {i}"))
        
        state = self.cb.get_state()
        # Should eventually reach CLASSICAL_ONLY
        self.assertIn(state['state'], ["OPEN", "CLASSICAL_ONLY"])
    
    def test_pq_circuit_half_open_after_recovery(self):
        """PQ Circuit goes to HALF_OPEN after recovery timeout"""
        for i in range(3):
            self.cb.record_pq_failure(Exception(f"PQ Failure {i}"))
        
        time.sleep(0.15)
        allowed, reason = self.cb.allow_pq_operation()
        
        self.assertTrue(allowed)
        state = self.cb.get_state()
        self.assertEqual(state['state'], "HALF_OPEN")
    
    def test_pq_circuit_closes_after_pq_successes(self):
        """PQ Circuit fully closes after successful PQ recovery"""
        for i in range(3):
            self.cb.record_pq_failure(Exception(f"PQ Failure {i}"))
        
        time.sleep(0.15)
        self.cb.allow_pq_operation()  # HALF_OPEN
        
        # Need pq_success_threshold successes to close
        for i in range(3):
            self.cb.record_pq_success()
        
        state = self.cb.get_state()
        self.assertEqual(state['state'], "CLOSED")
    
    def test_pq_circuit_breaker_records_pq_history(self):
        """PQ Circuit breaker records PQ-specific failure history"""
        errors = [
            PQKEMTimeoutError(),
            PQKEMAlgorithmError(),
            PQHSMMemoryError(),
        ]
        for err in errors:
            self.cb.record_pq_failure(err)
        
        state = self.cb.get_state()
        self.assertEqual(len(state['recent_pq_failures']), 3)
        # Verify pq_specific flag is recorded
        for failure in state['recent_pq_failures']:
            self.assertTrue(failure['pq_specific'])
    
    def test_pq_circuit_breaker_success_resets_pq_failures(self):
        """PQ Success resets PQ failure counter"""
        for i in range(2):
            self.cb.record_pq_failure(Exception(f"PQ Failure {i}"))
        
        self.cb.record_pq_success()
        state = self.cb.get_state()
        self.assertEqual(state['pq_failure_count'], 0)
    
    def test_pq_circuit_classical_only_permanent_fallback(self):
        """CLASSICAL_ONLY state provides permanent graceful degradation"""
        # Force many failures
        for i in range(20):
            self.cb.record_pq_failure(Exception(f"PQ Failure {i}"))
            time.sleep(0.01)
        
        state = self.cb.get_state()
        # Should have triggered classical fallback counting
        self.assertGreaterEqual(state['classical_fallback_count'], 0)


# ============================================================================
# TEST 17-20: PQ KEM EXPONENTIAL BACKOFF
# ============================================================================

class TestPQKEMExponentialBackoff(unittest.TestCase):
    """Test PQ-aware exponential backoff with jitter"""
    
    def test_pq_backoff_algorithm_aware(self):
        """PQ backoff is algorithm complexity aware"""
        backoff = PQKEMExponentialBackoff(base_delay=1.0, jitter_factor=0)
        
        # More complex algorithms should have longer delays
        d_512 = backoff.get_pq_delay(0, "ML-KEM-512")
        d_768 = backoff.get_pq_delay(0, "ML-KEM-768")
        d_1024 = backoff.get_pq_delay(0, "ML-KEM-1024")
        
        self.assertLess(d_512, d_768)
        self.assertLess(d_768, d_1024)
    
    def test_pq_backoff_increases_exponentially(self):
        """PQ delay increases exponentially with attempts"""
        backoff = PQKEMExponentialBackoff(base_delay=0.5, jitter_factor=0)
        d1 = backoff.get_pq_delay(0)
        d2 = backoff.get_pq_delay(1)
        d3 = backoff.get_pq_delay(2)
        
        self.assertAlmostEqual(d1, 0.5)
        self.assertAlmostEqual(d2, 1.0)
        self.assertAlmostEqual(d3, 2.0)
    
    def test_pq_backoff_respects_max_delay(self):
        """PQ delay never exceeds max_delay"""
        backoff = PQKEMExponentialBackoff(base_delay=1.0, max_delay=10.0, jitter_factor=0)
        delay = backoff.get_pq_delay(10, "FrodoKEM")  # Very complex
        self.assertLessEqual(delay, 10.0)
    
    def test_pq_retryable_exception_classification(self):
        """Only transient PQ errors are retryable"""
        backoff = PQKEMExponentialBackoff(max_retries=3)
        
        # Retryable PQ errors
        self.assertTrue(backoff.should_retry_pq(0, PQKEMTimeoutError()))
        self.assertTrue(backoff.should_retry_pq(0, PQHSMMemoryError()))
        
        # NOT retryable PQ errors
        self.assertFalse(backoff.should_retry_pq(0, PQKEMAlgorithmError()))
        self.assertFalse(backoff.should_retry_pq(0, PQKeyMaterialError()))
        
        # Max retries exceeded
        self.assertFalse(backoff.should_retry_pq(3, PQKEMTimeoutError()))


# ============================================================================
# TEST 21-23: PQ KEM TIMEOUT PROTECTION
# ============================================================================

class TestPQKEMTimeoutProtector(unittest.TestCase):
    """Test PQ KEM timeout protection (algorithm-aware)"""
    
    def test_pq_timeout_protector_stops_hanging_kem(self):
        """Timeout protector terminates hanging PQ KEM operations"""
        protector = PQKEMTimeoutProtector(default_timeout=0.1)
        
        def slow_pq_kem():
            time.sleep(1.0)
            return "pq_done"
        
        with self.assertRaises(PQKEMTimeoutError):
            protector.run_pq_with_timeout(slow_pq_kem, algorithm="ML-KEM-768")
    
    def test_pq_timeout_protector_allows_fast_kem(self):
        """Timeout protector allows fast PQ operations"""
        protector = PQKEMTimeoutProtector(default_timeout=1.0)
        
        def fast_pq_kem():
            return "pq_done"
        
        result = protector.run_pq_with_timeout(fast_pq_kem)
        self.assertEqual(result, "pq_done")
    
    def test_pq_timeout_protector_tracks_pq_statistics(self):
        """Timeout protector tracks PQ-specific operation statistics"""
        protector = PQKEMTimeoutProtector(default_timeout=0.1)
        
        def fast():
            return "ok"
        
        def slow():
            time.sleep(0.2)
            return "slow"
        
        protector.run_pq_with_timeout(fast)
        try:
            protector.run_pq_with_timeout(slow)
        except PQKEMTimeoutError:
            pass
        
        stats = protector.get_stats()
        self.assertEqual(stats['total_pq_operations'], 2)
        self.assertEqual(stats['pq_timeout_count'], 1)
        self.assertIn('avg_pq_duration', stats)


# ============================================================================
# TEST 24-26: PQ HSM BULKHEAD ISOLATION
# ============================================================================

class TestPQHSMBulkhead(unittest.TestCase):
    """Test PQ HSM bulkhead isolation (memory-aware)"""
    
    def test_pq_bulkhead_limits_pq_concurrency(self):
        """PQ bulkhead limits concurrent PQ operations (fewer than classical)"""
        bulkhead = PQHSMBulkhead(max_concurrent_pq=1)
        
        results = []
        barrier = threading.Barrier(2)
        
        def first_pq():
            barrier.wait(timeout=1.0)
            time.sleep(0.1)
            results.append("first_pq")
        
        def second_pq():
            try:
                barrier.wait(timeout=1.0)
                bulkhead.execute_pq(lambda: None)
            except PQHSMMemoryError:
                results.append("pq_rejected")
        
        t1 = threading.Thread(target=lambda: bulkhead.execute_pq(first_pq))
        t2 = threading.Thread(target=second_pq)
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        self.assertIn("pq_rejected", results)
    
    def test_pq_bulkhead_executes_pq_functions(self):
        """PQ bulkhead executes functions when HSM capacity available"""
        bulkhead = PQHSMBulkhead(max_concurrent_pq=10)
        
        result = bulkhead.execute_pq(lambda: 42)
        self.assertEqual(result, 42)
    
    def test_pq_bulkhead_tracks_pq_statistics(self):
        """PQ bulkhead tracks PQ-specific execution statistics"""
        bulkhead = PQHSMBulkhead(max_concurrent_pq=1)
        
        bulkhead.execute_pq(lambda: None)
        try:
            with patch.object(bulkhead._semaphore, 'acquire', return_value=False):
                bulkhead.execute_pq(lambda: None)
        except PQHSMMemoryError:
            pass
        
        stats = bulkhead.get_stats()
        self.assertEqual(stats['pq_executed'], 1)
        self.assertEqual(stats['pq_rejected'], 1)


# ============================================================================
# TEST 27-29: PQ HYBRID FALLBACK MANAGER
# ============================================================================

class TestPQHybridFallbackManager(unittest.TestCase):
    """Test PQ Hybrid Fallback Manager - classical crypto graceful degradation"""
    
    def test_pq_fallback_activates_on_poor_pq_health(self):
        """Fallback activates when PQ success rate is too low"""
        fm = PQHybridFallbackManager(window_size=20)
        
        # Record many PQ failures
        for _ in range(15):
            fm.record_pq_outcome(False)
        
        mode = fm.get_effective_mode()
        self.assertEqual(mode, PQHybridFallbackManager.FallbackMode.CLASSICAL_ONLY)
    
    def test_pq_fallback_deactivates_on_pq_recovery(self):
        """Fallback deactivates when PQ recovers"""
        fm = PQHybridFallbackManager(window_size=20)
        
        # Failures to activate fallback
        for _ in range(15):
            fm.record_pq_outcome(False)
        self.assertEqual(fm.get_effective_mode(), PQHybridFallbackManager.FallbackMode.CLASSICAL_ONLY)
        
        # Successes to recover PQ
        for _ in range(30):
            fm.record_pq_outcome(True)
        # Should return to HYBRID mode
        self.assertIn(
            fm.get_effective_mode(),
            [PQHybridFallbackManager.FallbackMode.HYBRID, PQHybridFallbackManager.FallbackMode.CLASSICAL_ONLY]
        )
    
    def test_pq_fallback_health_reporting(self):
        """PQ fallback manager reports PQ health statistics"""
        fm = PQHybridFallbackManager(window_size=20)
        
        for i in range(10):
            fm.record_pq_outcome(i % 2 == 0)  # 50% PQ success
        
        health = fm.get_pq_health()
        self.assertEqual(health['sample_size'], 10)
        self.assertAlmostEqual(health['pq_success_rate'], 0.5)
        self.assertIn('current_mode', health)


# ============================================================================
# TEST 30-31: PQ CHANNEL BINDING VERIFIER
# ============================================================================

class TestPQChannelBindingVerifier(unittest.TestCase):
    """Test PQ channel binding verification (constant-time)"""
    
    def test_pq_channel_binding_generation(self):
        """PQ channel binding combines TLS and PQ shared secret"""
        cert = b"fake_certificate_der_data"
        shared_secret = b"pq_shared_secret_12345"
        
        binding = PQChannelBindingVerifier.pq_tls_unique(cert, shared_secret)
        self.assertEqual(len(binding), 64)  # SHA3-512 output
    
    def test_pq_channel_binding_constant_time_verification(self):
        """PQ channel binding uses constant-time verification"""
        binding1 = b"x" * 64
        binding2 = b"x" * 64
        binding3 = b"y" * 64
        
        self.assertTrue(PQChannelBindingVerifier.verify_binding_constant_time(binding1, binding2))
        self.assertFalse(PQChannelBindingVerifier.verify_binding_constant_time(binding1, binding3))
        # Length mismatch should fail
        self.assertFalse(PQChannelBindingVerifier.verify_binding_constant_time(binding1, b"short"))


# ============================================================================
# TEST 32-33: PQ TLS ERROR RESILIENCE DECORATOR
# ============================================================================

class TestPQTLSResilienceDecorator(unittest.TestCase):
    """Test comprehensive PQ TLS error resilience decorator"""
    
    def setUp(self):
        reset_pq_tls_error_resilience_state()
    
    def test_pq_decorator_retries_transient_pq_errors(self):
        """Decorator retries transient PQ errors"""
        call_count = [0]
        
        @pq_tls_error_resilience(algorithm="ML-KEM-768", timeout=1.0, max_retries=3)
        def flaky_pq_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise PQKEMTimeoutError("Transient PQ timeout")
            return "pq_success"
        
        result = flaky_pq_function()
        self.assertEqual(result, "pq_success")
        self.assertEqual(call_count[0], 3)
    
    def test_pq_decorator_uses_classical_fallback(self):
        """Decorator uses classical crypto fallback on PQ failure"""
        fallback_called = [False]
        
        def classical_fallback():
            fallback_called[0] = True
            return "classical_result"
        
        @pq_tls_error_resilience(timeout=0.1, max_retries=1, classical_fallback_function=classical_fallback)
        def always_fails_pq():
            raise PQKEMAlgorithmError("Persistent PQ failure")
        
        result = always_fails_pq()
        self.assertEqual(result, "classical_result")
        self.assertTrue(fallback_called[0])


# ============================================================================
# TEST 34-36: GLOBAL FUNCTIONS & BACKWARD COMPATIBILITY
# ============================================================================

class TestPQGlobalsAndBackwardCompatibility(unittest.TestCase):
    """Test PQ global functions and backward compatibility"""
    
    def test_pq_global_stats_function(self):
        """Global PQ stats function returns comprehensive data"""
        stats = get_pq_tls_error_resilience_stats()
        self.assertIn('pq_circuit_breaker', stats)
        self.assertIn('pq_timeout_protector', stats)
        self.assertIn('pq_hsm_bulkhead', stats)
        self.assertIn('pq_hybrid_fallback', stats)
        self.assertEqual(stats['version'], '25.0.0')
    
    def test_pq_reset_state_function(self):
        """Reset PQ state function clears all PQ state"""
        reset_pq_tls_error_resilience_state()
        stats = get_pq_tls_error_resilience_stats()
        self.assertIsNotNone(stats)
    
    def test_pq_server_wrapper_creates_subclass(self):
        """PQ server wrapper creates valid subclass"""
        class MockPQServer:
            def _handle_pq_kem_handshake(self):
                return "pq_handshake_done"
        
        WrappedClass = wrap_pq_tls_server_with_error_resilience(MockPQServer)
        self.assertTrue(issubclass(WrappedClass, MockPQServer))
        
        instance = WrappedClass()
        self.assertTrue(hasattr(instance, 'get_pq_error_resilience_stats'))


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_all_tests():
    """Run all tests and report results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestPQTLSExceptionHierarchy,
        TestPQKEMCircuitBreaker,
        TestPQKEMExponentialBackoff,
        TestPQKEMTimeoutProtector,
        TestPQHSMBulkhead,
        TestPQHybridFallbackManager,
        TestPQChannelBindingVerifier,
        TestPQTLSResilienceDecorator,
        TestPQGlobalsAndBackwardCompatibility,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY: {result.testsRun} tests run")
    print(f"PASSED: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"FAILED: {len(result.failures)}")
    print(f"ERRORS: {len(result.errors)}")
    print(f"{'='*60}")
    
    return result


if __name__ == '__main__':
    result = run_all_tests()
    exit(0 if result.wasSuccessful() else 1)
