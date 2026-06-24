"""
Test Suite for PQ Error Resilience Framework v21
QuantumCrypt-AI | Session 129 | Dimension E

STRICT DIMENSION E COMPLIANCE:
- 100% ADD-ONLY - no existing production code modified
- All new code wraps existing functionality
- All existing tests continue to pass
"""

import unittest
import time
import threading
import sys

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.error_resilience_pq_key_operations_v21_2026_june import (
    # Exceptions
    QuantumCryptError,
    PQKeyOperationError,
    KeyGenerationTimeoutError,
    KeyOperationFailedError,
    HSMTemporaryError,
    AlgorithmDowngradeError,
    KeyMaterialCorruptedError,
    EntropyDepletedError,
    PQCircuitBreakerOpenError,
    SecureMemoryError,
    
    # Secure Memory
    secure_zeroize,
    SecureCleanupContext,
    
    # PQ Circuit Breaker
    PQCircuitState,
    PQCircuitBreakerConfig,
    PQCircuitBreaker,
    get_pq_circuit_breaker,
    
    # PQ Timeout
    PQOperationTimeout,
    pq_timeout,
    
    # PQ Retry
    PQRetryConfig,
    PQRetryStrategy,
    pq_retry,
    
    # Algorithm Fallback
    AlgorithmFallbackChain,
    create_pq_classic_fallback,
    
    # PQ Bulkhead
    PQOperationBulkhead,
    
    # Factory
    create_resilient_pq_operation,
    
    # Version
    get_version_info,
    is_backward_compatible,
    VERSION,
    VERSION_CODE
)


class TestPQExceptionHierarchy(unittest.TestCase):
    """Test PQ-specific exception hierarchy."""
    
    def test_base_exception_properties(self):
        """Test base QuantumCryptError properties."""
        err = QuantumCryptError(
            "test error", 
            "QC_TEST_001", 
            retryable=True,
            sensitive=True,
            details={"key_id": "test_key"}
        )
        self.assertEqual(str(err), "test error")
        self.assertEqual(err.error_code, "QC_TEST_001")
        self.assertTrue(err.retryable)
        self.assertTrue(err.sensitive)
        self.assertIn("key_id", err.details)
        self.assertIsNotNone(err.timestamp)
    
    def test_pq_exception_inheritance(self):
        """Test proper inheritance chain for PQ exceptions."""
        self.assertTrue(issubclass(PQKeyOperationError, QuantumCryptError))
        self.assertTrue(issubclass(KeyGenerationTimeoutError, PQKeyOperationError))
        self.assertTrue(issubclass(KeyOperationFailedError, PQKeyOperationError))
        self.assertTrue(issubclass(HSMTemporaryError, PQKeyOperationError))
        self.assertTrue(issubclass(AlgorithmDowngradeError, PQKeyOperationError))
        self.assertTrue(issubclass(KeyMaterialCorruptedError, PQKeyOperationError))
    
    def test_sensitive_exception_flag(self):
        """Test sensitive flag for key material errors."""
        err = KeyMaterialCorruptedError()
        self.assertTrue(err.sensitive)  # Key material errors are sensitive
        
        err2 = HSMTemporaryError()
        self.assertFalse(err2.sensitive)  # HSM errors are not sensitive
    
    def test_hsm_error_retryable(self):
        """HSM temporary errors should be retryable."""
        err = HSMTemporaryError()
        self.assertTrue(err.retryable)
        self.assertIn("retry_after_seconds", err.details)
    
    def test_algorithm_downgrade_details(self):
        """Algorithm downgrade should track requested and fallback algorithms."""
        err = AlgorithmDowngradeError(
            requested_algorithm="CRYSTALS-Kyber",
            fallback_algorithm="RSA-4096"
        )
        self.assertEqual(err.details["requested_algorithm"], "CRYSTALS-Kyber")
        self.assertEqual(err.details["fallback_algorithm"], "RSA-4096")


class TestSecureMemoryZeroization(unittest.TestCase):
    """Test secure memory cleanup utilities."""
    
    def test_bytearray_zeroization(self):
        """Test bytearray zeroization works."""
        sensitive = bytearray(b"secret_key_material_12345")
        original = bytes(sensitive)
        
        secure_zeroize(sensitive)
        
        # Should all be zeros now
        self.assertEqual(len(sensitive), len(original))
        self.assertTrue(all(b == 0 for b in sensitive))
    
    def test_list_zeroization(self):
        """Test list of values zeroization."""
        sensitive = [1, 2, 3, 4, 5]
        secure_zeroize(sensitive)
        self.assertEqual(sensitive, [0, 0, 0, 0, 0])
    
    def test_cleanup_context_manager(self):
        """Test secure cleanup context manager."""
        data = bytearray(b"test_data")
        
        with SecureCleanupContext(data) as ctx:
            self.assertEqual(bytes(data), b"test_data")
        
        # Should be zeroized after context exit
        self.assertTrue(all(b == 0 for b in data))
    
    def test_cleanup_add_object(self):
        """Test adding objects to cleanup context."""
        data1 = bytearray(b"first")
        data2 = bytearray(b"second")
        
        with SecureCleanupContext(data1) as ctx:
            ctx.add(data2)
        
        self.assertTrue(all(b == 0 for b in data1))
        self.assertTrue(all(b == 0 for b in data2))


class TestPQCircuitBreaker(unittest.TestCase):
    """Test PQ-specific circuit breaker."""
    
    def test_pq_circuit_starts_closed(self):
        """New PQ circuit should start CLOSED."""
        cb = PQCircuitBreaker("CRYSTALS-Kyber")
        self.assertEqual(cb.state, PQCircuitState.CLOSED)
    
    def test_pq_circuit_opens_after_failures(self):
        """Circuit should OPEN after threshold failures."""
        config = PQCircuitBreakerConfig(failure_threshold=2, reset_timeout_seconds=60.0)
        cb = PQCircuitBreaker("Kyber", config)
        
        def failing_op():
            raise KeyOperationFailedError(operation="keygen")
        
        # First failure
        with self.assertRaises(KeyOperationFailedError):
            cb.execute(failing_op)
        self.assertEqual(cb.state, PQCircuitState.CLOSED)
        
        # Second failure - opens circuit
        with self.assertRaises(KeyOperationFailedError):
            cb.execute(failing_op)
        self.assertEqual(cb.state, PQCircuitState.OPEN)
    
    def test_open_circuit_blocks_operations(self):
        """Open circuit should block with PQCircuitBreakerOpenError."""
        config = PQCircuitBreakerConfig(failure_threshold=1)
        cb = PQCircuitBreaker("Dilithium", config)
        
        def failing_op():
            raise KeyOperationFailedError()
        
        with self.assertRaises(KeyOperationFailedError):
            cb.execute(failing_op)
        
        # Now circuit should be open
        with self.assertRaises(PQCircuitBreakerOpenError) as ctx:
            cb.execute(failing_op)
        
        self.assertEqual(ctx.exception.details["circuit_name"], "Dilithium")
    
    def test_pq_circuit_reset(self):
        """Manual circuit reset should work."""
        cb = PQCircuitBreaker("Falcon", PQCircuitBreakerConfig(failure_threshold=1))
        
        def failing_op():
            raise KeyOperationFailedError()
        
        with self.assertRaises(KeyOperationFailedError):
            cb.execute(failing_op)
        
        cb.reset()
        self.assertEqual(cb.state, PQCircuitState.CLOSED)
        self.assertEqual(cb.stats.total_calls, 0)
    
    def test_pq_circuit_registry(self):
        """Circuit registry should return same instance."""
        cb1 = get_pq_circuit_breaker("SPHINCS+")
        cb2 = get_pq_circuit_breaker("SPHINCS+")
        self.assertIs(cb1, cb2)


class TestPQOperationTimeout(unittest.TestCase):
    """Test PQ operation timeout wrappers."""
    
    def test_pq_timeout_completes(self):
        """Quick operation should succeed."""
        @pq_timeout(seconds=1.0, algorithm="Kyber", operation="keygen")
        def quick_op():
            return {"key": "generated"}
        
        result = quick_op()
        self.assertEqual(result["key"], "generated")
    
    def test_pq_timeout_raises(self):
        """Slow PQ operation should timeout."""
        @pq_timeout(seconds=0.1, algorithm="Kyber", operation="keygen")
        def slow_op():
            time.sleep(0.5)
            return {"key": "too_slow"}
        
        with self.assertRaises(KeyGenerationTimeoutError) as ctx:
            slow_op()
        
        self.assertEqual(ctx.exception.details["algorithm"], "Kyber")
        self.assertEqual(ctx.exception.details["operation"], "keygen")
    
    def test_pq_timeout_context_manager(self):
        """Test timeout as context manager."""
        with pq_timeout(seconds=1.0):
            result = "success"
        self.assertEqual(result, "success")


class TestPQRetryStrategy(unittest.TestCase):
    """Test PQ-optimized retry strategy."""
    
    def test_pq_retry_hsm_failure(self):
        """HSM temporary failures should be retried."""
        call_count = [0]
        
        @pq_retry(max_attempts=3, initial_delay_seconds=0.01)
        def flaky_hsm():
            call_count[0] += 1
            if call_count[0] < 3:
                raise HSMTemporaryError(hsm_id="hsm_001")
            return {"status": "connected"}
        
        result = flaky_hsm()
        self.assertEqual(result["status"], "connected")
        self.assertEqual(call_count[0], 3)
    
    def test_pq_retry_permanent_failure(self):
        """Permanent failures should NOT be retried."""
        call_count = [0]
        
        @pq_retry(max_attempts=3, initial_delay_seconds=0.01)
        def permanent_fail():
            call_count[0] += 1
            raise KeyMaterialCorruptedError()  # Not in retry list
        
        with self.assertRaises(KeyMaterialCorruptedError):
            permanent_fail()
        
        self.assertEqual(call_count[0], 1)  # No retry
    
    def test_pq_retry_backoff_calculation(self):
        """Test PQ backoff delay calculation."""
        config = PQRetryConfig(
            initial_delay_seconds=1.0,
            backoff_factor=1.5,
            max_delay_seconds=10.0
        )
        strategy = PQRetryStrategy(config)
        
        delays = [strategy._calculate_delay(i) for i in range(5)]
        
        # Should increase
        self.assertLess(delays[0], delays[1])
        # Should not exceed max
        for d in delays:
            self.assertLessEqual(d, 10.0)


class TestAlgorithmFallbackChain(unittest.TestCase):
    """Test algorithm graceful degradation."""
    
    def test_primary_algorithm_succeeds(self):
        """Primary algorithm succeeding uses no fallback."""
        chain = AlgorithmFallbackChain("test")
        
        def pq_impl():
            return {"algorithm": "pq", "key": "pq_key"}
        
        def classic_impl():
            return {"algorithm": "classic", "key": "classic_key"}
        
        chain.add_algorithm("PQ", pq_impl)
        chain.add_algorithm("Classic", classic_impl)
        
        result, used = chain.execute()
        self.assertEqual(used, "PQ")
        self.assertEqual(result["algorithm"], "pq")
        self.assertEqual(len(chain.fallback_events), 0)
    
    def test_algorithm_fallback_activates(self):
        """Primary failing should use fallback."""
        chain = AlgorithmFallbackChain("pq_fallback")
        
        def pq_fails():
            raise KeyOperationFailedError("PQ unavailable")
        
        def classic_works():
            return {"key": "classic_fallback"}
        
        chain.add_algorithm("Kyber", pq_fails)
        chain.add_algorithm("RSA", classic_works)
        
        result, used = chain.execute()
        self.assertEqual(used, "RSA")
        self.assertEqual(len(chain.fallback_events), 1)
        self.assertEqual(chain.fallback_events[0]["fallback_to"], "RSA")
    
    def test_create_pq_classic_fallback(self):
        """Test standard PQ->Classic fallback factory."""
        def pq():
            raise KeyOperationFailedError()
        
        def classic():
            return {"key": "rsa_key"}
        
        chain = create_pq_classic_fallback(pq, classic)
        result, alg = chain.execute()
        
        self.assertEqual(alg, "RSA-4096")
        self.assertEqual(result["key"], "rsa_key")
    
    def test_all_algorithms_fail(self):
        """All algorithms failing should raise."""
        chain = AlgorithmFallbackChain("all_fail")
        
        def fail1():
            raise KeyOperationFailedError("1")
        
        def fail2():
            raise KeyOperationFailedError("2")
        
        chain.add_algorithm("1", fail1)
        chain.add_algorithm("2", fail2)
        
        with self.assertRaises(KeyOperationFailedError) as ctx:
            chain.execute()
        
        self.assertIn("algorithm_failures", ctx.exception.details)


class TestPQOperationBulkhead(unittest.TestCase):
    """Test PQ operation bulkhead isolation."""
    
    def test_bulkhead_executes(self):
        """Bulkhead should execute operations normally."""
        bulkhead = PQOperationBulkhead("keygen", max_concurrent=2)
        
        def keygen():
            return {"key": "generated"}
        
        result = bulkhead.execute(keygen)
        self.assertEqual(result["key"], "generated")
        self.assertEqual(bulkhead.stats["executed"], 1)
    
    def test_bulkhead_concurrency_limit(self):
        """Bulkhead should limit concurrent operations."""
        max_concurrent = 2
        bulkhead = PQOperationBulkhead("test", max_concurrent=max_concurrent)
        active = [0]
        max_active = [0]
        lock = threading.Lock()
        
        def limited_op():
            with lock:
                active[0] += 1
                max_active[0] = max(max_active[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
        
        threads = [threading.Thread(target=lambda: bulkhead.execute(limited_op)) 
                  for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertLessEqual(max_active[0], max_concurrent)
    
    def test_bulkhead_decorator(self):
        """Test bulkhead as decorator."""
        bulkhead = PQOperationBulkhead("decorator")
        
        @bulkhead
        def op():
            return "decorated"
        
        self.assertEqual(op(), "decorated")


class TestPQResilienceFactory(unittest.TestCase):
    """Test full PQ resilience stack factory."""
    
    def test_create_resilient_pq_operation(self):
        """Test full resilience stack creation."""
        call_count = [0]
        
        def flaky_keygen():
            call_count[0] += 1
            if call_count[0] < 2:
                raise HSMTemporaryError()
            return {"private_key": "secret", "public_key": "pub"}
        
        resilient = create_resilient_pq_operation(
            flaky_keygen,
            algorithm="Kyber",
            operation="keygen",
            timeout_seconds=10.0,
            max_attempts=3,
            enable_circuit=True,
            enable_bulkhead=True
        )
        
        result = resilient()
        self.assertIn("private_key", result)
        self.assertGreaterEqual(call_count[0], 2)


class TestVersionAndMetadata(unittest.TestCase):
    """Test version information."""
    
    def test_version_info(self):
        """Version info should be correct."""
        info = get_version_info()
        self.assertEqual(info["version"], VERSION)
        self.assertEqual(info["version_code"], VERSION_CODE)
        self.assertEqual(info["dimension"], "E - Error Resilience")
        self.assertEqual(info["session"], "129")
        self.assertIn("secure_memory_zeroization", info["features"])
    
    def test_backward_compatible(self):
        """Should always be backward compatible."""
        self.assertTrue(is_backward_compatible())


if __name__ == '__main__':
    unittest.main(verbosity=2)
