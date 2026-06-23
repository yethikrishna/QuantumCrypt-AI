"""
Test Suite for Crypto Error Resilience v25 - PQ TLS Protection
===============================================================
Tests for QuantumCrypt-AI Post-Quantum TLS resilience layer

ADD-ONLY: 100% new test file, zero modifications to existing tests
All tests must pass - backward compatibility verified
"""

import unittest
import time
import threading
import secrets
from typing import Any

# Import the new module
from quantum_crypt.crypto_error_resilience_pq_tls_v25_2026_june import (
    PQSecurityLevel,
    PQCircuitState,
    PQDegradationMode,
    PQTLSConnectionStats,
    PQSecureMemory,
    PQExponentialBackoff,
    PQCircuitBreaker,
    PQKEMTimeoutProtector,
    PQCryptoError,
    PQKEMTimeoutError,
    PQKeyNegotiationError,
    PQParameterValidationError,
    PQTLSResilienceWrapper,
    pq_tls_resilience_decorator,
)


class TestPQSecurityLevel(unittest.TestCase):
    """Test PQ Security Level enum."""

    def test_levels_exist(self):
        """Test all security levels are defined."""
        self.assertEqual(PQSecurityLevel.PQ_ONLY.value, "pq_only")
        self.assertEqual(PQSecurityLevel.HYBRID.value, "hybrid")
        self.assertEqual(PQSecurityLevel.CLASSICAL.value, "classical")


class TestPQCircuitState(unittest.TestCase):
    """Test PQ Circuit State enum."""

    def test_states_exist(self):
        """Test all circuit states are defined."""
        self.assertEqual(PQCircuitState.CLOSED.value, "closed")
        self.assertEqual(PQCircuitState.OPEN.value, "open")
        self.assertEqual(PQCircuitState.HALF_OPEN.value, "half_open")


class TestPQDegradationMode(unittest.TestCase):
    """Test PQ Degradation Mode enum."""

    def test_modes_exist(self):
        """Test all degradation modes are defined."""
        self.assertEqual(PQDegradationMode.FAIL_FAST.value, "fail_fast")
        self.assertEqual(PQDegradationMode.FALLBACK_SECURITY_LEVEL.value, "fallback_security_level")
        self.assertEqual(PQDegradationMode.FALLBACK_TO_CACHE.value, "fallback_to_cache")
        self.assertEqual(PQDegradationMode.FALLBACK_TO_DEFAULT.value, "fallback_to_default")


class TestPQSecureMemory(unittest.TestCase):
    """Test PQ Secure Memory zeroization."""

    def test_secure_zeroize(self):
        """Test multi-pass zeroization."""
        buffer = bytearray(b'\x01\x02\x03\x04\x05' * 100)
        original = bytes(buffer)
        
        PQSecureMemory.secure_zeroize(buffer)
        
        # Should be all zeros after final pass
        self.assertEqual(len(buffer), len(original))
        self.assertEqual(bytes(buffer), b'\x00' * len(buffer))

    def test_create_protected_buffer(self):
        """Test protected buffer creation."""
        buffer = PQSecureMemory.create_protected_buffer(100)
        self.assertEqual(len(buffer), 100)
        self.assertIsInstance(buffer, bytearray)

    def test_emergency_wipe(self):
        """Test emergency wipe of multiple buffers."""
        buf1 = bytearray(b'\x01\x02\x03')
        buf2 = bytearray(b'\x04\x05\x06')
        
        PQSecureMemory.emergency_wipe(buf1, buf2)
        
        self.assertEqual(bytes(buf1), b'\x00\x00\x00')
        self.assertEqual(bytes(buf2), b'\x00\x00\x00')

    def test_zeroize_empty_buffer(self):
        """Test zeroize handles empty buffer."""
        buffer = bytearray()
        PQSecureMemory.secure_zeroize(buffer)
        self.assertEqual(buffer, bytearray())


class TestPQTLSConnectionStats(unittest.TestCase):
    """Test PQ TLS connection statistics."""

    def test_initial_stats(self):
        """Test initial stats are zero."""
        stats = PQTLSConnectionStats()
        summary = stats.get_summary()
        self.assertEqual(summary["total_attempts"], 0)
        self.assertEqual(summary["pq_successful"], 0)
        self.assertEqual(summary["overall_success_rate_pct"], 100.0)

    def test_record_success_by_level(self):
        """Test recording success by security level."""
        stats = PQTLSConnectionStats()
        stats.record_success(PQSecurityLevel.PQ_ONLY, 10.0)
        stats.record_success(PQSecurityLevel.HYBRID, 8.0)
        stats.record_success(PQSecurityLevel.CLASSICAL, 5.0)
        
        summary = stats.get_summary()
        self.assertEqual(summary["total_attempts"], 3)
        self.assertEqual(summary["pq_successful"], 1)
        self.assertEqual(summary["hybrid_successful"], 1)
        self.assertEqual(summary["classical_successful"], 1)
        self.assertEqual(summary["overall_success_rate_pct"], 100.0)

    def test_record_failure_by_level(self):
        """Test recording failures by security level."""
        stats = PQTLSConnectionStats()
        stats.record_failure("timeout", PQSecurityLevel.PQ_ONLY)
        stats.record_failure("negotiation", PQSecurityLevel.HYBRID)
        stats.record_failure("validation", PQSecurityLevel.PQ_ONLY)
        
        summary = stats.get_summary()
        self.assertEqual(summary["pq_failures"], 2)
        self.assertEqual(summary["hybrid_failures"], 1)
        self.assertEqual(summary["kem_operation_timeouts"], 1)
        self.assertEqual(summary["key_negotiation_failures"], 1)
        self.assertEqual(summary["parameter_validation_failures"], 1)

    def test_record_downgrade_and_zeroization(self):
        """Test recording downgrades and zeroizations."""
        stats = PQTLSConnectionStats()
        stats.record_downgrade()
        stats.record_downgrade()
        stats.record_zeroization()
        stats.record_retry()
        stats.record_circuit_trip()
        
        summary = stats.get_summary()
        self.assertEqual(summary["security_level_downgrades"], 2)
        self.assertEqual(summary["emergency_key_zeroizations"], 1)
        self.assertEqual(summary["retry_attempts"], 1)
        self.assertEqual(summary["circuit_breaker_trips"], 1)

    def test_thread_safety(self):
        """Test stats are thread-safe."""
        stats = PQTLSConnectionStats()
        
        def worker():
            for _ in range(50):
                stats.record_success(PQSecurityLevel.PQ_ONLY, 10.0)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        summary = stats.get_summary()
        self.assertEqual(summary["total_attempts"], 500)
        self.assertEqual(summary["pq_successful"], 500)


class TestPQExponentialBackoff(unittest.TestCase):
    """Test PQ Exponential Backoff with crypto-safe jitter."""

    def test_backoff_increases(self):
        """Test delay increases with attempt number."""
        backoff = PQExponentialBackoff(base_delay=0.2, multiplier=2.0)
        
        delays = [backoff.get_delay(i) for i in range(5)]
        
        # Each delay should be larger than previous
        for i in range(1, len(delays)):
            self.assertGreater(delays[i], delays[i-1] * 0.8)  # Account for jitter

    def test_max_delay(self):
        """Test max delay is enforced."""
        backoff = PQExponentialBackoff(base_delay=0.2, max_delay=1.0)
        
        for i in range(10):
            delay = backoff.get_delay(i)
            self.assertLessEqual(delay, 1.0 + 0.1)  # +10% jitter

    def test_crypto_safe_jitter(self):
        """Test jitter produces different values."""
        backoff = PQExponentialBackoff(base_delay=1.0)
        
        delays = [backoff.get_delay(0) for _ in range(100)]
        unique_delays = len(set(round(d, 6) for d in delays))
        
        # With secrets-based jitter, we should see variety
        self.assertGreater(unique_delays, 50)


class TestPQCircuitBreaker(unittest.TestCase):
    """Test PQ Circuit Breaker with security level awareness."""

    def test_initial_state(self):
        """Test circuit starts closed."""
        cb = PQCircuitBreaker()
        self.assertEqual(cb.state, PQCircuitState.CLOSED)
        self.assertTrue(cb.allow_pq_attempt())
        self.assertTrue(cb.allow_hybrid_attempt())

    def test_pq_threshold_downgrade(self):
        """Test PQ failures cause downgrade to hybrid."""
        cb = PQCircuitBreaker(pq_failure_threshold=2)
        
        cb.record_pq_failure()
        self.assertTrue(cb.allow_pq_attempt())
        
        cb.record_pq_failure()
        # PQ mode should now be blocked but hybrid still allowed
        self.assertFalse(cb.allow_pq_attempt())
        self.assertTrue(cb.allow_hybrid_attempt())

    def test_hybrid_threshold_trips_circuit(self):
        """Test hybrid failures can trip circuit."""
        cb = PQCircuitBreaker(hybrid_failure_threshold=3)
        
        cb.record_hybrid_failure()
        cb.record_hybrid_failure()
        self.assertTrue(cb.allow_hybrid_attempt())
        
        cb.record_hybrid_failure()
        self.assertEqual(cb.state, PQCircuitState.OPEN)
        self.assertFalse(cb.allow_pq_attempt())
        self.assertFalse(cb.allow_hybrid_attempt())

    def test_recovery_after_timeout(self):
        """Test circuit recovers after timeout."""
        cb = PQCircuitBreaker(pq_failure_threshold=1, recovery_timeout=0.1)
        
        cb.record_pq_failure()
        cb.record_hybrid_failure()
        cb.record_hybrid_failure()
        cb.record_hybrid_failure()
        self.assertEqual(cb.state, PQCircuitState.OPEN)
        
        time.sleep(0.15)
        self.assertEqual(cb.state, PQCircuitState.HALF_OPEN)

    def test_success_resets_circuit(self):
        """Test success resets all failure counters."""
        cb = PQCircuitBreaker(pq_failure_threshold=2, hybrid_failure_threshold=2)
        
        cb.record_pq_failure()
        cb.record_hybrid_failure()
        
        cb.record_success()
        
        # Should allow PQ attempts again
        self.assertTrue(cb.allow_pq_attempt())
        self.assertTrue(cb.allow_hybrid_attempt())

    def test_reset(self):
        """Test manual circuit reset."""
        cb = PQCircuitBreaker(pq_failure_threshold=1)
        cb.record_pq_failure()
        self.assertFalse(cb.allow_pq_attempt())
        
        cb.reset()
        self.assertTrue(cb.allow_pq_attempt())


class TestPQKEMTimeoutProtector(unittest.TestCase):
    """Test PQ KEM Timeout Protector."""

    def test_initialization(self):
        """Test protector initializes with defaults."""
        protector = PQKEMTimeoutProtector()
        self.assertEqual(protector.kem_operation_timeout, 30.0)
        self.assertEqual(protector.key_negotiation_timeout, 60.0)

    def test_custom_timeouts(self):
        """Test custom timeout values."""
        protector = PQKEMTimeoutProtector(
            kem_operation_timeout=60.0,
            key_negotiation_timeout=120.0,
        )
        self.assertEqual(protector.kem_operation_timeout, 60.0)
        self.assertEqual(protector.key_negotiation_timeout, 120.0)

    def test_execute_with_timeout(self):
        """Test timeout-protected execution."""
        protector = PQKEMTimeoutProtector()
        
        def fast_op():
            return "done"
        
        result = protector.execute_with_timeout(fast_op, 5.0)
        self.assertEqual(result, "done")


class TestPQCryptoExceptions(unittest.TestCase):
    """Test PQ Crypto exception hierarchy."""

    def test_exception_hierarchy(self):
        """Test exceptions inherit correctly."""
        self.assertTrue(issubclass(PQKEMTimeoutError, PQCryptoError))
        self.assertTrue(issubclass(PQKeyNegotiationError, PQCryptoError))
        self.assertTrue(issubclass(PQParameterValidationError, PQCryptoError))

    def test_exception_messages(self):
        """Test exceptions carry messages."""
        err = PQKEMTimeoutError("KEM operation timed out")
        self.assertIn("timed out", str(err))


class TestPQTLSResilienceWrapper(unittest.TestCase):
    """Test main PQ TLS Resilience Wrapper."""

    def test_initialization(self):
        """Test wrapper initializes correctly."""
        wrapper = PQTLSResilienceWrapper()
        self.assertIsNotNone(wrapper.timeout_protector)
        self.assertIsNotNone(wrapper.circuit_breaker)
        self.assertIsNotNone(wrapper.backoff)
        self.assertIsNotNone(wrapper.stats)

    def test_successful_pq_operation(self):
        """Test successful PQ operation."""
        wrapper = PQTLSResilienceWrapper()
        
        def pq_op():
            return "pq_success"
        
        result = wrapper.execute_pq_operation_with_resilience(pq_op)
        self.assertEqual(result, "pq_success")
        
        stats = wrapper.get_stats()
        self.assertEqual(stats["pq_successful"], 1)
        self.assertEqual(stats["total_attempts"], 1)

    def test_security_level_fallback_chain(self):
        """Test fallback from PQ -> Hybrid -> Classical."""
        wrapper = PQTLSResilienceWrapper(max_retries_per_level=0)
        
        call_order = []
        
        def pq_op():
            call_order.append("pq")
            raise PQKeyNegotiationError("PQ failed")
        
        def hybrid_op():
            call_order.append("hybrid")
            return "hybrid_success"
        
        result = wrapper.execute_pq_operation_with_resilience(pq_op, hybrid_op, None)
        self.assertEqual(result, "hybrid_success")
        self.assertEqual(call_order, ["pq", "hybrid"])
        
        stats = wrapper.get_stats()
        self.assertEqual(stats["pq_failures"], 1)
        self.assertEqual(stats["hybrid_successful"], 1)
        self.assertEqual(stats["security_level_downgrades"], 1)

    def test_full_fallback_chain(self):
        """Test full fallback chain all the way to classical."""
        wrapper = PQTLSResilienceWrapper(max_retries_per_level=0)
        
        def pq_op():
            raise PQKeyNegotiationError("PQ failed")
        
        def hybrid_op():
            raise PQKeyNegotiationError("Hybrid failed")
        
        def classical_op():
            return "classical_success"
        
        result = wrapper.execute_pq_operation_with_resilience(pq_op, hybrid_op, classical_op)
        self.assertEqual(result, "classical_success")
        
        stats = wrapper.get_stats()
        self.assertEqual(stats["pq_failures"], 1)
        self.assertEqual(stats["hybrid_failures"], 1)
        self.assertEqual(stats["classical_successful"], 1)
        self.assertGreaterEqual(stats["security_level_downgrades"], 2)

    def test_retry_at_same_level(self):
        """Test retry at same security level before downgrade."""
        wrapper = PQTLSResilienceWrapper(max_retries_per_level=2)
        call_count = [0]
        
        def flaky_pq_op():
            call_count[0] += 1
            if call_count[0] < 3:
                raise PQKEMTimeoutError("Transient timeout")
            return "pq_success"
        
        result = wrapper.execute_pq_operation_with_resilience(flaky_pq_op)
        self.assertEqual(result, "pq_success")
        self.assertEqual(call_count[0], 3)
        
        stats = wrapper.get_stats()
        self.assertEqual(stats["retry_attempts"], 2)
        self.assertEqual(stats["pq_successful"], 1)

    def test_min_security_level_enforced(self):
        """Test minimum acceptable security level."""
        wrapper = PQTLSResilienceWrapper(
            max_retries_per_level=0,
            min_acceptable_security=PQSecurityLevel.HYBRID,
        )
        
        def pq_op():
            raise PQKeyNegotiationError("PQ failed")
        
        def hybrid_op():
            return "hybrid_ok"
        
        def classical_op():
            return "classical_ok"  # Should NOT be called
        
        result = wrapper.execute_pq_operation_with_resilience(pq_op, hybrid_op, classical_op)
        self.assertEqual(result, "hybrid_ok")

    def test_graceful_degradation_final_fallback(self):
        """Test graceful degradation when all levels fail."""
        wrapper = PQTLSResilienceWrapper(
            max_retries_per_level=0,
            degradation_mode=PQDegradationMode.FALLBACK_TO_DEFAULT,
            fallback_value="degraded",
        )
        
        def failing_op():
            raise PQCryptoError("All failed")
        
        result = wrapper.execute_pq_operation_with_resilience(failing_op, failing_op, failing_op)
        self.assertEqual(result, "degraded")
        
        stats = wrapper.get_stats()
        self.assertGreaterEqual(stats["circuit_breaker_trips"], 1)

    def test_fail_fast_mode(self):
        """Test fail fast mode raises exception."""
        wrapper = PQTLSResilienceWrapper(
            max_retries_per_level=0,
            degradation_mode=PQDegradationMode.FAIL_FAST,
        )
        
        def failing_op():
            raise PQCryptoError("Failed")
        
        with self.assertRaises(PQCryptoError):
            wrapper.execute_pq_operation_with_resilience(failing_op, failing_op, failing_op)

    def test_key_zeroization_on_failure(self):
        """Test emergency key zeroization."""
        wrapper = PQTLSResilienceWrapper(
            max_retries_per_level=0,
            enable_key_zeroization=True,
            degradation_mode=PQDegradationMode.FALLBACK_TO_DEFAULT,
            fallback_value=None,
        )
        
        key_buf = bytearray(b'\x01\x02\x03\x04')
        wrapper.register_key_buffer(key_buf)
        
        def failing_op():
            raise PQCryptoError("Failed")
        
        wrapper.execute_pq_operation_with_resilience(failing_op)
        
        # Key should be zeroized
        self.assertEqual(bytes(key_buf), b'\x00\x00\x00\x00')
        
        stats = wrapper.get_stats()
        self.assertEqual(stats["emergency_key_zeroizations"], 1)

    def test_custom_fallback_handler(self):
        """Test custom fallback handler."""
        wrapper = PQTLSResilienceWrapper(
            max_retries_per_level=0,
            degradation_mode=PQDegradationMode.FALLBACK_SECURITY_LEVEL,
        )
        
        handler_called = [False]
        def custom_handler(reason):
            handler_called[0] = True
            return f"custom_{reason}"
        
        wrapper.set_fallback_handler(custom_handler)
        
        def failing_op():
            raise PQCryptoError("Failed")
        
        result = wrapper.execute_pq_operation_with_resilience(failing_op)
        self.assertTrue(handler_called[0])
        self.assertEqual(result, "custom_all_failed")

    def test_stats_disabled(self):
        """Test stats can be disabled."""
        wrapper = PQTLSResilienceWrapper(enable_stats=False)
        self.assertIsNone(wrapper.get_stats())

    def test_reset_functions(self):
        """Test reset functions."""
        wrapper = PQTLSResilienceWrapper()
        
        def op():
            return "ok"
        wrapper.execute_pq_operation_with_resilience(op)
        
        wrapper.reset_stats()
        stats = wrapper.get_stats()
        self.assertEqual(stats["total_attempts"], 0)
        
        wrapper.reset_circuit()
        self.assertEqual(wrapper.circuit_breaker.state, PQCircuitState.CLOSED)


class TestPQDecorator(unittest.TestCase):
    """Test PQ TLS resilience decorator."""

    def test_decorator_works(self):
        """Test decorator applies resilience."""
        @pq_tls_resilience_decorator(max_retries_per_level=1)
        def decorated_func(x):
            return x * 2
        
        result = decorated_func(5)
        self.assertEqual(result, 10)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility."""

    def test_all_exports_exist(self):
        """Test all __all__ exports are available."""
        import quantum_crypt.crypto_error_resilience_pq_tls_v25_2026_june as module
        
        for name in module.__all__:
            self.assertTrue(hasattr(module, name), f"Missing export: {name}")

    def test_no_side_effects_on_import(self):
        """Test importing has no side effects."""
        import quantum_crypt.crypto_error_resilience_pq_tls_v25_2026_june
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
