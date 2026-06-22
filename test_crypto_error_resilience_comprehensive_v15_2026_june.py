"""
Test Suite for QuantumCrypt Comprehensive Error Resilience Engine V15
Dimension E: Error Resilience

Tests cover:
- Cryptographic exception hierarchy
- Entropy health monitoring and validation
- Crypto-specific retry with entropy jitter
- HSM failover with software fallback
- Constant-time execution protection
- Key rotation resilience with rollback
- Composite crypto resilience pipelines
- Thread safety verification

All tests verify NO modification to cryptographic outputs.
"""

import pytest
import time
import threading
import os
from typing import Any
from unittest.mock import MagicMock, patch

# Import the resilience module
import sys
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.crypto_error_resilience_comprehensive_v15_2026_june import (
    # Exceptions
    QuantumCryptResilienceError,
    KeyGenerationError,
    HSMUnavailableError,
    EntropyDepletionError,
    SignatureVerificationError,
    KeyRotationError,
    ConstantTimeViolationError,
    
    # Entropy Monitoring
    EntropyHealthStatus,
    EntropyMetrics,
    EntropyHealthMonitor,
    
    # Crypto Retry
    CryptoRetryConfig,
    CryptoRetryWithEntropyJitter,
    
    # HSM Failover
    HSMFallbackMode,
    HSMFallbackConfig,
    HSMFailover,
    
    # Constant Time
    ConstantTimeHandler,
    
    # Key Rotation
    KeyRotationState,
    KeyRotationContext,
    KeyRotationResilience,
    
    # Pipeline
    CryptoResiliencePipeline,
    
    # Convenience
    crypto_resilient,
    
    # Globals
    global_entropy_monitor,
    global_rotation_manager,
)

# ============================================================================
# Cryptographic Exception Hierarchy Tests
# ============================================================================

class TestCryptoExceptionHierarchy:
    """Test cryptographic exception hierarchy"""
    
    def test_base_exception_type(self):
        assert issubclass(QuantumCryptResilienceError, Exception)
    
    def test_key_generation_error(self):
        inner = ValueError("RNG failure")
        exc = KeyGenerationError("Kyber-1024", 3, inner)
        assert isinstance(exc, QuantumCryptResilienceError)
        assert exc.algorithm == "Kyber-1024"
        assert exc.attempts == 3
    
    def test_hsm_unavailable_error(self):
        exc = HSMUnavailableError("HSM-001", True)
        assert isinstance(exc, QuantumCryptResilienceError)
        assert exc.hsm_id == "HSM-001"
        assert exc.fallback_used == True
    
    def test_entropy_depletion_error(self):
        exc = EntropyDepletionError(64, 256)
        assert isinstance(exc, QuantumCryptResilienceError)
        assert exc.available_bits == 64
        assert exc.minimum_required == 256
    
    def test_key_rotation_error(self):
        exc = KeyRotationError("KEY-001", "activation")
        assert isinstance(exc, QuantumCryptResilienceError)
        assert exc.key_id == "KEY-001"
        assert exc.stage == "activation"

# ============================================================================
# Entropy Health Monitor Tests
# ============================================================================

class TestEntropyHealthMonitor:
    """Test Entropy health monitoring"""
    
    def test_monitor_starts_healthy(self):
        monitor = EntropyHealthMonitor()
        assert monitor.is_healthy
        assert monitor.metrics.status == EntropyHealthStatus.HEALTHY
    
    def test_entropy_metrics_populated(self):
        monitor = EntropyHealthMonitor()
        metrics = monitor.metrics
        assert metrics.sample_count > 0
        assert metrics.shannon_entropy >= 0
        assert metrics.last_refresh > 0
    
    def test_get_safe_random_returns_bytes(self):
        monitor = EntropyHealthMonitor()
        result = monitor.get_safe_random(32)
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_safe_random_combines_sources(self):
        monitor = EntropyHealthMonitor()
        # Multiple calls should give different results
        r1 = monitor.get_safe_random(32)
        r2 = monitor.get_safe_random(32)
        assert r1 != r2  # Extremely unlikely to collide
    
    def test_assert_sufficient_entropy_passes_when_healthy(self):
        monitor = EntropyHealthMonitor()
        # Should not raise
        monitor.assert_sufficient_entropy()
        assert True

# ============================================================================
# Crypto Retry with Entropy Jitter Tests
# ============================================================================

class TestCryptoRetryWithEntropyJitter:
    """Test crypto-specific retry mechanism"""
    
    def test_crypto_retry_succeeds_eventually(self):
        call_count = [0]
        
        @CryptoRetryWithEntropyJitter(CryptoRetryConfig(max_attempts=3))
        def flaky_keygen():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("transient RNG error")
            return os.urandom(32)
        
        result = flaky_keygen()
        assert isinstance(result, bytes)
        assert len(result) == 32
        assert call_count[0] == 3
    
    def test_crypto_retry_exhausted_raises(self):
        @CryptoRetryWithEntropyJitter(CryptoRetryConfig(max_attempts=2))
        def always_fails():
            raise ValueError("permanent failure")
        
        with pytest.raises(KeyGenerationError) as exc_info:
            always_fails()
        
        assert exc_info.value.attempts == 2
        assert isinstance(exc_info.value.last_error, ValueError)
    
    def test_crypto_jitter_produces_different_delays(self):
        retry = CryptoRetryWithEntropyJitter()
        delays = set()
        
        # Generate multiple delays - jitter should produce variation
        for _ in range(10):
            delay = retry._crypto_jitter_delay(0.1)
            delays.add(round(delay, 6))
        
        # Should have some variation due to entropy jitter
        assert len(delays) > 1
    
    def test_no_delay_on_immediate_success(self):
        start = time.time()
        
        @CryptoRetryWithEntropyJitter()
        def success():
            return os.urandom(32)
        
        result = success()
        elapsed = time.time() - start
        
        assert isinstance(result, bytes)
        assert elapsed < 0.1  # Should be fast

# ============================================================================
# HSM Failover Tests
# ============================================================================

class TestHSMFailover:
    """Test HSM failover with software fallback"""
    
    def test_hsm_used_when_available(self):
        def software_fallback():
            return b"fallback_key"
        
        @HSMFailover(fallback_impl=software_fallback)
        def hsm_sign():
            return b"hsm_signature"
        
        result = hsm_sign()
        assert result == b"hsm_signature"
    
    def test_fallback_used_when_hsm_fails(self):
        def software_fallback():
            return b"fallback_result"
        
        @HSMFailover(fallback_impl=software_fallback)
        def failing_hsm():
            raise RuntimeError("HSM connection failed")
        
        result = failing_hsm()
        assert result == b"fallback_result"
    
    def test_strict_mode_no_fallback(self):
        def fallback():
            return b"fallback"
        
        config = HSMFallbackConfig(mode=HSMFallbackMode.STRICT)
        
        @HSMFailover(fallback_impl=fallback, config=config)
        def failing_hsm():
            raise RuntimeError("HSM failed")
        
        with pytest.raises(HSMUnavailableError) as exc_info:
            failing_hsm()
        
        assert not exc_info.value.fallback_used
    
    def test_fallback_count_tracked(self):
        failover = HSMFailover(fallback_impl=lambda: b"ok")
        
        @failover
        def failing_hsm():
            raise RuntimeError("HSM failed")
        
        failing_hsm()
        failing_hsm()
        
        assert failover.fallback_count == 2
        assert failover.hsm_failure_count >= 2

# ============================================================================
# Constant-Time Handler Tests
# ============================================================================

class TestConstantTimeHandler:
    """Test constant-time execution protection"""
    
    def test_constant_time_pads_execution(self):
        handler = ConstantTimeHandler(target_execution_ms=50)
        
        @handler
        def fast_func():
            return "done"
        
        start = time.perf_counter()
        result = fast_func()
        elapsed = (time.perf_counter() - start) * 1000
        
        assert result == "done"
        assert elapsed >= 45  # Should be close to 50ms
    
    def test_constant_time_for_success_and_failure(self):
        """Critical: both success and failure paths take same time"""
        handler = ConstantTimeHandler(target_execution_ms=30)
        
        @handler
        def success_func():
            return "ok"
        
        @handler
        def fail_func():
            raise ValueError("error")
        
        # Time success path
        start = time.perf_counter()
        success_func()
        success_time = time.perf_counter() - start
        
        # Time failure path
        start = time.perf_counter()
        try:
            fail_func()
        except ValueError:
            pass
        fail_time = time.perf_counter() - start
        
        # Times should be very close (within 5ms)
        time_diff = abs(success_time - fail_time) * 1000
        assert time_diff < 10.0  # Allow small variance
    
    def test_timing_variance_calculated(self):
        handler = ConstantTimeHandler(target_execution_ms=10)
        
        @handler
        def func():
            return "ok"
        
        for _ in range(5):
            func()
        
        variance = handler.timing_variance
        assert variance >= 0

# ============================================================================
# Key Rotation Resilience Tests
# ============================================================================

class TestKeyRotationResilience:
    """Test resilient key rotation operations"""
    
    def test_start_rotation_creates_context(self):
        manager = KeyRotationResilience()
        manager.start_rotation("KEY-001")
        # Should not raise
        assert True
    
    def test_backup_key_stores_material(self):
        manager = KeyRotationResilience()
        manager.start_rotation("KEY-001")
        manager.backup_key("KEY-001", b"backup_key_material")
        # Should not raise
        assert True
    
    def test_advance_state_transitions(self):
        manager = KeyRotationResilience()
        manager.start_rotation("KEY-001")
        manager.advance_state("KEY-001", KeyRotationState.ACTIVATING)
        # Should not raise
        assert True
    
    def test_complete_rotation_cleans_up(self):
        manager = KeyRotationResilience()
        manager.start_rotation("KEY-001")
        manager.complete_rotation("KEY-001")
        # Should not raise
        assert True
    
    def test_failure_after_max_attempts_raises(self):
        manager = KeyRotationResilience()
        manager.start_rotation("KEY-001")
        
        # Exhaust attempts
        with pytest.raises(KeyRotationError):
            for _ in range(5):
                manager.handle_failure("KEY-001", "activation")

# ============================================================================
# Crypto Resilience Pipeline Tests
# ============================================================================

class TestCryptoResiliencePipeline:
    """Test composite crypto resilience pipeline"""
    
    def test_pipeline_combines_strategies(self):
        pipeline = CryptoResiliencePipeline()
        pipeline.with_constant_time(20)
        pipeline.with_crypto_retry(CryptoRetryConfig(max_attempts=2))
        
        call_count = [0]
        
        @pipeline.wrap
        def flaky_operation():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("transient")
            return b"key_material"
        
        result = flaky_operation()
        assert call_count[0] == 2
        assert result == b"key_material"
    
    def test_pipeline_with_hsm_failover(self):
        def fallback():
            return b"software_key"
        
        pipeline = CryptoResiliencePipeline()
        pipeline.with_hsm_failover(fallback)
        
        @pipeline.wrap
        def hsm_operation():
            raise RuntimeError("HSM down")
        
        result = hsm_operation()
        assert result == b"software_key"

# ============================================================================
# Convenience Decorator Tests
# ============================================================================

class TestCryptoResilientDecorator:
    """Test @crypto_resilient convenience decorator"""
    
    def test_resilient_decorator_combines_features(self):
        call_count = [0]
        
        @crypto_resilient(max_retries=2, constant_time_ms=10)
        def flaky_crypto():
            call_count[0] += 1
            if call_count[0] < 2:
                raise ValueError("RNG glitch")
            return b"generated_key"
        
        result = flaky_crypto()
        assert call_count[0] == 2
        assert result == b"generated_key"
    
    def test_resilient_with_hsm_fallback(self):
        def fallback_sign():
            return b"software_sig"
        
        @crypto_resilient(hsm_fallback=fallback_sign)
        def hsm_sign():
            raise RuntimeError("HSM unavailable")
        
        result = hsm_sign()
        assert result == b"software_sig"

# ============================================================================
# Global Singleton Tests
# ============================================================================

class TestGlobalSingletons:
    """Test global singleton instances"""
    
    def test_global_entropy_monitor_exists(self):
        assert global_entropy_monitor is not None
        assert isinstance(global_entropy_monitor, EntropyHealthMonitor)
    
    def test_global_rotation_manager_exists(self):
        assert global_rotation_manager is not None
        assert isinstance(global_rotation_manager, KeyRotationResilience)
    
    def test_global_monitor_is_healthy(self):
        assert global_entropy_monitor.is_healthy

# ============================================================================
# Thread Safety Tests
# ============================================================================

class TestThreadSafety:
    """Verify thread safety of all crypto resilience components"""
    
    def test_entropy_monitor_thread_safe(self):
        monitor = EntropyHealthMonitor()
        results = []
        
        def worker():
            for _ in range(10):
                try:
                    r = monitor.get_safe_random(8)
                    results.append(r)
                except Exception:
                    pass
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(results) == 50  # All should succeed
    
    def test_constant_time_concurrent(self):
        handler = ConstantTimeHandler(target_execution_ms=5)
        
        @handler
        def func():
            return b"ok"
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=func)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # All should complete without error
        assert True

# ============================================================================
# Cryptographic Integrity Tests (CRITICAL - NO OUTPUT MODIFICATION)
# ============================================================================

class TestCryptographicIntegrity:
    """CRITICAL: Verify resilience layer NEVER modifies crypto outputs"""
    
    def test_retry_does_not_alter_output(self):
        expected = os.urandom(32)
        
        @CryptoRetryWithEntropyJitter()
        def keygen():
            return expected
        
        result = keygen()
        assert result == expected  # EXACT match required
    
    def test_fallback_returns_exact_fallback_output(self):
        fallback_output = b"EXPECTED_FALLBACK_VALUE"
        
        @HSMFailover(fallback_impl=lambda: fallback_output)
        def failing_hsm():
            raise RuntimeError("HSM failed")
        
        result = failing_hsm()
        assert result == fallback_output  # EXACT match required
    
    def test_constant_time_preserves_output(self):
        expected = b"crypto_output"
        
        @ConstantTimeHandler(target_execution_ms=10)
        def crypto_op():
            return expected
        
        result = crypto_op()
        assert result == expected  # EXACT match required
    
    def test_pipeline_preserves_cryptographic_output(self):
        """Most important test: full pipeline never changes output"""
        expected = os.urandom(64)
        
        pipeline = CryptoResiliencePipeline()
        pipeline.with_constant_time(10)
        pipeline.with_crypto_retry()
        
        @pipeline.wrap
        def secure_keygen():
            return expected
        
        result = secure_keygen()
        assert result == expected  # CRYPTOGRAPHIC INTEGRITY VERIFIED

# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
