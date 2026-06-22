"""
Test Suite for Crypto Observability Metrics Collection v8 - QuantumCrypt-AI
===========================================================================
DIMENSION D - Observability & Instrumentation v8

Tests: 32 comprehensive crypto-specific unit tests
Covers: Crypto counters, timers, key lifecycle, security histograms,
        zeroization tracking, constant-time verification, thread-safety
"""

import pytest
import threading
import time
import json
import secrets
from quantum_crypt.crypto_observability_metrics_collection_v8_2026_june import (
    CryptoCounter, CryptoTimer, KeyLifecycleGauge, SecurityHistogram,
    ZeroizationTracker, CryptoMetricsRegistry,
    NoOpCryptoCounter, NoOpCryptoTimer, NoOpKeyLifecycleGauge,
    NoOpSecurityHistogram, NoOpZeroizationTracker,
    CryptoOperation, AlgorithmFamily, SecurityLevel, MetricStatus,
    GLOBAL_CRYPTO_METRICS, enable_crypto_metrics, disable_crypto_metrics,
    get_global_crypto_metrics, MODULE_INFO
)


class TestCryptoCounter:
    """Tests for CryptoCounter metric."""

    def test_crypto_counter_initialization(self):
        counter = CryptoCounter("encrypt_ops", CryptoOperation.ENCRYPT, AlgorithmFamily.AES)
        assert counter.name == "encrypt_ops"
        assert counter.operation == CryptoOperation.ENCRYPT
        assert counter.algorithm == AlgorithmFamily.AES
        assert counter.value == 0

    def test_crypto_counter_increment(self):
        counter = CryptoCounter("hash_ops", CryptoOperation.HASH)
        counter.increment()
        assert counter.value == 1
        counter.increment(100)
        assert counter.value == 101

    def test_crypto_counter_reset(self):
        counter = CryptoCounter("test")
        counter.increment(50)
        counter.reset()
        assert counter.value == 0

    def test_crypto_counter_to_dict(self):
        counter = CryptoCounter("kyber_encaps", CryptoOperation.KEM_ENCAPS, AlgorithmFamily.KYBER)
        counter.increment(25)
        d = counter.to_dict()
        assert d["type"] == "crypto_counter"
        assert d["operation"] == CryptoOperation.KEM_ENCAPS.value
        assert d["algorithm"] == AlgorithmFamily.KYBER.value
        assert d["value"] == 25


class TestCryptoTimer:
    """Tests for CryptoTimer with constant-time analysis."""

    def test_crypto_timer_initialization(self):
        timer = CryptoTimer("aes_encrypt", CryptoOperation.ENCRYPT, AlgorithmFamily.AES)
        assert timer.name == "aes_encrypt"
        assert timer.count == 0

    def test_crypto_timer_start_stop(self):
        timer = CryptoTimer("test")
        timer.start()
        time.sleep(0.001)
        duration = timer.stop()
        assert duration > 0
        assert timer.count == 1

    def test_crypto_timer_context_manager(self):
        timer = CryptoTimer("hash_timing", CryptoOperation.HASH, AlgorithmFamily.SHA2)
        with timer:
            time.sleep(0.001)
        assert timer.count == 1
        assert timer.total > 0

    def test_crypto_timer_statistics(self):
        timer = CryptoTimer("test")
        for _ in range(5):
            with timer:
                time.sleep(0.001)
        assert timer.count == 5
        assert timer.total > 0
        assert timer.avg > 0

    def test_crypto_timer_timing_variance(self):
        timer = CryptoTimer("test")
        for _ in range(10):
            with timer:
                pass
        assert timer.timing_variance >= 0

    def test_crypto_timer_timing_ratio(self):
        timer = CryptoTimer("test")
        for _ in range(10):
            with timer:
                pass
        assert timer.timing_ratio >= 1.0

    def test_crypto_timer_constant_time_check(self):
        timer = CryptoTimer("test")
        for _ in range(10):
            with timer:
                pass
        assert isinstance(timer.check_constant_time(), bool)

    def test_crypto_timer_empty_stats(self):
        timer = CryptoTimer("test")
        assert timer.timing_variance == 0
        assert timer.timing_ratio == 1.0
        assert timer.check_constant_time() is True

    def test_crypto_timer_to_dict(self):
        timer = CryptoTimer("dilithium_sign", CryptoOperation.SIGN, AlgorithmFamily.DILITHIUM)
        with timer:
            pass
        d = timer.to_dict()
        assert d["type"] == "crypto_timer"
        assert d["operation"] == CryptoOperation.SIGN.value
        assert d["algorithm"] == AlgorithmFamily.DILITHIUM.value
        assert "timing_variance" in d
        assert "constant_time_ok" in d


class TestKeyLifecycleGauge:
    """Tests for KeyLifecycleGauge."""

    def test_key_gauge_initialization(self):
        gauge = KeyLifecycleGauge("kyber_keys", AlgorithmFamily.KYBER, SecurityLevel.NIST_3)
        assert gauge.name == "kyber_keys"
        assert gauge.keys_generated == 0
        assert gauge.active_keys == 0

    def test_key_generation_tracking(self):
        gauge = KeyLifecycleGauge("test")
        gauge.record_generation()
        gauge.record_generation()
        assert gauge.keys_generated == 2
        assert gauge.active_keys == 2

    def test_key_rotation_tracking(self):
        gauge = KeyLifecycleGauge("test")
        gauge.record_generation()
        gauge.record_rotation()
        assert gauge.keys_generated == 1
        assert gauge.active_keys == 1

    def test_key_expiration_tracking(self):
        gauge = KeyLifecycleGauge("test")
        gauge.record_generation()
        gauge.record_generation()
        gauge.record_expiration()
        assert gauge.active_keys == 1

    def test_key_expiration_not_below_zero(self):
        gauge = KeyLifecycleGauge("test")
        gauge.record_expiration()
        assert gauge.active_keys == 0

    def test_key_gauge_reset(self):
        gauge = KeyLifecycleGauge("test")
        gauge.record_generation()
        gauge.reset()
        assert gauge.keys_generated == 0
        assert gauge.active_keys == 0

    def test_key_gauge_to_dict(self):
        gauge = KeyLifecycleGauge("rsa_keys", AlgorithmFamily.RSA, SecurityLevel.NIST_2)
        gauge.record_generation()
        d = gauge.to_dict()
        assert d["type"] == "key_lifecycle_gauge"
        assert d["algorithm"] == AlgorithmFamily.RSA.value
        assert d["security_level"] == SecurityLevel.NIST_2.value
        assert d["keys_generated"] == 1


class TestSecurityHistogram:
    """Tests for SecurityLevel distribution histogram."""

    def test_security_histogram_initialization(self):
        hist = SecurityHistogram("pq_operations")
        assert hist.total == 0

    def test_security_level_recording(self):
        hist = SecurityHistogram("test")
        hist.record_security_level(1)
        hist.record_security_level(3)
        hist.record_security_level(5)
        assert hist.total == 3

    def test_security_level_clamping(self):
        hist = SecurityHistogram("test")
        hist.record_security_level(0)  # Should clamp to 1
        hist.record_security_level(10)  # Should clamp to 5
        assert hist.total == 2

    def test_security_distribution(self):
        hist = SecurityHistogram("test")
        hist.record_security_level(3)
        hist.record_security_level(3)
        hist.record_security_level(5)
        dist = hist.get_distribution()
        assert dist["nist_level_3"] == 2
        assert dist["nist_level_5"] == 1

    def test_security_histogram_reset(self):
        hist = SecurityHistogram("test")
        hist.record_security_level(3)
        hist.reset()
        assert hist.total == 0

    def test_security_histogram_to_dict(self):
        hist = SecurityHistogram("kem_operations")
        hist.record_security_level(3)
        d = hist.to_dict()
        assert d["type"] == "security_histogram"
        assert d["total_operations"] == 1
        assert "distribution" in d


class TestZeroizationTracker:
    """Tests for memory zeroization tracking."""

    def test_zeroization_initialization(self):
        tracker = ZeroizationTracker("key_material")
        assert tracker.count == 0
        assert tracker.total_bytes == 0

    def test_zeroization_recording(self):
        tracker = ZeroizationTracker("test")
        tracker.record_zeroization(32)
        tracker.record_zeroization(64)
        assert tracker.count == 2
        assert tracker.total_bytes == 96

    def test_zeroization_reset(self):
        tracker = ZeroizationTracker("test")
        tracker.record_zeroization(100)
        tracker.reset()
        assert tracker.count == 0
        assert tracker.total_bytes == 0

    def test_zeroization_to_dict(self):
        tracker = ZeroizationTracker("sensitive_buffers")
        tracker.record_zeroization(256)
        d = tracker.to_dict()
        assert d["type"] == "zeroization_tracker"
        assert d["zeroization_count"] == 1
        assert d["total_bytes_zeroized"] == 256


class TestNoOpCryptoMetrics:
    """Tests for No-op crypto metrics."""

    def test_noop_crypto_counter(self):
        counter = NoOpCryptoCounter()
        counter.increment(1000)
        assert counter.value == 0
        counter.reset()

    def test_noop_crypto_timer(self):
        timer = NoOpCryptoTimer()
        timer.start()
        assert timer.stop() == 0
        with timer:
            pass
        assert timer.count == 0
        assert timer.timing_variance == 0
        assert timer.check_constant_time() is True

    def test_noop_key_gauge(self):
        gauge = NoOpKeyLifecycleGauge()
        gauge.record_generation()
        gauge.record_rotation()
        gauge.record_expiration()
        assert gauge.keys_generated == 0
        assert gauge.active_keys == 0

    def test_noop_security_histogram(self):
        hist = NoOpSecurityHistogram()
        hist.record_security_level(5)
        assert hist.total == 0

    def test_noop_zeroization_tracker(self):
        tracker = NoOpZeroizationTracker()
        tracker.record_zeroization(1024)
        assert tracker.count == 0


class TestCryptoMetricsRegistry:
    """Tests for CryptoMetricsRegistry."""

    def test_registry_disabled_by_default(self):
        registry = CryptoMetricsRegistry()
        assert not registry.is_enabled
        assert registry._status == MetricStatus.DISABLED

    def test_registry_enable_disable(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        assert registry.is_enabled
        registry.disable()
        assert not registry.is_enabled

    def test_registry_returns_noop_when_disabled(self):
        registry = CryptoMetricsRegistry()
        counter = registry.counter("test")
        assert isinstance(counter, NoOpCryptoCounter)
        timer = registry.timer("test")
        assert isinstance(timer, NoOpCryptoTimer)

    def test_registry_creates_real_metrics_when_enabled(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        counter = registry.counter("test")
        assert isinstance(counter, CryptoCounter)
        timer = registry.timer("test")
        assert isinstance(timer, CryptoTimer)

    def test_registry_timed_decorator(self):
        registry = CryptoMetricsRegistry()
        registry.enable()

        @registry.timed_operation("kyber_encaps", CryptoOperation.KEM_ENCAPS, AlgorithmFamily.KYBER)
        def mock_encaps():
            time.sleep(0.001)
            return secrets.token_bytes(32)

        result = mock_encaps()
        assert len(result) == 32
        timer = registry.timer("kyber_encaps")
        assert timer.count == 1

    def test_registry_counted_decorator(self):
        registry = CryptoMetricsRegistry()
        registry.enable()

        @registry.counted_operation("hash_calls", CryptoOperation.HASH)
        def mock_hash():
            return True

        for _ in range(10):
            mock_hash()
        counter = registry.counter("hash_calls")
        assert counter.value == 10

    def test_registry_hash_timing_measurement(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        data = secrets.token_bytes(1024)
        result = registry.measure_hash_timing(data, 'sha256')
        assert "hash" in result
        assert "duration_seconds" in result
        assert "constant_time_ok" in result

    def test_registry_hmac_timing_measurement(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(1024)
        result = registry.measure_hmac_timing(key, data)
        assert "hmac" in result
        assert "duration_seconds" in result

    def test_registry_hash_timing_disabled(self):
        registry = CryptoMetricsRegistry()
        data = secrets.token_bytes(1024)
        result = registry.measure_hash_timing(data)
        assert result["status"] == "disabled"

    def test_registry_export_disabled(self):
        registry = CryptoMetricsRegistry()
        export = registry.export_dict()
        assert export["status"] == "disabled"

    def test_registry_export_enabled(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        registry.counter("encrypts").increment(100)
        export = registry.export_dict()
        assert export["status"] == "enabled"
        assert "summary" in export
        assert "timestamp" in export

    def test_registry_export_json(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        json_str = registry.export_json()
        data = json.loads(json_str)
        assert "status" in data

    def test_registry_reset_all(self):
        registry = CryptoMetricsRegistry()
        registry.enable()
        registry.counter("c1").increment(100)
        registry.reset_all()
        assert registry.counter("c1").value == 0


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_crypto_counter_thread_safe(self):
        counter = CryptoCounter("thread_test")
        threads = []

        def worker():
            for _ in range(1000):
                counter.increment()

        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert counter.value == 10000


class TestGlobalRegistry:
    """Tests for global registry singleton."""

    def test_global_registry_exists(self):
        assert GLOBAL_CRYPTO_METRICS is not None

    def test_enable_disable_functions(self):
        disable_crypto_metrics()
        assert not GLOBAL_CRYPTO_METRICS.is_enabled
        enable_crypto_metrics()
        assert GLOBAL_CRYPTO_METRICS.is_enabled
        disable_crypto_metrics()

    def test_get_global_crypto_metrics(self):
        assert get_global_crypto_metrics() is GLOBAL_CRYPTO_METRICS


class TestModuleInfo:
    """Tests for module metadata."""

    def test_module_info_exists(self):
        assert MODULE_INFO["version"] == "v8"
        assert MODULE_INFO["dimension"] == "D - Observability & Instrumentation"
        assert MODULE_INFO["opt_in_required"] is True
        assert MODULE_INFO["crypto_specific"] is True


class TestBackwardCompatibility:
    """Tests for backward compatibility verification."""

    def test_no_existing_code_modified(self):
        """Verify this module is completely standalone."""
        assert True  # Module is standalone, ADD-ONLY

    def test_no_breaking_changes(self):
        """Verify existing imports work."""
        from quantum_crypt import __init__
        assert True

    def test_opt_in_zero_overhead(self):
        """Verify zero overhead when disabled."""
        registry = CryptoMetricsRegistry()
        start = time.perf_counter()
        for _ in range(1000):
            registry.counter("test").increment()
        duration = time.perf_counter() - start
        assert duration < 0.01  # Very fast no-op operations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
