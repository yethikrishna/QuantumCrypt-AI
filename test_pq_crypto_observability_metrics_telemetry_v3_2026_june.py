"""
Test suite for QuantumCrypt Post-Quantum Crypto Observability, Metrics & Telemetry v3
DIMENSION D: Observability & Instrumentation
All tests must pass - ADD-ONLY implementation
"""

import pytest
import time
import threading
from quantum_crypt.pq_crypto_observability_metrics_telemetry_v3_2026_june import (
    CryptoOperation, CryptoAlgorithm, SecurityEventType, CryptoMetricLabels,
    CryptoOperationTimer, AlgorithmPerformanceTracker, SecurityEventLogger,
    KeyLifecycleMetrics, CryptoTelemetryRegistry, CryptoOperationContext,
    crypto_timed, enable_crypto_telemetry, disable_crypto_telemetry,
    log_security_event, record_key_generation, record_key_rotation,
    get_crypto_telemetry_report, security_events
)


class TestCryptoMetricLabels:
    def test_labels_to_dict(self):
        labels = CryptoMetricLabels(
            algorithm="kyber768",
            operation="key_gen",
            key_size=768,
            security_level="NIST-3"
        )
        d = labels.to_dict()
        assert d["algorithm"] == "kyber768"
        assert d["operation"] == "key_gen"
        assert d["key_size"] == "768"
        assert d["security_level"] == "NIST-3"
    
    def test_labels_partial(self):
        labels = CryptoMetricLabels(algorithm="dilithium3")
        d = labels.to_dict()
        assert d["algorithm"] == "dilithium3"
        assert "operation" not in d
    
    def test_labels_to_key_consistent(self):
        labels1 = CryptoMetricLabels(algorithm="a", operation="b")
        labels2 = CryptoMetricLabels(operation="b", algorithm="a")
        assert labels1.to_key() == labels2.to_key()


class TestCryptoOperationTimer:
    def test_record_success(self):
        timer = CryptoOperationTimer()
        labels = CryptoMetricLabels(
            algorithm=CryptoAlgorithm.KYBER_768.value,
            operation=CryptoOperation.KEY_GEN.value
        )
        timer.record_success(0.05, labels)
        timer.record_success(0.06, labels)
        stats = timer.get_stats(labels)
        assert stats["count"] == 2
        assert stats["failures"] == 0
        assert stats["failure_rate"] == 0.0
        assert stats["avg_ms"] == 55.0
    
    def test_record_failure(self):
        timer = CryptoOperationTimer()
        labels = CryptoMetricLabels(
            algorithm=CryptoAlgorithm.DILITHIUM_3.value,
            operation=CryptoOperation.SIGN.value
        )
        timer.record_success(0.1, labels)
        timer.record_failure(labels)
        timer.record_failure(labels)
        stats = timer.get_stats(labels)
        assert stats["count"] == 1
        assert stats["failures"] == 2
        assert stats["failure_rate"] == 2/3
    
    def test_percentiles(self):
        timer = CryptoOperationTimer()
        labels = CryptoMetricLabels(algorithm="test", operation="test")
        for i in range(100):
            timer.record_success(i / 1000.0, labels)
        stats = timer.get_stats(labels)
        assert stats["p50_ms"] is not None
        assert stats["p95_ms"] is not None
        assert stats["p99_ms"] is not None
    
    def test_thread_safe(self):
        timer = CryptoOperationTimer()
        labels = CryptoMetricLabels(algorithm="threaded", operation="test")
        
        def worker():
            for _ in range(50):
                timer.record_success(0.01, labels)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = timer.get_stats(labels)
        assert stats["count"] == 500
    
    def test_empty_stats(self):
        timer = CryptoOperationTimer()
        labels = CryptoMetricLabels(algorithm="nonexistent")
        stats = timer.get_stats(labels)
        assert stats["count"] == 0
        assert stats["failures"] == 0


class TestAlgorithmPerformanceTracker:
    def test_baseline_and_deviation(self):
        tracker = AlgorithmPerformanceTracker()
        tracker.set_baseline("kyber768", 10.0)  # 10ms baseline
        
        # Record samples slightly slower than baseline
        for _ in range(10):
            tracker.record_sample("kyber768", 11.0)
        
        deviation = tracker.get_deviation("kyber768")
        assert deviation is not None
        assert 9.0 <= deviation <= 11.0  # ~10% slower
    
    def test_no_baseline_returns_none(self):
        tracker = AlgorithmPerformanceTracker()
        assert tracker.get_deviation("unknown") is None


class TestSecurityEventLogger:
    def test_log_event(self):
        logger = SecurityEventLogger()
        logger.log(SecurityEventType.KEY_ROTATION, True, key_id="key-123")
        logger.log(SecurityEventType.SIGNATURE_VERIFICATION, False, reason="invalid")
        
        events = logger.get_recent(10)
        assert len(events) == 2
        assert events[0]["event_type"] == "key_rotation"
        assert events[0]["success"] is True
        assert events[1]["event_type"] == "signature_verification"
        assert events[1]["success"] is False
    
    def test_filter_by_type(self):
        logger = SecurityEventLogger()
        logger.log(SecurityEventType.KEY_ROTATION, True)
        logger.log(SecurityEventType.KEY_GENERATION, True)
        logger.log(SecurityEventType.KEY_ROTATION, False)
        
        rotations = logger.get_recent(10, SecurityEventType.KEY_ROTATION)
        assert len(rotations) == 2
    
    def test_failure_rate(self):
        logger = SecurityEventLogger()
        for _ in range(90):
            logger.log(SecurityEventType.CERTIFICATE_VALIDATION, True)
        for _ in range(10):
            logger.log(SecurityEventType.CERTIFICATE_VALIDATION, False)
        
        rate = logger.get_failure_rate(SecurityEventType.CERTIFICATE_VALIDATION)
        assert 0.09 <= rate <= 0.11  # ~10% failure rate
    
    def test_counts_by_type(self):
        logger = SecurityEventLogger()
        logger.log(SecurityEventType.KEY_ROTATION, True)
        logger.log(SecurityEventType.KEY_ROTATION, True)
        logger.log(SecurityEventType.KEY_ROTATION, False)
        logger.log(SecurityEventType.INTEGRITY_CHECK, True)
        
        counts = logger.get_counts_by_type()
        assert counts["key_rotation"]["success"] == 2
        assert counts["key_rotation"]["failure"] == 1
        assert counts["integrity_check"]["success"] == 1
    
    def test_event_ids_unique(self):
        logger = SecurityEventLogger()
        logger.log(SecurityEventType.KEY_GENERATION, True)
        logger.log(SecurityEventType.KEY_GENERATION, True)
        events = logger.get_recent(10)
        assert events[0]["event_id"] != events[1]["event_id"]


class TestKeyLifecycleMetrics:
    def test_key_generation(self):
        klm = KeyLifecycleMetrics()
        klm.record_key_generation("kyber768")
        klm.record_key_generation("kyber768")
        klm.record_key_generation("dilithium3")
        stats = klm.get_stats()
        assert stats["key_generations"]["kyber768"] == 2
        assert stats["key_generations"]["dilithium3"] == 1
    
    def test_key_rotation(self):
        klm = KeyLifecycleMetrics()
        klm.record_key_rotation("aes256gcm")
        stats = klm.get_stats()
        assert stats["key_rotations"]["aes256gcm"] == 1
        assert "aes256gcm" in stats["last_rotation_times"]
    
    def test_key_usage(self):
        klm = KeyLifecycleMetrics()
        for _ in range(100):
            klm.record_key_usage("kyber512")
        stats = klm.get_stats()
        assert stats["key_usage_counts"]["kyber512"] == 100


class TestCryptoTelemetryRegistry:
    def test_singleton(self):
        r1 = CryptoTelemetryRegistry.get_instance()
        r2 = CryptoTelemetryRegistry.get_instance()
        assert r1 is r2
    
    def test_disabled_by_default(self):
        # Create fresh instance for clean test
        registry = CryptoTelemetryRegistry()
        assert registry.enabled is False
    
    def test_enable_disable(self):
        registry = CryptoTelemetryRegistry()
        registry.enable()
        assert registry.enabled is True
        registry.disable()
        assert registry.enabled is False
    
    def test_context_manager_timing(self):
        registry = CryptoTelemetryRegistry()
        registry.enable()
        
        labels = CryptoMetricLabels(
            operation=CryptoOperation.ENCRYPT.value,
            algorithm=CryptoAlgorithm.AES_256_GCM.value
        )
        ctx = CryptoOperationContext(registry, labels)
        with ctx:
            time.sleep(0.01)
        
        # Verify the operation was recorded
        stats = registry.operation_timer.get_stats(labels)
        assert stats["count"] == 1
        assert stats["avg_ms"] > 0
        
        registry.disable()
    
    def test_context_manager_failure(self):
        registry = CryptoTelemetryRegistry()
        registry.enable()
        
        labels = CryptoMetricLabels(
            operation=CryptoOperation.DECRYPT.value,
            algorithm=CryptoAlgorithm.CHACHA20_POLY1305.value
        )
        
        try:
            with CryptoOperationContext(registry, labels):
                raise ValueError("Decryption failed")
        except ValueError:
            pass
        
        stats = registry.operation_timer.get_stats(labels)
        assert stats["failures"] == 1
        registry.disable()
    
    def test_custom_metrics(self):
        registry = CryptoTelemetryRegistry()
        registry.enable()
        registry.set_gauge("active_keys", 42.0)
        registry.inc_counter("signatures", 5)
        registry.inc_counter("signatures", 3)
        
        report = registry.get_full_report()
        assert report["custom_metrics"]["gauges"]["active_keys"] == 42.0
        assert report["custom_metrics"]["counters"]["signatures"] == 8
        registry.disable()
    
    def test_full_report_structure(self):
        registry = CryptoTelemetryRegistry()
        report = registry.get_full_report()
        assert "enabled" in report
        assert "operation_performance" in report
        assert "security_events" in report
        assert "key_lifecycle" in report
        assert "custom_metrics" in report


class TestCryptoTimedDecorator:
    def test_decorator_disabled(self):
        @crypto_timed(CryptoOperation.HASH, CryptoAlgorithm.SHA2_256)
        def hash_func(data):
            return data[::-1]
        
        # Should work when disabled
        result = hash_func("test data")
        assert result == "atad tset"
    
    def test_decorator_enabled(self):
        enable_crypto_telemetry()
        
        @crypto_timed(CryptoOperation.SIGN, CryptoAlgorithm.DILITHIUM_3)
        def sign_func(msg):
            time.sleep(0.005)
            return f"signed:{msg}"
        
        result = sign_func("hello")
        assert result == "signed:hello"
        
        disable_crypto_telemetry()
    
    def test_decorator_exception_propagation(self):
        enable_crypto_telemetry()
        
        @crypto_timed(CryptoOperation.VERIFY, CryptoAlgorithm.FALCON_512)
        def verify_func():
            raise ValueError("Invalid signature")
        
        with pytest.raises(ValueError, match="Invalid signature"):
            verify_func()
        
        disable_crypto_telemetry()


class TestConvenienceFunctions:
    def test_functions_disabled_no_error(self):
        disable_crypto_telemetry()
        # All should be no-ops without error
        log_security_event(SecurityEventType.KEY_ROTATION, True)
        record_key_generation("kyber768")
        record_key_rotation("dilithium5")
        report = get_crypto_telemetry_report()
        assert report["enabled"] is False
    
    def test_functions_enabled(self):
        enable_crypto_telemetry()
        log_security_event(SecurityEventType.INTEGRITY_CHECK, True, checksum="abc123")
        record_key_generation("sphincs+")
        record_key_rotation("aes128gcm")
        report = get_crypto_telemetry_report()
        assert report["enabled"] is True
        disable_crypto_telemetry()


class TestGlobalSecurityEvents:
    def test_global_logger_exists(self):
        assert security_events is not None
        security_events.log(SecurityEventType.RANDOMNESS_ENTROPY_TEST, True, bits=256)
        events = security_events.get_recent(1)
        assert len(events) == 1


class TestOptInBehavior:
    def test_no_side_effects_when_disabled(self):
        """CRITICAL: All instrumentation must be no-op when disabled"""
        disable_crypto_telemetry()
        registry = CryptoTelemetryRegistry.get_instance()
        
        # Operations should complete without recording anything
        with registry.time_operation(CryptoOperation.KEY_GEN, CryptoAlgorithm.KYBER_512):
            pass
        
        registry.set_gauge("should_not_exist", 1.0)
        registry.inc_counter("should_not_exist")
        
        # Verify state
        report = registry.get_full_report()
        assert report["enabled"] is False
        # Custom metrics should be empty when disabled
        assert len(report["custom_metrics"]["gauges"]) == 0 or "should_not_exist" not in report["custom_metrics"]["gauges"]
    
    def test_happy_path_unchanged(self):
        """CRITICAL: Happy path behavior must be 100% preserved"""
        def original_sign(x):
            return f"signature({x})"
        
        @crypto_timed(CryptoOperation.SIGN, CryptoAlgorithm.DILITHIUM_2)
        def instrumented_sign(x):
            return f"signature({x})"
        
        # Both should produce identical results regardless of telemetry state
        disable_crypto_telemetry()
        assert original_sign("test") == instrumented_sign("test")
        
        enable_crypto_telemetry()
        assert original_sign("test") == instrumented_sign("test")
        disable_crypto_telemetry()


class TestEnums:
    def test_crypto_operations_complete(self):
        ops = list(CryptoOperation)
        assert len(ops) >= 10
        assert CryptoOperation.KEY_GEN in ops
        assert CryptoOperation.SIGN in ops
        assert CryptoOperation.VERIFY in ops
        assert CryptoOperation.ENCRYPT in ops
        assert CryptoOperation.DECRYPT in ops
    
    def test_crypto_algorithms_complete(self):
        algs = list(CryptoAlgorithm)
        assert len(algs) >= 15
        # PQ algorithms
        assert CryptoAlgorithm.DILITHIUM_2 in algs
        assert CryptoAlgorithm.KYBER_768 in algs
        assert CryptoAlgorithm.FALCON_512 in algs
        assert CryptoAlgorithm.SPHINCS_PLUS in algs
        # Classic algorithms
        assert CryptoAlgorithm.AES_256_GCM in algs
        assert CryptoAlgorithm.SHA2_256 in algs
    
    def test_security_event_types(self):
        events = list(SecurityEventType)
        assert len(events) >= 6
        assert SecurityEventType.KEY_ROTATION in events
        assert SecurityEventType.CERTIFICATE_VALIDATION in events
        assert SecurityEventType.AUTHENTICATION_FAILURE in events


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
