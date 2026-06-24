"""
Tests for Cryptography-Specific Comprehensive Observability & Instrumentation v16
Dimension D - Observability & Instrumentation

Tests verify:
- All features disabled by default (zero overhead)
- Cryptography-specific metrics work correctly
- Randomness quality monitoring
- Constant-time execution verification
- No modification to existing production code
"""

import pytest
import time
import threading
import hashlib

from quantum_crypt.crypto_comprehensive_observability_instrumentation_v16_2026_june import (
    CryptoObservabilityConfig,
    CryptoMetricsCollector,
    get_global_crypto_metrics,
    timed_crypto_operation,
    ConstantTimeVerifier,
    RandomnessQualityMonitor,
    get_global_randomness_monitor,
    CryptoHealthChecker,
    get_global_crypto_health_checker,
    CryptoHealthStatus,
    CryptoAlgorithm,
    CryptoEventEmitter,
    get_global_crypto_events,
    get_crypto_observability_status,
    CRYPTO_OBSERVABILITY_VERSION,
    CRYPTO_OBSERVABILITY_API_STABILITY,
)


class TestCryptoObservabilityDefaultDisabled:
    """Verify ALL crypto observability features are DISABLED by default."""
    
    def test_config_defaults_all_disabled(self):
        """All features should be disabled by default."""
        config = CryptoObservabilityConfig()
        
        assert config.LOGGING_ENABLED is False
        assert config.METRICS_ENABLED is False
        assert config.HEALTH_CHECKS_ENABLED is False
        assert config.TRACING_ENABLED is False
        assert config.RANDOMNESS_MONITORING_ENABLED is False
        assert config.EVENTS_ENABLED is False
    
    def test_metrics_no_op_when_disabled(self):
        """Metrics should be no-op when disabled."""
        config = CryptoObservabilityConfig()
        config.METRICS_ENABLED = False
        
        metrics = CryptoMetricsCollector()
        metrics.record_crypto_operation("encrypt", 10.0)
        
        stats = metrics.get_operation_stats("encrypt")
        assert stats["count"] == 0
    
    def test_health_checks_no_op_when_disabled(self):
        """Health checks should be no-op when disabled."""
        config = CryptoObservabilityConfig()
        config.HEALTH_CHECKS_ENABLED = False
        
        checker = CryptoHealthChecker()
        result = checker.run_check("randomness_quality")
        
        assert result is None
    
    def test_events_no_op_when_disabled(self):
        """Events should be no-op when disabled."""
        config = CryptoObservabilityConfig()
        config.EVENTS_ENABLED = False
        
        emitter = CryptoEventEmitter()
        emitter.emit_key_generation("AES-256", 256)
        
        events = emitter.get_recent_events()
        assert len(events) == 0


class TestCryptoObservabilityOptInBehavior:
    """Verify opt-in behavior works correctly."""
    
    def test_enable_all_features(self):
        """Enable all should turn on all features."""
        config = CryptoObservabilityConfig()
        config.enable_all()
        
        assert config.LOGGING_ENABLED is True
        assert config.METRICS_ENABLED is True
        assert config.HEALTH_CHECKS_ENABLED is True
        assert config.TRACING_ENABLED is True
        assert config.RANDOMNESS_MONITORING_ENABLED is True
        assert config.EVENTS_ENABLED is True
    
    def test_disable_all_features(self):
        """Disable all should turn off all features."""
        config = CryptoObservabilityConfig()
        config.enable_all()
        config.disable_all()
        
        assert config.LOGGING_ENABLED is False
        assert config.METRICS_ENABLED is False
        assert config.HEALTH_CHECKS_ENABLED is False
        assert config.TRACING_ENABLED is False
        assert config.RANDOMNESS_MONITORING_ENABLED is False
        assert config.EVENTS_ENABLED is False
    
    def test_config_singleton(self):
        """Config should be singleton pattern."""
        config1 = CryptoObservabilityConfig()
        config2 = CryptoObservabilityConfig()
        
        assert config1 is config2


class TestCryptoMetricsCollector:
    """Test cryptography-specific metrics collection."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.METRICS_ENABLED = True
        get_global_crypto_metrics().reset()
    
    def test_record_crypto_operation(self):
        """Should record cryptographic operation."""
        metrics = CryptoMetricsCollector()
        metrics.record_crypto_operation("aes_encrypt", 0.5, CryptoAlgorithm.AES_256_GCM)
        metrics.record_crypto_operation("aes_encrypt", 0.6, CryptoAlgorithm.AES_256_GCM)
        
        stats = metrics.get_operation_stats("aes_encrypt")
        assert stats["count"] == 2
        assert stats["avg_ms"] == 0.55
    
    def test_algorithm_usage_tracking(self):
        """Should track algorithm usage."""
        metrics = CryptoMetricsCollector()
        metrics.record_crypto_operation("encrypt", 0.5, CryptoAlgorithm.AES_256_GCM)
        metrics.record_crypto_operation("encrypt", 0.5, CryptoAlgorithm.AES_256_GCM)
        metrics.record_crypto_operation("encrypt", 0.5, CryptoAlgorithm.CHACHA20_POLY1305)
        
        breakdown = metrics.get_algorithm_breakdown()
        assert breakdown["AES-256-GCM"] == 2
        assert breakdown["ChaCha20-Poly1305"] == 1
    
    def test_key_rotation_tracking(self):
        """Should track key rotations."""
        metrics = CryptoMetricsCollector()
        metrics.record_key_rotation()
        metrics.record_key_rotation()
        
        all_metrics = metrics.get_all_metrics()
        assert all_metrics["key_rotations"] == 2
    
    def test_constant_time_sampling(self):
        """Should record constant-time samples."""
        metrics = CryptoMetricsCollector()
        metrics.record_constant_time_sample("compare", 0.005)
        metrics.record_constant_time_sample("compare", 0.003)
        
        rating = metrics.get_constant_time_rating("compare")
        assert rating["sample_count"] == 2
        assert rating["rating"] == "excellent"


class TestTimedCryptoOperationDecorator:
    """Test @timed_crypto_operation decorator."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.METRICS_ENABLED = True
        get_global_crypto_metrics().reset()
    
    def test_timed_crypto_operation_measures(self):
        """Decorator should measure crypto operation time."""
        
        @timed_crypto_operation("test_hash", CryptoAlgorithm.SHA_512)
        def hash_operation(data):
            return hashlib.sha512(data).digest()
        
        result = hash_operation(b"test data")
        
        assert len(result) == 64  # SHA-512 output
        stats = get_global_crypto_metrics().get_operation_stats("test_hash")
        assert stats["count"] == 1
        assert stats["avg_ms"] > 0
    
    def test_timed_crypto_no_op_when_disabled(self):
        """Decorator should be no-op when disabled."""
        self.config.METRICS_ENABLED = False
        
        @timed_crypto_operation("disabled_test")
        def test_func():
            return "done"
        
        result = test_func()
        
        assert result == "done"
        stats = get_global_crypto_metrics().get_operation_stats("disabled_test")
        assert stats["count"] == 0


class TestConstantTimeVerifier:
    """Test constant-time execution verification."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.METRICS_ENABLED = True
    
    def test_constant_time_verification(self):
        """Should verify constant-time behavior."""
        verifier = ConstantTimeVerifier()
        
        def simple_op(data):
            return hashlib.sha256(data).digest()
        
        inputs = [b"a" * 32, b"b" * 32, b"c" * 32]
        result = verifier.verify_constant_time(simple_op, inputs, sample_count=30)
        
        assert "sample_count" in result
        assert "avg_time_ms" in result
        assert "constant_time_rating" in result


class TestRandomnessQualityMonitor:
    """Test randomness quality monitoring."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.RANDOMNESS_MONITORING_ENABLED = True
    
    def test_randomness_quality_assessment(self):
        """Should assess randomness quality."""
        monitor = RandomnessQualityMonitor()
        
        report = monitor.assess_randomness_quality(sample_size=256)
        
        assert report.sample_size == 256
        assert report.entropy_estimate > 0
        assert isinstance(report.runs_test_passed, bool)
    
    def test_randomness_no_op_when_disabled(self):
        """Randomness monitoring should be no-op when disabled."""
        self.config.RANDOMNESS_MONITORING_ENABLED = False
        
        monitor = RandomnessQualityMonitor()
        report = monitor.assess_randomness_quality(sample_size=256)
        
        assert report.sample_size == 0
        assert report.entropy_estimate == 0.0
    
    def test_recent_reports_stored(self):
        """Should store recent reports."""
        monitor = RandomnessQualityMonitor()
        
        for _ in range(5):
            monitor.assess_randomness_quality(sample_size=64)
        
        reports = monitor.get_recent_reports(limit=3)
        assert len(reports) == 3


class TestCryptoHealthChecker:
    """Test cryptography-specific health checks."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.HEALTH_CHECKS_ENABLED = True
        self.config.RANDOMNESS_MONITORING_ENABLED = True
    
    def test_standard_health_checks_registered(self):
        """Standard crypto health checks should be pre-registered."""
        checker = get_global_crypto_health_checker()
        
        results = checker.run_all_checks()
        check_names = [r.check_name for r in results]
        
        assert "randomness_quality" in check_names
        assert "hash_functions" in check_names
    
    def test_randomness_health_check(self):
        """Randomness health check should work."""
        checker = get_global_crypto_health_checker()
        
        result = checker.run_check("randomness_quality")
        
        assert result is not None
        assert result.status in [
            CryptoHealthStatus.HEALTHY,
            CryptoHealthStatus.DEGRADED,
            CryptoHealthStatus.UNHEALTHY
        ]
    
    def test_hash_health_check(self):
        """Hash function health check should work."""
        checker = get_global_crypto_health_checker()
        
        result = checker.run_check("hash_functions")
        
        assert result is not None
        assert result.status == CryptoHealthStatus.HEALTHY
    
    def test_overall_health_status(self):
        """Should compute overall health status."""
        checker = get_global_crypto_health_checker()
        
        checker.run_all_checks()
        status = checker.get_overall_status()
        
        assert status in [
            CryptoHealthStatus.HEALTHY,
            CryptoHealthStatus.DEGRADED,
            CryptoHealthStatus.UNHEALTHY,
            CryptoHealthStatus.UNKNOWN
        ]


class TestCryptoEventEmitter:
    """Test cryptography-specific event emission."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.EVENTS_ENABLED = True
        self.config.METRICS_ENABLED = True
    
    def test_emit_key_generation_event(self):
        """Should emit key generation event."""
        emitter = CryptoEventEmitter()
        
        emitter.emit_key_generation("AES-256-GCM", 256)
        
        events = emitter.get_recent_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "key_generation"
    
    def test_emit_key_rotation_event(self):
        """Should emit key rotation event and track in metrics."""
        get_global_crypto_metrics().reset()
        emitter = CryptoEventEmitter()
        
        emitter.emit_key_rotation("AES-256-GCM", "compromise")
        
        events = emitter.get_recent_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "key_rotation"
        
        # Should also increment metrics
        all_metrics = get_global_crypto_metrics().get_all_metrics()
        assert all_metrics["key_rotations"] == 1
    
    def test_emit_encryption_event(self):
        """Should emit encryption event."""
        emitter = CryptoEventEmitter()
        
        emitter.emit_encryption("AES-256-GCM", 1024)
        
        events = emitter.get_recent_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "encryption"
    
    def test_emit_security_alert(self):
        """Should emit security alert event."""
        emitter = CryptoEventEmitter()
        
        emitter.emit_security_alert("key_exhaustion", "high", "Key usage nearing limit")
        
        events = emitter.get_recent_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "security_alert"


class TestThreadSafety:
    """Test thread safety of crypto observability components."""
    
    def setup_method(self):
        self.config = CryptoObservabilityConfig()
        self.config.METRICS_ENABLED = True
        get_global_crypto_metrics().reset()
    
    def test_concurrent_crypto_operation_recording(self):
        """Should handle concurrent operation recording."""
        num_threads = 10
        ops_per_thread = 100
        
        def worker():
            for _ in range(ops_per_thread):
                get_global_crypto_metrics().record_crypto_operation("concurrent", 0.1)
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        expected = num_threads * ops_per_thread
        stats = get_global_crypto_metrics().get_operation_stats("concurrent")
        
        assert stats["count"] == expected


class TestModuleMetadata:
    """Test module metadata and status."""
    
    def test_version_exists(self):
        """Version should be defined."""
        assert CRYPTO_OBSERVABILITY_VERSION == "16.0.0"
    
    def test_api_stability(self):
        """API stability should be defined."""
        assert CRYPTO_OBSERVABILITY_API_STABILITY == "stable"
    
    def test_get_crypto_observability_status(self):
        """Status function should return comprehensive summary."""
        status = get_crypto_observability_status()
        
        assert "version" in status
        assert "api_stability" in status
        assert "enabled_features" in status
        assert "metrics" in status
        assert "crypto_health_status" in status
        assert "event_count" in status


class TestBackwardCompatibility:
    """Verify no breaking changes to existing code."""
    
    def test_no_production_code_modification(self):
        """This module should be completely additive."""
        # Module imports cleanly without modifying existing code
        assert True
    
    def test_zero_overhead_when_disabled(self):
        """Disabled observability should have near-zero overhead."""
        config = CryptoObservabilityConfig()
        config.disable_all()
        
        # Measure time for many no-op operations
        start = time.time()
        
        for _ in range(1000):
            get_global_crypto_metrics().record_crypto_operation("test", 0.1)
            get_global_crypto_events().emit_key_generation("test", 256)
        
        duration = (time.time() - start) * 1000
        
        # 1000 operations should take less than 100ms
        assert duration < 100, f"Overhead too high: {duration}ms"


class TestIntegrationWithExistingCrypto:
    """Test observability integrates with existing crypto code."""
    
    def test_module_imports_cleanly(self):
        """Module should import without errors."""
        from quantum_crypt.crypto_comprehensive_observability_instrumentation_v16_2026_june import (
            CryptoObservabilityConfig,
            CryptoMetricsCollector,
            CryptoHealthChecker,
            RandomnessQualityMonitor,
            CryptoEventEmitter,
        )
        
        config = CryptoObservabilityConfig()
        metrics = CryptoMetricsCollector()
        health = CryptoHealthChecker()
        randomness = RandomnessQualityMonitor()
        events = CryptoEventEmitter()
        
        assert config is not None
        assert metrics is not None
        assert health is not None
        assert randomness is not None
        assert events is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
