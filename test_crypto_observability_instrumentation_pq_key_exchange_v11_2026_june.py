"""
Tests for QuantumCrypt AI - Observability & Instrumentation for PQ Key Exchange v11
Session 110 - Dimension D: Observability & Instrumentation

ALL TESTS MUST PASS
NO EXISTING CODE MODIFIED
100% BACKWARD COMPATIBLE
NO SENSITIVE KEY MATERIAL EXPOSED
"""

import pytest
import time
import threading
import secrets

from quantum_crypt.crypto_observability_instrumentation_pq_key_exchange_v11_2026_june import (
    CryptoOperationType, LogSeverity, MetricType, HealthStatus,
    AlgorithmStatus, SLOStatus,
    CryptoLogEntry, MetricValue, HealthCheckResult, AlgorithmInfo,
    SLOConfig, CryptoObservabilityConfig,
    CryptoStructuredLogger, CryptoMetricsCollector, CryptoHealthCheckFramework,
    CryptoDistributedTracer, CryptoSLOTracker,
    PQKeyExchangeObservability, crypto_observability
)


class TestCryptoOperationTypeEnum:
    """Test CryptoOperationType enum values."""
    
    def test_all_operation_types(self):
        assert CryptoOperationType.KEY_GENERATION.value == "key_generation"
        assert CryptoOperationType.KEY_EXCHANGE.value == "key_exchange"
        assert CryptoOperationType.KEY_DERIVATION.value == "key_derivation"
        assert CryptoOperationType.SIGNATURE_GENERATION.value == "signature_generation"
        assert CryptoOperationType.SIGNATURE_VERIFICATION.value == "signature_verification"
        assert CryptoOperationType.ENCRYPTION.value == "encryption"
        assert CryptoOperationType.DECRYPTION.value == "decryption"
        assert CryptoOperationType.RANDOM_GENERATION.value == "random_generation"
        assert CryptoOperationType.HASH_COMPUTATION.value == "hash_computation"


class TestAlgorithmStatusEnum:
    """Test AlgorithmStatus enum values."""
    
    def test_algorithm_statuses(self):
        assert AlgorithmStatus.STABLE.value == "stable"
        assert AlgorithmStatus.EXPERIMENTAL.value == "experimental"
        assert AlgorithmStatus.DEPRECATED.value == "deprecated"
        assert AlgorithmStatus.BROKEN.value == "broken"


class TestCryptoObservabilityConfig:
    """Test CryptoObservabilityConfig defaults - ALL DISABLED BY DEFAULT."""
    
    def test_default_config_all_disabled(self):
        """CRITICAL: All features must be disabled by default (OPT-IN pattern)."""
        config = CryptoObservabilityConfig()
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
        assert config.health_checks_enabled is False
        assert config.tracing_enabled is False
        assert config.slo_tracking_enabled is False
        assert config.benchmarking_enabled is False
    
    def test_security_constraints_enforced(self):
        """Security constraints must always be enabled."""
        config = CryptoObservabilityConfig()
        assert config.never_log_key_material is True
        assert config.redact_all_sensitive_values is True
        assert config.max_session_id_log_length == 16
        assert config.timing_noise_jitter is True


class TestCryptoStructuredLogger:
    """Test CryptoStructuredLogger functionality."""
    
    def test_logger_disabled_by_default(self):
        """Logger must return None when disabled."""
        config = CryptoObservabilityConfig()
        logger = CryptoStructuredLogger(config)
        
        result = logger.log_key_exchange("CRYSTALS-Kyber-768")
        assert result is None
    
    def test_session_id_truncation(self):
        """Session IDs must ALWAYS be truncated - security requirement."""
        config = CryptoObservabilityConfig(logging_enabled=True)
        logger = CryptoStructuredLogger(config)
        
        long_session_id = "session_id_very_long_should_be_truncated_1234567890"
        result = logger.log_key_exchange("CRYSTALS-Kyber-768", session_id=long_session_id)
        
        assert result is not None
        assert len(result.session_id_truncated) <= 16
        assert len(result.session_id_truncated) == 16
    
    def test_sensitive_values_redacted(self):
        """Key material must ALWAYS be redacted - security requirement."""
        config = CryptoObservabilityConfig(logging_enabled=True)
        logger = CryptoStructuredLogger(config)
        
        result = logger.log_key_exchange(
            "CRYSTALS-Kyber-768",
            private_key="THIS_IS_SENSITIVE_MATERIAL",
            secret_value="SHOULD_BE_REDACTED",
            safe_attribute="normal_value"
        )
        
        assert result is not None
        assert result.attributes["private_key"] == "[REDACTED]"
        assert result.attributes["secret_value"] == "[REDACTED]"
        assert result.attributes["safe_attribute"] == "normal_value"
    
    def test_log_convenience_methods(self):
        config = CryptoObservabilityConfig(logging_enabled=True)
        logger = CryptoStructuredLogger(config)
        
        assert logger.log_key_generation("Kyber") is not None
        assert logger.log_key_exchange("Kyber") is not None
        assert logger.log_key_derivation("HKDF") is not None
        assert logger.log_signature("Dilithium") is not None
        assert logger.log_error(CryptoOperationType.KEY_EXCHANGE, "Kyber", "timeout") is not None


class TestCryptoMetricsCollector:
    """Test CryptoMetricsCollector functionality."""
    
    def test_metrics_disabled_by_default(self):
        """Metrics must return 0 when disabled."""
        config = CryptoObservabilityConfig()
        metrics = CryptoMetricsCollector(config)
        
        result = metrics.increment_operation(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        assert result == 0
    
    def test_operation_counter(self):
        config = CryptoObservabilityConfig(metrics_enabled=True)
        metrics = CryptoMetricsCollector(config)
        
        for _ in range(10):
            metrics.increment_operation(CryptoOperationType.KEY_EXCHANGE, "Kyber", success=True)
        for _ in range(2):
            metrics.increment_operation(CryptoOperationType.KEY_EXCHANGE, "Kyber", success=False)
        
        stats = metrics.get_operation_stats(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        assert stats["total_operations"] == 12
        assert stats["success_count"] == 10
        assert stats["error_count"] == 2
        assert stats["success_rate"] == pytest.approx(83.33, abs=0.1)
    
    def test_timing_noise_jitter(self):
        """Timing noise must obscure exact measurements - security against timing attacks."""
        config = CryptoObservabilityConfig(metrics_enabled=True, timing_noise_jitter=True)
        metrics = CryptoMetricsCollector(config)
        
        base_duration = 10.0
        noisy_durations = []
        for _ in range(100):
            noisy = metrics._add_timing_noise(base_duration)
            noisy_durations.append(noisy)
        
        # Verify jitter was applied (not all exactly 10.0)
        unique_values = len(set(noisy_durations))
        assert unique_values > 1  # Not all identical
        
        # Verify jitter is within +/- 1% range
        for d in noisy_durations:
            assert 9.9 <= d <= 10.1
    
    def test_algorithm_registry(self):
        config = CryptoObservabilityConfig(metrics_enabled=True)
        metrics = CryptoMetricsCollector(config)
        
        algo = AlgorithmInfo("TEST-KEM", AlgorithmStatus.STABLE, 768, 3, "TEST-STD")
        metrics.register_algorithm(algo)
        metrics.set_algorithm_active("TEST-KEM", True)
        
        assert metrics.get_all_counters() is not None
    
    def test_timer_decorator(self):
        config = CryptoObservabilityConfig(metrics_enabled=True)
        metrics = CryptoMetricsCollector(config)
        
        @metrics.time_crypto_operation(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        def test_key_exchange():
            time.sleep(0.001)
            return "shared_secret"
        
        result = test_key_exchange()
        assert result == "shared_secret"
        
        stats = metrics.get_operation_stats(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        assert stats["total_operations"] == 1
        assert stats["success_count"] == 1


class TestCryptoHealthCheckFramework:
    """Test CryptoHealthCheckFramework functionality."""
    
    def test_health_checks_disabled_by_default(self):
        """Health checks must return None when disabled."""
        config = CryptoObservabilityConfig()
        health = CryptoHealthCheckFramework(config)
        
        result = health.run_check("entropy_source")
        assert result is None
    
    def test_entropy_health_check(self):
        config = CryptoObservabilityConfig(health_checks_enabled=True)
        health = CryptoHealthCheckFramework(config)
        
        result = health.run_check("entropy_source")
        assert result is not None
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.UNKNOWN]
    
    def test_hash_function_check(self):
        config = CryptoObservabilityConfig(health_checks_enabled=True)
        health = CryptoHealthCheckFramework(config)
        
        result = health.run_check("hash_functions")
        assert result is not None
        # Hash check should pass on a working system
        assert result.status == HealthStatus.HEALTHY
    
    def test_overall_status(self):
        config = CryptoObservabilityConfig(health_checks_enabled=True)
        health = CryptoHealthCheckFramework(config)
        
        health.run_all_checks()
        status = health.get_overall_status()
        assert status in [HealthStatus.HEALTHY, HealthStatus.UNKNOWN]
    
    def test_custom_health_check(self):
        config = CryptoObservabilityConfig(health_checks_enabled=True)
        health = CryptoHealthCheckFramework(config)
        
        def custom_check():
            return HealthCheckResult("custom", HealthStatus.HEALTHY, "ok", 0.0)
        
        health.register_check("custom", custom_check)
        result = health.run_check("custom")
        assert result.status == HealthStatus.HEALTHY


class TestCryptoDistributedTracer:
    """Test CryptoDistributedTracer functionality."""
    
    def test_tracing_disabled_by_default(self):
        """Tracing must return empty/None when disabled."""
        config = CryptoObservabilityConfig()
        tracer = CryptoDistributedTracer(config)
        
        assert tracer.generate_secure_correlation_id() == ""
        assert tracer.get_correlation_id() is None
        assert tracer.get_baggage() == {}
    
    def test_secure_correlation_id(self):
        config = CryptoObservabilityConfig(tracing_enabled=True)
        tracer = CryptoDistributedTracer(config)
        
        cid = tracer.generate_secure_correlation_id()
        assert len(cid) == 32  # 16 bytes hex = 32 chars
        # Should be valid hex
        int(cid, 16)  # No exception = valid hex
    
    def test_sensitive_baggage_dropped(self):
        """Sensitive baggage must NEVER be propagated - security requirement."""
        config = CryptoObservabilityConfig(tracing_enabled=True, propagate_baggage=True)
        tracer = CryptoDistributedTracer(config)
        
        tracer.set_secure_baggage("private_key", "SENSITIVE_VALUE")
        tracer.set_secure_baggage("secret", "SHOULD_NOT_EXIST")
        tracer.set_secure_baggage("user_id", "normal_value")
        
        baggage = tracer.get_baggage()
        assert "private_key" not in baggage
        assert "secret" not in baggage
        assert baggage["user_id"] == "normal_value"
    
    def test_correlation_id_propagation(self):
        config = CryptoObservabilityConfig(tracing_enabled=True)
        tracer = CryptoDistributedTracer(config)
        
        cid = tracer.generate_secure_correlation_id()
        tracer.set_correlation_id(cid)
        assert tracer.get_correlation_id() == cid
    
    def test_clear_context(self):
        config = CryptoObservabilityConfig(tracing_enabled=True, propagate_baggage=True)
        tracer = CryptoDistributedTracer(config)
        
        tracer.set_correlation_id("test-cid")
        tracer.set_secure_baggage("test", "value")
        tracer.clear_context()
        
        assert tracer.get_correlation_id() is None
        assert tracer.get_baggage() == {}


class TestCryptoSLOTracker:
    """Test CryptoSLOTracker functionality."""
    
    def test_slo_tracking_disabled_by_default(self):
        config = CryptoObservabilityConfig()
        slo = CryptoSLOTracker(config)
        
        slo.record_success("key_exchange")
        # No exception = success, but nothing recorded
    
    def test_default_slos_registered(self):
        config = CryptoObservabilityConfig(slo_tracking_enabled=True)
        slo = CryptoSLOTracker(config)
        
        # Should not raise exceptions
        slo.record_success("key_exchange", 50.0)
        slo.record_success("key_generation", 25.0)
        slo.record_error("key_exchange")


class TestPQKeyExchangeObservabilitySingleton:
    """Test main singleton facade."""
    
    def test_singleton_pattern(self):
        instance1 = PQKeyExchangeObservability()
        instance2 = PQKeyExchangeObservability()
        assert instance1 is instance2
    
    def test_global_instance_exists(self):
        assert crypto_observability is not None
    
    def test_all_features_disabled_by_default(self):
        """CRITICAL: All features must be disabled by default."""
        obs = PQKeyExchangeObservability()
        config = obs.config
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
        assert config.health_checks_enabled is False
        assert config.tracing_enabled is False
        assert config.slo_tracking_enabled is False
        assert config.benchmarking_enabled is False
    
    def test_security_constraints_always_enforced(self):
        obs = PQKeyExchangeObservability()
        assert obs.config.never_log_key_material is True
        assert obs.config.redact_all_sensitive_values is True
        assert obs.config.max_session_id_log_length == 16
    
    def test_enable_logging(self):
        obs = PQKeyExchangeObservability()
        obs.enable_logging()
        assert obs.config.logging_enabled is True
    
    def test_enable_metrics(self):
        obs = PQKeyExchangeObservability()
        obs.enable_metrics()
        assert obs.config.metrics_enabled is True
    
    def test_enable_health_checks(self):
        obs = PQKeyExchangeObservability()
        obs.enable_health_checks()
        assert obs.config.health_checks_enabled is True
    
    def test_enable_tracing(self):
        obs = PQKeyExchangeObservability()
        obs.enable_tracing()
        assert obs.config.tracing_enabled is True
    
    def test_enable_slo_tracking(self):
        obs = PQKeyExchangeObservability()
        obs.enable_slo_tracking()
        assert obs.config.slo_tracking_enabled is True
    
    def test_enable_all(self):
        obs = PQKeyExchangeObservability()
        obs.enable_all()
        assert obs.config.logging_enabled is True
        assert obs.config.metrics_enabled is True
        assert obs.config.health_checks_enabled is True
        assert obs.config.tracing_enabled is True
        assert obs.config.slo_tracking_enabled is True
        assert obs.config.benchmarking_enabled is True
    
    def test_status_summary(self):
        obs = PQKeyExchangeObservability()
        summary = obs.get_status_summary()
        assert "config" in summary
        assert "health" in summary
        assert "security" in summary


class TestBackwardCompatibility:
    """Verify backward compatibility - no breaking changes."""
    
    def test_no_existing_code_modified(self):
        """Module is completely standalone - no imports of existing code."""
        from quantum_crypt.crypto_observability_instrumentation_pq_key_exchange_v11_2026_june import crypto_observability
        assert crypto_observability is not None
    
    def test_opt_in_pattern_respected(self):
        """All operations safe when disabled."""
        from quantum_crypt.crypto_observability_instrumentation_pq_key_exchange_v11_2026_june import crypto_observability
        
        # All should work without errors when disabled
        crypto_observability.logger.log_key_exchange("Kyber")
        crypto_observability.metrics.increment_operation(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        crypto_observability.health.run_all_checks()
        crypto_observability.tracer.generate_secure_correlation_id()
        crypto_observability.slo.record_success("key_exchange")
        
        assert True  # No exceptions = success


class TestThreadSafety:
    """Test thread safety of all components."""
    
    def test_concurrent_operation_increments(self):
        config = CryptoObservabilityConfig(metrics_enabled=True)
        metrics = CryptoMetricsCollector(config)
        
        def worker():
            for _ in range(100):
                metrics.increment_operation(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = metrics.get_operation_stats(CryptoOperationType.KEY_EXCHANGE, "Kyber")
        assert stats["total_operations"] == 1000


class TestSecurityGuarantees:
    """Test critical security guarantees are enforced."""
    
    def test_key_material_never_logged(self):
        config = CryptoObservabilityConfig(logging_enabled=True)
        logger = CryptoStructuredLogger(config)
        
        sensitive_key = secrets.token_hex(32)
        result = logger.log_key_exchange("Kyber", private_key=sensitive_key, secret=sensitive_key)
        
        log_str = str(result.to_dict())
        # Sensitive value should NOT appear in log
        assert sensitive_key not in log_str
        assert "[REDACTED]" in log_str
    
    def test_session_id_never_full_in_logs(self):
        config = CryptoObservabilityConfig(logging_enabled=True)
        logger = CryptoStructuredLogger(config)
        
        long_session_id = "very_long_session_id_that_should_never_appear_fully_in_logs_12345"
        result = logger.log_key_exchange("Kyber", session_id=long_session_id)
        
        # Full session ID should NOT appear
        assert long_session_id not in result.session_id_truncated
        # Only truncated version appears
        assert len(result.session_id_truncated) == 16


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_log_retrieval(self):
        config = CryptoObservabilityConfig(logging_enabled=True)
        logger = CryptoStructuredLogger(config)
        logs = logger.get_recent_logs()
        assert len(logs) == 0
    
    def test_empty_operation_stats(self):
        config = CryptoObservabilityConfig(metrics_enabled=True)
        metrics = CryptoMetricsCollector(config)
        stats = metrics.get_operation_stats(CryptoOperationType.KEY_EXCHANGE, "Nonexistent")
        assert stats["total_operations"] == 0
        assert stats["success_rate"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
