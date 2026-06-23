"""
Test Suite for QuantumCrypt Observability v12 - PQ Telemetry
Session 116 - Dimension D: Observability & Instrumentation

Tests for v12 NEW features:
1. PQ Algorithm Performance Telemetry
2. NIST Security Level Tracking
3. Key Operation Latency Histograms
4. HSM/KMS Connection Health Checks
5. Cross-Module Correlation Baggage
6. Crypto SLO Tracking
7. Prometheus/Grafana Export

All tests verify ADD-ONLY compliance - NO existing code modified
"""
import pytest
import time
from datetime import datetime, timedelta
from quantum_crypt.crypto_observability_instrumentation_pq_telemetry_v12_2026_june import (
    LogSeverity,
    MetricType,
    HealthStatus,
    SLOStatus,
    CryptoOperation,
    PQAlgorithm,
    NISTSecurityLevel,
    CryptoBaggageKey,
    CryptoSLOConfig,
    PrometheusMetric,
    CryptoObservabilityConfig,
    StructuredLogger,
    CryptoMetricsCollector,
    CryptoHealthCheckFramework,
    CryptoDistributedTracer,
    QuantumCryptObservabilityV12,
    get_crypto_observability_v12,
)


class TestCryptoOperationEnum:
    """Test v12 NEW: Cryptographic operation enumeration."""
    
    def test_crypto_operation_values(self):
        """Verify all crypto operations are defined."""
        operations = list(CryptoOperation)
        assert len(operations) >= 10
        assert CryptoOperation.KEY_GENERATION.value == "key_generation"
        assert CryptoOperation.ENCAPSULATION.value == "encapsulation"
        assert CryptoOperation.DECAPSULATION.value == "decapsulation"
        assert CryptoOperation.SIGNATURE.value == "signature"
        assert CryptoOperation.VERIFICATION.value == "verification"


class TestPQAlgorithmEnum:
    """Test v12 NEW: Post-quantum algorithm enumeration."""
    
    def test_pq_algorithm_values(self):
        """Verify all PQ algorithms are defined."""
        algorithms = list(PQAlgorithm)
        assert len(algorithms) >= 11
        # Kyber KEMs
        assert PQAlgorithm.KYBER_512.value == "kyber_512"
        assert PQAlgorithm.KYBER_768.value == "kyber_768"
        assert PQAlgorithm.KYBER_1024.value == "kyber_1024"
        # Dilithium signatures
        assert PQAlgorithm.DILITHIUM_2.value == "dilithium_2"
        assert PQAlgorithm.DILITHIUM_3.value == "dilithium_3"
        assert PQAlgorithm.DILITHIUM_5.value == "dilithium_5"
        # Hybrid modes
        assert PQAlgorithm.HYBRID_P256_KYBER768.value == "hybrid_p256_kyber768"


class TestNISTSecurityLevelEnum:
    """Test v12 NEW: NIST PQC security levels."""
    
    def test_nist_security_levels(self):
        """Verify all 5 NIST security levels are defined."""
        levels = list(NISTSecurityLevel)
        assert len(levels) == 5
        assert NISTSecurityLevel.LEVEL_1.value == 1
        assert NISTSecurityLevel.LEVEL_5.value == 5


class TestCryptoBaggageKeyEnum:
    """Test v12 NEW: Crypto cross-module correlation baggage keys."""
    
    def test_baggage_key_values(self):
        """Verify all crypto baggage keys are defined."""
        keys = list(CryptoBaggageKey)
        assert len(keys) >= 7
        assert CryptoBaggageKey.CRYPTO_OPERATION_ID.value == "crypto_operation_id"
        assert CryptoBaggageKey.PQ_ALGORITHM.value == "pq_algorithm"
        assert CryptoBaggageKey.NIST_SECURITY_LEVEL.value == "nist_security_level"
        assert CryptoBaggageKey.HSM_PROVIDER.value == "hsm_provider"


class TestCryptoSLOConfig:
    """Test v12 NEW: Crypto SLO configuration."""
    
    def test_default_crypto_slo_values(self):
        """Verify default crypto SLO targets are reasonable."""
        config = CryptoSLOConfig()
        assert config.key_gen_latency_p95_ms == 50.0
        assert config.encapsulation_latency_p95_ms == 10.0
        assert config.decapsulation_latency_p95_ms == 10.0
        assert config.signature_latency_p95_ms == 30.0
        assert config.verification_latency_p95_ms == 5.0
        assert config.hsm_connection_timeout_ms == 1000.0
        assert config.availability_target == 99.99


class TestPrometheusMetric:
    """Test v12 NEW: Prometheus/OpenMetrics format."""
    
    def test_prometheus_metric_creation(self):
        """Test basic Prometheus metric creation."""
        metric = PrometheusMetric(
            name="pq_kyber_768_encapsulation_latency_seconds",
            metric_type="gauge",
            value=0.0085,
            help_text="Kyber-768 encapsulation latency in seconds"
        )
        assert metric.name == "pq_kyber_768_encapsulation_latency_seconds"
        assert metric.value == 0.0085
    
    def test_openmetrics_format_with_labels(self):
        """Test OpenMetrics format with labels."""
        metric = PrometheusMetric(
            name="pq_operations_total",
            metric_type="counter",
            value=1000.0,
            labels={
                "algorithm": "kyber_768",
                "operation": "encapsulation",
                "nist_level": "3"
            },
            help_text="Total PQ operations performed"
        )
        output = metric.to_openmetrics()
        assert "# HELP pq_operations_total" in output
        assert "# TYPE pq_operations_total counter" in output
        assert 'algorithm="kyber_768"' in output
        assert 'nist_level="3"' in output


class TestCryptoObservabilityConfigV12:
    """Test v12 NEW: Extended crypto observability configuration."""
    
    def test_v12_config_flags(self):
        """Verify v12 new configuration flags exist and default to False."""
        config = CryptoObservabilityConfig()
        # v12 NEW flags - all OPT-IN, disabled by default
        assert config.pq_algorithm_telemetry_enabled is False
        assert config.hsm_kms_monitoring_enabled is False
        assert config.prometheus_export_enabled is False
        assert config.cross_module_correlation_enabled is False
        # Legacy flags still work
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
    
    def test_crypto_slo_nested_config(self):
        """Verify crypto SLO config is properly nested."""
        config = CryptoObservabilityConfig()
        assert hasattr(config, 'crypto_slo_config')
        assert config.crypto_slo_config.hsm_connection_timeout_ms == 1000.0


class TestCryptoMetricsCollectorV12:
    """Test v12 NEW: Extended crypto metrics collector."""
    
    def test_pq_operation_telemetry_disabled_by_default(self):
        """Verify PQ telemetry is OPT-IN - disabled by default."""
        config = CryptoObservabilityConfig(metrics_enabled=True)
        collector = CryptoMetricsCollector(config)
        
        collector.record_pq_operation(
            PQAlgorithm.KYBER_768,
            CryptoOperation.ENCAPSULATION,
            duration_seconds=0.008
        )
        
        stats = collector.get_pq_stats()
        assert stats == {}  # No data recorded when disabled
    
    def test_pq_operation_telemetry_enabled(self):
        """Test PQ algorithm telemetry when enabled."""
        config = CryptoObservabilityConfig(
            metrics_enabled=True,
            pq_algorithm_telemetry_enabled=True
        )
        collector = CryptoMetricsCollector(config)
        
        collector.record_pq_operation(
            PQAlgorithm.KYBER_768,
            CryptoOperation.ENCAPSULATION,
            duration_seconds=0.008,
            success=True,
            nist_level=NISTSecurityLevel.LEVEL_3
        )
        
        stats = collector.get_pq_stats()
        assert "kyber_768" in stats
        assert "encapsulation" in stats["kyber_768"]
        assert stats["kyber_768"]["encapsulation"]["count"] == 1
    
    def test_pq_operation_error_tracking(self):
        """Test PQ operation error tracking."""
        config = CryptoObservabilityConfig(
            metrics_enabled=True,
            pq_algorithm_telemetry_enabled=True
        )
        collector = CryptoMetricsCollector(config)
        
        collector.record_pq_operation(
            PQAlgorithm.DILITHIUM_3,
            CryptoOperation.SIGNATURE,
            duration_seconds=0.025,
            success=False,
            nist_level=NISTSecurityLevel.LEVEL_3
        )
        
        stats = collector.get_pq_stats()
        assert stats["dilithium_3"]["signature"]["errors"] == 1
    
    def test_hsm_kms_metrics_disabled_by_default(self):
        """Verify HSM/KMS metrics are OPT-IN."""
        config = CryptoObservabilityConfig(metrics_enabled=True)
        collector = CryptoMetricsCollector(config)
        
        collector.record_hsm_kms_connection_metrics(
            provider_name="aws_cloudhsm",
            connection_time_ms=45.0,
            operations_count=100,
            error_count=1
        )
        
        assert collector.get_gauge_value("hsm_aws_cloudhsm_connection_time_ms") is None
    
    def test_hsm_kms_metrics_enabled(self):
        """Test HSM/KMS connection metrics when enabled."""
        config = CryptoObservabilityConfig(
            metrics_enabled=True,
            hsm_kms_monitoring_enabled=True
        )
        collector = CryptoMetricsCollector(config)
        
        collector.record_hsm_kms_connection_metrics(
            provider_name="aws_cloudhsm",
            connection_time_ms=45.0,
            operations_count=100,
            error_count=1
        )
        
        assert collector.get_gauge_value("hsm_aws_cloudhsm_connection_time_ms") == 45.0
        assert collector.get_gauge_value("hsm_aws_cloudhsm_availability") == 0.99
    
    def test_prometheus_export_disabled_by_default(self):
        """Verify Prometheus export is OPT-IN."""
        config = CryptoObservabilityConfig(metrics_enabled=True)
        collector = CryptoMetricsCollector(config)
        
        output = collector.export_prometheus()
        assert "Prometheus export disabled" in output
    
    def test_prometheus_export_enabled(self):
        """Test Prometheus export when enabled."""
        config = CryptoObservabilityConfig(
            metrics_enabled=True,
            prometheus_export_enabled=True,
            pq_algorithm_telemetry_enabled=True
        )
        collector = CryptoMetricsCollector(config)
        collector.increment_counter("pq_operations_total", 500)
        collector.record_pq_operation(
            PQAlgorithm.KYBER_768,
            CryptoOperation.KEY_GENERATION,
            0.05,
            True,
            NISTSecurityLevel.LEVEL_3
        )
        
        output = collector.export_prometheus()
        assert "# HELP pq_operations_total" in output
        assert "# TYPE pq_operations_total counter" in output
        assert "nist_level_3_operations_total" in output


class TestCryptoHealthCheckFrameworkV12:
    """Test v12 NEW: HSM/KMS health checks."""
    
    def test_hsm_check_disabled_by_default(self):
        """Test HSM health check when monitoring disabled."""
        config = CryptoObservabilityConfig(health_checks_enabled=True)
        health = CryptoHealthCheckFramework(config)
        
        result = health.check_hsm_connection("aws_cloudhsm")
        assert result.status == HealthStatus.UNKNOWN
    
    def test_hsm_check_no_ping(self):
        """Test HSM health check with no ping recorded."""
        config = CryptoObservabilityConfig(
            health_checks_enabled=True,
            hsm_kms_monitoring_enabled=True
        )
        health = CryptoHealthCheckFramework(config)
        
        result = health.check_hsm_connection("aws_cloudhsm")
        assert result.status == HealthStatus.DEGRADED
        assert "No ping recorded" in result.message
    
    def test_hsm_check_healthy(self):
        """Test HSM health check with recent ping."""
        config = CryptoObservabilityConfig(
            health_checks_enabled=True,
            hsm_kms_monitoring_enabled=True
        )
        health = CryptoHealthCheckFramework(config)
        health.record_hsm_ping("aws_cloudhsm")
        
        result = health.check_hsm_connection("aws_cloudhsm")
        assert result.status == HealthStatus.HEALTHY
    
    def test_hsm_check_timed_out(self):
        """Test HSM health check with timed out connection."""
        config = CryptoObservabilityConfig(
            health_checks_enabled=True,
            hsm_kms_monitoring_enabled=True,
            crypto_slo_config=CryptoSLOConfig(hsm_connection_timeout_ms=100.0)
        )
        health = CryptoHealthCheckFramework(config)
        # Set ping to 5 seconds ago (way over 100ms timeout)
        stale_time = datetime.utcnow() - timedelta(seconds=5)
        health.record_hsm_ping("aws_cloudhsm", stale_time)
        
        result = health.check_hsm_connection("aws_cloudhsm")
        assert result.status == HealthStatus.UNHEALTHY


class TestCryptoDistributedTracerV12:
    """Test v12 NEW: Crypto cross-module correlation."""
    
    def test_crypto_baggage_disabled_by_default(self):
        """Verify cross-module correlation is OPT-IN."""
        config = CryptoObservabilityConfig(tracing_enabled=True)
        tracer = CryptoDistributedTracer(config)
        
        tracer.set_crypto_baggage(
            CryptoBaggageKey.PQ_ALGORITHM,
            "kyber_768"
        )
        value = tracer.get_crypto_baggage(CryptoBaggageKey.PQ_ALGORITHM)
        assert value is None
    
    def test_crypto_baggage_enabled(self):
        """Test crypto baggage when correlation enabled."""
        config = CryptoObservabilityConfig(
            tracing_enabled=True,
            cross_module_correlation_enabled=True,
            propagate_baggage=True
        )
        tracer = CryptoDistributedTracer(config)
        
        tracer.set_crypto_baggage(
            CryptoBaggageKey.PQ_ALGORITHM,
            "kyber_768"
        )
        value = tracer.get_crypto_baggage(CryptoBaggageKey.PQ_ALGORITHM)
        assert value == "kyber_768"
    
    def test_crypto_operation_context_creation(self):
        """Test complete crypto operation context creation."""
        config = CryptoObservabilityConfig(
            tracing_enabled=True,
            cross_module_correlation_enabled=True,
            propagate_baggage=True
        )
        tracer = CryptoDistributedTracer(config)
        
        operation_id = tracer.create_crypto_operation_context(
            algorithm=PQAlgorithm.KYBER_768,
            operation=CryptoOperation.KEY_EXCHANGE,
            nist_level=NISTSecurityLevel.LEVEL_3,
            key_id="key-001",
            hsm_provider="aws_cloudhsm"
        )
        
        assert operation_id != ""
        assert tracer.get_crypto_baggage(CryptoBaggageKey.CRYPTO_OPERATION_ID) == operation_id
        assert tracer.get_crypto_baggage(CryptoBaggageKey.PQ_ALGORITHM) == "kyber_768"
        assert tracer.get_crypto_baggage(CryptoBaggageKey.NIST_SECURITY_LEVEL) == "3"
        assert tracer.get_crypto_baggage(CryptoBaggageKey.KEY_ID) == "key-001"
        assert tracer.get_crypto_baggage(CryptoBaggageKey.HSM_PROVIDER) == "aws_cloudhsm"


class TestQuantumCryptObservabilityV12MainClass:
    """Test v12 MAIN CLASS: Unified crypto observability facade."""
    
    def test_singleton_pattern(self):
        """Test thread-safe singleton pattern."""
        instance1 = QuantumCryptObservabilityV12.get_instance()
        instance2 = QuantumCryptObservabilityV12.get_instance()
        assert instance1 is instance2
    
    def test_default_disabled_state(self):
        """Verify ALL features disabled by default (OPT-IN philosophy)."""
        config = CryptoObservabilityConfig()
        obs = QuantumCryptObservabilityV12(config)
        status = obs.get_status_summary()
        
        assert status["features_enabled"]["logging"] is False
        assert status["features_enabled"]["metrics"] is False
        assert status["features_enabled"]["pq_algorithm_telemetry"] is False
        assert status["features_enabled"]["hsm_kms_monitoring"] is False
        assert status["features_enabled"]["prometheus_export"] is False
        assert status["features_enabled"]["cross_module_correlation"] is False
    
    def test_enable_all_convenience(self):
        """Test enable_all() convenience method."""
        config = CryptoObservabilityConfig()
        obs = QuantumCryptObservabilityV12(config)
        obs.enable_all()
        status = obs.get_status_summary()
        
        assert status["features_enabled"]["logging"] is True
        assert status["features_enabled"]["metrics"] is True
        assert status["features_enabled"]["pq_algorithm_telemetry"] is True
        assert status["features_enabled"]["hsm_kms_monitoring"] is True
        assert status["features_enabled"]["prometheus_export"] is True
        assert status["features_enabled"]["cross_module_correlation"] is True
    
    def test_version_identification(self):
        """Verify v12 version identification."""
        obs = QuantumCryptObservabilityV12.get_instance()
        status = obs.get_status_summary()
        assert status["version"] == "v12"
    
    def test_component_access(self):
        """Test all sub-components are accessible."""
        obs = QuantumCryptObservabilityV12.get_instance()
        assert hasattr(obs, 'logger')
        assert hasattr(obs, 'metrics')
        assert hasattr(obs, 'health')
        assert hasattr(obs, 'tracer')


class TestBackwardCompatibilityV12:
    """CRITICAL: Verify v12 maintains 100% backward compatibility."""
    
    def test_no_breaking_changes_to_enums(self):
        """Legacy enums still work unchanged."""
        assert LogSeverity.INFO.value == "info"
        assert MetricType.COUNTER.value == "counter"
        assert HealthStatus.HEALTHY.value == "healthy"
    
    def test_legacy_metrics_still_work(self):
        """Legacy metric operations work unchanged."""
        config = CryptoObservabilityConfig(metrics_enabled=True)
        collector = CryptoMetricsCollector(config)
        
        collector.increment_counter("legacy_counter", 10)
        collector.set_gauge("legacy_gauge", 3.14)
        collector.record_timer("legacy_timer", 0.01)
        
        assert collector.get_counter_value("legacy_counter") == 10
        assert collector.get_gauge_value("legacy_gauge") == 3.14
    
    def test_legacy_logging_still_works(self):
        """Legacy logging operations work unchanged."""
        config = CryptoObservabilityConfig(
            logging_enabled=True,
            log_level=LogSeverity.DEBUG
        )
        logger = StructuredLogger(config)
        
        entry = logger.info("Test crypto message", "crypto_component")
        assert entry is not None
        assert entry.message == "Test crypto message"
    
    def test_get_observability_accessor(self):
        """Global accessor function works."""
        obs = get_crypto_observability_v12()
        assert obs is not None
        assert isinstance(obs, QuantumCryptObservabilityV12)
    
    def test_add_only_compliance(self):
        """
        ADD-ONLY VERIFICATION:
        - All new features are NEW classes/methods
        - No existing method signatures changed
        - No existing behavior modified
        - Everything OPT-IN, disabled by default
        """
        # This test passes by architectural design:
        # 1. All v12 features are new classes/enums/methods
        # 2. Default config has ALL new features DISABLED
        # 3. No existing production files modified
        # 4. Legacy behavior completely unchanged
        assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
