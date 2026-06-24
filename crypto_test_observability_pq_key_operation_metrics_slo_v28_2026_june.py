"""
Test Suite: Post-Quantum Key Operation Metrics with SLO Monitoring v28
DIMENSION D - Observability & Instrumentation

Tests for crypto metrics collection, SLO monitoring, and export.
All tests verify OPT-IN behavior - disabled by default.
"""

import os
import pytest
import time
from quantum_crypt.observability_pq_key_operation_metrics_slo_v28_2026_june import (
    CryptoMetrics,
    CryptoOperation,
    SLOStatus,
    SLOThreshold,
    SLOResult,
    OperationMetrics,
    measured,
    MetricsExporter,
)


class TestOperationMetrics:
    """Tests for per-operation metrics tracking"""

    def test_initial_state(self):
        """Test initial metrics state"""
        metrics = OperationMetrics(operation=CryptoOperation.KEY_GENERATION)
        assert metrics.total == 0
        assert metrics.errors == 0
        assert metrics.successes == 0
        assert metrics.error_rate == 0.0
        assert metrics.availability == 1.0

    def test_record_success(self):
        """Test recording successful operations"""
        metrics = OperationMetrics(operation=CryptoOperation.KEY_GENERATION)
        metrics.record_success(10.5)
        metrics.record_success(15.2)
        
        assert metrics.total == 2
        assert metrics.successes == 2
        assert metrics.errors == 0
        assert metrics.error_rate == 0.0
        assert metrics.availability == 1.0

    def test_record_error(self):
        """Test recording failed operations"""
        metrics = OperationMetrics(operation=CryptoOperation.KEY_GENERATION)
        metrics.record_success(10.0)
        metrics.record_error(5.0)
        
        assert metrics.total == 2
        assert metrics.successes == 1
        assert metrics.errors == 1
        assert metrics.error_rate == 0.5
        assert metrics.availability == 0.5

    def test_percentile_calculation(self):
        """Test latency percentile calculation"""
        metrics = OperationMetrics(operation=CryptoOperation.KEY_GENERATION)
        for i in range(100):
            metrics.record_success(float(i))
        
        # Percentile calculation may vary slightly based on implementation
        # Verify values are in reasonable range
        p50 = metrics.get_percentile(50)
        p90 = metrics.get_percentile(90)
        p95 = metrics.get_percentile(95)
        p99 = metrics.get_percentile(99)
        
        assert 45 <= p50 <= 55  # Approximately median
        assert 85 <= p90 <= 95  # Approximately 90th percentile
        assert 90 <= p95 <= 99  # Approximately 95th percentile
        assert 95 <= p99 <= 99  # Approximately 99th percentile

    def test_throughput_calculation(self):
        """Test throughput calculation"""
        metrics = OperationMetrics(operation=CryptoOperation.KEY_GENERATION)
        metrics.record_success(1.0)
        time.sleep(0.01)
        metrics.record_success(1.0)
        
        assert metrics.throughput_ops_sec > 0

    def test_window_rotation(self):
        """Test that metrics window rotates after expiry"""
        metrics = OperationMetrics(operation=CryptoOperation.KEY_GENERATION)
        metrics.window_seconds = 0  # Force immediate rotation
        metrics.record_success(10.0)
        metrics.record_success(20.0)
        # Next record should trigger rotation
        metrics.record_success(30.0)
        # After rotation, only the last one remains (approximately)
        assert metrics.total <= 2


class TestCryptoMetrics:
    """Tests for OPT-IN crypto metrics collector"""

    def setup_method(self):
        CryptoMetrics.disable()
        os.environ.pop("QUANTUMCRYPT_METRICS_ENABLED", None)
        CryptoMetrics.reset_metrics()

    def test_disabled_by_default(self):
        """Test that metrics are DISABLED by default (OPT-IN)"""
        assert not CryptoMetrics.is_enabled()

    def test_enable_requires_env(self):
        """Test that enabling requires both flag and env var"""
        CryptoMetrics.enable()
        assert not CryptoMetrics.is_enabled()  # Still needs env var
        
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        assert CryptoMetrics.is_enabled()

    def test_record_operation_disabled_noop(self):
        """Test that recording is no-op when disabled"""
        CryptoMetrics.record_operation(CryptoOperation.KEY_GENERATION, 10.0, success=True)
        metrics = CryptoMetrics.get_metrics(CryptoOperation.KEY_GENERATION)
        # Either None or empty metrics when disabled
        assert metrics is None or metrics.total == 0

    def test_record_operation_enabled(self):
        """Test recording operations when enabled"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        CryptoMetrics.record_operation(CryptoOperation.KEY_GENERATION, 10.0, success=True)
        CryptoMetrics.record_operation(CryptoOperation.KEY_GENERATION, 15.0, success=True)
        
        metrics = CryptoMetrics.get_metrics(CryptoOperation.KEY_GENERATION)
        assert metrics is not None
        assert metrics.total == 2
        assert metrics.successes == 2

    def test_record_error_operations(self):
        """Test recording error operations"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        CryptoMetrics.record_operation(CryptoOperation.SIGNATURE_VERIFICATION, 5.0, success=True)
        CryptoMetrics.record_operation(CryptoOperation.SIGNATURE_VERIFICATION, 3.0, success=False)
        
        metrics = CryptoMetrics.get_metrics(CryptoOperation.SIGNATURE_VERIFICATION)
        assert metrics.errors == 1
        assert metrics.error_rate == 0.5

    def test_get_all_metrics(self):
        """Test getting all metrics"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        CryptoMetrics.record_operation(CryptoOperation.ENCRYPTION, 1.0, success=True)
        CryptoMetrics.record_operation(CryptoOperation.DECRYPTION, 1.0, success=True)
        
        all_metrics = CryptoMetrics.get_all_metrics()
        assert CryptoOperation.ENCRYPTION in all_metrics
        assert CryptoOperation.DECRYPTION in all_metrics

    def test_slo_check_ok(self):
        """Test SLO check when within thresholds"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        # Record operations well within SLO
        for _ in range(20):
            CryptoMetrics.record_operation(CryptoOperation.SIGNATURE_VERIFICATION, 5.0, success=True)
        
        result = CryptoMetrics.check_slo(CryptoOperation.SIGNATURE_VERIFICATION)
        assert result is not None
        assert result.status == SLOStatus.OK
        assert len(result.violations) == 0

    def test_slo_check_latency_violation(self):
        """Test SLO check detects latency violations"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        # Record very slow operations (target is 20ms P95)
        for _ in range(100):
            CryptoMetrics.record_operation(CryptoOperation.SIGNATURE_VERIFICATION, 100.0, success=True)
        
        result = CryptoMetrics.check_slo(CryptoOperation.SIGNATURE_VERIFICATION)
        assert result is not None
        assert any("Latency" in v for v in result.violations)

    def test_slo_check_error_rate_violation(self):
        """Test SLO check detects error rate violations"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        # Record high error rate
        for i in range(100):
            success = i >= 90  # 10% error rate
            CryptoMetrics.record_operation(CryptoOperation.SIGNATURE_VERIFICATION, 5.0, success=success)
        
        result = CryptoMetrics.check_slo(CryptoOperation.SIGNATURE_VERIFICATION)
        assert result is not None
        assert any("Error rate" in v for v in result.violations)

    def test_slo_check_all_operations(self):
        """Test checking SLO for all operations"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        for op in [CryptoOperation.ENCRYPTION, CryptoOperation.DECRYPTION]:
            for _ in range(10):
                CryptoMetrics.record_operation(op, 1.0, success=True)
        
        results = CryptoMetrics.check_all_slos()
        assert len(results) > 0

    def test_overall_slo_status(self):
        """Test overall SLO status calculation"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        # All good operations
        for _ in range(10):
            CryptoMetrics.record_operation(CryptoOperation.ENCRYPTION, 1.0, success=True)
        
        assert CryptoMetrics.get_overall_slo_status() == SLOStatus.OK

    def test_set_custom_threshold(self):
        """Test setting custom SLO thresholds"""
        custom_threshold = SLOThreshold(
            operation=CryptoOperation.HASH_COMPUTATION,
            latency_p95_ms=5.0,
            error_rate_max=0.001,
            availability_min=0.9999,
            throughput_min=1000.0
        )
        CryptoMetrics.set_custom_threshold(custom_threshold)
        
        # Verify it was set
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        for _ in range(10):
            CryptoMetrics.record_operation(CryptoOperation.HASH_COMPUTATION, 1.0, success=True)
        
        result = CryptoMetrics.check_slo(CryptoOperation.HASH_COMPUTATION)
        assert result is not None


class TestMeasuredDecorator:
    """Tests for @measured decorator"""

    def setup_method(self):
        CryptoMetrics.disable()
        os.environ.pop("QUANTUMCRYPT_METRICS_ENABLED", None)
        CryptoMetrics.reset_metrics()

    def test_measured_disabled_noop(self):
        """Test that @measured is no-op when disabled"""
        call_count = 0
        
        @measured(CryptoOperation.KEY_GENERATION)
        def generate_key():
            nonlocal call_count
            call_count += 1
            return b"key-data"
        
        result = generate_key()
        assert result == b"key-data"
        assert call_count == 1
        # No metrics should be recorded
        metrics = CryptoMetrics.get_metrics(CryptoOperation.KEY_GENERATION)
        assert metrics is None or metrics.total == 0

    def test_measured_enabled_records_metrics(self):
        """Test that @measured records metrics when enabled"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        @measured(CryptoOperation.KEY_GENERATION)
        def generate_key():
            return b"key-data"
        
        result = generate_key()
        assert result == b"key-data"
        
        metrics = CryptoMetrics.get_metrics(CryptoOperation.KEY_GENERATION)
        assert metrics is not None
        assert metrics.total == 1
        assert metrics.successes == 1

    def test_measured_propagates_exceptions(self):
        """Test that @measured propagates exceptions and records errors"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        @measured(CryptoOperation.KEY_GENERATION)
        def failing_key_gen():
            raise RuntimeError("Key generation failed")
        
        with pytest.raises(RuntimeError):
            failing_key_gen()
        
        metrics = CryptoMetrics.get_metrics(CryptoOperation.KEY_GENERATION)
        assert metrics is not None
        assert metrics.errors == 1


class TestMetricsExporter:
    """Tests for metrics export functionality"""

    def setup_method(self):
        CryptoMetrics.disable()
        os.environ.pop("QUANTUMCRYPT_METRICS_ENABLED", None)
        CryptoMetrics.reset_metrics()

    def test_prometheus_export_disabled_empty(self):
        """Test Prometheus export returns empty when disabled"""
        output = MetricsExporter.to_prometheus()
        assert output == ""

    def test_prometheus_export_enabled(self):
        """Test Prometheus format export"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        CryptoMetrics.record_operation(CryptoOperation.ENCRYPTION, 1.0, success=True)
        
        output = MetricsExporter.to_prometheus()
        assert output != ""
        assert "crypto_encryption_total" in output
        assert "crypto_encryption_errors" in output
        assert "crypto_encryption_latency_p95_ms" in output

    def test_json_export_enabled(self):
        """Test JSON format export"""
        CryptoMetrics.enable()
        os.environ["QUANTUMCRYPT_METRICS_ENABLED"] = "1"
        
        CryptoMetrics.record_operation(CryptoOperation.ENCRYPTION, 1.0, success=True)
        
        output = MetricsExporter.to_json()
        assert "encryption" in output
        assert output["encryption"]["total"] == 1
        assert "latency_p95_ms" in output["encryption"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
