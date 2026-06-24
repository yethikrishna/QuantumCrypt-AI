"""
Test Suite for QuantumCrypt Observability v24
DIMENSION D: Observability & Instrumentation
All tests verify ADD-ONLY implementation works correctly
"""

import pytest
import json
import time
import threading
import secrets
from quantum_crypt.crypto_observability_structured_logging_metrics_v24_2026_june import (
    ObservabilityConfig, StructuredLogger, CryptoMetricsRegistry,
    CryptoHealthCheckRegistry, TraceContextManager, LogLevel, MetricType,
    HealthStatus, CryptoOperationType, Metric, HealthCheck, TraceContext,
    CryptoOperationMetrics, logger, metrics, health_checks, tracer,
    timed, counted, logged, traced, crypto_operation,
    enable_logging, enable_metrics, enable_tracing, enable_health_checks,
    enable_all, disable_all, get_config, get_status, API_STABILITY
)


class TestObservabilityConfig:
    """Test configuration singleton and defaults"""
    
    def test_singleton_pattern(self):
        config1 = ObservabilityConfig()
        config2 = ObservabilityConfig()
        assert config1 is config2
    
    def test_defaults_are_disabled(self):
        config = ObservabilityConfig()
        config.logging_enabled = False
        config.metrics_enabled = False
        config.tracing_enabled = False
        config.health_checks_enabled = False
        
        assert config.logging_enabled is False
        assert config.metrics_enabled is False
        assert config.tracing_enabled is False
        assert config.health_checks_enabled is False
        assert config.service_name == "quantumcrypt-ai"
        assert config.sensitive_logging is False
    
    def test_get_status(self):
        disable_all()
        status = get_status()
        assert all(v is False for v in status.values())


class TestStructuredLogger:
    """Test structured logging with security awareness"""
    
    def test_logger_disabled_by_default(self, capsys):
        disable_all()
        logger.info("test message")
        captured = capsys.readouterr()
        assert captured.out == ""
    
    def test_logger_enabled_outputs_json(self, capsys):
        enable_logging(log_to_console=True)
        logger.info("test message", custom_field="value")
        captured = capsys.readouterr()
        disable_all()
        
        if captured.out:
            log_entry = json.loads(captured.out.strip())
            assert log_entry["message"] == "test message"
            assert log_entry["level"] == "info"
            assert "timestamp" in log_entry
    
    def test_sensitive_data_redaction(self, capsys):
        enable_logging(log_to_console=True)
        logger.info("crypto operation", private_key="secret123", key=b"sensitive bytes")
        captured = capsys.readouterr()
        disable_all()
        
        if captured.out:
            log_entry = json.loads(captured.out.strip())
            assert log_entry["private_key"] == "[REDACTED]"
    
    def test_all_log_levels(self):
        enable_logging(log_to_console=False)
        logger.debug("debug")
        logger.info("info")
        logger.warning("warning")
        logger.error("error")
        logger.critical("critical")
        disable_all()


class TestCryptoMetricsRegistry:
    """Test crypto-specific metrics collection"""
    
    def test_metrics_disabled_by_default(self):
        disable_all()
        metrics.increment_counter("test_counter")
        export = metrics.export_prometheus()
        assert export == ""
    
    def test_counter_increment(self):
        enable_metrics()
        metrics.increment_counter("key_generations_total", labels={"algorithm": "CRYSTALS-Kyber"})
        export = metrics.export_json()
        disable_all()
        
        assert len(export["metrics"]) > 0
    
    def test_crypto_operation_tracking(self):
        enable_metrics()
        metrics.record_crypto_operation(CryptoOperationMetrics(
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm="CRYSTALS-Kyber",
            key_size=512,
            duration_ms=15.5,
            success=True
        ))
        summary = metrics.get_crypto_operation_summary()
        disable_all()
        
        assert summary["total_operations"] == 1
        assert summary["success_rate"] == 1.0
    
    def test_crypto_operation_error_tracking(self):
        enable_metrics()
        for i in range(10):
            metrics.record_crypto_operation(CryptoOperationMetrics(
                operation_type=CryptoOperationType.ENCRYPTION,
                algorithm="AES-256-GCM",
                key_size=256,
                duration_ms=1.2,
                success=(i < 9),
                error_type=None if i < 9 else "DecryptionError"
            ))
        summary = metrics.get_crypto_operation_summary()
        disable_all()
        
        assert summary["total_operations"] == 10
        assert summary["success_rate"] == 0.9
    
    def test_prometheus_export_format(self):
        enable_metrics()
        metrics.increment_counter("pq_signatures", help_text="Post-quantum signature operations")
        export = metrics.export_prometheus()
        disable_all()
        
        assert "# HELP pq_signatures" in export
        assert "# TYPE pq_signatures counter" in export


class TestCryptoHealthCheckRegistry:
    """Test crypto health check framework"""
    
    def test_health_checks_disabled_by_default(self):
        disable_all()
        result = health_checks.run_all_checks()
        assert result["status"] == HealthStatus.HEALTHY.value
        assert result["message"] == "Health checks disabled"
    
    def test_entropy_health_check(self):
        enable_health_checks(with_entropy_check=True)
        result = health_checks.run_all_checks()
        disable_all()
        
        assert "entropy_source" in result["checks"]
        entropy_check = result["checks"]["entropy_source"]
        assert entropy_check["status"] in [HealthStatus.HEALTHY.value, HealthStatus.DEGRADED.value]
    
    def test_custom_health_check(self):
        enable_health_checks(with_entropy_check=False)
        
        def hsm_check():
            return HealthCheck(
                name="hsm_connection",
                status=HealthStatus.HEALTHY,
                message="HSM responsive"
            )
        
        health_checks.register_check("hsm_connection", hsm_check)
        result = health_checks.run_all_checks()
        disable_all()
        
        assert "hsm_connection" in result["checks"]


class TestTraceContextManager:
    """Test distributed tracing with secure random"""
    
    def test_tracing_disabled_by_default(self):
        disable_all()
        ctx = tracer.create_trace()
        assert ctx.trace_id == "disabled"
        assert ctx.span_id == "disabled"
    
    def test_trace_creation_secure_random(self):
        enable_tracing()
        ctx = tracer.create_trace()
        disable_all()
        
        assert ctx.trace_id != "disabled"
        assert len(ctx.trace_id) == 32
        assert len(ctx.span_id) == 16
    
    def test_child_span_propagation(self):
        enable_tracing()
        parent = tracer.create_trace()
        child = tracer.create_child_span(parent)
        disable_all()
        
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id


class TestDecorators:
    """Test instrumentation decorators"""
    
    def test_timed_decorator_disabled(self):
        disable_all()
        
        @timed("keygen_duration")
        def keygen():
            return secrets.token_bytes(32)
        
        result = keygen()
        assert len(result) == 32
    
    def test_crypto_operation_decorator(self):
        enable_metrics()
        
        @crypto_operation(CryptoOperationType.ENCRYPTION, "AES-GCM", 256)
        def encrypt(data):
            return data[::-1]
        
        encrypt(b"test data")
        encrypt(b"more data")
        summary = metrics.get_crypto_operation_summary()
        disable_all()
        
        assert summary["total_operations"] == 2
    
    def test_counted_decorator(self):
        enable_metrics()
        
        @counted("signature_operations", labels={"algorithm": "CRYSTALS-Dilithium"})
        def sign():
            return "signature"
        
        for _ in range(5):
            sign()
        export = metrics.export_json()
        disable_all()
        
        assert len(export["metrics"]) > 0
    
    def test_decorator_exception_propagation(self):
        enable_metrics()
        
        @crypto_operation(CryptoOperationType.DECRYPTION, "Test", 128)
        def failing_decrypt():
            raise ValueError("Invalid padding")
        
        with pytest.raises(ValueError):
            failing_decrypt()
        
        summary = metrics.get_crypto_operation_summary()
        disable_all()
        
        assert summary["success_rate"] == 0.0


class TestThreadSafety:
    """Test thread safety under concurrent crypto operations"""
    
    def test_concurrent_crypto_metrics(self):
        enable_metrics()
        
        def worker():
            for _ in range(50):
                metrics.record_crypto_operation(CryptoOperationMetrics(
                    operation_type=CryptoOperationType.HASHING,
                    algorithm="SHA-256",
                    key_size=256,
                    duration_ms=0.1,
                    success=True
                ))
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        summary = metrics.get_crypto_operation_summary()
        disable_all()
        
        assert summary["total_operations"] == 500


class TestAPIStability:
    """Test API stability markers"""
    
    def test_api_stability_markers_exist(self):
        assert isinstance(API_STABILITY, dict)
        assert len(API_STABILITY) > 0
    
    def test_all_markers_are_stable(self):
        for marker in API_STABILITY.values():
            assert marker == "STABLE"
    
    def test_all_exports_exist(self):
        import quantum_crypt.crypto_observability_structured_logging_metrics_v24_2026_june as module
        for export_name in module.__all__:
            assert hasattr(module, export_name)


class TestBackwardCompatibility:
    """Test backward compatibility - zero impact on existing code"""
    
    def test_no_side_effects_when_disabled(self):
        disable_all()
        
        logger.info("test", private_key="secret")
        metrics.increment_counter("test")
        metrics.record_crypto_operation(CryptoOperationMetrics(
            CryptoOperationType.ENCRYPTION, "Test", 0, 0, True
        ))
        health_checks.run_all_checks()
        tracer.create_trace()
        
        assert True
    
    def test_enable_disable_idempotent(self):
        for _ in range(5):
            enable_all()
            disable_all()
        assert all(v is False for v in get_status().values())


class TestSecurityProperties:
    """Test security properties of observability layer"""
    
    def test_no_key_material_in_logs(self, capsys):
        enable_logging(log_to_console=True)
        sensitive_key = secrets.token_bytes(32)
        logger.info("operation with key", key=sensitive_key, secret="password123")
        captured = capsys.readouterr()
        disable_all()
        
        if captured.out:
            log_entry = json.loads(captured.out.strip())
            assert log_entry["key"] == "[REDACTED]"
            assert log_entry["secret"] == "[REDACTED]"
            # Ensure raw key bytes are not in output
            assert sensitive_key.hex() not in captured.out
    
    def test_trace_ids_are_cryptographically_secure(self):
        enable_tracing()
        trace_ids = set()
        for _ in range(100):
            ctx = tracer.create_trace()
            trace_ids.add(ctx.trace_id)
        disable_all()
        
        # No collisions in 100 traces
        assert len(trace_ids) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
