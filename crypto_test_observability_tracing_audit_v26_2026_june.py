"""
Test Suite for QuantumCrypt Observability v26 - Dimension D
PQ Crypto Tracing, Audit Logging, HSM Health, Entropy Metrics, Percentiles
"""
import unittest
import time
import threading
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from pq_crypto_observability_tracing_audit_v26_2026_june import (
    CryptoObservabilityConfig, get_config,
    CryptoOperationType, PQSecurityLevel, AuditLogLevel, HealthStatus, HealthCheck,
    CryptoMetric, PercentileResult, KeyOperationContext,
    EntropyMetrics, PercentileHistogram,
    SensitiveDataRedactor,
    CryptoAuditLogger, get_audit_logger, audited_crypto_operation,
    PQCryptoMetricsCollector, get_crypto_metrics,
    KeyOperationTracingManager, get_tracing_manager, traced_crypto_operation,
    HSMHealthMonitor, get_health_monitor
)


class TestCryptoObservabilityConfig(unittest.TestCase):
    """Test global configuration - ALL OPT-IN by default"""
    
    def setUp(self):
        """Reset singleton for test isolation"""
        CryptoObservabilityConfig._reset_for_testing()
    
    def test_all_features_disabled_by_default(self):
        """CRITICAL: All crypto observability must be OPT-IN only"""
        config = CryptoObservabilityConfig()
        
        self.assertFalse(config.audit_logging_enabled)
        self.assertFalse(config.crypto_metrics_enabled)
        self.assertFalse(config.health_monitoring_enabled)
        self.assertFalse(config.tracing_enabled)
        self.assertFalse(config.entropy_monitoring_enabled)
        self.assertFalse(config.prometheus_exposition_enabled)
        self.assertTrue(config.sensitive_data_redaction)  # Redaction ON by default
    
    def test_enable_all(self):
        """Test enabling all crypto observability features"""
        config = get_config()
        config.enable_all()
        
        self.assertTrue(config.audit_logging_enabled)
        self.assertTrue(config.crypto_metrics_enabled)
        self.assertTrue(config.health_monitoring_enabled)
        self.assertTrue(config.tracing_enabled)
        self.assertTrue(config.entropy_monitoring_enabled)
        self.assertTrue(config.prometheus_exposition_enabled)


class TestSensitiveDataRedaction(unittest.TestCase):
    """Test sensitive crypto material redaction"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
    
    def test_bytes_redaction(self):
        """Test byte key material is redacted"""
        result = SensitiveDataRedactor.redact_key_material(b"secret_key_material")
        self.assertEqual(result, b"[REDACTED]")
    
    def test_hex_string_redaction(self):
        """Test long hex strings are detected and redacted"""
        long_hex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
        result = SensitiveDataRedactor.redact_key_material(long_hex)
        self.assertIn("[REDACTED]", result)
    
    def test_normal_string_not_redacted(self):
        """Test normal strings pass through"""
        result = SensitiveDataRedactor.redact_key_material("Kyber-512")
        self.assertEqual(result, "Kyber-512")
    
    def test_nested_dict_redaction(self):
        """Test recursive redaction in nested structures"""
        data = {
            "algorithm": "Kyber",
            "private_key": b"secret",
            "nested": {
                "key_material": b"also_secret"
            }
        }
        result = SensitiveDataRedactor.redact_key_material(data)
        self.assertEqual(result["private_key"], b"[REDACTED]")
        self.assertEqual(result["nested"]["key_material"], b"[REDACTED]")
        self.assertEqual(result["algorithm"], "Kyber")
    
    def test_key_id_hashing(self):
        """Test safe key ID generation"""
        key_id = SensitiveDataRedactor.hash_key_id(b"test_key")
        self.assertTrue(key_id.startswith("key-"))
        self.assertEqual(len(key_id), 4 + 8)


class TestPercentileHistogram(unittest.TestCase):
    """Test crypto latency percentile calculation"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
    
    def test_crypto_operation_percentiles(self):
        """Test P50, P95, P99 for crypto operations"""
        hist = PercentileHistogram()
        
        # Simulate key generation latencies
        latencies = [1.5, 2.0, 2.5, 3.0, 5.0, 10.0, 15.0, 20.0, 50.0, 100.0]
        for l in latencies:
            hist.record(l)
        
        result = hist.get_percentiles()
        
        self.assertEqual(result.count, 10)
        self.assertEqual(result.min, 1.5)
        self.assertEqual(result.max, 100.0)
        self.assertGreaterEqual(result.p99, result.p95)
        self.assertGreaterEqual(result.p95, result.p50)


class TestKeyOperationTracing(unittest.TestCase):
    """Test PQ crypto key operation tracing"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
        get_config().enable_tracing()
    
    def test_operation_id_generation(self):
        """Test unique operation ID format"""
        tracing = KeyOperationTracingManager()
        op_id = tracing.generate_operation_id()
        
        self.assertTrue(op_id.startswith("crypto-op-"))
        self.assertEqual(len(op_id), 10 + 12)
    
    def test_start_key_operation_context(self):
        """Test starting a key operation creates proper context"""
        tracing = KeyOperationTracingManager()
        
        ctx = tracing.start_operation(
            algorithm="CRYSTALS-Kyber",
            operation_type=CryptoOperationType.KEY_GENERATION,
            security_level=PQSecurityLevel.LEVEL_5
        )
        
        self.assertIsNotNone(ctx.operation_id)
        self.assertEqual(ctx.algorithm, "CRYSTALS-Kyber")
        self.assertEqual(ctx.operation_type, CryptoOperationType.KEY_GENERATION)
        self.assertEqual(ctx.security_level, PQSecurityLevel.LEVEL_5)
        self.assertGreater(ctx.start_time, 0)
    
    def test_end_operation_records_metrics(self):
        """Test ending operation records metrics"""
        get_config().enable_metrics()
        tracing = KeyOperationTracingManager()
        metrics = get_crypto_metrics()
        metrics.reset()
        
        ctx = tracing.start_operation(
            "Kyber-768",
            CryptoOperationType.KEY_EXCHANGE,
            PQSecurityLevel.LEVEL_3
        )
        time.sleep(0.001)
        duration = tracing.end_operation(ctx)
        
        self.assertGreater(duration, 0)
        
        all_metrics = metrics.get_all_metrics()
        self.assertGreater(len(all_metrics["operation_latency"]), 0)
    
    def test_correlation_id_propagation(self):
        """Test correlation ID is set during tracing"""
        tracing = KeyOperationTracingManager()
        
        ctx = tracing.start_operation("Dilithium", CryptoOperationType.SIGNATURE, PQSecurityLevel.LEVEL_5)
        cid = tracing.get_correlation_id()
        
        self.assertIsNotNone(cid)
        self.assertTrue(cid.startswith("qc-cid-"))


class TestPQCryptoMetricsCollector(unittest.TestCase):
    """Test PQ crypto-specific metrics collection"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
        get_config().enable_metrics()
        get_config().enable_prometheus()
    
    def test_record_crypto_operation(self):
        """Test recording algorithm-specific metrics"""
        metrics = get_crypto_metrics()
        metrics.reset()
        
        metrics.record_operation(
            algorithm="Kyber-512",
            operation_type=CryptoOperationType.KEY_GENERATION,
            security_level=PQSecurityLevel.LEVEL_1,
            duration_ms=45.5
        )
        
        all_metrics = metrics.get_all_metrics()
        latency_key = "Kyber-512_key_generation_NIST_LEVEL_1"
        
        self.assertIn(latency_key, all_metrics["operation_latency"])
        self.assertEqual(all_metrics["operation_latency"][latency_key]["count"], 1)
    
    def test_operation_percentiles_by_algorithm(self):
        """Test percentiles per algorithm and operation type"""
        metrics = get_crypto_metrics()
        metrics.reset()
        
        for i in range(10):
            metrics.record_operation(
                "Falcon-512",
                CryptoOperationType.SIGNATURE,
                PQSecurityLevel.LEVEL_1,
                float(10 + i * 5)
            )
        
        percentiles = metrics.get_operation_percentiles(
            "Falcon-512",
            CryptoOperationType.SIGNATURE
        )
        
        self.assertIsNotNone(percentiles)
        self.assertEqual(percentiles.count, 10)
        self.assertGreater(percentiles.p99, percentiles.p50)
    
    def test_entropy_metrics_tracking(self):
        """Test randomness entropy monitoring"""
        get_config().enable_entropy_monitoring()
        metrics = get_crypto_metrics()
        metrics.reset()
        
        metrics.update_entropy(bits_consumed=256, quality_score=0.98)
        metrics.update_entropy(bits_consumed=128)
        
        all_metrics = metrics.get_all_metrics()
        self.assertEqual(all_metrics["entropy"]["bits_consumed"], 384)
        self.assertEqual(all_metrics["entropy"]["quality_score"], 0.98)
    
    def test_prometheus_export(self):
        """Test Prometheus format export for crypto metrics"""
        metrics = get_crypto_metrics()
        metrics.reset()
        
        metrics.increment_counter("kyber_keygen_total", 100)
        metrics.record_operation(
            "Kyber",
            CryptoOperationType.KEY_GENERATION,
            PQSecurityLevel.LEVEL_5,
            50.0
        )
        
        prom_output = metrics.export_prometheus()
        
        self.assertIn("crypto_kyber_keygen_total", prom_output)
        self.assertIn("quantile=", prom_output)


class TestCryptoAuditLogger(unittest.TestCase):
    """Test crypto audit logging with redaction"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
        get_config().enable_audit_logging()
    
    def test_audit_log_levels(self):
        """Test all audit log levels work"""
        logger = CryptoAuditLogger()
        
        # These should not raise exceptions
        logger.audit("Key generation completed")
        logger.security("HSM connection established")
        logger.operational("Signature verified")
        logger.debug("Debug info")
    
    def test_redaction_enabled_by_default(self):
        """Test sensitive data redaction is on by default"""
        config = CryptoObservabilityConfig()
        self.assertTrue(config.sensitive_data_redaction)


class TestHSMHealthMonitor(unittest.TestCase):
    """Test HSM health monitoring with dependencies"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
        get_config().enable_health_monitoring()
        # Reset health monitor state for each test
        get_health_monitor().reset()
    
    def test_hsm_connection_stats_tracking(self):
        """Test HSM connection statistics"""
        monitor = get_health_monitor()
        
        monitor.record_hsm_connection(success=True)
        monitor.record_hsm_connection(success=True)
        monitor.record_hsm_connection(success=False)
        monitor.record_hsm_timeout()
        
        results = monitor.run_health_checks()
        self.assertEqual(results["hsm_stats"]["successful_connections"], 2)
        self.assertEqual(results["hsm_stats"]["failed_connections"], 1)
        self.assertEqual(results["hsm_stats"]["connection_timeouts"], 1)
    
    def test_health_check_with_dependencies(self):
        """Test health check dependency resolution"""
        monitor = get_health_monitor()
        
        def hsm_healthy():
            return HealthCheck(name="hsm_connection", status=HealthStatus.HEALTHY)
        
        def pq_engine_healthy():
            return HealthCheck(name="pq_engine", status=HealthStatus.HEALTHY)
        
        monitor.register_health_check("hsm_connection", hsm_healthy)
        monitor.register_health_check("pq_engine", pq_engine_healthy, dependencies=["hsm_connection"])
        
        results = monitor.run_health_checks()
        self.assertEqual(results["overall_status"], "healthy")
    
    def test_hsm_failure_cascades(self):
        """Test HSM failure cascades to dependent services"""
        monitor = get_health_monitor()
        
        def hsm_unhealthy():
            return HealthCheck(name="hsm", status=HealthStatus.UNHEALTHY, message="Connection refused")
        
        def key_manager_healthy():
            return HealthCheck(name="key_manager", status=HealthStatus.HEALTHY)
        
        monitor.register_health_check("hsm", hsm_unhealthy)
        monitor.register_health_check("key_manager", key_manager_healthy, dependencies=["hsm"])
        
        results = monitor.run_health_checks()
        self.assertEqual(results["overall_status"], "unhealthy")


class TestDecorators(unittest.TestCase):
    """Test crypto observability decorators"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
        get_config().enable_all()
    
    def test_traced_crypto_operation(self):
        """Test tracing decorator for crypto operations"""
        metrics = get_crypto_metrics()
        metrics.reset()
        
        @traced_crypto_operation("Kyber-768", CryptoOperationType.KEY_EXCHANGE, PQSecurityLevel.LEVEL_3)
        def simulate_key_exchange():
            time.sleep(0.001)
            return "shared_secret"
        
        result = simulate_key_exchange()
        self.assertEqual(result, "shared_secret")
        
        all_metrics = metrics.get_all_metrics()
        self.assertGreater(len(all_metrics["operation_latency"]), 0)
    
    def test_audited_crypto_operation(self):
        """Test audit decorator for crypto operations"""
        @audited_crypto_operation(AuditLogLevel.AUDIT)
        def sensitive_key_op():
            return "key_generated"
        
        result = sensitive_key_op()
        self.assertEqual(result, "key_generated")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility - no breaking changes"""
    
    def setUp(self):
        CryptoObservabilityConfig._reset_for_testing()
    
    def test_no_op_when_disabled(self):
        """All functions are no-ops when disabled - ZERO overhead"""
        config = get_config()
        
        # Explicitly disable everything
        config.audit_logging_enabled = False
        config.crypto_metrics_enabled = False
        config.tracing_enabled = False
        config.health_monitoring_enabled = False
        
        metrics = get_crypto_metrics()
        tracing = KeyOperationTracingManager()
        logger = CryptoAuditLogger()
        
        # These should all be no-ops
        metrics.record_operation("Kyber", CryptoOperationType.SIGNATURE, PQSecurityLevel.LEVEL_5, 10.0)
        ctx = tracing.start_operation("Test", CryptoOperationType.ENCRYPTION, PQSecurityLevel.LEVEL_1)
        logger.audit("test")
        
        # Verify no metrics collected
        self.assertEqual(ctx.operation_id, "")
        self.assertEqual(len(metrics.get_all_metrics()["operation_latency"]), 0)
    
    def test_singleton_instances(self):
        """Test all singleton getters work"""
        self.assertIsNotNone(get_audit_logger())
        self.assertIsNotNone(get_crypto_metrics())
        self.assertIsNotNone(get_health_monitor())
        self.assertIsNotNone(get_tracing_manager())
        self.assertIsNotNone(get_config())


if __name__ == "__main__":
    unittest.main(verbosity=2)
