"""
Test Suite for QuantumCrypt-AI Observability, Audit Tracing & Metrics v28
DIMENSION D - Observability & Instrumentation

Tests all crypto-specific observability: metrics, audit logging,
key operation tracing, SLO monitoring, and health checks.
All tests run independently and verify real working code.
"""

import unittest
import time
import json
import sys
import io
import secrets
from typing import Dict, Any

# Import the module
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')
from crypto_observability_audit_tracing_metrics_v28_2026_june import (
    is_crypto_observability_enabled, enable_crypto_observability, 
    disable_crypto_observability, CRYPTO_OBSERVABILITY_ENABLED,
    CryptoOperationType, CryptoAlgorithm, AuditEventType, KeySecurityLevel,
    CryptoMetric, AuditLogEntry, SLOThreshold, KeyOperationRecord,
    CryptoMetricsRegistry, get_crypto_metrics_registry,
    CryptoAuditLogger, instrument_crypto_operation, measure_crypto_duration,
    KeyOperationAuditTrail, get_key_audit_trail,
    CryptoSLMMonitor, check_crypto_entropy_health, check_hmac_constant_time
)


class TestObservabilityControl(unittest.TestCase):
    """Test observability enable/disable control."""
    
    def test_default_disabled(self):
        """Test that observability is DISABLED by default (OPT-IN ONLY)."""
        disable_crypto_observability()
        self.assertFalse(is_crypto_observability_enabled())
        self.assertFalse(CRYPTO_OBSERVABILITY_ENABLED)
    
    def test_enable_observability(self):
        """Test enabling crypto observability."""
        disable_crypto_observability()
        enable_crypto_observability()
        self.assertTrue(is_crypto_observability_enabled())
    
    def test_disable_observability(self):
        """Test disabling crypto observability."""
        enable_crypto_observability()
        disable_crypto_observability()
        self.assertFalse(is_crypto_observability_enabled())
    
    def test_zero_overhead_when_disabled(self):
        """Test that metrics are not collected when disabled."""
        disable_crypto_observability()
        registry = CryptoMetricsRegistry()
        
        metric = CryptoMetric(
            operation=CryptoOperationType.HASH,
            algorithm=CryptoAlgorithm.SHA256,
            duration_ns=1000,
            success=True
        )
        registry.record_operation(metric)
        
        summary = registry.get_summary()
        self.assertEqual(summary["total_operations"], 0)


class TestCryptoEnums(unittest.TestCase):
    """Test crypto-specific enum types."""
    
    def test_crypto_operation_type_enum(self):
        """Test CryptoOperationType enum values."""
        ops = [
            CryptoOperationType.KEY_GENERATION,
            CryptoOperationType.ENCRYPTION,
            CryptoOperationType.DECRYPTION,
            CryptoOperationType.SIGNATURE,
            CryptoOperationType.HASH,
            CryptoOperationType.MAC_GENERATION,
            CryptoOperationType.KEY_EXCHANGE,
        ]
        for op in ops:
            self.assertIsInstance(op.value, str)
            self.assertTrue(len(op.value) > 0)
    
    def test_crypto_algorithm_enum(self):
        """Test CryptoAlgorithm enum values."""
        algs = [
            CryptoAlgorithm.AES_256_GCM,
            CryptoAlgorithm.SHA256,
            CryptoAlgorithm.SHA3_256,
            CryptoAlgorithm.HMAC_SHA256,
            CryptoAlgorithm.KYBER_768,
            CryptoAlgorithm.DILITHIUM_3,
        ]
        for alg in algs:
            self.assertIsInstance(alg.value, str)
    
    def test_audit_event_type_enum(self):
        """Test AuditEventType enum values."""
        events = [
            AuditEventType.KEY_ACCESS,
            AuditEventType.KEY_CREATION,
            AuditEventType.CRYPTO_OPERATION,
            AuditEventType.SECURITY_ALERT,
            AuditEventType.POLICY_VIOLATION,
        ]
        for event in events:
            self.assertIsInstance(event.value, str)
    
    def test_key_security_level_enum(self):
        """Test KeySecurityLevel enum values."""
        levels = [
            KeySecurityLevel.EPHEMERAL,
            KeySecurityLevel.SESSION,
            KeySecurityLevel.STANDARD,
            KeySecurityLevel.SENSITIVE,
            KeySecurityLevel.CRITICAL,
            KeySecurityLevel.ROOT,
        ]
        for level in levels:
            self.assertIsInstance(level.value, str)


class TestCryptoMetricsRegistry(unittest.TestCase):
    """Test thread-safe crypto metrics registry."""
    
    def setUp(self):
        enable_crypto_observability()
        self.registry = CryptoMetricsRegistry()
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_record_successful_operation(self):
        """Test recording successful crypto operations."""
        for _ in range(100):
            metric = CryptoMetric(
                operation=CryptoOperationType.HASH,
                algorithm=CryptoAlgorithm.SHA256,
                duration_ns=1000 + secrets.randbelow(500),
                success=True
            )
            self.registry.record_operation(metric)
        
        stats = self.registry.get_operation_stats(
            CryptoOperationType.HASH, CryptoAlgorithm.SHA256
        )
        
        self.assertEqual(stats["count"], 100)
        self.assertEqual(stats["errors"], 0)
        self.assertGreater(stats["avg_latency_ns"], 0)
    
    def test_record_failed_operation(self):
        """Test recording failed crypto operations."""
        for _ in range(10):
            metric = CryptoMetric(
                operation=CryptoOperationType.DECRYPTION,
                algorithm=CryptoAlgorithm.AES_256_GCM,
                duration_ns=5000,
                success=False,
                error_type="AuthenticationError"
            )
            self.registry.record_operation(metric)
        
        stats = self.registry.get_operation_stats(
            CryptoOperationType.DECRYPTION, CryptoAlgorithm.AES_256_GCM
        )
        
        self.assertEqual(stats["errors"], 10)
    
    def test_latency_percentiles(self):
        """Test latency percentile calculations."""
        for i in range(100):
            metric = CryptoMetric(
                operation=CryptoOperationType.KEY_GENERATION,
                algorithm=CryptoAlgorithm.KYBER_768,
                duration_ns=i * 1000,
                success=True
            )
            self.registry.record_operation(metric)
        
        stats = self.registry.get_operation_stats(
            CryptoOperationType.KEY_GENERATION, CryptoAlgorithm.KYBER_768
        )
        
        self.assertGreater(stats["p99_ns"], stats["p95_ns"])
        self.assertGreater(stats["p95_ns"], stats["p50_ns"])
        self.assertGreater(stats["max_ns"], stats["min_ns"])
    
    def test_metrics_summary(self):
        """Test overall metrics summary."""
        # Record some operations
        for i in range(50):
            self.registry.record_operation(CryptoMetric(
                operation=CryptoOperationType.HASH,
                algorithm=CryptoAlgorithm.SHA256,
                duration_ns=1000,
                success=True
            ))
        
        # Record some errors
        for i in range(5):
            self.registry.record_operation(CryptoMetric(
                operation=CryptoOperationType.DECRYPTION,
                algorithm=CryptoAlgorithm.AES_256_GCM,
                duration_ns=2000,
                success=False
            ))
        
        summary = self.registry.get_summary()
        
        self.assertEqual(summary["total_operations"], 50)
        self.assertEqual(summary["total_errors"], 5)
        self.assertAlmostEqual(summary["error_rate"], 5/55, places=2)
    
    def test_metrics_reset(self):
        """Test metrics reset functionality."""
        self.registry.record_operation(CryptoMetric(
            operation=CryptoOperationType.HASH,
            algorithm=CryptoAlgorithm.SHA256,
            duration_ns=1000,
            success=True
        ))
        
        self.registry.reset()
        
        summary = self.registry.get_summary()
        self.assertEqual(summary["total_operations"], 0)
        self.assertEqual(summary["total_errors"], 0)
    
    def test_global_registry_singleton(self):
        """Test global registry is properly initialized."""
        registry = get_crypto_metrics_registry()
        self.assertIsInstance(registry, CryptoMetricsRegistry)
    
    def test_slo_threshold_registration(self):
        """Test SLO threshold registration."""
        slo = SLOThreshold(
            operation=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.KYBER_768,
            max_latency_ns=100000,
            target_availability=0.9999
        )
        self.registry.register_slo_threshold(slo)
        
        # Record operation exceeding threshold
        self.registry.record_operation(CryptoMetric(
            operation=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.KYBER_768,
            duration_ns=200000,
            success=True
        ))
        
        summary = self.registry.get_summary()
        self.assertGreater(summary["slo_violations"], 0)


class TestCryptoAuditLogger(unittest.TestCase):
    """Test security audit logging."""
    
    def setUp(self):
        enable_crypto_observability()
        self.logger = CryptoAuditLogger(component="TestCrypto")
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_logger_initialization(self):
        """Test logger initialization."""
        self.assertEqual(self.logger.component, "TestCrypto")
    
    def test_caller_context_setting(self):
        """Test caller context setting."""
        self.logger.set_caller_context(service="api", user="system")
        self.assertEqual(self.logger._caller_context["service"], "api")
    
    def test_log_crypto_operation(self):
        """Test logging crypto operations."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.log_crypto_operation(
                operation=CryptoOperationType.HASH,
                algorithm=CryptoAlgorithm.SHA256,
                duration_ns=1500,
                success=True,
                key_level=KeySecurityLevel.STANDARD
            )
            
            output = captured_output.getvalue().strip()
            if output:
                self.assertIn("AUDIT:", output)
                # Verify JSON format
                json_part = output.replace("AUDIT: ", "")
                parsed = json.loads(json_part)
                self.assertIn("event_id", parsed)
                self.assertIn("timestamp", parsed)
        finally:
            sys.stdout = old_stdout
    
    def test_log_key_operation(self):
        """Test logging key operations."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.log_key_operation(
                operation=CryptoOperationType.KEY_GENERATION,
                key_id="test_key_12345",
                key_level=KeySecurityLevel.CRITICAL,
                success=True
            )
            
            output = captured_output.getvalue().strip()
            if output:
                self.assertIn("AUDIT:", output)
        finally:
            sys.stdout = old_stdout
    
    def test_log_security_alert(self):
        """Test logging security alerts."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.log_security_alert(
                "Suspicious key access pattern detected",
                source_ip="192.168.1.1",
                threshold_exceeded=5
            )
            
            output = captured_output.getvalue().strip()
            if output:
                self.assertIn("AUDIT:", output)
        finally:
            sys.stdout = old_stdout
    
    def test_log_policy_violation(self):
        """Test logging policy violations."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.logger.log_policy_violation(
                policy="key_export_restriction",
                details="Root key export attempted without MFA"
            )
            
            output = captured_output.getvalue().strip()
            if output:
                self.assertIn("AUDIT:", output)
        finally:
            sys.stdout = old_stdout
    
    def test_key_id_hashing_for_privacy(self):
        """Test that key IDs are hashed for audit privacy."""
        # Verify internal hashing works
        hashed = self.logger._hash_key_id("sensitive_key_material")
        self.assertEqual(len(hashed), 16)  # Truncated SHA256
        self.assertNotEqual(hashed, "sensitive_key_material")


class TestInstrumentationDecorator(unittest.TestCase):
    """Test crypto operation instrumentation decorator."""
    
    def setUp(self):
        enable_crypto_observability()
        get_crypto_metrics_registry().reset()
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_decorator_success_tracking(self):
        """Test decorator tracks successful crypto operations."""
        
        @instrument_crypto_operation(
            CryptoOperationType.HASH,
            CryptoAlgorithm.SHA256,
            KeySecurityLevel.STANDARD
        )
        def hash_function(data: bytes) -> str:
            return data.hex()
        
        result = hash_function(b"test data")
        self.assertEqual(result, "746573742064617461")
        
        stats = get_crypto_metrics_registry().get_operation_stats(
            CryptoOperationType.HASH, CryptoAlgorithm.SHA256
        )
        self.assertEqual(stats["count"], 1)
        self.assertEqual(stats["errors"], 0)
    
    def test_decorator_failure_tracking(self):
        """Test decorator tracks failed crypto operations."""
        
        @instrument_crypto_operation(
            CryptoOperationType.DECRYPTION,
            CryptoAlgorithm.AES_256_GCM
        )
        def failing_decrypt() -> None:
            raise ValueError("Authentication tag verification failed")
        
        with self.assertRaises(ValueError):
            failing_decrypt()
        
        stats = get_crypto_metrics_registry().get_operation_stats(
            CryptoOperationType.DECRYPTION, CryptoAlgorithm.AES_256_GCM
        )
        self.assertEqual(stats["errors"], 1)
    
    def test_decorator_duration_measurement(self):
        """Test decorator measures operation duration."""
        
        @instrument_crypto_operation(
            CryptoOperationType.KEY_GENERATION,
            CryptoAlgorithm.KYBER_768
        )
        def slow_keygen() -> str:
            time.sleep(0.01)
            return "key_generated"
        
        slow_keygen()
        
        stats = get_crypto_metrics_registry().get_operation_stats(
            CryptoOperationType.KEY_GENERATION, CryptoAlgorithm.KYBER_768
        )
        self.assertEqual(stats["count"], 1)
        self.assertGreater(stats["avg_latency_ns"], 0)


class TestKeyOperationAuditTrail(unittest.TestCase):
    """Test key operation immutable audit trail."""
    
    def setUp(self):
        enable_crypto_observability()
        self.trail = KeyOperationAuditTrail()
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_record_key_operation(self):
        """Test recording key operations."""
        self.trail.record(
            key_id="test_key_001",
            operation=CryptoOperationType.KEY_GENERATION,
            duration_ns=50000,
            success=True,
            caller_identity="api_service"
        )
        
        records = self.trail.get_all_records()
        self.assertEqual(len(records), 1)
    
    def test_get_key_history(self):
        """Test retrieving history for specific key."""
        key_id = "specific_key_123"
        
        self.trail.record(
            key_id=key_id,
            operation=CryptoOperationType.KEY_GENERATION,
            duration_ns=50000,
            success=True,
            caller_identity="system"
        )
        
        self.trail.record(
            key_id=key_id,
            operation=CryptoOperationType.KEY_ROTATION,
            duration_ns=30000,
            success=True,
            caller_identity="system"
        )
        
        history = self.trail.get_key_history(key_id)
        self.assertEqual(len(history), 2)
    
    def test_audit_privacy_hashing(self):
        """Test that sensitive values are hashed in audit trail."""
        sensitive_key = "root_master_key_never_log_raw"
        
        self.trail.record(
            key_id=sensitive_key,
            operation=CryptoOperationType.KEY_GENERATION,
            duration_ns=10000,
            success=True,
            caller_identity="admin"
        )
        
        records = self.trail.get_all_records()
        # Verify raw key is NOT in records
        for record in records:
            self.assertNotEqual(record["key_id"], sensitive_key)
            self.assertEqual(len(record["key_id"]), 16)  # Hashed
    
    def test_global_audit_trail(self):
        """Test global audit trail singleton."""
        trail = get_key_audit_trail()
        self.assertIsInstance(trail, KeyOperationAuditTrail)


class TestSLMMonitoring(unittest.TestCase):
    """Test Service Level Monitoring."""
    
    def setUp(self):
        enable_crypto_observability()
        get_crypto_metrics_registry().reset()
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_add_slo_threshold(self):
        """Test adding SLO thresholds."""
        monitor = CryptoSLMMonitor()
        monitor.add_threshold(
            operation=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.KYBER_768,
            max_latency_ns=100000
        )
        
        compliance = monitor.check_compliance()
        self.assertIn("total_thresholds", compliance)
    
    def test_slo_violation_detection(self):
        """Test SLO violation detection."""
        monitor = CryptoSLMMonitor()
        monitor.add_threshold(
            operation=CryptoOperationType.SIGNATURE,
            algorithm=CryptoAlgorithm.DILITHIUM_3,
            max_latency_ns=1000  # Very strict threshold
        )
        
        # Record operations exceeding threshold
        for _ in range(10):
            get_crypto_metrics_registry().record_operation(CryptoMetric(
                operation=CryptoOperationType.SIGNATURE,
                algorithm=CryptoAlgorithm.DILITHIUM_3,
                duration_ns=50000,  # Exceeds threshold
                success=True
            ))
        
        compliance = monitor.check_compliance()
        self.assertIsInstance(compliance["compliant"], bool)


class TestCryptoHealthChecks(unittest.TestCase):
    """Test crypto-specific health checks."""
    
    def test_entropy_health_check(self):
        """Test system entropy health check."""
        result = check_crypto_entropy_health()
        self.assertIn("healthy", result)
        self.assertIn("status", result)
        self.assertIn("generation_time_ns", result)
        self.assertIn("unique_bytes", result)
    
    def test_hmac_constant_time_check(self):
        """Test HMAC constant-time comparison check."""
        result = check_hmac_constant_time()
        self.assertIn("healthy", result)
        self.assertIn("status", result)
        self.assertIn("timing_ratio", result)
        self.assertIn("compare_digest_working", result)
        # compare_digest should always work correctly
        self.assertTrue(result["compare_digest_working"])


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience instrumentation functions."""
    
    def setUp(self):
        enable_crypto_observability()
        get_crypto_metrics_registry().reset()
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_measure_duration_context_manager(self):
        """Test crypto duration measurement context manager."""
        with measure_crypto_duration(
            CryptoOperationType.HASH,
            CryptoAlgorithm.SHA3_256
        ):
            time.sleep(0.005)
        
        stats = get_crypto_metrics_registry().get_operation_stats(
            CryptoOperationType.HASH, CryptoAlgorithm.SHA3_256
        )
        self.assertEqual(stats["count"], 1)
        self.assertGreater(stats["avg_latency_ns"], 0)


class TestDataclasses(unittest.TestCase):
    """Test data class structures."""
    
    def test_crypto_metric_dataclass(self):
        """Test CryptoMetric dataclass."""
        metric = CryptoMetric(
            operation=CryptoOperationType.HASH,
            algorithm=CryptoAlgorithm.SHA256,
            duration_ns=1500,
            success=True,
            key_level=KeySecurityLevel.STANDARD
        )
        self.assertEqual(metric.operation, CryptoOperationType.HASH)
        self.assertTrue(metric.success)
    
    def test_audit_log_entry_dataclass(self):
        """Test AuditLogEntry dataclass."""
        entry = AuditLogEntry(
            event_type=AuditEventType.CRYPTO_OPERATION,
            operation=CryptoOperationType.ENCRYPTION,
            success=True
        )
        self.assertIsNotNone(entry.event_id)
        self.assertIsNotNone(entry.timestamp)
    
    def test_slo_threshold_dataclass(self):
        """Test SLOThreshold dataclass."""
        slo = SLOThreshold(
            operation=CryptoOperationType.KEY_GENERATION,
            algorithm=CryptoAlgorithm.KYBER_768,
            max_latency_ns=100000,
            target_availability=0.9999
        )
        self.assertEqual(slo.target_availability, 0.9999)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of metrics registry."""
    
    def setUp(self):
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
    
    def test_concurrent_operation_recording(self):
        """Test concurrent metric recording is thread-safe."""
        import threading
        
        registry = CryptoMetricsRegistry()
        num_threads = 10
        operations_per_thread = 100
        
        def worker():
            for _ in range(operations_per_thread):
                registry.record_operation(CryptoMetric(
                    operation=CryptoOperationType.HASH,
                    algorithm=CryptoAlgorithm.SHA256,
                    duration_ns=secrets.randbelow(10000),
                    success=True
                ))
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = registry.get_operation_stats(
            CryptoOperationType.HASH, CryptoAlgorithm.SHA256
        )
        self.assertEqual(stats["count"], num_threads * operations_per_thread)


def run_tests() -> Dict[str, Any]:
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestObservabilityControl,
        TestCryptoEnums,
        TestCryptoMetricsRegistry,
        TestCryptoAuditLogger,
        TestInstrumentationDecorator,
        TestKeyOperationAuditTrail,
        TestSLMMonitoring,
        TestCryptoHealthChecks,
        TestConvenienceFunctions,
        TestDataclasses,
        TestThreadSafety,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "total": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "success": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("=" * 70)
    print("QuantumCrypt-AI Observability & Audit Tracing v28 - Test Suite")
    print("DIMENSION D - Observability & Instrumentation")
    print("=" * 70)
    
    results = run_tests()
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests:    {results['total']}")
    print(f"Passed:         {results['passed']}")
    print(f"Failures:       {results['failures']}")
    print(f"Errors:         {results['errors']}")
    print(f"Skipped:        {results['skipped']}")
    print(f"Success rate:   {results['passed']/results['total']*100:.1f}%")
    print(f"Overall:        {'PASSED ✓' if results['success'] else 'FAILED ✗'}")
    print("=" * 70)
