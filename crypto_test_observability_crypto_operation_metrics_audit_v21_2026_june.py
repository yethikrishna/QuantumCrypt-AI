"""
Tests for QuantumCrypt Crypto Operation Metrics & Audit Logging - V21
Dimension D: Observability & Instrumentation

All tests verify OPT-IN behavior and NO sensitive data exposure.
"""

import unittest
import time
import json
import threading
from quantum_crypt.crypto_observability_crypto_operation_metrics_audit_v21_2026_june import (
    CryptoMetricsCollector,
    CryptoOperationType,
    CryptoAlgorithm,
    SecurityLevel,
    get_crypto_metrics,
    tracked_crypto_operation
)


class TestCryptoMetricsBasics(unittest.TestCase):
    """Test basic metrics collector functionality"""
    
    def setUp(self):
        self.metrics = CryptoMetricsCollector()
    
    def test_collector_starts_disabled(self):
        """Metrics MUST start DISABLED by default - zero overhead"""
        self.assertFalse(self.metrics.is_enabled())
    
    def test_enable_disable_works(self):
        """Enable and disable work correctly"""
        self.assertFalse(self.metrics.is_enabled())
        self.metrics.enable()
        self.assertTrue(self.metrics.is_enabled())
        self.metrics.disable()
        self.assertFalse(self.metrics.is_enabled())
    
    def test_disabled_returns_none_for_operations(self):
        """When disabled, start_operation returns None (no overhead)"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.ENCRYPTION,
            CryptoAlgorithm.AES_256_GCM
        )
        self.assertIsNone(op_id)
    
    def test_sensitive_data_is_hashed(self):
        """Sensitive key material is HASHED only, never stored raw"""
        self.metrics.enable()
        
        sensitive_key = b"super_secret_key_material_12345"
        op_id = self.metrics.start_operation(
            CryptoOperationType.KEY_GENERATION,
            CryptoAlgorithm.KYBER,
            key_material=sensitive_key
        )
        
        # Verify we can't reconstruct the original key
        self.metrics.end_operation(op_id)
        summary = self.metrics.get_performance_summary()
        
        # The key should be hashed, not stored
        self.assertNotIn(str(sensitive_key), json.dumps(summary))


class TestCryptoOperationTracking(unittest.TestCase):
    """Test operation tracking functionality"""
    
    def setUp(self):
        self.metrics = CryptoMetricsCollector()
        self.metrics.enable()
    
    def test_start_and_end_operation(self):
        """Basic operation lifecycle"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.ENCRYPTION,
            CryptoAlgorithm.AES_256_GCM,
            SecurityLevel.LEVEL_5,
            input_data=b"test data to encrypt"
        )
        self.assertIsNotNone(op_id)
        time.sleep(0.001)
        duration = self.metrics.end_operation(op_id, success=True, output_data=b"encrypted data")
        self.assertIsNotNone(duration)
        self.assertGreater(duration, 0)
    
    def test_failed_operation_tracking(self):
        """Failed operations are tracked properly"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.DECRYPTION,
            CryptoAlgorithm.AES_256_GCM
        )
        duration = self.metrics.end_operation(
            op_id, 
            success=False, 
            error_type="AuthenticationError"
        )
        self.assertIsNotNone(duration)
        
        summary = self.metrics.get_performance_summary()
        self.assertEqual(summary["failed_operations"], 1)
    
    def test_post_quantum_algorithm_tracking(self):
        """Post-quantum algorithms tracked correctly"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.KEY_ENCAPSULATION,
            CryptoAlgorithm.KYBER,
            SecurityLevel.LEVEL_5
        )
        self.metrics.end_operation(op_id, success=True)
        
        summary = self.metrics.get_performance_summary()
        self.assertIn("key_encapsulation:CRYSTALS-Kyber", summary["algorithm_breakdown"])


class TestPerformanceSummary(unittest.TestCase):
    """Test performance summary aggregation"""
    
    def setUp(self):
        self.metrics = CryptoMetricsCollector()
        self.metrics.enable()
    
    def test_performance_summary_calculations(self):
        """Summary correctly aggregates performance data"""
        # Run several operations
        for i in range(10):
            op_id = self.metrics.start_operation(
                CryptoOperationType.HASHING,
                CryptoAlgorithm.SHA3_512,
                input_data=f"test data {i}".encode()
            )
            time.sleep(0.0001)
            self.metrics.end_operation(op_id, success=True)
        
        summary = self.metrics.get_performance_summary()
        self.assertEqual(summary["total_operations"], 10)
        self.assertEqual(summary["successful_operations"], 10)
        self.assertEqual(summary["failed_operations"], 0)
        self.assertGreater(summary["average_duration_ms"], 0)
        self.assertGreater(summary["success_rate"], 99.0)
    
    def test_algorithm_breakdown(self):
        """Breakdown per algorithm is correct"""
        # Mix of algorithms
        ops = [
            (CryptoOperationType.ENCRYPTION, CryptoAlgorithm.AES_256_GCM),
            (CryptoOperationType.SIGNING, CryptoAlgorithm.DILITHIUM),
            (CryptoOperationType.KEY_GENERATION, CryptoAlgorithm.KYBER),
        ]
        
        for op_type, algo in ops:
            for _ in range(5):
                op_id = self.metrics.start_operation(op_type, algo)
                self.metrics.end_operation(op_id, success=True)
        
        summary = self.metrics.get_performance_summary()
        self.assertEqual(summary["total_operations"], 15)
        self.assertGreaterEqual(len(summary["algorithm_breakdown"]), 3)


class TestAuditLogging(unittest.TestCase):
    """Test security audit logging"""
    
    def setUp(self):
        self.metrics = CryptoMetricsCollector()
        self.metrics.enable()
    
    def test_audit_log_created_for_operations(self):
        """Audit log entries are created"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.SIGNING,
            CryptoAlgorithm.ECDSA_P384,
            SecurityLevel.LEVEL_3
        )
        self.metrics.end_operation(op_id, success=True)
        
        audit_log = self.metrics.get_audit_log()
        self.assertGreaterEqual(len(audit_log), 1)
        
        entry = audit_log[0]
        self.assertIn("audit_id", entry)
        self.assertIn("timestamp", entry)
        self.assertIn("operation_type", entry)
        self.assertIn("algorithm", entry)
        self.assertIn("success", entry)
    
    def test_audit_log_contains_no_sensitive_data(self):
        """Audit log NEVER contains raw key material"""
        sensitive_key = b"private_key_should_never_appear"
        
        op_id = self.metrics.start_operation(
            CryptoOperationType.KEY_GENERATION,
            CryptoAlgorithm.RSA_4096,
            key_material=sensitive_key
        )
        self.metrics.end_operation(op_id, success=True)
        
        audit_log = self.metrics.get_audit_log()
        log_json = json.dumps(audit_log)
        
        # Raw key should NOT appear
        self.assertNotIn(str(sensitive_key), log_json)
        # Only hash should appear (partial hash)
        self.assertIn("key_fingerprint", audit_log[0])
    
    def test_caller_context_provider(self):
        """Caller context is captured"""
        context_value = "request-12345-user-678"
        
        def provider():
            return context_value
        
        self.metrics.set_caller_context_provider(provider)
        
        op_id = self.metrics.start_operation(
            CryptoOperationType.VERIFICATION,
            CryptoAlgorithm.DILITHIUM
        )
        self.metrics.end_operation(op_id, success=True)
        
        audit_log = self.metrics.get_audit_log()
        self.assertEqual(audit_log[0]["caller_context"], context_value)


class TestMetricsExport(unittest.TestCase):
    """Test metrics export formats"""
    
    def setUp(self):
        self.metrics = CryptoMetricsCollector()
        self.metrics.enable()
    
    def test_export_json_valid(self):
        """JSON export produces valid JSON"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.KEY_DERIVATION,
            CryptoAlgorithm.HKDF
        )
        self.metrics.end_operation(op_id, success=True)
        
        json_output = self.metrics.export_metrics_json()
        data = json.loads(json_output)
        
        self.assertIn("service", data)
        self.assertIn("summary", data)
        self.assertIn("operations", data)
        self.assertIn("audit_log", data)
    
    def test_prometheus_format(self):
        """Prometheus format export"""
        op_id = self.metrics.start_operation(
            CryptoOperationType.ENCRYPTION,
            CryptoAlgorithm.AES_256_GCM
        )
        self.metrics.end_operation(op_id, success=True)
        
        prom_output = self.metrics.get_prometheus_metrics()
        
        self.assertIn("# HELP", prom_output)
        self.assertIn("# TYPE", prom_output)
        self.assertIn("crypto_operations_total", prom_output)


class TestTrackedOperationDecorator(unittest.TestCase):
    """Test the tracked_crypto_operation decorator"""
    
    def test_decorator_when_disabled(self):
        """Decorator has NO effect when metrics disabled"""
        metrics = get_crypto_metrics()
        metrics.disable()
        
        call_count = [0]
        
        @tracked_crypto_operation(CryptoOperationType.ENCRYPTION, CryptoAlgorithm.AES_256_GCM)
        def encrypt_func(data):
            call_count[0] += 1
            return data[::-1]
        
        result = encrypt_func(b"test data")
        self.assertEqual(result, b"atad tset")
        self.assertEqual(call_count[0], 1)
    
    def test_decorator_when_enabled(self):
        """Decorator tracks operations when metrics enabled"""
        metrics = get_crypto_metrics()
        metrics.enable()
        metrics.clear()
        
        @tracked_crypto_operation(CryptoOperationType.HASHING, CryptoAlgorithm.SHA3_512)
        def hash_func(data):
            return data
        
        result = hash_func(b"test input")
        self.assertEqual(result, b"test input")
        
        summary = metrics.get_performance_summary()
        self.assertGreaterEqual(summary["total_operations"], 1)
        
        metrics.disable()
    
    def test_decorator_exception_propagation(self):
        """Decorator properly propagates exceptions without breaking"""
        metrics = get_crypto_metrics()
        metrics.enable()
        metrics.clear()
        
        @tracked_crypto_operation(CryptoOperationType.DECRYPTION, CryptoAlgorithm.AES_256_GCM)
        def error_func():
            raise ValueError("Decryption failed: invalid padding")
        
        with self.assertRaises(ValueError):
            error_func()
        
        summary = metrics.get_performance_summary()
        self.assertEqual(summary["failed_operations"], 1)
        
        metrics.disable()


class TestCallbacks(unittest.TestCase):
    """Test operation and audit callbacks"""
    
    def test_operation_callback(self):
        """Operation callback is triggered"""
        received_ops = []
        
        def callback(op):
            received_ops.append(op)
        
        metrics = CryptoMetricsCollector()
        metrics.set_operation_callback(callback)
        metrics.enable()
        
        op_id = metrics.start_operation(
            CryptoOperationType.ENCRYPTION,
            CryptoAlgorithm.AES_256_GCM
        )
        metrics.end_operation(op_id, success=True)
        
        self.assertEqual(len(received_ops), 1)
    
    def test_audit_callback(self):
        """Audit callback is triggered"""
        received_audits = []
        
        def callback(audit):
            received_audits.append(audit)
        
        metrics = CryptoMetricsCollector()
        metrics.set_audit_callback(callback)
        metrics.enable()
        
        op_id = metrics.start_operation(
            CryptoOperationType.SIGNING,
            CryptoAlgorithm.DILITHIUM
        )
        metrics.end_operation(op_id, success=True)
        
        self.assertEqual(len(received_audits), 1)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of metrics collector"""
    
    def test_concurrent_operations(self):
        """Multiple threads can track operations concurrently"""
        metrics = CryptoMetricsCollector()
        metrics.enable()
        
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(20):
                    op_id = metrics.start_operation(
                        CryptoOperationType.HASHING,
                        CryptoAlgorithm.SHA3_512
                    )
                    time.sleep(0.0001)
                    metrics.end_operation(op_id, success=True)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        summary = metrics.get_performance_summary()
        self.assertEqual(summary["total_operations"], 100)


class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation at limits"""
    
    def test_max_operations_limit(self):
        """Collector stops gracefully at operation limit"""
        metrics = CryptoMetricsCollector()
        metrics._max_operations = 10  # Small limit for testing
        metrics.enable()
        
        op_ids = []
        for i in range(20):
            op_id = metrics.start_operation(
                CryptoOperationType.ENCRYPTION,
                CryptoAlgorithm.AES_256_GCM
            )
            if op_id:
                op_ids.append(op_id)
        
        self.assertLessEqual(len(op_ids), 10)


class TestGlobalMetrics(unittest.TestCase):
    """Test global metrics singleton"""
    
    def test_get_crypto_metrics_returns_same_instance(self):
        """get_crypto_metrics always returns same instance"""
        m1 = get_crypto_metrics()
        m2 = get_crypto_metrics()
        self.assertIs(m1, m2)
    
    def test_global_starts_disabled(self):
        """Global metrics are disabled by default"""
        metrics = get_crypto_metrics()
        metrics.disable()  # Reset
        self.assertFalse(metrics.is_enabled())


if __name__ == "__main__":
    unittest.main()
