"""
Test Suite for QuantumCrypt-AI Post-Quantum Crypto Observability & Audit Logging
June 2026 - Production Grade Tests
Covers all audit logging, key lifecycle tracking, performance monitoring,
and export functionality. All tests are ADD-ONLY.
"""
import unittest
import time
import json
import tempfile
import os
import threading
from quantum_crypt.pq_crypto_observability_audit_logging_2026_june import (
    enable_crypto_observability,
    disable_crypto_observability,
    reset_crypto_observability,
    get_crypto_audit_logs,
    get_crypto_performance_report,
    export_crypto_audit_json,
    export_crypto_audit_csv,
    CryptoObservabilityState,
    CryptoOperation,
    AlgorithmClass,
    KeyLifecycleEvent,
    AuditSeverity,
    audit_crypto_operation,
    KeyLifecycleTracker,
    AuditExporter,
    CryptoPerformanceMonitor,
)
class TestObservabilityState(unittest.TestCase):
    """Tests for the global crypto observability state."""
    
    def setUp(self):
        reset_crypto_observability()
        disable_crypto_observability()
    
    def test_disabled_by_default(self):
        """Crypto observability should be DISABLED by default."""
        self.assertFalse(CryptoObservabilityState.is_enabled())
    
    def test_enable_disable(self):
        """Can enable and disable observability correctly."""
        enable_crypto_observability()
        self.assertTrue(CryptoObservabilityState.is_enabled())
        disable_crypto_observability()
        self.assertFalse(CryptoObservabilityState.is_enabled())
    
    def test_reset_clears_state(self):
        """Reset clears all audit records and metrics."""
        enable_crypto_observability()
        
        @audit_crypto_operation(operation=CryptoOperation.ENCRYPTION, algorithm="AES-256")
        def encrypt():
            return "ciphertext"
        
        encrypt()
        self.assertGreater(len(CryptoObservabilityState.get_audit_records()), 0)
        
        reset_crypto_observability()
        self.assertEqual(len(CryptoObservabilityState.get_audit_records()), 0)
class TestAuditDecorator(unittest.TestCase):
    """Tests for the @audit_crypto_operation decorator."""
    
    def setUp(self):
        reset_crypto_observability()
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
        reset_crypto_observability()
    
    def test_decorator_creates_audit_record(self):
        """Decorator creates an audit record for crypto operations."""
        @audit_crypto_operation(
            operation=CryptoOperation.ENCRYPTION,
            algorithm="AES-256-GCM",
            algorithm_class=AlgorithmClass.CLASSIC
        )
        def encrypt_data(data):
            return f"encrypted:{data}"
        
        result = encrypt_data("secret")
        self.assertEqual(result, "encrypted:secret")
        
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].operation, "encryption")
        self.assertEqual(records[0].algorithm, "AES-256-GCM")
        self.assertEqual(records[0].algorithm_class, "classic")
        self.assertTrue(records[0].success)
    
    def test_decorator_post_quantum_algorithm(self):
        """Decorator works with post-quantum algorithm classification."""
        @audit_crypto_operation(
            operation=CryptoOperation.KEY_GENERATION,
            algorithm="CRYSTALS-Kyber-768",
            algorithm_class=AlgorithmClass.POST_QUANTUM
        )
        def generate_key():
            return "key_material"
        
        generate_key()
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(records[0].algorithm_class, "post_quantum")
    
    def test_decorator_hybrid_algorithm(self):
        """Decorator works with hybrid PQ+Classic algorithms."""
        @audit_crypto_operation(
            operation=CryptoOperation.KEY_EXCHANGE,
            algorithm="Kyber+X25519",
            algorithm_class=AlgorithmClass.HYBRID
        )
        def key_exchange():
            return "shared_secret"
        
        key_exchange()
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(records[0].algorithm_class, "hybrid")
    
    def test_decorator_captures_failures(self):
        """Decorator captures and logs operation failures."""
        @audit_crypto_operation(
            operation=CryptoOperation.DECRYPTION,
            algorithm="AES-256"
        )
        def failing_decrypt():
            raise ValueError("Invalid padding")
        
        with self.assertRaises(ValueError):
            failing_decrypt()
        
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0].success)
        self.assertEqual(records[0].severity, "error")
        self.assertIn("Invalid padding", records[0].error_message)
    
    def test_decorator_with_severity(self):
        """Decorator supports custom severity levels."""
        @audit_crypto_operation(
            operation=CryptoOperation.KEY_DESTRUCTION,
            algorithm="RSA-4096",
            severity=AuditSeverity.CRITICAL
        )
        def destroy_key():
            return True
        
        destroy_key()
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(records[0].severity, "critical")
    
    def test_decorator_with_key_id(self):
        """Decorator extracts key_id from kwargs."""
        @audit_crypto_operation(
            operation=CryptoOperation.SIGNING,
            algorithm="ECDSA-P384"
        )
        def sign_data(data, key_id=None):
            return "signature"
        
        sign_data("test", key_id="key-12345")
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(records[0].key_id, "key-12345")
class TestKeyLifecycleTracking(unittest.TestCase):
    """Tests for key lifecycle event tracking."""
    
    def setUp(self):
        reset_crypto_observability()
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
        reset_crypto_observability()
    
    def test_record_key_lifecycle_events(self):
        """Can record key lifecycle events."""
        key_id = "test-key-001"
        
        KeyLifecycleTracker.record_key_event(
            key_id, "CRYSTALS-Dilithium-5", 256, KeyLifecycleEvent.CREATED
        )
        KeyLifecycleTracker.record_key_event(
            key_id, "CRYSTALS-Dilithium-5", 256, KeyLifecycleEvent.ACTIVATED
        )
        KeyLifecycleTracker.record_key_event(
            key_id, "CRYSTALS-Dilithium-5", 256, KeyLifecycleEvent.ROTATED,
            previous_key="old-key-001"
        )
        
        status = KeyLifecycleTracker.get_key_status(key_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["key_id"], key_id)
        self.assertEqual(status["current_state"], "rotated")
        self.assertEqual(status["event_count"], 3)
    
    def test_get_all_tracked_keys(self):
        """Can get list of all tracked keys."""
        KeyLifecycleTracker.record_key_event(
            "key-a", "Kyber-512", 16, KeyLifecycleEvent.CREATED
        )
        KeyLifecycleTracker.record_key_event(
            "key-b", "Kyber-768", 24, KeyLifecycleEvent.CREATED
        )
        KeyLifecycleTracker.record_key_event(
            "key-b", "Kyber-768", 24, KeyLifecycleEvent.ACTIVATED
        )
        
        all_keys = KeyLifecycleTracker.get_all_keys()
        self.assertEqual(len(all_keys), 2)
        key_ids = [k["key_id"] for k in all_keys]
        self.assertIn("key-a", key_ids)
        self.assertIn("key-b", key_ids)
    
    def test_get_nonexistent_key(self):
        """Getting status for unknown key returns None."""
        status = KeyLifecycleTracker.get_key_status("nonexistent-key")
        self.assertIsNone(status)
class TestAuditChainIntegrity(unittest.TestCase):
    """Tests for audit chain hash integrity."""
    
    def setUp(self):
        reset_crypto_observability()
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
        reset_crypto_observability()
    
    def test_audit_chain_hashing(self):
        """Audit records are chained with previous record hashes."""
        @audit_crypto_operation(operation=CryptoOperation.HASHING, algorithm="SHA-256")
        def hash_data():
            return "hash"
        
        # Create 3 records
        hash_data()
        hash_data()
        hash_data()
        
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(len(records), 3)
        
        # Verify chain linking
        self.assertIsNone(records[0].previous_record_hash)
        self.assertEqual(records[1].previous_record_hash, records[0].record_hash)
        self.assertEqual(records[2].previous_record_hash, records[1].record_hash)
        
        # Each record has its own hash
        for record in records:
            self.assertIsNotNone(record.record_hash)
            self.assertEqual(len(record.record_hash), 64)  # SHA-256 hex
class TestDisabledMode(unittest.TestCase):
    """Tests for no-op behavior when observability is disabled."""
    
    def setUp(self):
        reset_crypto_observability()
        disable_crypto_observability()
    
    def test_disabled_creates_no_records(self):
        """When disabled, no audit records are created."""
        @audit_crypto_operation(operation=CryptoOperation.ENCRYPTION, algorithm="AES")
        def encrypt():
            return "data"
        
        for _ in range(100):
            encrypt()
        
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(len(records), 0)
    
    def test_disabled_key_tracking_noop(self):
        """Key lifecycle tracking is no-op when disabled."""
        KeyLifecycleTracker.record_key_event(
            "should-not-track", "AES", 32, KeyLifecycleEvent.CREATED
        )
        keys = KeyLifecycleTracker.get_all_keys()
        self.assertEqual(len(keys), 0)
    
    def test_disabled_performance(self):
        """Disabled mode has near-zero overhead."""
        @audit_crypto_operation(operation=CryptoOperation.HASHING, algorithm="SHA-256")
        def fast_hash():
            return True
        
        start = time.perf_counter()
        for _ in range(10000):
            fast_hash()
        duration = time.perf_counter() - start
        
        # 10k calls should be near-instant (< 50ms)
        self.assertLess(duration, 0.05)
class TestPerformanceMonitoring(unittest.TestCase):
    """Tests for crypto performance monitoring."""
    
    def setUp(self):
        reset_crypto_observability()
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
        reset_crypto_observability()
    
    def test_performance_metrics_collection(self):
        """Performance metrics are collected for each operation."""
        @audit_crypto_operation(operation=CryptoOperation.ENCRYPTION, algorithm="AES-256")
        def fast_encrypt():
            time.sleep(0.001)
            return "ok"
        
        @audit_crypto_operation(operation=CryptoOperation.KEY_GENERATION, algorithm="Kyber-768")
        def slow_keygen():
            time.sleep(0.005)
            return "key"
        
        for _ in range(5):
            fast_encrypt()
        for _ in range(3):
            slow_keygen()
        
        report = CryptoPerformanceMonitor.get_performance_report()
        self.assertEqual(report["summary"]["total_operations"], 8)
        self.assertIn("encryption:AES-256", report["operation_details"])
        self.assertIn("key_generation:Kyber-768", report["operation_details"])
    
    def test_algorithm_distribution(self):
        """Algorithm usage distribution is calculated correctly."""
        @audit_crypto_operation(operation=CryptoOperation.SIGNING, algorithm="RSA")
        def rsa_sign():
            return "sig"
        
        @audit_crypto_operation(operation=CryptoOperation.SIGNING, algorithm="Dilithium")
        def pq_sign():
            return "sig"
        
        for _ in range(7):
            rsa_sign()
        for _ in range(3):
            pq_sign()
        
        report = CryptoPerformanceMonitor.get_performance_report()
        self.assertEqual(report["summary"]["algorithms_used"], 2)
        self.assertEqual(report["algorithm_distribution"]["RSA"]["count"], 7)
        self.assertEqual(report["algorithm_distribution"]["Dilithium"]["count"], 3)
    
    def test_failure_rate_calculation(self):
        """Failure rates are calculated correctly."""
        @audit_crypto_operation(operation=CryptoOperation.DECRYPTION, algorithm="AES")
        def sometimes_fail(should_fail=False):
            if should_fail:
                raise ValueError("decrypt failed")
            return "ok"
        
        # 7 successes, 3 failures
        for _ in range(7):
            sometimes_fail(False)
        for _ in range(3):
            try:
                sometimes_fail(True)
            except ValueError:
                pass
        
        report = CryptoPerformanceMonitor.get_performance_report()
        self.assertEqual(report["summary"]["total_failures"], 3)
        self.assertEqual(report["summary"]["failure_rate"], 0.3)
    
    def test_slow_operations_detection(self):
        """Can detect operations exceeding performance thresholds."""
        @audit_crypto_operation(operation=CryptoOperation.KEY_GENERATION, algorithm="SLOW-ALGO")
        def slow_op():
            time.sleep(0.02)
            return "key"
        
        for _ in range(3):
            slow_op()
        
        slow_ops = CryptoPerformanceMonitor.get_slow_operations(threshold_ms=10.0)
        self.assertGreater(len(slow_ops), 0)
        self.assertGreater(slow_ops[0]["avg_duration_ms"], 10.0)
class TestAuditExporting(unittest.TestCase):
    """Tests for audit log export functionality."""
    
    def setUp(self):
        reset_crypto_observability()
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
        reset_crypto_observability()
    
    def test_export_to_json(self):
        """Can export audit logs to JSON format."""
        @audit_crypto_operation(operation=CryptoOperation.HASHING, algorithm="SHA-512")
        def do_hash():
            return "hash"
        
        do_hash()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            export_crypto_audit_json(filepath)
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data["record_count"], 1)
            self.assertIn("chain_integrity_hash", data)
            self.assertEqual(data["records"][0]["operation"], "hashing")
        finally:
            os.unlink(filepath)
    
    def test_export_to_csv(self):
        """Can export audit logs to CSV format."""
        @audit_crypto_operation(operation=CryptoOperation.ENCRYPTION, algorithm="AES")
        def do_encrypt():
            return "cipher"
        
        do_encrypt()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            export_crypto_audit_csv(filepath)
            
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            # Header + 1 data row
            self.assertEqual(len(lines), 2)
            self.assertIn("operation", lines[0])
            self.assertIn("encryption", lines[1])
        finally:
            os.unlink(filepath)
    
    def test_export_to_syslog_format(self):
        """Can export audit logs in syslog format."""
        @audit_crypto_operation(operation=CryptoOperation.SIGNING, algorithm="ECDSA")
        def do_sign():
            return "sig"
        
        do_sign()
        
        lines = AuditExporter.to_syslog_format()
        self.assertEqual(len(lines), 1)
        self.assertIn("CRYPTO_AUDIT", lines[0])
        self.assertIn("op=signing", lines[0])
        self.assertIn("algo=ECDSA", lines[0])
class TestPublicAPI(unittest.TestCase):
    """Tests for the public API functions."""
    
    def setUp(self):
        reset_crypto_observability()
    
    def test_public_api_functions(self):
        """All public API functions work correctly."""
        # Enable
        enable_crypto_observability()
        self.assertTrue(CryptoObservabilityState.is_enabled())
        
        # Create some audit records
        @audit_crypto_operation(operation=CryptoOperation.HASHING, algorithm="SHA-256")
        def test_fn():
            return True
        
        test_fn()
        
        # Get logs via public API
        logs = get_crypto_audit_logs()
        self.assertEqual(len(logs), 1)
        
        # Get performance report
        report = get_crypto_performance_report()
        self.assertIn("summary", report)
        
        # Reset
        reset_crypto_observability()
        self.assertEqual(len(CryptoObservabilityState.get_audit_records()), 0)
        
        # Disable
        disable_crypto_observability()
        self.assertFalse(CryptoObservabilityState.is_enabled())
class TestThreadSafety(unittest.TestCase):
    """Tests for thread-safe audit logging."""
    
    def setUp(self):
        reset_crypto_observability()
        enable_crypto_observability()
    
    def tearDown(self):
        disable_crypto_observability()
        reset_crypto_observability()
    
    def test_concurrent_audit_logging(self):
        """Audit logging works correctly across multiple threads."""
        @audit_crypto_operation(operation=CryptoOperation.HASHING, algorithm="SHA-256")
        def hash_worker(thread_id):
            time.sleep(0.001)
            return thread_id
        
        def thread_worker(tid):
            for _ in range(10):
                hash_worker(tid)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=thread_worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        records = CryptoObservabilityState.get_audit_records()
        self.assertEqual(len(records), 50)  # 5 threads × 10 calls
if __name__ == "__main__":
    unittest.main(verbosity=2)
