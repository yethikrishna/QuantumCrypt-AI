"""
Test Suite for QuantumCrypt Error Resilience - Bulkhead Isolation v26
Dimension E: Error Resilience - ADD-ONLY implementation

Tests verify:
1. Crypto bulkhead compartment basic functionality
2. Isolation between crypto operation categories
3. Circuit breaker / trip functionality
4. Secure fallback mechanisms
5. Security-focused metrics collection
6. Thread safety for concurrent operations

All tests are ADD-ONLY - no modification to existing tests
"""

import unittest
import time
import threading
import sys
import os
import hashlib

# Add source directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_error_resilience_bulkhead_isolation_pq_operations_v26_2026_june import (
    CryptoBulkheadCompartment,
    CryptoBulkheadConfig,
    CryptoBulkheadState,
    CryptoBulkheadTrippedError,
    CryptoOperationBulkheadManager,
    get_crypto_bulkhead_manager,
    bulkheaded_crypto,
    secure_null_fallback,
    secure_deny_fallback,
    secure_empty_result_fallback
)


class TestCryptoBulkheadConfig(unittest.TestCase):
    """Test crypto bulkhead configuration"""

    def test_default_config(self):
        """Test default crypto-specific configuration values"""
        config = CryptoBulkheadConfig()
        self.assertEqual(config.max_concurrent_operations, 4)  # Lower for crypto
        self.assertEqual(config.max_queue_size, 32)
        self.assertEqual(config.operation_timeout_seconds, 120.0)  # Longer for crypto
        self.assertEqual(config.failure_threshold, 3)

    def test_category_specific_configs(self):
        """Test predefined category configs are properly tuned"""
        categories = CryptoOperationBulkheadManager.CRYPTO_CATEGORIES
        
        # Key generation should have low concurrency (CPU heavy)
        self.assertLessEqual(
            categories["key_generation"].max_concurrent_operations, 2
        )
        self.assertGreaterEqual(
            categories["key_generation"].operation_timeout_seconds, 120
        )
        
        # Hash operations should have high concurrency (fast)
        self.assertGreaterEqual(
            categories["hash_operation"].max_concurrent_operations, 8
        )


class TestCryptoBulkheadCompartment(unittest.TestCase):
    """Test crypto bulkhead compartment functionality"""

    def setUp(self):
        self.bulkhead = CryptoBulkheadCompartment(
            name="test_crypto",
            config=CryptoBulkheadConfig(max_concurrent_operations=2)
        )

    def tearDown(self):
        self.bulkhead.shutdown()

    def test_successful_crypto_operation(self):
        """Test successful crypto operation execution"""
        def hash_operation(data):
            return hashlib.sha256(data.encode()).hexdigest()

        result = self.bulkhead.execute(hash_operation, "test data")
        self.assertEqual(len(result), 64)  # SHA256 hex length

    def test_metrics_on_success(self):
        """Test metrics update on successful crypto operation"""
        def simple_op(x):
            return x

        self.bulkhead.execute(simple_op, "test")
        metrics = self.bulkhead.get_metrics()
        
        self.assertEqual(metrics["completed_operations"], 1)
        self.assertEqual(metrics["failed_operations"], 0)
        self.assertEqual(metrics["state"], "healthy")
        self.assertIn("total_operations_processed", metrics)

    def test_exception_propagation(self):
        """Test that exceptions propagate correctly"""
        def failing_op(x):
            raise ValueError("Crypto operation failed")

        with self.assertRaises(ValueError):
            self.bulkhead.execute(failing_op, None)

    def test_metrics_on_failure(self):
        """Test metrics update on crypto operation failure"""
        def failing_op(x):
            raise ValueError("Crypto operation failed")

        try:
            self.bulkhead.execute(failing_op, None)
        except ValueError:
            pass

        metrics = self.bulkhead.get_metrics()
        self.assertEqual(metrics["failed_operations"], 1)

    def test_fallback_on_failure(self):
        """Test fallback function on crypto operation failure"""
        def failing_op(x):
            raise ValueError("Crypto operation failed")

        def fallback(e):
            return {"success": False, "fallback_used": True, "error": str(e)}

        result = self.bulkhead.execute(failing_op, None, fallback)
        self.assertTrue(result["fallback_used"])
        self.assertFalse(result["success"])

    def test_operation_id_tracking(self):
        """Test operation ID tracking for auditing"""
        def simple_op(x):
            return x

        # With explicit operation ID
        result = self.bulkhead.execute(
            simple_op, "test", operation_id="test-op-001"
        )
        self.assertEqual(result, "test")

        # Without operation ID (auto-generated)
        result = self.bulkhead.execute(simple_op, "test2")
        self.assertEqual(result, "test2")

    def test_reset(self):
        """Test bulkhead reset functionality"""
        def failing_op(x):
            raise ValueError("Failure")

        for _ in range(2):
            try:
                self.bulkhead.execute(failing_op, None)
            except ValueError:
                pass

        metrics_before = self.bulkhead.get_metrics()
        self.assertGreater(metrics_before["failed_operations"], 0)
        
        self.bulkhead.reset()
        
        metrics_after = self.bulkhead.get_metrics()
        self.assertEqual(metrics_after["failed_operations"], 0)
        self.assertEqual(metrics_after["state"], "healthy")


class TestCryptoBulkheadCircuitBreaker(unittest.TestCase):
    """Test crypto bulkhead circuit breaker functionality"""

    def test_circuit_breaker_trip(self):
        """Test that circuit breaker trips after threshold failures"""
        config = CryptoBulkheadConfig(
            max_concurrent_operations=2,
            failure_threshold=2,
            failure_window_seconds=60.0,
            recovery_timeout_seconds=1.0
        )
        bulkhead = CryptoBulkheadCompartment(name="circuit_test", config=config)

        def failing_op(x):
            raise ValueError("Controlled crypto failure")

        # Trigger failures to trip
        for _ in range(2):
            try:
                bulkhead.execute(failing_op, None)
            except ValueError:
                pass

        # Now circuit should be tripped
        with self.assertRaises(CryptoBulkheadTrippedError):
            bulkhead.execute(failing_op, None)

        metrics = bulkhead.get_metrics()
        self.assertEqual(metrics["state"], "tripped")
        self.assertTrue(metrics["tripped"])
        
        bulkhead.shutdown()

    def test_fallback_when_tripped(self):
        """Test fallback works when circuit is tripped"""
        config = CryptoBulkheadConfig(
            max_concurrent_operations=2,
            failure_threshold=2,
            recovery_timeout_seconds=1.0
        )
        bulkhead = CryptoBulkheadCompartment(name="fallback_test", config=config)

        def failing_op(x):
            raise ValueError("Failure")

        def fallback(e):
            return {"success": False, "fallback_used": True, "protected": True}

        # Trigger trip
        for _ in range(2):
            try:
                bulkhead.execute(failing_op, None)
            except ValueError:
                pass

        # Should use fallback now
        result = bulkhead.execute(failing_op, None, fallback)
        self.assertTrue(result["fallback_used"])
        self.assertTrue(result["protected"])
        
        bulkhead.shutdown()

    def test_circuit_recovery(self):
        """Test circuit recovers after timeout"""
        config = CryptoBulkheadConfig(
            max_concurrent_operations=2,
            failure_threshold=2,
            recovery_timeout_seconds=0.2
        )
        bulkhead = CryptoBulkheadCompartment(name="recovery_test", config=config)

        def failing_op(x):
            raise ValueError("Failure")

        # Trigger trip
        for _ in range(2):
            try:
                bulkhead.execute(failing_op, None)
            except ValueError:
                pass

        # Verify tripped
        metrics = bulkhead.get_metrics()
        self.assertEqual(metrics["state"], "tripped")

        # Wait for recovery
        time.sleep(0.3)

        # Should be recovered now
        metrics = bulkhead.get_metrics()
        self.assertEqual(metrics["state"], "healthy")
        
        bulkhead.shutdown()


class TestCryptoBulkheadIsolation(unittest.TestCase):
    """Test that crypto bulkheads are properly isolated"""

    def test_category_isolation(self):
        """Test failures in one crypto category don't affect others"""
        bulkhead_sign = CryptoBulkheadCompartment(
            name="signature",
            config=CryptoBulkheadConfig(failure_threshold=2, recovery_timeout_seconds=10)
        )
        bulkhead_verify = CryptoBulkheadCompartment(
            name="verification",
            config=CryptoBulkheadConfig(failure_threshold=10)
        )

        def failing_op(x):
            raise ValueError("Signature failure")

        def success_op(x):
            return hashlib.sha256(x.encode()).hexdigest()

        # Trip signature bulkhead
        for _ in range(2):
            try:
                bulkhead_sign.execute(failing_op, None)
            except ValueError:
                pass

        # Signature should be tripped
        self.assertEqual(bulkhead_sign.get_metrics()["state"], "tripped")
        
        # Verification should still be healthy and working
        self.assertEqual(bulkhead_verify.get_metrics()["state"], "healthy")
        result = bulkhead_verify.execute(success_op, "test")
        self.assertEqual(len(result), 64)

        bulkhead_sign.shutdown()
        bulkhead_verify.shutdown()


class TestCryptoOperationBulkheadManager(unittest.TestCase):
    """Test the crypto bulkhead manager"""

    def setUp(self):
        self.manager = CryptoOperationBulkheadManager()

    def tearDown(self):
        self.manager.shutdown_all()

    def test_different_categories_isolated(self):
        """Test different crypto categories get proper isolation"""
        def hash_op(data):
            return hashlib.sha256(data.encode()).hexdigest()

        result1 = self.manager.execute_operation(
            "hash_operation", hash_op, "test1"
        )
        result2 = self.manager.execute_operation(
            "digital_signature", hash_op, "test2"
        )

        self.assertEqual(len(result1), 64)
        self.assertEqual(len(result2), 64)

        metrics = self.manager.get_all_metrics()
        self.assertIn("hash_operation", metrics)
        self.assertIn("digital_signature", metrics)

    def test_security_health_report(self):
        """Test security health report generation"""
        def hash_op(data):
            return hashlib.sha256(data.encode()).hexdigest()

        self.manager.execute_operation("hash_operation", hash_op, "test")
        
        health = self.manager.get_security_health()
        self.assertIn("security_status", health)
        self.assertIn("failure_rate", health)
        self.assertIn("total_operations", health)
        self.assertIn("total_failures", health)
        self.assertIn("total_bulkheads", health)

    def test_unknown_category_uses_default(self):
        """Test unknown categories use default config"""
        def simple_op(x):
            return x

        result = self.manager.execute_operation(
            "unknown_crypto_op_123", simple_op, "test"
        )
        self.assertEqual(result, "test")

        metrics = self.manager.get_all_metrics()
        self.assertIn("unknown_crypto_op_123", metrics)


class TestCryptoBulkheadDecorator(unittest.TestCase):
    """Test the crypto bulkhead decorator"""

    @classmethod
    def setUpClass(cls):
        # Clear any existing manager
        mgr = get_crypto_bulkhead_manager()
        mgr.shutdown_all()

    def test_decorator_basic(self):
        """Test basic decorator functionality"""
        @bulkheaded_crypto("hash_operation")
        def my_hash(data):
            return hashlib.sha256(data.encode()).hexdigest()

        result = my_hash("test_input")
        self.assertEqual(len(result), 64)

    def test_decorator_with_fallback(self):
        """Test decorator with fallback function"""
        def my_fallback(e):
            return {"fallback": True, "error": str(e)}

        @bulkheaded_crypto("key_generation", fallback=my_fallback)
        def failing_op(data):
            raise ValueError("Key generation failed")

        result = failing_op("test")
        self.assertTrue(result["fallback"])


class TestSecureFallbackFunctions(unittest.TestCase):
    """Test secure fallback functions for crypto"""

    def test_secure_null_fallback(self):
        """Test secure null fallback returns random bytes"""
        error = ValueError("Test error")
        result = secure_null_fallback(error)
        
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)  # 256 bits of randomness

    def test_secure_deny_fallback(self):
        """Test secure deny fallback"""
        error = ValueError("Test error")
        result = secure_deny_fallback(error)
        
        self.assertFalse(result["success"])
        self.assertTrue(result["bulkhead_protection"])
        self.assertTrue(result["retry_allowed"])
        self.assertIn("retry_after_seconds", result)

    def test_secure_empty_result_fallback(self):
        """Test secure empty result fallback"""
        error = ValueError("Test error")
        result = secure_empty_result_fallback(error)
        
        self.assertFalse(result["success"])
        self.assertIsNone(result["result"])
        self.assertTrue(result["bulkhead_protection"])


class TestConcurrentCryptoOperations(unittest.TestCase):
    """Test thread safety of concurrent crypto operations"""

    def test_concurrent_hash_operations(self):
        """Test multiple concurrent hash operations work safely"""
        bulkhead = CryptoBulkheadCompartment(
            name="concurrent_hash",
            config=CryptoBulkheadConfig(max_concurrent_operations=4)
        )

        def hash_worker(i):
            data = f"test_data_{i}"
            return hashlib.sha256(data.encode()).hexdigest()

        results = []
        threads = []
        
        for i in range(20):
            t = threading.Thread(
                target=lambda: results.append(bulkhead.execute(hash_worker, i))
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(results), 20)
        # All results should be valid SHA256 hashes
        for r in results:
            self.assertEqual(len(r), 64)
        
        bulkhead.shutdown()


class TestGlobalSingleton(unittest.TestCase):
    """Test global singleton manager"""

    def test_get_manager_singleton(self):
        """Test manager is a proper singleton"""
        mgr1 = get_crypto_bulkhead_manager()
        mgr2 = get_crypto_bulkhead_manager()
        
        self.assertIs(mgr1, mgr2)
        
        mgr1.shutdown_all()


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
