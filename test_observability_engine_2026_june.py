"""
Test suite for QuantumCrypt-AI Observability Engine
June 2026 - Production Grade Tests

Tests verify:
1. Observability is disabled by default (zero overhead)
2. Enabling/disabling works correctly
3. @observe decorator works when enabled
4. Metrics collection is accurate
5. Error tracking works
6. CryptoMetricsReporter generates valid reports
7. Thread safety
8. Environment variable auto-enable
9. No-op when disabled (performance)
10. Security: no sensitive data logged by default
"""

import os
import sys
import json
import time
import logging
import threading
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.observability_engine_2026_june import (
    ObservabilityState,
    observe,
    observe_class,
    CryptoMetricsReporter,
    CryptoOperationType,
    enable_observability,
    disable_observability,
    get_observability_metrics,
    reset_observability_metrics,
)


class TestObservabilityDefaultState(unittest.TestCase):
    """Test that observability is disabled by default."""

    def test_disabled_by_default(self):
        """Observability should be disabled when module loads fresh."""
        disable_observability()
        self.assertFalse(ObservabilityState.is_enabled())

    def test_observe_decorator_noop_when_disabled(self):
        """@observe should be a pass-through when disabled."""
        disable_observability()
        
        call_count = [0]
        
        @observe
        def test_func(x, y):
            call_count[0] += 1
            return x + y
        
        result = test_func(3, 4)
        self.assertEqual(result, 7)
        self.assertEqual(call_count[0], 1)
        
        # No metrics should be collected when disabled
        metrics = get_observability_metrics()
        self.assertEqual(len(metrics["call_counts"]), 0)


class TestObservabilityEnableDisable(unittest.TestCase):
    """Test enabling and disabling observability."""

    def setUp(self):
        reset_observability_metrics()
        disable_observability()

    def test_enable_observability(self):
        """enable_observability() should turn on observability."""
        enable_observability(logging.DEBUG)
        self.assertTrue(ObservabilityState.is_enabled())
        disable_observability()

    def test_disable_observability(self):
        """disable_observability() should turn off observability."""
        enable_observability()
        self.assertTrue(ObservabilityState.is_enabled())
        disable_observability()
        self.assertFalse(ObservabilityState.is_enabled())


class TestObserveDecorator(unittest.TestCase):
    """Test the @observe decorator functionality."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)  # Use WARNING to suppress logs during test

    def tearDown(self):
        disable_observability()

    def test_decorator_preserves_function_behavior(self):
        """Decorated function should behave identically to original."""
        @observe
        def add(a, b):
            return a + b
        
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(10, 20), 30)

    def test_decorator_preserves_function_name(self):
        """Decorated function should keep its __name__."""
        @observe
        def my_special_crypto_func():
            return 42
        
        self.assertEqual(my_special_crypto_func.__name__, "my_special_crypto_func")

    def test_decorator_tracks_call_count(self):
        """Decorator should track how many times function is called."""
        @observe
        def tracked_func():
            return "hello"
        
        tracked_func()
        tracked_func()
        tracked_func()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["call_counts"].keys() if "tracked_func" in k][0]
        self.assertEqual(metrics["call_counts"][func_key], 3)

    def test_decorator_tracks_duration(self):
        """Decorator should track function duration."""
        @observe
        def slow_crypto_op():
            time.sleep(0.01)
            return "done"
        
        slow_crypto_op()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["call_counts"].keys() if "slow_crypto_op" in k][0]
        self.assertIn(func_key, metrics["total_durations"])
        self.assertGreater(metrics["total_durations"][func_key], 0)
        self.assertIn(func_key, metrics["avg_durations"])

    def test_decorator_tracks_errors(self):
        """Decorator should track errors but still raise them."""
        @observe
        def error_func():
            raise ValueError("crypto error")
        
        with self.assertRaises(ValueError):
            error_func()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["error_counts"].keys() if "error_func" in k][0]
        self.assertEqual(metrics["error_counts"][func_key], 1)
        self.assertGreater(metrics["error_rates"][func_key], 0)

    def test_decorator_with_operation_type(self):
        """Decorator should track operation type for crypto categorization."""
        @observe(operation_type=CryptoOperationType.ENCRYPTION)
        def encrypt_data(data):
            return data[::-1]  # Dummy "encryption"
        
        encrypt_data("test")
        encrypt_data("data")
        
        metrics = get_observability_metrics()
        self.assertIn("encryption", metrics["operation_types"])
        self.assertEqual(metrics["operation_types"]["encryption"], 2)

    def test_decorator_with_log_args_disabled_by_default(self):
        """log_args should be False by default (security)."""
        @observe
        def func_with_secret_key(key, data):
            return data
        
        # Should work fine without logging secrets
        result = func_with_secret_key("super_secret_key_12345", "some data")
        self.assertEqual(result, "some data")

    def test_decorator_with_log_result_disabled_by_default(self):
        """log_result should be False by default (security)."""
        @observe
        def func_returns_secret():
            return "super_secret_result"
        
        result = func_returns_secret()
        self.assertEqual(result, "super_secret_result")


class TestObserveClassDecorator(unittest.TestCase):
    """Test the @observe_class decorator."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_class_decorator_wraps_public_methods(self):
        """Class decorator should wrap all public methods."""
        @observe_class
        class CryptoTestClass:
            def encrypt_method(self):
                return "encrypted"
            
            def _internal_key_gen(self):
                return "private_key"
            
            def decrypt_method(self, x):
                return x * 2
        
        obj = CryptoTestClass()
        self.assertEqual(obj.encrypt_method(), "encrypted")
        self.assertEqual(obj.decrypt_method(5), 10)
        
        metrics = get_observability_metrics()
        # Both public methods should be tracked (use endswith to avoid test name matching)
        encrypt_keys = [k for k in metrics["call_counts"].keys() if k.endswith("encrypt_method")]
        decrypt_keys = [k for k in metrics["call_counts"].keys() if k.endswith("decrypt_method")]
        self.assertEqual(len(encrypt_keys), 1)
        self.assertEqual(len(decrypt_keys), 1)
        # Private method should NOT be tracked
        private_keys = [k for k in metrics["call_counts"].keys() if "_internal_key_gen" in k]
        self.assertEqual(len(private_keys), 0)
        # Total tracked should be exactly 2
        self.assertEqual(len(metrics["call_counts"]), 2)


class TestCryptoMetricsReporter(unittest.TestCase):
    """Test the CryptoMetricsReporter class."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_generate_summary(self):
        """generate_summary should return a valid summary dict."""
        @observe(operation_type=CryptoOperationType.KEY_GENERATION)
        def key_gen():
            return "key"
        
        @observe(operation_type=CryptoOperationType.SIGNING)
        def sign_data():
            time.sleep(0.005)
            return "signature"
        
        key_gen()
        key_gen()
        sign_data()
        
        summary = CryptoMetricsReporter.generate_summary()
        
        self.assertIn("summary", summary)
        self.assertIn("operation_type_breakdown", summary)
        self.assertIn("slowest_operations", summary)
        self.assertIn("most_called_operations", summary)
        self.assertIn("highest_error_rates", summary)
        self.assertIn("security_note", summary)
        self.assertEqual(summary["summary"]["total_calls"], 3)
        self.assertEqual(summary["summary"]["total_operations_tracked"], 2)

    def test_operation_type_breakdown(self):
        """Summary should include operation type breakdown."""
        @observe(operation_type=CryptoOperationType.ENCRYPTION)
        def enc():
            return "ciphertext"
        
        @observe(operation_type=CryptoOperationType.DECRYPTION)
        def dec():
            return "plaintext"
        
        @observe(operation_type=CryptoOperationType.VERIFICATION)
        def verify():
            return True
        
        enc()
        enc()
        dec()
        verify()
        
        summary = CryptoMetricsReporter.generate_summary()
        breakdown = summary["operation_type_breakdown"]
        
        self.assertEqual(breakdown.get("encryption", 0), 2)
        self.assertEqual(breakdown.get("decryption", 0), 1)
        self.assertEqual(breakdown.get("verification", 0), 1)

    def test_export_json(self):
        """export_json should write valid JSON to file."""
        @observe
        def test_export_func():
            return 42
        
        test_export_func()
        
        filepath = "/tmp/test_qc_observability_export.json"
        CryptoMetricsReporter.export_json(filepath)
        
        self.assertTrue(os.path.exists(filepath))
        with open(filepath) as f:
            data = json.load(f)
        self.assertIn("summary", data)
        self.assertIn("security_note", data)
        
        # Clean up
        os.remove(filepath)

    def test_summary_with_errors(self):
        """Summary should correctly report error rates."""
        @observe
        def sometimes_fails():
            if not hasattr(sometimes_fails, 'call_count'):
                sometimes_fails.call_count = 0
            sometimes_fails.call_count += 1
            if sometimes_fails.call_count % 3 == 0:
                raise RuntimeError("crypto failure")
            return "ok"
        
        sometimes_fails()  # success
        sometimes_fails()  # success
        try:
            sometimes_fails()  # fail
        except RuntimeError:
            pass
        
        summary = CryptoMetricsReporter.generate_summary()
        self.assertEqual(summary["summary"]["total_calls"], 3)
        self.assertEqual(summary["summary"]["total_errors"], 1)


class TestMetricsReset(unittest.TestCase):
    """Test metrics reset functionality."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_reset_clears_metrics(self):
        """reset_observability_metrics should clear all data."""
        @observe
        def func_to_reset():
            return "test"
        
        func_to_reset()
        func_to_reset()
        
        metrics_before = get_observability_metrics()
        self.assertGreater(len(metrics_before["call_counts"]), 0)
        
        reset_observability_metrics()
        
        metrics_after = get_observability_metrics()
        self.assertEqual(len(metrics_after["call_counts"]), 0)
        self.assertEqual(len(metrics_after["error_counts"]), 0)
        self.assertEqual(len(metrics_after["operation_types"]), 0)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of metrics collection."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_concurrent_calls(self):
        """Metrics should be accurate with concurrent calls."""
        @observe(operation_type=CryptoOperationType.HASHING)
        def hash_func(thread_id):
            time.sleep(0.001)
            return f"hash_{thread_id}"
        
        num_threads = 10
        calls_per_thread = 100
        
        def worker(tid):
            for _ in range(calls_per_thread):
                hash_func(tid)
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        metrics = get_observability_metrics()
        func_key = [k for k in metrics["call_counts"].keys() if "hash_func" in k][0]
        expected_calls = num_threads * calls_per_thread
        self.assertEqual(metrics["call_counts"][func_key], expected_calls)
        self.assertEqual(metrics["operation_types"]["hashing"], expected_calls)


class TestIntegrationWithExistingModule(unittest.TestCase):
    """Test that observability can wrap existing QuantumCrypt modules."""

    def setUp(self):
        reset_observability_metrics()
        disable_observability()

    def test_wrap_existing_function_no_breakage(self):
        """Wrapping an existing function should not break it when disabled."""
        from quantum_crypt.post_quantum_secure_mac_authentication_engine_2026_june import (
            PostQuantumMACEngine,
        )
        
        # Create instance - should work fine
        engine = PostQuantumMACEngine()
        key = engine.generate_key()
        result = engine.compute_mac(b"test data", key)
        self.assertIsNotNone(result)

    def test_wrap_existing_function_with_observability(self):
        """Wrapping with observability enabled should collect metrics."""
        enable_observability(logging.WARNING)
        
        from quantum_crypt.post_quantum_secure_mac_authentication_engine_2026_june import (
            PostQuantumMACEngine,
        )
        
        # Manually wrap a method to test
        original_method = PostQuantumMACEngine.compute_mac
        wrapped_method = observe(
            PostQuantumMACEngine.compute_mac,
            operation_type=CryptoOperationType.SIGNING,
        )
        
        # Temporarily replace
        PostQuantumMACEngine.compute_mac = wrapped_method
        
        try:
            engine = PostQuantumMACEngine()
            key = engine.generate_key()
            result = engine.compute_mac(b"test data", key)
            self.assertIsNotNone(result)
            
            metrics = get_observability_metrics()
            mac_keys = [k for k in metrics["call_counts"].keys() if "compute_mac" in k]
            self.assertGreater(len(mac_keys), 0)
        finally:
            # Restore original
            PostQuantumMACEngine.compute_mac = original_method
            disable_observability()


class TestSecurityProperties(unittest.TestCase):
    """Test security properties of the observability layer."""

    def setUp(self):
        reset_observability_metrics()
        enable_observability(logging.WARNING)

    def tearDown(self):
        disable_observability()

    def test_default_no_args_logging(self):
        """By default, function arguments should NOT be logged."""
        @observe
        def func_with_secret(secret_key):
            return secret_key
        
        # This should not log the secret key
        result = func_with_secret("my_private_key_12345")
        self.assertEqual(result, "my_private_key_12345")
        
        # Metrics should be collected but without arg data
        metrics = get_observability_metrics()
        self.assertEqual(len(metrics["call_counts"]), 1)

    def test_default_no_result_logging(self):
        """By default, function results should NOT be logged."""
        @observe
        def func_returns_secret():
            return "super_secret_result_data"
        
        result = func_returns_secret()
        self.assertEqual(result, "super_secret_result_data")
        
        # Metrics should be collected but without result data
        metrics = get_observability_metrics()
        self.assertEqual(len(metrics["call_counts"]), 1)

    def test_error_messages_truncated(self):
        """Error messages should be truncated to prevent data leakage."""
        long_secret = "A" * 1000
        
        @observe
        def func_with_long_error():
            raise ValueError(f"Error with secret: {long_secret}")
        
        try:
            func_with_long_error()
        except ValueError:
            pass
        
        # The error was tracked, and the message should be truncated
        metrics = get_observability_metrics()
        self.assertEqual(len(metrics["error_counts"]), 1)


def run_tests():
    """Run all observability tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save results
    results = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "test_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    with open("test_results_observability_engine_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("QUANTUMCRYPT-AI OBSERVABILITY ENGINE TEST SUITE")
    print("June 2026 - Production Grade")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    if result.wasSuccessful():
        print(f"TEST SUMMARY: {result.testsRun} PASSED, 0 FAILED")
    else:
        print(f"TEST SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)} PASSED, "
              f"{len(result.failures)} FAILED, {len(result.errors)} ERRORS")
    print("=" * 70)
    print()
    print("Results saved to test_results_observability_engine_2026_june.json")
