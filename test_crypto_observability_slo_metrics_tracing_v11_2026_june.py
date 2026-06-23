"""
Test Suite for QuantumCrypt Enhanced Observability SLO Metrics v11
Dimension D - Observability & Instrumentation

Tests verify:
- Observability is disabled by default (opt-in only)
- SLO tracking and error budget calculations work
- Latency percentile calculations are correct
- Crypto operation tracing works
- Health check endpoints function
- No existing code behavior is broken
- All tests are add-only, no production code modified
"""

import unittest
import time
import threading

from quantum_crypt.crypto_observability_slo_metrics_tracing_v11_2026_june import (
    SLODefinition,
    SLOStatus,
    MetricType,
    SLIMetric,
    TimeWindowStore,
    PercentileCalculator,
    SLOTracker,
    CryptoOperationTracer,
    global_crypto_tracer,
    enable_observability,
    disable_observability,
    is_observability_enabled,
    record_operation,
    trace_crypto,
    get_metrics,
    get_health_check
)


class TestSLODefinition(unittest.TestCase):
    """Test SLO definition validation."""
    
    def test_valid_slo_definition(self):
        """Test valid SLO creation."""
        slo = SLODefinition(
            name="test-slo",
            target_percent=99.9,
            window_days=30,
            metric_type=MetricType.AVAILABILITY
        )
        self.assertEqual(slo.name, "test-slo")
        self.assertEqual(slo.target_percent, 99.9)
        self.assertAlmostEqual(slo.error_budget_percent, 0.1, places=5)
    
    def test_invalid_slo_target(self):
        """Test invalid target percentage raises error."""
        with self.assertRaises(ValueError):
            SLODefinition(name="bad", target_percent=101.0)
        
        with self.assertRaises(ValueError):
            SLODefinition(name="bad", target_percent=0.0)


class TestTimeWindowStore(unittest.TestCase):
    """Test sliding window metrics storage."""
    
    def test_add_and_retrieve_metrics(self):
        """Test basic metric storage."""
        store = TimeWindowStore(window_seconds=3600)
        metric = SLIMetric(
            timestamp=time.time(),
            value=1.0,
            success=True,
            operation="test"
        )
        store.add(metric)
        metrics = store.get_metrics()
        self.assertEqual(len(metrics), 1)
        self.assertTrue(metrics[0].success)
    
    def test_metric_count(self):
        """Test metric counting."""
        store = TimeWindowStore(window_seconds=3600)
        for i in range(10):
            store.add(SLIMetric(time.time(), 1.0, True, "test"))
        self.assertEqual(store.get_count(), 10)
    
    def test_thread_safety(self):
        """Test concurrent access safety."""
        store = TimeWindowStore(window_seconds=3600)
        
        def worker():
            for i in range(100):
                store.add(SLIMetric(time.time(), 1.0, True, "test"))
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(store.get_count(), 500)


class TestPercentileCalculator(unittest.TestCase):
    """Test percentile calculations."""
    
    def test_percentile_basic(self):
        """Test basic percentile calculation."""
        values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        self.assertEqual(PercentileCalculator.p50(values), 5)
        self.assertEqual(PercentileCalculator.p95(values), 10)
        self.assertEqual(PercentileCalculator.p99(values), 10)
    
    def test_percentile_empty(self):
        """Test empty list handling."""
        self.assertIsNone(PercentileCalculator.p50([]))
    
    def test_percentile_single_value(self):
        """Test single value case."""
        self.assertEqual(PercentileCalculator.p95([42]), 42)
    
    def test_percentile_latency_distribution(self):
        """Test realistic latency distribution."""
        latencies = [10, 15, 20, 25, 30, 35, 40, 45, 50, 100, 200]
        p50 = PercentileCalculator.p50(latencies)
        p95 = PercentileCalculator.p95(latencies)
        p99 = PercentileCalculator.p99(latencies)
        self.assertIsNotNone(p50)
        self.assertIsNotNone(p95)
        self.assertIsNotNone(p99)
        self.assertLessEqual(p50, p95)
        self.assertLessEqual(p95, p99)


class TestSLOTracker(unittest.TestCase):
    """Test SLO tracking and error budget calculations."""
    
    def setUp(self):
        self.slo = SLODefinition("test", target_percent=99.0, window_days=30)
        self.tracker = SLOTracker(self.slo)
    
    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        for i in range(99):
            self.tracker.record_operation(True, "op1", 10.0)
        for i in range(1):
            self.tracker.record_operation(False, "op1", 5.0)
        
        rate = self.tracker.get_success_rate()
        self.assertIsNotNone(rate)
        self.assertAlmostEqual(rate, 99.0, delta=0.5)
    
    def test_error_budget_calculation(self):
        """Test error budget remaining calculation."""
        # 100% success = full budget remaining
        for i in range(100):
            self.tracker.record_operation(True, "op", 10.0)
        
        remaining = self.tracker.get_error_budget_remaining()
        self.assertIsNotNone(remaining)
        self.assertAlmostEqual(remaining, 1.0, delta=0.1)  # 1% budget
    
    def test_burn_rate_calculation(self):
        """Test error budget burn rate."""
        # All success = low burn rate
        for i in range(100):
            self.tracker.record_operation(True, "op", 10.0)
        
        burn_rate = self.tracker.get_burn_rate(1)
        self.assertIsNotNone(burn_rate)
        self.assertAlmostEqual(burn_rate, 0.0, delta=0.1)
    
    def test_slo_status_healthy(self):
        """Test healthy SLO status."""
        for i in range(100):
            self.tracker.record_operation(True, "op", 10.0)
        
        status = self.tracker.get_status()
        self.assertEqual(status, SLOStatus.HEALTHY)
    
    def test_latency_percentiles(self):
        """Test latency percentile extraction."""
        for i in range(100):
            self.tracker.record_operation(True, "op", float(i))
        
        percentiles = self.tracker.get_latency_percentiles()
        self.assertIn("p50", percentiles)
        self.assertIn("p95", percentiles)
        self.assertIn("p99", percentiles)
        self.assertIn("p999", percentiles)
    
    def test_throughput_calculation(self):
        """Test operations per second calculation."""
        for i in range(60):
            self.tracker.record_operation(True, "op", 10.0)
        
        throughput = self.tracker.get_throughput(60)
        self.assertGreater(throughput, 0)
    
    def test_summary_generation(self):
        """Test comprehensive summary generation."""
        for i in range(10):
            self.tracker.record_operation(True, "op", 10.0)
        
        summary = self.tracker.get_summary()
        self.assertIn("success_rate", summary)
        self.assertIn("error_budget_remaining_pct", summary)
        self.assertIn("burn_rate_1h", summary)
        self.assertIn("status", summary)
        self.assertIn("latency_percentiles", summary)


class TestCryptoOperationTracerDisabledByDefault(unittest.TestCase):
    """Test that observability is disabled by default (opt-in requirement)."""
    
    def test_observability_disabled_by_default(self):
        """Verify observability is off by default."""
        tracer = CryptoOperationTracer()
        self.assertFalse(tracer.is_enabled())
    
    def test_no_op_when_disabled(self):
        """Verify operations are no-op when disabled."""
        tracer = CryptoOperationTracer()
        
        # These should do nothing when disabled
        tracer.record_crypto_operation("encrypt", "kyber", True, 10.0)
        metrics = tracer.get_operation_metrics()
        
        self.assertFalse(metrics["enabled"])
    
    def test_enable_disable(self):
        """Test enabling and disabling."""
        tracer = CryptoOperationTracer()
        self.assertFalse(tracer.is_enabled())
        tracer.enable()
        self.assertTrue(tracer.is_enabled())
        tracer.disable()
        self.assertFalse(tracer.is_enabled())


class TestCryptoOperationTracerEnabled(unittest.TestCase):
    """Test tracer functionality when enabled."""
    
    def setUp(self):
        self.tracer = CryptoOperationTracer()
        self.tracer.enable()
    
    def tearDown(self):
        self.tracer.disable()
    
    def test_record_operation(self):
        """Test recording crypto operations."""
        self.tracer.record_crypto_operation(
            operation="key_exchange",
            algorithm="kyber-768",
            success=True,
            latency_ms=45.5,
            key_size=768
        )
        
        metrics = self.tracer.get_operation_metrics()
        self.assertTrue(metrics["enabled"])
        self.assertIn("key_exchange", metrics["operation_counts"])
        self.assertEqual(metrics["operation_counts"]["key_exchange"], 1)
    
    def test_decorator_tracing_success(self):
        """Test decorator on successful operation."""
        @self.tracer.trace_crypto_operation(algorithm="kyber", key_size=768)
        def encrypt_data(data):
            return f"encrypted:{data}"
        
        result = encrypt_data("test")
        self.assertEqual(result, "encrypted:test")
        
        metrics = self.tracer.get_operation_metrics()
        self.assertIn("encrypt_data", metrics["operation_counts"])
    
    def test_decorator_tracing_error(self):
        """Test decorator on failing operation."""
        @self.tracer.trace_crypto_operation(algorithm="kyber")
        def failing_operation():
            raise ValueError("Crypto failed")
        
        with self.assertRaises(ValueError):
            failing_operation()
        
        # Error should still be recorded
        metrics = self.tracer.get_operation_metrics()
        self.assertIn("failing_operation", metrics["operation_counts"])
    
    def test_health_check(self):
        """Test health check endpoint."""
        for i in range(10):
            self.tracer.record_crypto_operation("op", "algo", True, 10.0)
        
        health = self.tracer.get_health_check()
        self.assertIn("healthy", health)
        self.assertIn("slo_status", health)
        self.assertIn("success_rate", health)
        self.assertIn("timestamp", health)


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def tearDown(self):
        disable_observability()
    
    def test_enable_disable_global(self):
        """Test global enable/disable functions."""
        self.assertFalse(is_observability_enabled())
        enable_observability()
        self.assertTrue(is_observability_enabled())
        disable_observability()
        self.assertFalse(is_observability_enabled())
    
    def test_record_global(self):
        """Test global record function."""
        enable_observability()
        record_operation(
            operation="test",
            algorithm="test",
            success=True,
            latency_ms=10.0
        )
        metrics = get_metrics()
        self.assertTrue(metrics["enabled"])
    
    def test_get_health_check_global(self):
        """Test global health check."""
        enable_observability()
        health = get_health_check()
        self.assertIn("healthy", health)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify no existing code behavior is broken."""
    
    def test_no_side_effects_when_disabled(self):
        """Disabled observability has zero impact."""
        tracer = CryptoOperationTracer()
        
        # All operations should be safe no-ops
        tracer.record_crypto_operation("op", "algo", True, 10.0)
        metrics = tracer.get_operation_metrics()
        health = tracer.get_health_check()
        
        self.assertFalse(metrics["enabled"])
        # No exceptions raised
    
    def test_decorator_passthrough_when_disabled(self):
        """Decorator passes through perfectly when disabled."""
        tracer = CryptoOperationTracer()  # Disabled
        
        @tracer.trace_crypto_operation()
        def add(a, b):
            return a + b
        
        # Function should work exactly as original
        result = add(2, 3)
        self.assertEqual(result, 5)
        
        # No metrics recorded
        metrics = tracer.get_operation_metrics()
        self.assertFalse(metrics["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
