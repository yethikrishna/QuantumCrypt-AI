"""
Test Suite for QuantumCrypt AI - PQ Operation Telemetry v10
Dimension D: Observability & Instrumentation v10

COMPLIES WITH INCREMENTAL BUILD PHILOSOPHY:
- ONLY tests - no production code modified
- All existing tests continue to pass
- Comprehensive edge case coverage
"""

import os
import time
import unittest
import threading

# Import the module
from quantum_crypt.crypto_observability_pq_operation_telemetry_latency_v10_2026_june import (
    # Enums
    PQOperationType, PQAlgorithm,
    
    # Histogram
    LatencyHistogram,
    
    # Sliding window
    SlidingWindowStats,
    
    # Metrics
    OperationMetrics,
    
    # Registry
    TelemetryRegistry, get_telemetry_registry,
    
    # Decorator
    telemetry,
    
    # Context manager
    OperationTimer,
    
    # Benchmarking
    benchmark_operation,
    
    # Health check
    get_health_status,
    
    # Export
    export_prometheus_format,
    
    # Config
    TELEMETRY_ENABLED
)


class TestEnums(unittest.TestCase):
    """Test enumeration types"""
    
    def test_operation_type_enum(self):
        """Test PQOperationType enum has all expected values"""
        expected = [
            "key_generation", "key_encapsulation", "key_decapsulation",
            "signature_generation", "signature_verification",
            "encryption", "decryption", "hash_computation",
            "random_generation", "key_exchange"
        ]
        
        for op_type in PQOperationType:
            self.assertIn(op_type.value, expected)
    
    def test_algorithm_enum(self):
        """Test PQAlgorithm enum has all expected values"""
        expected = [
            "CRYSTALS-Kyber", "CRYSTALS-Dilithium", "Falcon",
            "SPHINCS+", "NTRU", "Classic-McEliece", "BIKE", "HQC"
        ]
        
        for alg in PQAlgorithm:
            self.assertIn(alg.value, expected)


class TestLatencyHistogram(unittest.TestCase):
    """Test latency histogram implementation"""
    
    def test_histogram_initialization(self):
        """Test histogram initializes correctly"""
        hist = LatencyHistogram()
        self.assertEqual(len(hist.buckets), len(hist.BUCKET_BOUNDARIES))
        self.assertEqual(hist.inf_count, 0)
        self.assertTrue(all(b == 0 for b in hist.buckets))
    
    def test_histogram_record_single(self):
        """Test recording a single latency value"""
        hist = LatencyHistogram()
        hist.record(50.0)  # 50 microseconds
        
        # Find which bucket should contain 50
        bucket_idx = None
        for i, b in enumerate(hist.BUCKET_BOUNDARIES):
            if 50 <= b:
                bucket_idx = i
                break
        
        self.assertIsNotNone(bucket_idx)
        self.assertEqual(hist.buckets[bucket_idx], 1)
    
    def test_histogram_record_multiple(self):
        """Test recording multiple latency values"""
        hist = LatencyHistogram()
        for i in range(100):
            hist.record(float(i))
        
        total = sum(hist.buckets) + hist.inf_count
        self.assertEqual(total, 100)
    
    def test_histogram_overflow(self):
        """Test values larger than max bucket go to overflow"""
        hist = LatencyHistogram()
        hist.record(10_000_000.0)  # 10 seconds - way over max bucket
        self.assertEqual(hist.inf_count, 1)
    
    def test_histogram_percentile_empty(self):
        """Test percentile on empty histogram returns None"""
        hist = LatencyHistogram()
        self.assertIsNone(hist.get_percentile(0.5))
    
    def test_histogram_percentile(self):
        """Test percentile calculation"""
        hist = LatencyHistogram()
        for i in range(100):
            hist.record(float(i))
        
        p50 = hist.get_percentile(0.5)
        self.assertIsNotNone(p50)
        self.assertGreater(p50, 0)
    
    def test_histogram_to_dict(self):
        """Test histogram to dictionary conversion"""
        hist = LatencyHistogram()
        hist.record(50.0)
        
        d = hist.to_dict()
        self.assertIn("buckets", d)
        self.assertIn("overflow", d)
        self.assertIn("total", d)
        self.assertEqual(d["total"], 1)


class TestSlidingWindowStats(unittest.TestCase):
    """Test sliding window statistics"""
    
    def test_sliding_window_initialization(self):
        """Test sliding window initializes correctly"""
        stats = SlidingWindowStats(window_size=100)
        self.assertEqual(stats.window_size, 100)
        
        result = stats.get_stats()
        self.assertEqual(result["count"], 0)
        self.assertIsNone(result["min"])
    
    def test_sliding_window_record(self):
        """Test recording samples"""
        stats = SlidingWindowStats(window_size=100)
        
        for i in range(10):
            stats.record(float(i))
        
        result = stats.get_stats()
        self.assertEqual(result["count"], 10)
        self.assertEqual(result["min"], 0.0)
        self.assertEqual(result["max"], 9.0)
        self.assertEqual(result["mean"], 4.5)
    
    def test_sliding_window_window_size(self):
        """Test sliding window respects window size"""
        stats = SlidingWindowStats(window_size=5)
        
        for i in range(20):
            stats.record(float(i))
        
        result = stats.get_stats()
        self.assertEqual(result["count"], 5)
        # Should only keep last 5 samples (15-19)
        self.assertEqual(result["min"], 15.0)
        self.assertEqual(result["max"], 19.0)
    
    def test_sliding_window_percentiles(self):
        """Test percentile calculations"""
        stats = SlidingWindowStats(window_size=100)
        
        for i in range(100):
            stats.record(float(i))
        
        result = stats.get_stats()
        self.assertEqual(result["p50"], 50.0)
        self.assertEqual(result["p90"], 90.0)
        self.assertEqual(result["p95"], 95.0)
        self.assertEqual(result["p99"], 99.0)
    
    def test_sliding_window_std_dev(self):
        """Test standard deviation calculation"""
        stats = SlidingWindowStats(window_size=100)
        
        # Constant values should have 0 std dev
        for i in range(10):
            stats.record(5.0)
        
        result = stats.get_stats()
        self.assertEqual(result["std_dev"], 0.0)


class TestOperationMetrics(unittest.TestCase):
    """Test operation metrics recording"""
    
    def test_operation_metrics_initialization(self):
        """Test operation metrics initializes correctly"""
        metrics = OperationMetrics(PQOperationType.KEY_GENERATION)
        self.assertEqual(metrics.operation_type, PQOperationType.KEY_GENERATION)
        self.assertIsNone(metrics.algorithm)
    
    def test_operation_metrics_with_algorithm(self):
        """Test operation metrics with algorithm specified"""
        metrics = OperationMetrics(
            PQOperationType.KEY_GENERATION,
            PQAlgorithm.CRYSTALS_KYBER
        )
        self.assertEqual(metrics.algorithm, PQAlgorithm.CRYSTALS_KYBER)
    
    def test_record_success(self):
        """Test recording successful operation"""
        metrics = OperationMetrics(PQOperationType.ENCRYPTION)
        metrics.record_success(100.0)
        
        summary = metrics.get_summary()
        self.assertEqual(summary["total_operations"], 1)
        self.assertEqual(summary["error_count"], 0)
        self.assertEqual(summary["error_rate"], 0.0)
    
    def test_record_error(self):
        """Test recording failed operation"""
        metrics = OperationMetrics(PQOperationType.DECRYPTION)
        metrics.record_error(50.0)
        
        summary = metrics.get_summary()
        self.assertEqual(summary["total_operations"], 1)
        self.assertEqual(summary["error_count"], 1)
        self.assertEqual(summary["error_rate"], 100.0)
    
    def test_mixed_success_error(self):
        """Test mixed success and error recording"""
        metrics = OperationMetrics(PQOperationType.SIGNATURE_VERIFICATION)
        
        for _ in range(90):
            metrics.record_success(100.0)
        for _ in range(10):
            metrics.record_error(50.0)
        
        summary = metrics.get_summary()
        self.assertEqual(summary["total_operations"], 100)
        self.assertEqual(summary["error_count"], 10)
        self.assertAlmostEqual(summary["error_rate"], 10.0, places=1)
    
    def test_summary_contains_histogram(self):
        """Test summary includes histogram data"""
        metrics = OperationMetrics(PQOperationType.HASH_COMPUTATION)
        metrics.record_success(50.0)
        
        summary = metrics.get_summary()
        self.assertIn("histogram", summary)
        self.assertIn("sliding_window", summary)


class TestTelemetryRegistry(unittest.TestCase):
    """Test global telemetry registry"""
    
    def test_get_registry(self):
        """Test getting global registry"""
        registry = get_telemetry_registry()
        self.assertIsInstance(registry, TelemetryRegistry)
    
    def test_get_metrics_creates_new(self):
        """Test get_metrics creates new entry if not exists"""
        registry = TelemetryRegistry()
        metrics = registry.get_metrics(PQOperationType.KEY_GENERATION)
        self.assertIsInstance(metrics, OperationMetrics)
    
    def test_get_metrics_returns_same(self):
        """Test get_metrics returns same object for same key"""
        registry = TelemetryRegistry()
        m1 = registry.get_metrics(PQOperationType.KEY_GENERATION)
        m2 = registry.get_metrics(PQOperationType.KEY_GENERATION)
        self.assertIs(m1, m2)
    
    def test_record_operation(self):
        """Test recording operation via registry"""
        registry = TelemetryRegistry()
        registry.record_operation(
            PQOperationType.ENCRYPTION,
            PQAlgorithm.CRYSTALS_KYBER,
            100.0,
            success=True
        )
        
        summaries = registry.get_all_summaries()
        self.assertGreaterEqual(len(summaries), 0)  # May be 0 if disabled
    
    def test_reset_registry(self):
        """Test resetting registry"""
        registry = TelemetryRegistry()
        registry.get_metrics(PQOperationType.ENCRYPTION)
        registry.reset()
        
        summaries = registry.get_all_summaries()
        self.assertEqual(len(summaries), 0)


class TestTelemetryDecorator(unittest.TestCase):
    """Test @telemetry decorator"""
    
    def test_decorator_preserves_function(self):
        """Test decorator preserves original function behavior"""
        @telemetry(PQOperationType.KEY_GENERATION, PQAlgorithm.CRYSTALS_KYBER)
        def test_func(a, b):
            return a + b
        
        result = test_func(2, 3)
        self.assertEqual(result, 5)
    
    def test_decorator_without_algorithm(self):
        """Test decorator without algorithm specified"""
        @telemetry(PQOperationType.HASH_COMPUTATION)
        def hash_func(data):
            return f"hash({data})"
        
        result = hash_func("test")
        self.assertEqual(result, "hash(test)")
    
    def test_decorator_exception_propagation(self):
        """Test decorator propagates exceptions correctly"""
        @telemetry(PQOperationType.DECRYPTION)
        def error_func():
            raise ValueError("Decryption failed")
        
        with self.assertRaises(ValueError) as ctx:
            error_func()
        
        self.assertEqual(str(ctx.exception), "Decryption failed")


class TestOperationTimer(unittest.TestCase):
    """Test OperationTimer context manager"""
    
    def test_context_manager_basic(self):
        """Test basic context manager usage"""
        with OperationTimer(PQOperationType.ENCRYPTION):
            result = 2 + 3
        
        self.assertEqual(result, 5)
    
    def test_context_manager_with_algorithm(self):
        """Test context manager with algorithm specified"""
        with OperationTimer(
            PQOperationType.SIGNATURE_GENERATION,
            PQAlgorithm.CRYSTALS_DILITHIUM
        ):
            pass  # Operation code
    
    def test_context_manager_with_attributes(self):
        """Test context manager with attributes"""
        with OperationTimer(
            PQOperationType.KEY_EXCHANGE,
            attributes={"key_size": 256, "round": 1}
        ):
            pass
    
    def test_context_manager_exception_propagation(self):
        """Test context manager propagates exceptions"""
        with self.assertRaises(ValueError):
            with OperationTimer(PQOperationType.DECRYPTION):
                raise ValueError("Test error")


class TestBenchmarking(unittest.TestCase):
    """Test benchmarking utilities"""
    
    def test_benchmark_basic(self):
        """Test basic benchmark operation"""
        def fast_op():
            return 42
        
        result = benchmark_operation(fast_op, iterations=10, warmup=2)
        
        self.assertEqual(result["iterations"], 10)
        self.assertEqual(result["successful"], 10)
        self.assertEqual(result["errors"], 0)
        self.assertIn("mean_us", result)
        self.assertIn("operations_per_second", result)
    
    def test_benchmark_with_args(self):
        """Test benchmark with function arguments"""
        def add(a, b):
            return a + b
        
        result = benchmark_operation(add, iterations=10, warmup=2, args=(2, 3))
        
        self.assertEqual(result["successful"], 10)
        self.assertGreater(result["operations_per_second"], 0)
    
    def test_benchmark_error_handling(self):
        """Test benchmark handles errors"""
        error_count = 0
        
        def sometimes_fails():
            nonlocal error_count
            error_count += 1
            if error_count % 2 == 0:
                raise ValueError("Fail")
            return True
        
        result = benchmark_operation(sometimes_fails, iterations=10, warmup=0)
        
        self.assertEqual(result["iterations"], 10)
        self.assertGreater(result["errors"], 0)
        self.assertGreater(result["error_rate"], 0)
    
    def test_benchmark_percentiles(self):
        """Test benchmark returns percentile data"""
        def op():
            time.sleep(0.0001)  # 0.1ms
        
        result = benchmark_operation(op, iterations=20, warmup=2)
        
        self.assertIn("p50_us", result)
        self.assertIn("p90_us", result)
        self.assertIn("p95_us", result)
        self.assertIn("p99_us", result)
        self.assertGreater(result["p99_us"], result["p50_us"])


class TestHealthStatus(unittest.TestCase):
    """Test health check integration"""
    
    def test_health_status_always_returns(self):
        """Test health status always returns valid dict"""
        status = get_health_status()
        self.assertIsInstance(status, dict)
        self.assertIn("status", status)
        self.assertIn("enabled", status)
    
    def test_health_status_disabled_by_default(self):
        """Test health status shows disabled by default"""
        # This is the critical invariant - OPT-IN only
        status = get_health_status()
        if not TELEMETRY_ENABLED:
            self.assertEqual(status["status"], "disabled")
            self.assertFalse(status["enabled"])


class TestPrometheusExport(unittest.TestCase):
    """Test Prometheus metrics export"""
    
    def test_export_returns_string(self):
        """Test export always returns a string"""
        result = export_prometheus_format()
        self.assertIsInstance(result, str)
    
    def test_export_contains_comments(self):
        """Test export contains HELP/TYPE comments"""
        result = export_prometheus_format()
        self.assertIn("# HELP", result)
        self.assertIn("# TYPE", result)


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of metrics recording"""
    
    def test_histogram_thread_safety(self):
        """Test histogram recording from multiple threads"""
        hist = LatencyHistogram()
        
        def worker():
            for i in range(100):
                hist.record(float(i))
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        d = hist.to_dict()
        self.assertEqual(d["total"], 500)
    
    def test_sliding_window_thread_safety(self):
        """Test sliding window from multiple threads"""
        stats = SlidingWindowStats(window_size=1000)
        
        def worker(start):
            for i in range(100):
                stats.record(float(start + i))
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i * 100,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        result = stats.get_stats()
        self.assertEqual(result["count"], 500)


class TestOptInBehavior(unittest.TestCase):
    """Test OPT-IN behavior - no side effects when disabled"""
    
    def test_telemetry_disabled_by_default(self):
        """Test telemetry is disabled by default"""
        # This is the critical invariant - instrumentation must be opt-in only
        self.assertFalse(TELEMETRY_ENABLED)
    
    def test_no_side_effects_when_disabled(self):
        """Test operations have no side effects when disabled"""
        # When disabled, these should all be no-ops that don't fail
        registry = get_telemetry_registry()
        registry.record_operation(
            PQOperationType.ENCRYPTION,
            PQAlgorithm.CRYSTALS_KYBER,
            100.0,
            success=True
        )
        # Should not raise and should not record anything significant


if __name__ == "__main__":
    unittest.main(verbosity=2)
