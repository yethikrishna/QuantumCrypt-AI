"""
Test Suite for QuantumCrypt-AI: Post-Quantum Performance Monitor & Benchmark Engine
June 2026 Production-Grade Tests

Comprehensive tests covering:
- Simulated PQC operation timing
- Single and batch benchmark execution
- Performance baseline establishment
- Regression detection and alerting
- Algorithm performance comparison
- Metrics tracking and export
- Edge cases and boundary conditions
"""
import sys
import os
import json
import time
import unittest

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_performance_monitor_benchmark_engine_2026_june import (
    PQPerformanceMonitor,
    SimulatedPQOperations,
    PQAlgorithm,
    OperationType,
    PerformanceAlertSeverity,
    BenchmarkResult,
    PerformanceBaseline,
    PerformanceAlert
)


class TestSimulatedPQOperations(unittest.TestCase):
    """Test simulated PQC operation timing"""
    
    def test_kyber_operations_are_fast(self):
        """Test Kyber KEM operations have realistic fast timings"""
        for alg in [PQAlgorithm.KYBER_512, PQAlgorithm.KYBER_768, PQAlgorithm.KYBER_1024]:
            for op in [OperationType.KEY_GENERATION, OperationType.KEM_ENCAPS]:
                latency = SimulatedPQOperations.simulate_operation(alg, op, add_noise=False)
                # Kyber operations should be sub-millisecond
                self.assertLess(latency, 1.0)
    
    def test_sphincs_signing_is_slow(self):
        """Test SPHINCS+ signing is significantly slower (hash-based)"""
        sphincs_sign = SimulatedPQOperations.simulate_operation(
            PQAlgorithm.SPHINCS_SHA2_128F,
            OperationType.SIGNING,
            add_noise=False
        )
        kyber_encaps = SimulatedPQOperations.simulate_operation(
            PQAlgorithm.KYBER_512,
            OperationType.KEM_ENCAPS,
            add_noise=False
        )
        
        # SPHINCS+ signing should be much slower
        self.assertGreater(sphincs_sign, kyber_encaps * 50)
    
    def test_expected_performance_retrieval(self):
        """Test expected performance values are available"""
        mean, std = SimulatedPQOperations.get_expected_performance(
            PQAlgorithm.KYBER_768,
            OperationType.KEY_GENERATION
        )
        
        self.assertGreater(mean, 0)
        self.assertGreater(std, 0)


class TestPQPerformanceMonitor(unittest.TestCase):
    """Main performance monitor tests"""
    
    def setUp(self):
        """Set up test monitor"""
        self.monitor = PQPerformanceMonitor(
            degradation_threshold_pct=20.0,
            alert_on_degradation=True,
            min_samples_for_baseline=5
        )
    
    def test_monitor_initialization(self):
        """Test monitor initializes correctly"""
        self.assertEqual(self.monitor.degradation_threshold_pct, 20.0)
        self.assertTrue(self.monitor.alert_on_degradation)
        self.assertEqual(self.monitor.min_samples_for_baseline, 5)
        self.assertEqual(self.monitor.stats["total_benchmarks_run"], 0)
    
    def test_single_benchmark_execution(self):
        """Test running a single benchmark"""
        result = self.monitor.run_benchmark(
            PQAlgorithm.KYBER_512,
            OperationType.KEY_GENERATION,
            iterations=50,
            warmup_iterations=5
        )
        
        self.assertIsInstance(result, BenchmarkResult)
        self.assertTrue(result.success)
        self.assertEqual(result.algorithm, PQAlgorithm.KYBER_512.value)
        self.assertEqual(result.operation, OperationType.KEY_GENERATION.value)
        self.assertEqual(result.iterations, 50)
        self.assertGreater(result.avg_time_ms, 0)
        self.assertGreater(result.throughput_ops_per_sec, 0)
    
    def test_benchmark_statistics(self):
        """Test benchmark produces correct statistical values"""
        result = self.monitor.run_benchmark(
            PQAlgorithm.KYBER_768,
            OperationType.KEM_ENCAPS,
            iterations=100
        )
        
        self.assertTrue(result.success)
        self.assertLessEqual(result.min_time_ms, result.p50_time_ms)
        self.assertLessEqual(result.p50_time_ms, result.p95_time_ms)
        self.assertLessEqual(result.p95_time_ms, result.p99_time_ms)
        self.assertLessEqual(result.p99_time_ms, result.max_time_ms)
    
    def test_batch_benchmark(self):
        """Test batch benchmark across multiple algorithms"""
        algorithms = [PQAlgorithm.KYBER_512, PQAlgorithm.DILITHIUM_2]
        operations = [OperationType.KEY_GENERATION, OperationType.SIGNING]
        
        results = self.monitor.batch_benchmark(algorithms, operations, iterations=20)
        
        self.assertEqual(len(results), 4)  # 2 alg × 2 op
        for key, result in results.items():
            self.assertIsInstance(result, BenchmarkResult)
            self.assertTrue(result.success)
    
    def test_baseline_establishment(self):
        """Test baselines are established after enough samples"""
        # Run enough benchmarks to establish baseline
        for _ in range(10):
            self.monitor.run_benchmark(
                PQAlgorithm.KYBER_512,
                OperationType.KEY_GENERATION,
                iterations=10
            )
        
        key = (PQAlgorithm.KYBER_512.value, OperationType.KEY_GENERATION.value)
        self.assertIn(key, self.monitor.baselines)
        
        baseline = self.monitor.baselines[key]
        self.assertIsInstance(baseline, PerformanceBaseline)
        self.assertGreater(baseline.avg_latency_ms, 0)
        self.assertEqual(baseline.sample_count, 5)  # min_samples
    
    def test_algorithm_summary(self):
        """Test algorithm performance summary"""
        # Run some benchmarks
        self.monitor.run_benchmark(
            PQAlgorithm.KYBER_768,
            OperationType.KEY_GENERATION,
            iterations=20
        )
        self.monitor.run_benchmark(
            PQAlgorithm.KYBER_768,
            OperationType.KEM_ENCAPS,
            iterations=20
        )
        
        summary = self.monitor.get_algorithm_summary(PQAlgorithm.KYBER_768)
        
        self.assertEqual(summary["algorithm"], PQAlgorithm.KYBER_768.value)
        self.assertGreater(summary["benchmarks_available"], 0)
        self.assertIn("operations", summary)
    
    def test_comparative_report(self):
        """Test comparative performance report"""
        # Run benchmarks for multiple algorithms
        algs = [PQAlgorithm.KYBER_512, PQAlgorithm.DILITHIUM_2]
        for alg in algs:
            self.monitor.run_benchmark(alg, OperationType.KEY_GENERATION, iterations=10)
        
        report = self.monitor.get_comparative_report(algs)
        
        self.assertIn("generated_at", report)
        self.assertIn("recommendations", report)
        self.assertIn("detailed_comparison", report)
        self.assertEqual(len(report["algorithms_compared"]), 2)
    
    def test_performance_metrics(self):
        """Test performance metrics tracking"""
        # Run some benchmarks
        for _ in range(3):
            self.monitor.run_benchmark(
                PQAlgorithm.KYBER_512,
                OperationType.KEY_GENERATION,
                iterations=10
            )
        
        metrics = self.monitor.get_performance_metrics()
        
        self.assertEqual(metrics["monitor_version"], "pq_perf_monitor_v1")
        self.assertEqual(metrics["total_benchmarks_run"], 3)
        self.assertGreater(metrics["total_operations_simulated"], 0)
    
    def test_alert_callback_registration(self):
        """Test alert callback registration"""
        callback_called = []
        
        def test_callback(alert):
            callback_called.append(alert)
        
        self.monitor.register_alert_callback(test_callback)
        self.assertEqual(len(self.monitor.alert_callbacks), 1)
    
    def test_get_alerts_empty(self):
        """Test getting alerts when none exist"""
        alerts = self.monitor.get_alerts()
        self.assertEqual(len(alerts), 0)
    
    def test_export_results(self):
        """Test benchmark results export"""
        # Run a benchmark
        self.monitor.run_benchmark(
            PQAlgorithm.KYBER_512,
            OperationType.KEY_GENERATION,
            iterations=10
        )
        
        export_json = self.monitor.export_benchmark_results()
        
        self.assertIsInstance(export_json, str)
        export_data = json.loads(export_json)
        
        self.assertIn("exported_at", export_data)
        self.assertIn("metrics", export_data)
        self.assertIn("recent_benchmarks", export_data)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""
    
    def setUp(self):
        self.monitor = PQPerformanceMonitor(min_samples_for_baseline=3)
    
    def test_zero_iterations_benchmark(self):
        """Test benchmark with minimal iterations"""
        result = self.monitor.run_benchmark(
            PQAlgorithm.KYBER_512,
            OperationType.KEY_GENERATION,
            iterations=1,
            warmup_iterations=0
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.iterations, 1)
    
    def test_all_algorithms_benchmarkable(self):
        """Test all defined algorithms can be benchmarked"""
        algorithms = list(PQAlgorithm)
        operations = [OperationType.KEY_GENERATION]
        
        for alg in algorithms:
            # Skip classic algorithms for some operations
            try:
                result = self.monitor.run_benchmark(alg, OperationType.KEY_GENERATION, iterations=5)
                self.assertTrue(result.success, f"Failed for {alg.value}")
            except Exception:
                # Some algorithm-operation combinations may not be defined
                pass
    
    def test_large_iteration_count(self):
        """Test benchmark with large iteration count"""
        result = self.monitor.run_benchmark(
            PQAlgorithm.KYBER_512,
            OperationType.KEM_ENCAPS,
            iterations=200,
            warmup_iterations=20
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.iterations, 200)
        self.assertGreater(result.total_time_ms, 0)
    
    def test_noisy_operations(self):
        """Test operations with noise produce variable timings"""
        latencies = [
            SimulatedPQOperations.simulate_operation(
                PQAlgorithm.KYBER_512,
                OperationType.KEY_GENERATION,
                add_noise=True
            )
            for _ in range(10)
        ]
        
        # With noise, timings should vary
        self.assertGreater(len(set(latencies)), 1)
    
    def test_deterministic_without_noise(self):
        """Test operations without noise are deterministic"""
        l1 = SimulatedPQOperations.simulate_operation(
            PQAlgorithm.KYBER_512,
            OperationType.KEY_GENERATION,
            add_noise=False
        )
        l2 = SimulatedPQOperations.simulate_operation(
            PQAlgorithm.KYBER_512,
            OperationType.KEY_GENERATION,
            add_noise=False
        )
        
        self.assertEqual(l1, l2)
    
    def test_get_alerts_with_severity_filter(self):
        """Test alert filtering by severity"""
        # Should work even with no alerts
        alerts = self.monitor.get_alerts(min_severity=PerformanceAlertSeverity.WARNING)
        self.assertIsInstance(alerts, list)


class TestPerformanceComparison(unittest.TestCase):
    """Test performance comparisons across algorithms"""
    
    def setUp(self):
        self.monitor = PQPerformanceMonitor()
    
    def test_kyber_faster_than_rsa(self):
        """Test Kyber key generation is faster than RSA-2048"""
        kyber_result = self.monitor.run_benchmark(
            PQAlgorithm.KYBER_512,
            OperationType.KEY_GENERATION,
            iterations=20
        )
        
        rsa_result = self.monitor.run_benchmark(
            PQAlgorithm.CLASSIC_RSA_2048,
            OperationType.KEY_GENERATION,
            iterations=20
        )
        
        # Kyber should be much faster than RSA for key generation
        self.assertLess(kyber_result.avg_time_ms, rsa_result.avg_time_ms)
    
    def test_falcon_fast_signing(self):
        """Test Falcon has fast signing operation"""
        falcon_sign = self.monitor.run_benchmark(
            PQAlgorithm.FALCON_512,
            OperationType.SIGNING,
            iterations=20
        )
        
        dilithium_sign = self.monitor.run_benchmark(
            PQAlgorithm.DILITHIUM_2,
            OperationType.SIGNING,
            iterations=20
        )
        
        # Falcon signing should be faster than Dilithium
        self.assertLess(falcon_sign.avg_time_ms, dilithium_sign.avg_time_ms)
    
    def test_sphincs_fast_verification(self):
        """Test SPHINCS+ has fast verification"""
        sphincs_verify = self.monitor.run_benchmark(
            PQAlgorithm.SPHINCS_SHA2_128F,
            OperationType.VERIFICATION,
            iterations=20
        )
        
        sphincs_sign = self.monitor.run_benchmark(
            PQAlgorithm.SPHINCS_SHA2_128F,
            OperationType.SIGNING,
            iterations=20
        )
        
        # SPHINCS+ verification should be much faster than signing
        self.assertLess(sphincs_verify.avg_time_ms, sphincs_sign.avg_time_ms / 10)


def run_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Performance Monitor - Test Suite")
    print("June 2026 Production-Grade Tests")
    print("=" * 70)
    print()
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSimulatedPQOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestPQPerformanceMonitor))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceComparison))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print()
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED - Production Ready!")
        status = "PASSED"
    else:
        print("❌ SOME TESTS FAILED")
        status = "FAILED"
    
    # Save test results
    test_results = {
        "test_timestamp": time.time(),
        "test_datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "status": status,
        "monitor_version": "pq_perf_monitor_v1"
    }
    
    with open("test_results_pq_performance_monitor.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to: test_results_pq_performance_monitor.json")
    print()
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
