#!/usr/bin/env python3
"""
Test suite for Post-Quantum Algorithm Benchmark Performance Profiler v3
QuantumCrypt AI - PQ Crypto Module Tests

Tests cover:
- Algorithm profiling
- Benchmark execution
- Performance scoring
- Algorithm comparison
- Optimization guidance
- Report generation
"""

import json
import unittest
from quantum_crypt.post_quantum_algorithm_benchmark_performance_profiler_v3_2026_june import (
    PQAlgorithmPerformanceProfiler,
    PQAlgorithm,
    BenchmarkMetric,
    SecurityLevel,
    BenchmarkResult,
    AlgorithmProfile,
    BenchmarkRunner,
    AlgorithmSimulator,
    PerformanceTimer
)


class TestPQAlgorithmPerformanceProfiler(unittest.TestCase):
    """Main test class for the profiler module"""

    def setUp(self):
        """Set up test fixtures"""
        self.profiler = PQAlgorithmPerformanceProfiler(iterations=10)

    def test_module_import(self):
        """Test that module imports correctly"""
        self.assertIsNotNone(PQAlgorithmPerformanceProfiler)
        self.assertIsNotNone(PQAlgorithm)
        self.assertIsNotNone(BenchmarkMetric)
        self.assertIsNotNone(SecurityLevel)
        self.assertIsNotNone(BenchmarkResult)
        self.assertIsNotNone(AlgorithmProfile)
        self.assertIsNotNone(BenchmarkRunner)
        self.assertIsNotNone(AlgorithmSimulator)
        self.assertIsNotNone(PerformanceTimer)

    def test_profiler_initialization(self):
        """Test profiler initialization"""
        self.assertEqual(len(self.profiler.profiles), 0)
        self.assertEqual(len(self.profiler.benchmark_history), 0)

    def test_performance_timer(self):
        """Test high-precision performance timer"""
        timer = PerformanceTimer()

        with timer:
            # Simulate some work
            import time
            time.sleep(0.001)

        self.assertGreater(timer.elapsed, 0)
        self.assertIsInstance(timer.elapsed, float)

    def test_algorithm_simulator(self):
        """Test algorithm simulator functionality"""
        # Test characteristic retrieval
        char = AlgorithmSimulator.get_characteristic("CRYSTALS-Kyber-768", "security_level")
        self.assertEqual(char, 3)

        # Test operation simulation
        time_ms = AlgorithmSimulator.simulate_operation("CRYSTALS-Kyber-768", "key_gen")
        self.assertGreater(time_ms, 0)

        # Test unknown algorithm
        char = AlgorithmSimulator.get_characteristic("Unknown-Algo", "security_level")
        self.assertIsNone(char)

    def test_profile_kyber_algorithm(self):
        """Test profiling CRYSTALS-Kyber algorithm"""
        profile = self.profiler.profile_algorithm("CRYSTALS-Kyber-768")

        self.assertEqual(profile.algorithm, "CRYSTALS-Kyber-768")
        self.assertEqual(profile.security_level, 3)
        self.assertTrue(profile.nist_standardized)
        self.assertGreater(profile.performance_score, 0)
        self.assertIn("key_generation", profile.benchmarks)
        self.assertIn("encapsulation", profile.benchmarks)
        self.assertIn("decapsulation", profile.benchmarks)
        self.assertIn("public_key_size", profile.benchmarks)
        self.assertIn("private_key_size", profile.benchmarks)

    def test_profile_dilithium_algorithm(self):
        """Test profiling CRYSTALS-Dilithium algorithm"""
        profile = self.profiler.profile_algorithm("CRYSTALS-Dilithium-3")

        self.assertEqual(profile.algorithm, "CRYSTALS-Dilithium-3")
        self.assertEqual(profile.security_level, 3)
        self.assertTrue(profile.nist_standardized)
        self.assertIn("signing", profile.benchmarks)
        self.assertIn("verification", profile.benchmarks)
        self.assertIn("signature_size", profile.benchmarks)

    def test_profile_falcon_algorithm(self):
        """Test profiling Falcon algorithm"""
        profile = self.profiler.profile_algorithm("Falcon-512")

        self.assertEqual(profile.algorithm, "Falcon-512")
        self.assertEqual(profile.security_level, 1)
        self.assertTrue(profile.nist_standardized)
        self.assertGreater(len(profile.use_case_recommendations), 0)

    def test_profile_sphincs_algorithm(self):
        """Test profiling SPHINCS+ algorithm"""
        profile = self.profiler.profile_algorithm("SPHINCS+-128f")

        self.assertEqual(profile.algorithm, "SPHINCS+-128f")
        self.assertEqual(profile.security_level, 1)
        self.assertTrue(profile.nist_standardized)
        # SPHINCS+ should have large signatures
        self.assertIn("large_signature_size", profile.known_limitations)

    def test_profile_classic_mceliece(self):
        """Test profiling Classic-McEliece algorithm"""
        profile = self.profiler.profile_algorithm("Classic-McEliece")

        self.assertEqual(profile.algorithm, "Classic-McEliece")
        self.assertEqual(profile.security_level, 5)
        self.assertTrue(profile.nist_standardized)
        # McEliece has large key size
        self.assertGreater(len(profile.known_limitations), 0)

    def test_unknown_algorithm_handling(self):
        """Test handling of unknown algorithms"""
        with self.assertRaises(ValueError):
            self.profiler.profile_algorithm("Unknown-PQ-Algorithm-123")

    def test_benchmark_result_structure(self):
        """Test benchmark result data structure"""
        profile = self.profiler.profile_algorithm("CRYSTALS-Kyber-512")
        bench = profile.benchmarks["key_generation"]

        self.assertIsInstance(bench.mean_value, float)
        self.assertIsInstance(bench.median_value, float)
        self.assertIsInstance(bench.min_value, float)
        self.assertIsInstance(bench.max_value, float)
        self.assertIsInstance(bench.std_dev, float)
        self.assertIsInstance(bench.p95_value, float)
        self.assertIsInstance(bench.p99_value, float)
        self.assertGreater(bench.sample_count, 0)
        self.assertEqual(bench.unit, "ms")

        # Convert to dict
        bench_dict = bench.to_dict()
        self.assertIn("mean", bench_dict)
        self.assertIn("median", bench_dict)
        self.assertIn("std_dev", bench_dict)

    def test_efficiency_rating(self):
        """Test efficiency rating calculation"""
        profile = self.profiler.profile_algorithm("CRYSTALS-Kyber-512")

        self.assertIn(profile.efficiency_rating,
                      ["excellent", "very_good", "good", "moderate", "poor"])

    def test_performance_score_range(self):
        """Test performance score is in valid range"""
        for algo in ["CRYSTALS-Kyber-512", "CRYSTALS-Dilithium-2", "Falcon-512"]:
            profile = self.profiler.profile_algorithm(algo)
            self.assertGreaterEqual(profile.performance_score, 0)
            self.assertLessEqual(profile.performance_score, 100)

    def test_use_case_recommendations(self):
        """Test use case recommendations"""
        profile = self.profiler.profile_algorithm("CRYSTALS-Kyber-768")

        # Kyber should be recommended for key exchange
        self.assertIn("key_exchange", profile.use_case_recommendations)

        # Kyber-768 (level 3) should be for financial services
        self.assertIn("financial_services", profile.use_case_recommendations)

    def test_known_limitations(self):
        """Test known limitations identification"""
        # SPHINCS+ has large signature size
        sphincs_profile = self.profiler.profile_algorithm("SPHINCS+-256f")
        self.assertIn("large_signature_size", sphincs_profile.known_limitations)

    def test_algorithm_comparison(self):
        """Test algorithm comparison functionality"""
        algorithms = ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"]

        comparison = self.profiler.compare_algorithms(algorithms)

        self.assertIn("algorithms", comparison)
        self.assertIn("profiles", comparison)
        self.assertIn("rankings", comparison)
        self.assertEqual(len(comparison["algorithms"]), 3)
        self.assertEqual(len(comparison["rankings"]["performance"]), 3)

        # Rankings should be ordered
        ranks = [r["rank"] for r in comparison["rankings"]["performance"]]
        self.assertEqual(ranks, [1, 2, 3])

    def test_optimization_guidance(self):
        """Test optimization guidance generation"""
        guidance = self.profiler.get_optimization_guidance("CRYSTALS-Dilithium-5")

        self.assertIn("algorithm", guidance)
        self.assertIn("performance_score", guidance)
        self.assertIn("bottlenecks", guidance)
        self.assertIn("optimizations", guidance)
        self.assertIn("deployment_tips", guidance)
        self.assertGreater(len(guidance["deployment_tips"]), 0)

    def test_report_generation(self):
        """Test comprehensive report generation"""
        # Profile some algorithms first
        self.profiler.profile_algorithm("CRYSTALS-Kyber-768")
        self.profiler.profile_algorithm("CRYSTALS-Dilithium-3")

        report = self.profiler.generate_report()

        self.assertIn("report_version", report)
        self.assertIn("generated_at", report)
        self.assertIn("system_info", report)
        self.assertIn("algorithm_profiles", report)
        self.assertIn("summary_statistics", report)
        self.assertEqual(report["report_version"], "v3")

    def test_algorithm_profile_to_dict(self):
        """Test algorithm profile dictionary conversion"""
        profile = self.profiler.profile_algorithm("CRYSTALS-Kyber-512")
        profile_dict = profile.to_dict()

        self.assertIn("algorithm", profile_dict)
        self.assertIn("security_level", profile_dict)
        self.assertIn("nist_standardized", profile_dict)
        self.assertIn("benchmarks", profile_dict)
        self.assertIn("performance_score", profile_dict)
        self.assertIn("efficiency_rating", profile_dict)
        self.assertIn("use_case_recommendations", profile_dict)
        self.assertIn("known_limitations", profile_dict)

    def test_security_level_enum(self):
        """Test security level enum values"""
        self.assertEqual(SecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(SecurityLevel.LEVEL_3.value, 3)
        self.assertEqual(SecurityLevel.LEVEL_5.value, 5)

    def test_pq_algorithm_enum(self):
        """Test PQ algorithm enum values"""
        self.assertIn("CRYSTALS-Kyber-768", [a.value for a in PQAlgorithm])
        self.assertIn("CRYSTALS-Dilithium-3", [a.value for a in PQAlgorithm])
        self.assertIn("Falcon-512", [a.value for a in PQAlgorithm])
        self.assertIn("SPHINCS+-128f", [a.value for a in PQAlgorithm])

    def test_benchmark_metric_enum(self):
        """Test benchmark metric enum"""
        metrics = [m.value for m in BenchmarkMetric]
        self.assertIn("key_gen_time", metrics)
        self.assertIn("signing_time", metrics)
        self.assertIn("public_key_size", metrics)
        self.assertIn("throughput", metrics)

    def test_benchmark_runner_system_info(self):
        """Test benchmark runner system info collection"""
        runner = BenchmarkRunner(iterations=10)
        sys_info = runner.system_info

        self.assertIn("platform", sys_info)
        self.assertIn("architecture", sys_info)
        self.assertIn("cpu_count", sys_info)
        self.assertIn("benchmark_version", sys_info)
        self.assertEqual(sys_info["benchmark_version"], "v3")

    def test_size_benchmark(self):
        """Test size benchmark functionality"""
        runner = BenchmarkRunner(iterations=10)
        result = runner.run_size_benchmark("CRYSTALS-Kyber-768", "public_key")

        self.assertEqual(result.metric, "public_key_size")
        self.assertEqual(result.unit, "bytes")
        self.assertGreater(result.mean_value, 0)

    def test_multiple_profiling_calls(self):
        """Test multiple profiling calls don't cause issues"""
        # Profile same algorithm multiple times
        profile1 = self.profiler.profile_algorithm("CRYSTALS-Kyber-512")
        profile2 = self.profiler.profile_algorithm("CRYSTALS-Kyber-512")

        # Should return same cached profile
        self.assertEqual(profile1.algorithm, profile2.algorithm)

    def test_benchmark_history_tracking(self):
        """Test benchmark history tracking"""
        initial_count = len(self.profiler.benchmark_history)

        self.profiler.profile_algorithm("CRYSTALS-Kyber-512")
        self.profiler.profile_algorithm("CRYSTALS-Dilithium-2")

        final_count = len(self.profiler.benchmark_history)
        self.assertGreater(final_count, initial_count)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPQAlgorithmPerformanceProfiler)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "was_successful": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("Running Post-Quantum Algorithm Benchmark Performance Profiler v3 Tests")
    print("=" * 70)
    results = run_tests()
    print("=" * 70)
    print(f"Tests Run: {results['tests_run']}")
    print(f"Failures: {results['failures']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {results['was_successful']}")

    # Save test results
    with open("test_results_pq_benchmark_profiler_v3_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
