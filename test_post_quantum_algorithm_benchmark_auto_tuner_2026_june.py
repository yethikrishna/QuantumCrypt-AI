#!/usr/bin/env python3
"""
Test suite for Post-Quantum Algorithm Benchmark Auto-Tuner
Production-grade testing with real assertions and performance validation.
"""

import sys
import time
import json

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_algorithm_benchmark_auto_tuner_2026_june import (
    PQAlgorithmBenchmark,
    PQAlgorithmAutoTuner,
    PQAlgorithm,
    OptimizationTarget,
    HardwareProfile,
    TuningParameters,
    BenchmarkResult
)


def test_benchmark_execution():
    """Test actual benchmark execution with timing measurements"""
    print("Test 1: Benchmark Execution")

    benchmark = PQAlgorithmBenchmark()

    # Run real benchmark with timing
    result = benchmark.run_benchmark(
        PQAlgorithm.KYBER_768,
        operation="keygen",
        iterations=50
    )

    assert isinstance(result, BenchmarkResult), "Should return BenchmarkResult"
    assert result.algorithm == PQAlgorithm.KYBER_768
    assert result.iterations == 50
    assert result.total_time_ms > 0, "Should have measured time"
    assert result.avg_time_ms > 0, "Should have average time"
    assert result.operations_per_second > 0, "Should have ops/sec calculation"

    print(f"    KYBER-768 keygen: {result.avg_time_ms:.4f}ms avg")
    print(f"    Throughput: {result.operations_per_second:.1f} ops/sec")
    print("  ✓ PASSED: Benchmark execution works correctly")
    return True


def test_comparative_benchmark():
    """Test comparative benchmark across multiple algorithms"""
    print("\nTest 2: Comparative Benchmark")

    benchmark = PQAlgorithmBenchmark()

    algorithms = [
        PQAlgorithm.KYBER_512,
        PQAlgorithm.KYBER_768,
        PQAlgorithm.ECDSA_P256,
    ]

    results = benchmark.run_comparative_benchmark(
        algorithms,
        operations=["keygen", "verify"],
        iterations=30
    )

    assert len(results) >= 4, "Should have results for each algo+op"

    for key, result in results.items():
        assert result.avg_time_ms > 0, f"Result {key} should have timing"

    print(f"    Completed {len(results)} benchmark runs")
    print("  ✓ PASSED: Comparative benchmark works correctly")
    return True


def test_hardware_detection():
    """Test hardware profile detection"""
    print("\nTest 3: Hardware Detection")

    profile = HardwareProfile.detect()

    assert profile.cpu_cores > 0, "Should detect CPU cores"
    assert profile.architecture is not None, "Should detect architecture"
    assert isinstance(profile.has_aes_ni, bool), "Should have AES-NI detection"
    assert isinstance(profile.has_avx2, bool), "Should have AVX2 detection"

    hw_dict = profile.to_dict()
    assert "cpu_cores" in hw_dict
    assert "total_memory_gb" in hw_dict

    print(f"    CPU Cores: {profile.cpu_cores}")
    print(f"    Architecture: {profile.architecture}")
    print("  ✓ PASSED: Hardware detection works correctly")
    return True


def test_algorithm_recommendation():
    """Test algorithm recommendation engine"""
    print("\nTest 4: Algorithm Recommendation")

    tuner = PQAlgorithmAutoTuner()

    # Test different optimization targets
    for target in [
        OptimizationTarget.LATENCY,
        OptimizationTarget.THROUGHPUT,
        OptimizationTarget.MEMORY,
        OptimizationTarget.BALANCED
    ]:
        recommendations = tuner.recommend_algorithms(
            use_case="test",
            target=target,
            security_level_min=2,
            top_n=3
        )

        assert len(recommendations) == 3, f"Should return top 3 for {target.value}"
        assert all(r.score > 0 for r in recommendations), "All should have positive scores"
        assert all(r.confidence >= 0.7 for r in recommendations), "Should have confidence"

        # Verify scores are sorted
        scores = [r.score for r in recommendations]
        assert scores == sorted(scores, reverse=True), "Should be sorted descending"

    print(f"    Tested {len(OptimizationTarget)} optimization targets")
    print("  ✓ PASSED: Algorithm recommendation works correctly")
    return True


def test_recommendation_use_cases():
    """Test recommendations for different use cases"""
    print("\nTest 5: Use Case Recommendations")

    tuner = PQAlgorithmAutoTuner()

    # TLS Server (throughput optimized)
    tls_recs = tuner.recommend_algorithms(
        "tls_server",
        OptimizationTarget.THROUGHPUT,
        top_n=3
    )
    assert len(tls_recs) == 3

    # Embedded IoT (memory optimized)
    iot_recs = tuner.recommend_algorithms(
        "embedded_iot",
        OptimizationTarget.MEMORY,
        security_level_min=1,
        top_n=3
    )
    assert len(iot_recs) == 3

    # Code signing (balanced)
    code_recs = tuner.recommend_algorithms(
        "code_signing",
        OptimizationTarget.BALANCED,
        top_n=3
    )
    assert len(code_recs) == 3

    print("    TLS Server recommendations generated")
    print("    Embedded IoT recommendations generated")
    print("    Code Signing recommendations generated")
    print("  ✓ PASSED: Use case recommendations work correctly")
    return True


def test_parameter_optimization():
    """Test hardware-aware parameter optimization"""
    print("\nTest 6: Parameter Optimization")

    tuner = PQAlgorithmAutoTuner()

    for target in OptimizationTarget:
        params = tuner._optimize_parameters(PQAlgorithm.KYBER_768, target)
        assert isinstance(params, TuningParameters)
        assert params.batch_size > 0
        assert params.parallel_workers >= 1

        # Verify target-specific optimizations
        if target == OptimizationTarget.THROUGHPUT:
            assert params.batch_size >= 100, "Throughput should use larger batches"
        if target == OptimizationTarget.MEMORY:
            assert params.memory_optimization is True, "Memory target should optimize memory"

    print(f"    Optimized parameters for {len(OptimizationTarget)} targets")
    print("  ✓ PASSED: Parameter optimization works correctly")
    return True


def test_tuning_report_generation():
    """Test comprehensive tuning report generation"""
    print("\nTest 7: Tuning Report Generation")

    tuner = PQAlgorithmAutoTuner()
    report = tuner.generate_tuning_report()

    assert "timestamp" in report
    assert "hardware_profile" in report
    assert "recommendations" in report

    recs = report["recommendations"]
    assert "tls_server" in recs
    assert "code_signing" in recs
    assert "embedded_iot" in recs

    # Verify report structure
    assert len(recs["tls_server"]) == 3
    assert "algorithm" in recs["tls_server"][0]
    assert "score" in recs["tls_server"][0]

    print("    Generated complete tuning report")
    print("  ✓ PASSED: Tuning report generation works correctly")
    return True


def test_benchmark_statistics():
    """Test benchmark statistical calculations"""
    print("\nTest 8: Benchmark Statistics")

    benchmark = PQAlgorithmBenchmark()

    result = benchmark.run_benchmark(
        PQAlgorithm.DILITHIUM_3,
        operation="sign",
        iterations=100
    )

    # Verify statistical calculations
    assert result.min_time_ms <= result.avg_time_ms <= result.max_time_ms
    assert result.std_dev_ms >= 0
    assert result.total_time_ms == pytest.approx(
        result.avg_time_ms * result.iterations,
        rel=0.1  # Allow 10% tolerance for variance
    )

    result_dict = result.to_dict()
    assert all(isinstance(v, (str, int, float)) for v in result_dict.values())

    print(f"    Min: {result.min_time_ms:.4f}ms")
    print(f"    Avg: {result.avg_time_ms:.4f}ms")
    print(f"    Max: {result.max_time_ms:.4f}ms")
    print(f"    StdDev: {result.std_dev_ms:.4f}ms")
    print("  ✓ PASSED: Benchmark statistics calculated correctly")
    return True


def test_security_level_filtering():
    """Test security level filtering in recommendations"""
    print("\nTest 9: Security Level Filtering")

    tuner = PQAlgorithmAutoTuner()

    # High security requirement
    high_sec = tuner.recommend_algorithms(
        "high_value",
        OptimizationTarget.BALANCED,
        security_level_min=4,
        top_n=5
    )

    # All recommended should meet security requirement
    for rec in high_sec:
        sec_level = tuner.benchmark.SECURITY_LEVELS.get(rec.algorithm, 0)
        assert sec_level >= 4, f"{rec.algorithm} should meet security level 4"

    print(f"    Found {len(high_sec)} algorithms meeting security level >= 4")
    print("  ✓ PASSED: Security level filtering works correctly")
    return True


def test_baseline_establishment():
    """Test baseline performance establishment"""
    print("\nTest 10: Baseline Establishment")

    benchmark = PQAlgorithmBenchmark()
    benchmark.establish_baseline()

    assert len(benchmark.baseline_results) > 0, "Should have baseline results"

    for key, result in benchmark.baseline_results.items():
        assert result.avg_time_ms > 0, f"Baseline {key} should have timing"

    print(f"    Established {len(benchmark.baseline_results)} baseline measurements")
    print("  ✓ PASSED: Baseline establishment works correctly")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Post-Quantum Algorithm Benchmark Auto-Tuner - Test Suite")
    print("=" * 60)

    tests = [
        test_benchmark_execution,
        test_comparative_benchmark,
        test_hardware_detection,
        test_algorithm_recommendation,
        test_recommendation_use_cases,
        test_parameter_optimization,
        test_tuning_report_generation,
        test_benchmark_statistics,
        test_security_level_filtering,
        test_baseline_establishment,
    ]

    passed = 0
    failed = 0
    results = {}

    for test in tests:
        try:
            if test():
                passed += 1
                results[test.__name__] = "PASSED"
            else:
                failed += 1
                results[test.__name__] = "FAILED"
        except Exception as e:
            failed += 1
            results[test.__name__] = f"ERROR: {str(e)}"
            print(f"  ✗ FAILED with exception: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)

    # Write test results
    test_output = {
        "timestamp": time.time(),
        "test_module": "post_quantum_algorithm_benchmark_auto_tuner",
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "results": results
    }

    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_algorithm_benchmark_auto_tuner.json", "w") as f:
        json.dump(test_output, f, indent=2)

    print(f"\nTest results written to test_results_algorithm_benchmark_auto_tuner.json")

    return passed, failed


if __name__ == "__main__":
    # pytest compatibility helper
    class pytest:
        @staticmethod
        def approx(value, rel=0.1):
            class Approx:
                def __init__(self, v, r):
                    self.v = v
                    self.r = r
                def __eq__(self, other):
                    return abs(other - self.v) <= abs(self.v * self.r)
            return Approx(value, rel)

    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
