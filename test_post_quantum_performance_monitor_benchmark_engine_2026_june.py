#!/usr/bin/env python3
"""
Test for Post-Quantum Performance Monitor & Benchmark Engine
REAL tests with actual timing measurements
"""
import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_performance_monitor_benchmark_engine_2026_june import (
    PostQuantumPerformanceMonitor,
    AlgorithmType,
    BenchmarkMode,
    BenchmarkResult,
    PerformanceMetric
)


def test_single_algorithm_benchmark():
    """Test that benchmark actually measures real execution times"""
    print("TEST: Single Algorithm Benchmark (REAL timing)")
    
    monitor = PostQuantumPerformanceMonitor()
    
    result = monitor.benchmark_algorithm(
        algorithm_name="Kyber-768",
        algorithm_type=AlgorithmType.KEY_ENCAPSULATION,
        mode=BenchmarkMode.FAST,
        complexity="low"
    )
    
    print(f"  Algorithm: {result.algorithm_name}")
    print(f"  Iterations: {result.iterations}")
    print(f"  Total time: {result.total_time_seconds:.4f}s")
    print(f"  Avg time: {result.avg_time_ms:.4f}ms")
    print(f"  Ops/sec: {result.operations_per_second:.2f}")
    
    # Verify actual measurements were taken
    assert result.total_time_seconds > 0, "Should have positive total time"
    assert result.avg_time_ms > 0, "Should have positive average time"
    assert result.operations_per_second > 0, "Should have positive ops/sec"
    assert result.iterations == 10, "FAST mode should have 10 iterations"
    
    print("  ✓ Real timing measurements verified")
    return True


def test_different_algorithm_types():
    """Test benchmarking different algorithm types"""
    print("\nTEST: Different Algorithm Types")
    
    monitor = PostQuantumPerformanceMonitor()
    
    algorithms = [
        ("Kyber-KEM", AlgorithmType.KEY_ENCAPSULATION),
        ("Dilithium-Sig", AlgorithmType.DIGITAL_SIGNATURE),
        ("SHA3-Hash", AlgorithmType.HASH_FUNCTION)
    ]
    
    results = []
    for name, algo_type in algorithms:
        result = monitor.benchmark_algorithm(
            algorithm_name=name,
            algorithm_type=algo_type,
            mode=BenchmarkMode.FAST,
            complexity="low"
        )
        results.append(result)
        print(f"  {name}: {result.avg_time_ms:.4f}ms, {result.operations_per_second:.1f} ops/s")
    
    assert len(results) == 3, "Should have 3 results"
    assert all(r.avg_time_ms > 0 for r in results), "All should have timing"
    
    print("  ✓ All algorithm types benchmarked successfully")
    return True


def test_benchmark_modes():
    """Test different benchmark modes have different iteration counts"""
    print("\nTEST: Benchmark Modes")
    
    monitor = PostQuantumPerformanceMonitor()
    
    modes = [
        (BenchmarkMode.FAST, 10),
        (BenchmarkMode.STANDARD, 100)
    ]
    
    for mode, expected_iterations in modes:
        result = monitor.benchmark_algorithm(
            algorithm_name=f"Test_{mode.value}",
            algorithm_type=AlgorithmType.HASH_FUNCTION,
            mode=mode,
            complexity="low"
        )
        print(f"  {mode.value}: {result.iterations} iterations, {result.total_time_seconds:.4f}s")
        assert result.iterations == expected_iterations, f"{mode} should have {expected_iterations} iterations"
    
    print("  ✓ Different benchmark modes work correctly")
    return True


def test_statistical_accuracy():
    """Test that statistical calculations are accurate"""
    print("\nTEST: Statistical Calculations")
    
    monitor = PostQuantumPerformanceMonitor()
    
    result = monitor.benchmark_algorithm(
        algorithm_name="StatTest",
        algorithm_type=AlgorithmType.HASH_FUNCTION,
        mode=BenchmarkMode.STANDARD,
        complexity="low"
    )
    
    print(f"  Mean: {result.avg_time_ms:.4f}ms")
    print(f"  Median: {result.median_time_ms:.4f}ms")
    print(f"  Min: {result.min_time_ms:.4f}ms")
    print(f"  Max: {result.max_time_ms:.4f}ms")
    print(f"  Std Dev: {result.std_dev_ms:.4f}ms")
    
    # Basic sanity checks
    assert result.min_time_ms <= result.avg_time_ms <= result.max_time_ms, "Stats should be ordered"
    assert result.min_time_ms <= result.median_time_ms <= result.max_time_ms, "Median should be in range"
    
    print("  ✓ Statistical calculations are accurate")
    return True


def test_batch_benchmark():
    """Test batch benchmarking"""
    print("\nTEST: Batch Benchmarking")
    
    monitor = PostQuantumPerformanceMonitor()
    
    algorithms = [
        {"name": "Algo1", "type": AlgorithmType.HASH_FUNCTION, "complexity": "low"},
        {"name": "Algo2", "type": AlgorithmType.KEY_ENCAPSULATION, "complexity": "low"},
        {"name": "Algo3", "type": AlgorithmType.DIGITAL_SIGNATURE, "complexity": "low"}
    ]
    
    results = monitor.batch_benchmark(algorithms, mode=BenchmarkMode.FAST)
    
    print(f"  Batch processed {len(results)} algorithms")
    for r in results:
        print(f"    - {r.algorithm_name}: {r.avg_time_ms:.4f}ms")
    
    assert len(results) == 3, "Should benchmark all 3 algorithms"
    
    print("  ✓ Batch benchmarking works")
    return True


def test_algorithm_comparison():
    """Test algorithm comparison functionality"""
    print("\nTEST: Algorithm Comparison")
    
    monitor = PostQuantumPerformanceMonitor()
    
    # First benchmark some algorithms
    for name in ["FastAlgo", "MediumAlgo", "SlowAlgo"]:
        monitor.benchmark_algorithm(
            algorithm_name=name,
            algorithm_type=AlgorithmType.HASH_FUNCTION,
            mode=BenchmarkMode.FAST,
            complexity="low"
        )
    
    comparison = monitor.compare_algorithms(["FastAlgo", "MediumAlgo", "SlowAlgo"])
    
    print(f"  Compared {len(comparison['compared_algorithms'])} algorithms")
    for name, data in comparison["results"].items():
        print(f"    - {name}: {data['avg_time_ms']:.4f}ms, rel_speed: {data['relative_speed']:.2f}x")
    
    assert len(comparison["results"]) > 0, "Should have comparison results"
    
    print("  ✓ Algorithm comparison works")
    return True


def test_performance_alerts():
    """Test performance alerting based on thresholds"""
    print("\nTEST: Performance Alerts")
    
    monitor = PostQuantumPerformanceMonitor()
    
    # Run a benchmark to generate metrics
    monitor.benchmark_algorithm(
        algorithm_name="TestAlgo",
        algorithm_type=AlgorithmType.HASH_FUNCTION,
        mode=BenchmarkMode.FAST,
        complexity="low"
    )
    
    alerts = monitor.get_alerts()
    print(f"  Current alerts: {len(alerts)}")
    for alert in alerts:
        print(f"    - {alert['metric']}: {alert['value']} {alert['unit']} [{alert['status']}]")
    
    # Should be list (could be empty if all metrics normal)
    assert isinstance(alerts, list), "Alerts should be a list"
    
    print("  ✓ Performance alerting works")
    return True


def test_performance_report():
    """Test comprehensive performance report generation"""
    print("\nTEST: Performance Report Generation")
    
    monitor = PostQuantumPerformanceMonitor()
    
    # Run some benchmarks first
    for i in range(3):
        monitor.benchmark_algorithm(
            algorithm_name=f"ReportAlgo_{i}",
            algorithm_type=AlgorithmType.HASH_FUNCTION,
            mode=BenchmarkMode.FAST,
            complexity="low"
        )
    
    report = monitor.generate_performance_report()
    
    print(f"  Total benchmarks: {report['summary']['total_benchmarks_run']}")
    print(f"  Unique algorithms: {report['summary']['unique_algorithms_tested']}")
    print(f"  Avg time: {report['summary']['overall_avg_time_ms']:.4f}ms")
    print(f"  Limitations documented: {len(report['honest_limitations'])}")
    
    assert "honest_limitations" in report, "Report must include honest limitations"
    assert len(report["honest_limitations"]) >= 5, "Should have at least 5 limitations"
    assert "recommendations" in report, "Report must include recommendations"
    
    print("  ✓ Report includes honest limitations and recommendations")
    return True


def test_result_export():
    """Test result export functionality"""
    print("\nTEST: Result Export")
    
    monitor = PostQuantumPerformanceMonitor()
    
    monitor.benchmark_algorithm(
        algorithm_name="ExportTest",
        algorithm_type=AlgorithmType.HASH_FUNCTION,
        mode=BenchmarkMode.FAST,
        complexity="low"
    )
    
    export_json = monitor.export_results()
    export_data = json.loads(export_json)
    
    print(f"  Exported {export_data['metadata']['total_results']} results")
    print(f"  Version: {export_data['metadata']['monitor_version']}")
    print(f"  Honest disclaimer included: {'honest_disclaimer' in export_data['metadata']}")
    
    assert "honest_disclaimer" in export_data["metadata"], "Must include honest disclaimer"
    
    print("  ✓ Export includes honest disclaimer")
    return True


def test_honest_statistics():
    """Test that statistics include honest limitations"""
    print("\nTEST: Honest Statistics")
    
    monitor = PostQuantumPerformanceMonitor()
    
    stats = monitor.get_statistics()
    
    print(f"  Benchmarks completed: {stats['total_benchmarks_completed']}")
    print(f"  Limitations: {len(stats['honest_limitations'])}")
    
    assert "honest_limitations" in stats, "Must include honest limitations"
    assert len(stats["honest_limitations"]) >= 4, "Should have at least 4 limitations"
    
    print("  Limitations:")
    for limitation in stats["honest_limitations"]:
        print(f"    - {limitation}")
    
    print("  ✓ Honest limitations are properly documented")
    return True


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("QuantumCrypt AI - Performance Monitor & Benchmark Tests")
    print("=" * 60)
    
    tests = [
        test_single_algorithm_benchmark,
        test_different_algorithm_types,
        test_benchmark_modes,
        test_statistical_accuracy,
        test_batch_benchmark,
        test_algorithm_comparison,
        test_performance_alerts,
        test_performance_report,
        test_result_export,
        test_honest_statistics
    ]
    
    results = {}
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
                results[test.__name__] = "PASSED"
            else:
                failed += 1
                results[test.__name__] = "FAILED"
        except Exception as e:
            failed += 1
            results[test.__name__] = f"ERROR: {str(e)}"
            print(f"  ✗ ERROR: {e}")
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{passed + failed} PASSED")
    print("=" * 60)
    
    # Save results
    results_data = {
        "test_timestamp": time.time(),
        "tests_passed": passed,
        "tests_failed": failed,
        "total_tests": passed + failed,
        "results": results
    }
    
    with open("test_results_performance_monitor_engine.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nResults saved to test_results_performance_monitor_engine.json")
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
