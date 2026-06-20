#!/usr/bin/env python3
"""
Test suite for Post-Quantum Performance Monitor & Benchmark Engine
Production-grade tests with real validation
June 2026
"""

import sys
import os
import json
import time

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_performance_monitor_benchmark_engine_2026_june import (
    PostQuantumPerformanceBenchmarkEngine,
    AlgorithmBenchmarker,
    PerformanceMonitor,
    PerformanceAnalyzer,
    BenchmarkResult,
    OptimizationRecommendation
)


def test_algorithm_benchmarker():
    """Test algorithm benchmarking functionality"""
    print("=== Testing Algorithm Benchmarker ===")
    
    benchmarker = AlgorithmBenchmarker()
    
    # Test hash algorithm benchmarking
    hash_results = benchmarker.benchmark_hash_algorithms()
    print(f"  Hash benchmarks completed: {len(hash_results)} algorithms")
    
    for result in hash_results[:3]:
        print(f"    - {result.algorithm_name}: {result.operations_per_second:.0f} ops/sec, {result.avg_time_ms:.4f}ms avg")
    
    # Test symmetric operations
    sym_results = benchmarker.benchmark_symmetric_operations()
    print(f"  Symmetric benchmarks completed: {len(sym_results)} algorithms")
    
    # Test post-quantum KEM
    pq_results = benchmarker.benchmark_post_quantum_kem()
    print(f"  PQ KEM benchmarks completed: {len(pq_results)} operations")
    
    assert len(hash_results) > 0
    assert len(sym_results) > 0
    assert len(pq_results) > 0
    
    return True


def test_performance_monitor():
    """Test performance monitoring functionality"""
    print("\n=== Testing Performance Monitor ===")
    
    monitor = PerformanceMonitor()
    
    # Record some metrics
    for i in range(25):
        monitor.record_metric(
            metric_type='latency',
            value=0.5 + i * 0.01,
            unit='ms',
            algorithm='SHA-256',
            tags={'operation': 'hash'}
        )
    
    metrics = monitor.get_current_metrics()
    print(f"  Metrics recorded: {len(monitor.metrics_history)}")
    print(f"  Summary entries: {len(metrics['summary'])}")
    print(f"  Baselines established: {len(metrics['baselines'])}")
    
    assert len(monitor.metrics_history) == 25
    
    return True


def test_performance_analyzer():
    """Test performance analysis functionality"""
    print("\n=== Testing Performance Analyzer ===")
    
    analyzer = PerformanceAnalyzer()
    benchmarker = AlgorithmBenchmarker()
    
    # Get some benchmark results
    results = benchmarker.benchmark_hash_algorithms()
    
    # Test baseline comparison
    comparisons = [analyzer.compare_to_baseline(r) for r in results]
    print(f"  Baseline comparisons: {len(comparisons)}")
    
    for comp in comparisons[:3]:
        print(f"    - {comp['algorithm']}: {comp['rating']} ({comp['measured_ops_per_sec']:.0f} ops/sec)")
    
    # Test recommendations
    recommendations = analyzer.generate_recommendations(results)
    print(f"  Recommendations generated: {len(recommendations)}")
    
    for rec in recommendations[:3]:
        print(f"    - [{rec.severity}] {rec.algorithm}: {rec.recommendation[:50]}...")
    
    # Test comparative report
    report = analyzer.generate_comparative_report(results)
    print(f"  Report algorithms tested: {report['algorithms_tested']}")
    print(f"  Fastest algorithm: {report['fastest_by_ops']}")
    print(f"  Most efficient: {report['most_efficient']}")
    
    assert len(comparisons) > 0
    assert report['algorithms_tested'] > 0
    
    return True


def test_full_benchmark_suite():
    """Test the complete benchmark suite"""
    print("\n=== Testing Full Benchmark Suite ===")
    
    engine = PostQuantumPerformanceBenchmarkEngine()
    
    result = engine.run_full_benchmark_suite()
    
    print(f"  Suite run ID: {result['run_id']}")
    print(f"  Duration: {result['duration_seconds']:.2f}s")
    print(f"  Total benchmarks: {result['total_benchmarks']}")
    print(f"  Comparisons: {len(result['comparisons'])}")
    print(f"  Recommendations: {len(result['recommendations'])}")
    
    print("\n  Algorithm Performance Summary:")
    for algo, summary in result['report']['algorithm_summary'].items():
        print(f"    - {algo}: {summary['avg_operations_per_second']:.0f} ops/sec")
    
    assert result['total_benchmarks'] > 0
    assert result['duration_seconds'] > 0
    
    return True


def test_performance_dashboard():
    """Test performance dashboard functionality"""
    print("\n=== Testing Performance Dashboard ===")
    
    engine = PostQuantumPerformanceBenchmarkEngine()
    
    # Run benchmarks first
    engine.run_full_benchmark_suite()
    
    # Record some monitoring data
    for i in range(10):
        engine.monitor_operation('SHA-256', 'hash', 0.45 + i * 0.01)
    
    dashboard = engine.get_performance_dashboard()
    
    print(f"  Benchmark suites executed: {dashboard['benchmark_history_count']}")
    print(f"  Total benchmarks executed: {dashboard['total_benchmarks_executed']}")
    print(f"  Algorithms benchmarked: {dashboard['algorithms_benchmarked']}")
    print(f"  Monitoring alerts: {len(dashboard['monitoring']['alerts'])}")
    
    assert dashboard['total_benchmarks_executed'] > 0
    
    return True


def test_export_functionality():
    """Test benchmark result export"""
    print("\n=== Testing Export Functionality ===")
    
    engine = PostQuantumPerformanceBenchmarkEngine()
    engine.run_full_benchmark_suite()
    
    # Test JSON export
    json_export = engine.export_benchmark_results('json')
    print(f"  JSON export length: {len(json_export)} chars")
    
    # Parse and validate
    parsed = json.loads(json_export)
    print(f"  Exported benchmarks: {len(parsed)}")
    
    # Test CSV export
    csv_export = engine.export_benchmark_results('csv')
    print(f"  CSV export length: {len(csv_export)} chars")
    print(f"  CSV lines: {len(csv_export.splitlines())}")
    
    assert len(parsed) > 0
    assert len(csv_export.splitlines()) > 1
    
    return True


def test_engine_statistics():
    """Test engine statistics tracking"""
    print("\n=== Testing Engine Statistics ===")
    
    engine = PostQuantumPerformanceBenchmarkEngine()
    
    # Run multiple suites
    for i in range(3):
        engine.run_full_benchmark_suite()
    
    stats = engine.get_statistics()
    print(f"  Total benchmarks run: {stats['total_benchmarks_run']}")
    print(f"  Benchmark suites executed: {stats['benchmark_suites_executed']}")
    print(f"  Metrics recorded: {stats['metrics_recorded']}")
    print(f"  Alerts generated: {stats['alerts_generated']}")
    
    assert stats['benchmark_suites_executed'] == 3
    assert stats['total_benchmarks_run'] > 0
    
    return True


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("Post-Quantum Performance Monitor & Benchmark Engine Tests")
    print("=" * 60)
    print(f"Test started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("Algorithm Benchmarker", test_algorithm_benchmarker),
        ("Performance Monitor", test_performance_monitor),
        ("Performance Analyzer", test_performance_analyzer),
        ("Full Benchmark Suite", test_full_benchmark_suite),
        ("Performance Dashboard", test_performance_dashboard),
        ("Export Functionality", test_export_functionality),
        ("Engine Statistics", test_engine_statistics),
    ]
    
    results = {}
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                results[test_name] = "PASSED"
                passed += 1
            else:
                results[test_name] = "FAILED"
                failed += 1
        except Exception as e:
            results[test_name] = f"ERROR: {str(e)}"
            failed += 1
            print(f"  EXCEPTION: {e}")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "✓" if result == "PASSED" else "✗"
        print(f"  {status} {test_name}: {result}")
    
    print(f"\n  Total: {passed} PASSED, {failed} FAILED")
    print(f"  Success rate: {passed/(passed+failed)*100:.1f}%")
    
    # Save results
    result_data = {
        "test_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "module": "post_quantum_performance_monitor_benchmark_engine",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed/(passed+failed)*100,
        "results": results
    }
    
    with open("test_results_performance_monitor_benchmark_engine.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\n  Results saved to test_results_performance_monitor_benchmark_engine.json")
    print("=" * 60)
    
    return passed == len(tests)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
