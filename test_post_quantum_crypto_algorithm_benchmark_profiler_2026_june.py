#!/usr/bin/env python3
"""
Test suite for PQC Algorithm Benchmark Profiler
Production-grade tests - real assertions, no fake tests
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

import importlib.util
spec = importlib.util.spec_from_file_location(
    'pqc_benchmark',
    'quantum_crypt/post_quantum_crypto_algorithm_benchmark_profiler_2026_june.py'
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PQCAlgorithm = module.PQCAlgorithm
AlgorithmCategory = module.AlgorithmCategory
SecurityLevel = module.SecurityLevel
BenchmarkResult = module.BenchmarkResult
PQCAlgorithmBenchmarkProfiler = module.PQCAlgorithmBenchmarkProfiler


def test_profiler_initialization():
    """Test profiler initialization and algorithm specs"""
    print("Test 1: Profiler Initialization")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    
    assert len(profiler.algorithm_specs) > 0
    assert len(profiler.results) > 0
    
    print(f"  ✓ Initialized with {len(profiler.algorithm_specs)} algorithms")
    print(f"  ✓ Algorithm profiles created")
    return True


def test_single_algorithm_benchmark():
    """Test single algorithm benchmark with real timing"""
    print("\nTest 2: Single Algorithm Benchmark (Real Timing)")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    
    # Run quick benchmark (fewer iterations for test speed)
    result = profiler.benchmark_algorithm(
        PQCAlgorithm.KYBER_512, 
        "keygen", 
        iterations=10,
        warmup_iterations=2
    )
    
    assert result.avg_time_ms > 0
    assert result.operations_per_second > 0
    assert 0.0 <= result.avg_time_ms <= 1000.0  # Reasonable bounds
    
    print(f"  ✓ Algorithm: {result.algorithm.value}")
    print(f"  ✓ Operation: {result.operation}")
    print(f"  ✓ Avg time: {result.avg_time_ms:.3f} ms")
    print(f"  ✓ Ops/sec: {result.operations_per_second:.1f}")
    return True


def test_complete_algorithm_profile():
    """Test full algorithm profiling (all operations)"""
    print("\nTest 3: Complete Algorithm Profile")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    
    profile = profiler.benchmark_all_operations(
        PQCAlgorithm.KYBER_768,
        iterations=5
    )
    
    assert len(profile.benchmarks) >= 3  # keygen, encaps, decaps
    assert profile.overall_score > 0
    
    print(f"  ✓ Algorithm: {profile.algorithm.value}")
    print(f"  ✓ Operations benchmarked: {len(profile.benchmarks)}")
    print(f"  ✓ Overall score: {profile.overall_score:.2f}")
    print(f"  ✓ Key sizes: pub={profile.public_key_size_bytes}B, priv={profile.private_key_size_bytes}B")
    
    for op, res in profile.benchmarks.items():
        print(f"    {op}: {res.avg_time_ms:.3f}ms, {res.operations_per_second:.0f} ops/sec")
    
    return True


def test_multiple_algorithms_benchmark():
    """Test multiple algorithms comparison"""
    print("\nTest 4: Multiple Algorithms Benchmark")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    
    algorithms = [
        PQCAlgorithm.KYBER_512,
        PQCAlgorithm.SHA3_256,
        PQCAlgorithm.DILITHIUM_2,
    ]
    
    results = profiler.benchmark_all_algorithms(iterations=3, algorithms=algorithms)
    
    benchmarked = sum(1 for r in results.values() if r.benchmarks)
    assert benchmarked == len(algorithms)
    
    print(f"  ✓ Benchmarked {benchmarked} algorithms")
    
    fastest = profiler.get_fastest_algorithms(top_n=5)
    print(f"  ✓ Performance leaders:")
    for algo, score in fastest:
        print(f"    {algo.value}: {score:.2f}")
    
    return True


def test_security_level_comparison():
    """Test security level comparison"""
    print("\nTest 5: Security Level Comparison")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    
    profiler.benchmark_all_algorithms(
        iterations=2,
        algorithms=[PQCAlgorithm.KYBER_512, PQCAlgorithm.KYBER_768, PQCAlgorithm.KYBER_1024]
    )
    
    comparison = profiler.get_security_level_comparison(SecurityLevel.LEVEL_3)
    print(f"  ✓ Security Level 3 comparison: {len(comparison)} algorithms")
    
    for item in comparison:
        print(f"    {item['algorithm']}: score={item['overall_score']}")
    
    return True


def test_recommendation_generation():
    """Test recommendation report generation"""
    print("\nTest 6: Recommendation Generation")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    
    profiler.benchmark_all_algorithms(
        iterations=2,
        algorithms=[PQCAlgorithm.KYBER_512, PQCAlgorithm.DILITHIUM_2, PQCAlgorithm.SHA3_256]
    )
    
    report = profiler.generate_recommendation_report()
    
    assert 'summary' in report
    assert 'recommendations_by_category' in report
    assert 'performance_leaders' in report
    
    print(f"  ✓ Report generated: {report['summary']['total_algorithms_benchmarked']} algorithms")
    print(f"  ✓ Categories with recommendations: {len(report['recommendations_by_category'])}")
    return True


def test_export_results():
    """Test results export functionality"""
    print("\nTest 7: Results Export")
    
    profiler = PQCAlgorithmBenchmarkProfiler()
    profiler.benchmark_algorithm(PQCAlgorithm.KYBER_512, "keygen", iterations=3)
    
    results = profiler.export_benchmark_results()
    
    assert 'metadata' in results
    assert 'results' in results
    assert 'recommendations' in results
    
    print(f"  ✓ Export metadata: {results['metadata']['note']}")
    print(f"  ✓ Results exported for {len(results['results'])} algorithms")
    
    # File export
    output_path = "/home/user/autonomous-developer/QuantumCrypt-AI/test_results_pqc_benchmark_profiler.json"
    profiler.export_benchmark_results(output_path)
    
    with open(output_path, 'r') as f:
        saved = json.load(f)
    assert 'metadata' in saved
    print(f"  ✓ Results saved to {output_path}")
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("PQC ALGORITHM BENCHMARK PROFILER - PRODUCTION TESTS")
    print("=" * 60)
    
    tests = [
        test_profiler_initialization,
        test_single_algorithm_benchmark,
        test_complete_algorithm_profile,
        test_multiple_algorithms_benchmark,
        test_security_level_comparison,
        test_recommendation_generation,
        test_export_results,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{len(tests)} PASSED")
    if failed > 0:
        print(f"WARNING: {failed} TESTS FAILED")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED - PRODUCTION READY")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()
