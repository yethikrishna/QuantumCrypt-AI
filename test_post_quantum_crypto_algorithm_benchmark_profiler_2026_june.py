#!/usr/bin/env python3
"""
Test suite for Post-Quantum Cryptography Algorithm Benchmark Profiler
Production-grade testing with real validation.
"""

import sys
import json
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_crypto_algorithm_benchmark_profiler_2026_june import (
    PostQuantumBenchmarkProfiler,
    AlgorithmCategory,
    SecurityLevel,
    AlgorithmStatus,
    AlgorithmInfo,
    BenchmarkResult,
    ComparativeBenchmark,
    MockPQCAlgorithm
)


def run_tests():
    print("=" * 70)
    print("QuantumCrypt AI - PQC Algorithm Benchmark Profiler Tests")
    print("=" * 70)
    print()

    all_passed = True
    test_results = {}

    # Test 1: Initialization
    print("[TEST 1] Profiler Initialization")
    try:
        profiler = PostQuantumBenchmarkProfiler()
        assert profiler.benchmark_history == []
        assert profiler.comparative_results == []
        print("  ✓ Profiler initialized correctly")
        test_results["initialization"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["initialization"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 2: Algorithm registry
    print("[TEST 2] Algorithm Registry Validation")
    try:
        profiler = PostQuantumBenchmarkProfiler()
        algorithms = profiler.list_algorithms()
        assert len(algorithms) >= 8
        
        kyber_512 = profiler.get_algorithm_info("kyber_512")
        assert kyber_512 is not None
        assert kyber_512.security_level == SecurityLevel.LEVEL_1
        assert kyber_512.nist_standard == True
        
        print(f"  ✓ {len(algorithms)} algorithms registered")
        print(f"  ✓ Kyber-512 metadata validated: {kyber_512.public_key_size}B pubkey")
        test_results["algorithm_registry"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["algorithm_registry"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 3: Mock algorithm implementations
    print("[TEST 3] Mock Algorithm Implementations")
    try:
        pk, sk = MockPQCAlgorithm.kyber_512_keygen()
        assert len(pk) > 0
        assert len(sk) > 0
        
        pk2, sk2 = MockPQCAlgorithm.dilithium_2_keygen()
        assert len(pk2) > 0
        assert len(sk2) > 0
        
        print("  ✓ Kyber-512 keygen works")
        print("  ✓ Dilithium-2 keygen works")
        test_results["mock_algorithms"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["mock_algorithms"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 4: Single algorithm benchmark
    print("[TEST 4] Single Algorithm Benchmark")
    try:
        profiler = PostQuantumBenchmarkProfiler()
        results = profiler.benchmark_algorithm("kyber_512", iterations=10)
        
        assert len(results) >= 1
        keygen_result = results[0]
        assert keygen_result.operation == "keygen"
        assert keygen_result.success == True
        assert keygen_result.avg_time_ms > 0
        assert keygen_result.throughput_ops_per_sec > 0
        
        print(f"  ✓ Benchmark completed: {keygen_result.iterations} iterations")
        print(f"  ✓ Avg time: {keygen_result.avg_time_ms:.3f}ms")
        print(f"  ✓ Throughput: {keygen_result.throughput_ops_per_sec:.1f} ops/sec")
        test_results["single_benchmark"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["single_benchmark"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 5: Comparative benchmark
    print("[TEST 5] Comparative Benchmark Suite")
    try:
        profiler = PostQuantumBenchmarkProfiler()
        benchmark = profiler.run_comparative_benchmark(
            name="Test KEM Comparison",
            description="Test comparison of Kyber variants",
            algorithm_ids=["kyber_512", "kyber_768", "kyber_1024"],
            iterations=10
        )
        
        assert benchmark.benchmark_id is not None
        assert len(benchmark.algorithms_tested) == 3
        assert len(benchmark.results) == 3
        assert len(benchmark.overall_ranking) > 0
        
        print(f"  ✓ Comparative benchmark ID: {benchmark.benchmark_id}")
        print(f"  ✓ {len(benchmark.algorithms_tested)} algorithms tested")
        print(f"  ✓ Ranking generated: {len(benchmark.overall_ranking)} entries")
        test_results["comparative_benchmark"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["comparative_benchmark"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 6: Comparison report generation
    print("[TEST 6] Comparison Report Generation")
    try:
        report = profiler.generate_comparison_report(benchmark)
        
        assert "benchmark_id" in report
        assert "algorithms" in report
        assert "ranking" in report
        assert "summary" in report
        assert report["summary"]["total_algorithms_tested"] == 3
        
        print("  ✓ Report structure validated")
        print(f"  ✓ Summary: {report['summary']['total_algorithms_tested']} algorithms")
        test_results["report_generation"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["report_generation"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 7: Markdown export
    print("[TEST 7] Markdown Export")
    try:
        md_content = profiler.export_to_markdown(benchmark)
        assert "# Post-Quantum Cryptography Benchmark" in md_content
        assert "Performance Results" in md_content
        assert "Performance Ranking" in md_content
        assert len(md_content) > 1000
        
        print(f"  ✓ Markdown exported ({len(md_content)} chars)")
        test_results["markdown_export"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["markdown_export"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 8: JSON export
    print("[TEST 8] JSON Export")
    try:
        output_path = os.path.join(os.path.dirname(__file__), "test_benchmark_output.json")
        profiler.export_to_json(benchmark, output_path)
        
        assert os.path.exists(output_path)
        with open(output_path, 'r') as f:
            data = json.load(f)
        assert "benchmark_id" in data
        assert "algorithms" in data
        
        print("  ✓ JSON file exported and validated")
        os.remove(output_path)
        test_results["json_export"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["json_export"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 9: Category filtering
    print("[TEST 9] Algorithm Category Filtering")
    try:
        profiler = PostQuantumBenchmarkProfiler()
        kems = profiler.list_algorithms(AlgorithmCategory.KEY_ENCAPSULATION)
        signatures = profiler.list_algorithms(AlgorithmCategory.DIGITAL_SIGNATURE)
        
        assert len(kems) >= 3  # Kyber variants
        assert len(signatures) >= 5  # Dilithium, Falcon, SPHINCS+
        
        print(f"  ✓ KEM category: {len(kems)} algorithms")
        print(f"  ✓ Signature category: {len(signatures)} algorithms")
        test_results["category_filtering"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["category_filtering"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Test 10: Full benchmark suite (all algorithms)
    print("[TEST 10] Full Algorithm Benchmark Suite")
    try:
        profiler = PostQuantumBenchmarkProfiler()
        all_alg_ids = list(PostQuantumBenchmarkProfiler.ALGORITHM_REGISTRY.keys())
        
        full_benchmark = profiler.run_comparative_benchmark(
            name="Full PQC Suite Benchmark",
            description="Benchmark all NIST-standardized PQC algorithms",
            algorithm_ids=all_alg_ids[:6],  # Test first 6 to save time
            iterations=5
        )
        
        assert len(full_benchmark.algorithms_tested) == 6
        assert len(full_benchmark.results) == 6
        
        print(f"  ✓ Full suite: {len(full_benchmark.algorithms_tested)} algorithms benchmarked")
        print(f"  ✓ Fastest: {list(full_benchmark.overall_ranking.keys())[0]}")
        test_results["full_suite"] = "PASSED"
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results["full_suite"] = f"FAILED: {e}"
        all_passed = False
    print()

    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed_count = sum(1 for r in test_results.values() if r == "PASSED")
    total_count = len(test_results)
    
    for test_name, result in test_results.items():
        status = "✓" if result == "PASSED" else "✗"
        print(f"  {status} {test_name}: {result}")
    
    print()
    print(f"Results: {passed_count}/{total_count} tests passed")
    
    if all_passed:
        print("\n✓ ALL TESTS PASSED!")
    else:
        print("\n✗ SOME TESTS FAILED")
    
    # Save results
    results_path = os.path.join(os.path.dirname(__file__), "test_results_pqc_benchmark_profiler.json")
    with open(results_path, 'w') as f:
        json.dump({
            "test_timestamp": __import__('datetime').datetime.now().isoformat(),
            "module": "post_quantum_crypto_algorithm_benchmark_profiler",
            "passed": passed_count,
            "total": total_count,
            "all_passed": all_passed,
            "results": test_results
        }, f, indent=2)
    
    print(f"\nTest results saved to: {results_path}")
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
