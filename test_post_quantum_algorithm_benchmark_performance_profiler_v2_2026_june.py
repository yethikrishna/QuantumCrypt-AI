"""
Test suite for Post-Quantum Algorithm Benchmark & Performance Profiler v2
Real production-grade tests with actual verification
"""
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantum_crypt.post_quantum_algorithm_benchmark_performance_profiler_v2_2026_june import (
    PQAlgorithm,
    AlgorithmType,
    SecurityLevel,
    BenchmarkResult,
    AlgorithmProfile,
    PQKeySimulator,
    PerformanceProfiler,
    BenchmarkEngine
)
def run_tests():
    """Run all tests and return results"""
    results = {
        "test_timestamp": __import__('time').time(),
        "module": "post_quantum_algorithm_benchmark_performance_profiler_v2_2026_june",
        "tests_passed": 0,
        "tests_failed": 0,
        "test_cases": [],
        "summary": {}
    }
    
    # Test 1: PQKeySimulator initialization
    print("Test 1: PQKeySimulator initialization")
    try:
        simulator = PQKeySimulator()
        passed = simulator is not None and hasattr(simulator, 'key_sizes')
        print(f"  Simulator created: {simulator is not None}, key_sizes exists: {hasattr(simulator, 'key_sizes')}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "simulator_initialization",
            "passed": passed
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "simulator_initialization", "passed": False, "error": str(e)})
    
    # Test 2: Key generation for Kyber-512
    print("Test 2: Key generation for Kyber-512")
    try:
        simulator = PQKeySimulator()
        pub, priv = simulator.generate_keypair(PQAlgorithm.CRYSTALS_KYBER_512)
        passed = len(pub) == 800 and len(priv) == 1632
        print(f"  Public key size: {len(pub)}, Private key size: {len(priv)}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "kyber_512_keygen",
            "passed": passed,
            "pub_key_size": len(pub),
            "priv_key_size": len(priv)
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "kyber_512_keygen", "passed": False, "error": str(e)})
    
    # Test 3: KEM Encapsulation
    print("Test 3: KEM Encapsulation")
    try:
        simulator = PQKeySimulator()
        pub, priv = simulator.generate_keypair(PQAlgorithm.CRYSTALS_KYBER_768)
        ct, ss = simulator.encapsulate(PQAlgorithm.CRYSTALS_KYBER_768, pub)
        passed = len(ct) == 1088 and len(ss) == 32
        print(f"  Ciphertext size: {len(ct)}, Shared secret size: {len(ss)}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "kem_encapsulation",
            "passed": passed,
            "ciphertext_size": len(ct),
            "shared_secret_size": len(ss)
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "kem_encapsulation", "passed": False, "error": str(e)})
    
    # Test 4: KEM Decapsulation
    print("Test 4: KEM Decapsulation")
    try:
        simulator = PQKeySimulator()
        pub, priv = simulator.generate_keypair(PQAlgorithm.CRYSTALS_KYBER_768)
        ct, _ = simulator.encapsulate(PQAlgorithm.CRYSTALS_KYBER_768, pub)
        ss2 = simulator.decapsulate(PQAlgorithm.CRYSTALS_KYBER_768, priv, ct)
        passed = len(ss2) == 32
        print(f"  Decapsulated secret size: {len(ss2)}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "kem_decapsulation",
            "passed": passed,
            "decapsulated_size": len(ss2)
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "kem_decapsulation", "passed": False, "error": str(e)})
    
    # Test 5: Signature generation
    print("Test 5: Signature generation (Dilithium)")
    try:
        simulator = PQKeySimulator()
        pub, priv = simulator.generate_keypair(PQAlgorithm.CRYSTALS_DILITHIUM_2)
        msg = b"Test message for signing"
        sig = simulator.sign(PQAlgorithm.CRYSTALS_DILITHIUM_2, priv, msg)
        passed = len(sig) == 2420
        print(f"  Signature size: {len(sig)}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "signature_generation",
            "passed": passed,
            "signature_size": len(sig)
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "signature_generation", "passed": False, "error": str(e)})
    
    # Test 6: Signature verification
    print("Test 6: Signature verification")
    try:
        simulator = PQKeySimulator()
        pub, priv = simulator.generate_keypair(PQAlgorithm.CRYSTALS_DILITHIUM_2)
        msg = b"Test message"
        sig = simulator.sign(PQAlgorithm.CRYSTALS_DILITHIUM_2, priv, msg)
        valid = simulator.verify(PQAlgorithm.CRYSTALS_DILITHIUM_2, pub, msg, sig)
        passed = valid == True
        print(f"  Signature valid: {valid}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "signature_verification",
            "passed": passed,
            "is_valid": valid
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "signature_verification", "passed": False, "error": str(e)})
    
    # Test 7: PerformanceProfiler benchmark
    print("Test 7: PerformanceProfiler single benchmark")
    try:
        profiler = PerformanceProfiler()
        result = profiler.benchmark_operation(PQAlgorithm.CRYSTALS_KYBER_512, "keygen", iterations=10)
        passed = isinstance(result, BenchmarkResult) and result.avg_time_ms > 0 and result.operations_per_second > 0
        print(f"  Avg time: {result.avg_time_ms}ms, Ops/sec: {result.operations_per_second}, Memory: {result.peak_memory_kb}KB")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "single_benchmark",
            "passed": passed,
            "avg_time_ms": result.avg_time_ms,
            "ops_per_second": result.operations_per_second
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "single_benchmark", "passed": False, "error": str(e)})
    
    # Test 8: Algorithm profiling
    print("Test 8: Complete algorithm profiling")
    try:
        profiler = PerformanceProfiler()
        profile = profiler.profile_algorithm(PQAlgorithm.CRYSTALS_KYBER_512, iterations=5)
        passed = isinstance(profile, AlgorithmProfile) and len(profile.benchmarks) >= 3 and profile.overall_score > 0
        print(f"  Benchmarks: {list(profile.benchmarks.keys())}, Score: {profile.overall_score}, Recommendation: {profile.recommendation[:30]}...")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "algorithm_profiling",
            "passed": passed,
            "benchmark_count": len(profile.benchmarks),
            "overall_score": profile.overall_score
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "algorithm_profiling", "passed": False, "error": str(e)})
    
    # Test 9: BenchmarkEngine KEM benchmark
    print("Test 9: BenchmarkEngine KEM benchmark")
    try:
        engine = BenchmarkEngine()
        kem_results = engine.benchmark_all_kem(iterations=3)
        passed = len(kem_results) >= 4
        print(f"  KEM algorithms benchmarked: {len(kem_results)}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "kem_benchmark_batch",
            "passed": passed,
            "algorithms_benchmarked": len(kem_results)
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "kem_benchmark_batch", "passed": False, "error": str(e)})
    
    # Test 10: Comparison report generation
    print("Test 10: Comparison report generation")
    try:
        engine = BenchmarkEngine()
        engine.benchmark_all_kem(iterations=2)
        engine.benchmark_all_signatures(iterations=2)
        report = engine.generate_comparison_report()
        passed = "recommendations" in report and "fastest_keygen" in report
        print(f"  Recommendations: {len(report['recommendations'])}, Fastest keygen: {report['fastest_keygen']['algorithm']}")
        results["tests_passed" if passed else "tests_failed"] += 1
        results["test_cases"].append({
            "name": "comparison_report",
            "passed": passed,
            "recommendation_count": len(report["recommendations"]),
            "fastest_keygen": report["fastest_keygen"]["algorithm"]
        })
    except Exception as e:
        print(f"  FAILED with error: {e}")
        results["tests_failed"] += 1
        results["test_cases"].append({"name": "comparison_report", "passed": False, "error": str(e)})
    
    # Summary
    total = results["tests_passed"] + results["tests_failed"]
    results["summary"] = {
        "total_tests": total,
        "passed": results["tests_passed"],
        "failed": results["tests_failed"],
        "pass_rate": round(results["tests_passed"] / total * 100, 2) if total > 0 else 0
    }
    
    print(f"\n=== TEST SUMMARY ===")
    print(f"Total: {total}, Passed: {results['tests_passed']}, Failed: {results['tests_failed']}")
    print(f"Pass rate: {results['summary']['pass_rate']}%")
    
    return results
if __name__ == "__main__":
    test_results = run_tests()
    
    # Save results
    with open("test_results_post_quantum_algorithm_benchmark_performance_profiler_v2_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nResults saved to test_results_post_quantum_algorithm_benchmark_performance_profiler_v2_2026_june.json")
