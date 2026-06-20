"""
Test Suite for Post-Quantum Lattice Crypto Benchmark & Validation Suite v2
June 21, 2026

Production-grade tests with real assertions
"""

import json
import os
import sys
from datetime import datetime

# Add path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_lattice_crypto_benchmark_validation_suite_v2_2026_june import (
    LatticeCryptoBenchmarkV2,
    PQAlgorithm,
    OperationType,
    SecurityLevel,
    verify_lattice_benchmark_v2
)


def run_all_tests():
    """Run all test cases"""
    results = {
        "test_benchmark_single_operation": False,
        "test_benchmark_multiple_algorithms": False,
        "test_validation_correctness": False,
        "test_all_algorithms_validation": False,
        "test_comparison_report": False,
        "test_json_export": False,
        "test_algorithm_profiles": False,
        "test_statistical_calculations": False
    }
    
    print("=" * 60)
    print("Testing Lattice Crypto Benchmark v2")
    print("=" * 60)
    
    # Test 1: Single operation benchmark
    print("\n[TEST 1] Single operation benchmark...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        result = suite.benchmark_operation(
            PQAlgorithm.KYBER_768, 
            OperationType.KEYGEN, 
            iterations=20
        )
        
        assert result.algorithm == "CRYSTALS-Kyber-768"
        assert result.operation == "key_generation"
        assert result.iterations == 20
        assert result.mean_time_ms > 0
        assert result.operations_per_second > 0
        
        results["test_benchmark_single_operation"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 2: Multiple algorithms benchmark
    print("\n[TEST 2] Multiple algorithms benchmark...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        all_results = suite.benchmark_all_algorithms(iterations=10)
        
        assert len(all_results) > 0
        assert "CRYSTALS-Kyber-768" in all_results
        assert len(suite.benchmark_results) > 0
        
        results["test_benchmark_multiple_algorithms"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 3: Correctness validation
    print("\n[TEST 3] Correctness validation...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        validation = suite.validate_correctness(PQAlgorithm.KYBER_768)
        
        assert validation.algorithm == "CRYSTALS-Kyber-768"
        assert validation.test_type == "correctness_validation"
        assert validation.passed == True
        
        results["test_validation_correctness"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 4: All algorithms validation
    print("\n[TEST 4] All algorithms validation...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        validations = suite.validate_all_algorithms()
        
        assert len(validations) == len(PQAlgorithm)
        all_passed = all(v.passed for v in validations)
        assert all_passed, "Some validations failed"
        
        results["test_all_algorithms_validation"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 5: Comparison report
    print("\n[TEST 5] Comparison report generation...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        suite.benchmark_operation(PQAlgorithm.KYBER_768, OperationType.KEYGEN, 10)
        suite.validate_all_algorithms()
        
        report = suite.generate_comparison_report()
        assert "summary" in report
        assert "fastest_by_operation" in report
        assert "security_comparison" in report
        assert len(report["security_comparison"]) == len(PQAlgorithm)
        
        results["test_comparison_report"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 6: JSON export
    print("\n[TEST 6] JSON export...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        suite.benchmark_operation(PQAlgorithm.KYBER_768, OperationType.KEYGEN, 10)
        suite.validate_all_algorithms()
        
        export_path = "/tmp/test_lattice_benchmark_v2.json"
        success = suite.export_json_report(export_path)
        
        assert success
        assert os.path.exists(export_path)
        assert os.path.getsize(export_path) > 100
        
        with open(export_path) as f:
            data = json.load(f)
            assert "suite_version" in data
            assert data["suite_version"] == "v2"
            assert "benchmarks" in data
            assert "validations" in data
        
        results["test_json_export"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 7: Algorithm profiles
    print("\n[TEST 7] Algorithm profiles...")
    try:
        profiles = LatticeCryptoBenchmarkV2.ALGORITHM_PROFILES
        
        # Check Kyber-768 profile
        kyber768 = profiles[PQAlgorithm.KYBER_768]
        assert kyber768.security_level == SecurityLevel.LEVEL_3
        assert kyber768.public_key_size_bytes == 1184
        assert kyber768.estimated_quantum_security_bits == 192
        
        # Check Dilithium-5 profile
        dilithium5 = profiles[PQAlgorithm.DILITHIUM_5]
        assert dilithium5.security_level == SecurityLevel.LEVEL_5
        assert dilithium5.signature_size_bytes == 4595
        
        results["test_algorithm_profiles"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Test 8: Statistical calculations
    print("\n[TEST 8] Statistical calculations...")
    try:
        suite = LatticeCryptoBenchmarkV2()
        result = suite.benchmark_operation(
            PQAlgorithm.KYBER_512, 
            OperationType.ENCAPS, 
            iterations=50
        )
        
        # Statistics should be reasonable
        assert result.min_time_ms <= result.mean_time_ms <= result.max_time_ms
        assert result.median_time_ms > 0
        assert result.std_dev_ms >= 0
        
        results["test_statistical_calculations"] = True
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
    
    # Run built-in verification
    print("\n[VERIFICATION] Running built-in verification...")
    verify_result = verify_lattice_benchmark_v2()
    print(f"  Status: {verify_result['status']}")
    print(f"  Benchmarks: {verify_result['benchmarks_completed']}")
    print(f"  Validations: {verify_result['validations_passed']}/{verify_result['validations_completed']}")
    print(f"  Algorithms: {verify_result['algorithms_tested']}")
    print(f"  Export OK: {verify_result['export_ok']}")
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Save results
    test_results = {
        "test_timestamp": datetime.now().isoformat(),
        "module": "Lattice Crypto Benchmark v2",
        "passed": passed,
        "total": total,
        "results": results,
        "verification": verify_result
    }
    
    with open("/home/user/.super_doubao/super-doubao-runtime/workspace/QuantumCrypt-AI/test_results_lattice_benchmark_v2.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    return test_results


if __name__ == "__main__":
    run_all_tests()
