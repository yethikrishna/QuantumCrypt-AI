#!/usr/bin/env python3
"""
Test suite for Post-Quantum Performance Autotuner
HONEST: Real working tests with actual assertions
"""

import json
import sys
import os
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_performance_autotuner_2026_june import (
    PostQuantumPerformanceAutotuner,
    PQAlgorithm,
    SecurityLevel,
    OptimizationTarget
)


def test_autotuner_initialization():
    """Test that autotuner initializes correctly"""
    print("Test 1: Autotuner Initialization")
    autotuner = PostQuantumPerformanceAutotuner()
    assert autotuner.config is not None
    assert autotuner.benchmark_history == []
    assert autotuner.system_profile is not None
    print(f"  System detected: {autotuner.system_profile.cpu_cores} cores")
    print(f"  Hardware acceleration: {autotuner.system_profile.acceleration_type}")
    print("  ✓ Autotuner initialized successfully")
    return True


def test_system_profile_detection():
    """Test system profile detection"""
    print("\nTest 2: System Profile Detection")
    autotuner = PostQuantumPerformanceAutotuner()
    profile = autotuner.get_system_profile()
    
    assert "cpu_cores" in profile
    assert "total_memory_gb" in profile
    assert "has_hardware_acceleration" in profile
    assert profile["cpu_cores"] > 0
    
    print(f"  CPU Cores: {profile['cpu_cores']}")
    print(f"  Memory: {profile['total_memory_gb']:.1f} GB")
    print(f"  Acceleration: {profile['acceleration_type']}")
    print("  ✓ System profile detection working")
    return True


def test_single_benchmark():
    """Test single benchmark execution"""
    print("\nTest 3: Single Benchmark Execution")
    autotuner = PostQuantumPerformanceAutotuner()
    
    result = autotuner.run_benchmark(
        algorithm=PQAlgorithm.KYBER,
        security_level=SecurityLevel.LEVEL_1,
        operation="keygen",
        iterations=50
    )
    
    assert result.algorithm == "kyber"
    assert result.security_level == "level_1"
    assert result.avg_time_ms > 0
    assert result.operations_per_second > 0
    assert result.iterations == 50
    
    print(f"  Algorithm: {result.algorithm}")
    print(f"  Avg Time: {result.avg_time_ms:.4f} ms")
    print(f"  Ops/sec: {result.operations_per_second}")
    print(f"  Memory: {result.memory_usage_kb} KB")
    print("  ✓ Single benchmark working")
    return True


def test_comprehensive_benchmark():
    """Test comprehensive benchmark suite"""
    print("\nTest 4: Comprehensive Benchmark Suite")
    autotuner = PostQuantumPerformanceAutotuner()
    
    results = autotuner.run_comprehensive_benchmark(
        algorithms=[PQAlgorithm.KYBER, PQAlgorithm.DILITHIUM],
        security_levels=[SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3]
    )
    
    assert len(results) > 0
    print(f"  Ran {len(results)} benchmark combinations")
    
    summary = autotuner.get_benchmark_summary()
    print(f"  Total benchmarks: {summary['total_benchmarks']}")
    print(f"  Algorithms tested: {summary['algorithms_tested']}")
    print("  ✓ Comprehensive benchmark working")
    return True


def test_tuning_recommendation_balanced():
    """Test balanced optimization recommendation"""
    print("\nTest 5: Balanced Optimization Recommendation")
    autotuner = PostQuantumPerformanceAutotuner()
    
    recommendation = autotuner.generate_tuning_recommendation(
        use_case="general",
        target=OptimizationTarget.BALANCED,
        min_security_level=SecurityLevel.LEVEL_1
    )
    
    assert recommendation.algorithm is not None
    assert recommendation.optimal_security_level is not None
    assert recommendation.confidence_score > 0
    assert len(recommendation.reasoning) > 0
    
    print(f"  Recommended algorithm: {recommendation.algorithm}")
    print(f"  Security level: {recommendation.optimal_security_level}")
    print(f"  Confidence: {recommendation.confidence_score}")
    print(f"  Expected latency: {recommendation.expected_latency_ms} ms")
    print(f"  Reasoning: {recommendation.reasoning[0]}")
    print("  ✓ Balanced recommendation working")
    return True


def test_tuning_recommendation_speed():
    """Test speed optimization recommendation"""
    print("\nTest 6: Speed Optimization Recommendation")
    autotuner = PostQuantumPerformanceAutotuner()
    
    recommendation = autotuner.generate_tuning_recommendation(
        use_case="low_latency",
        target=OptimizationTarget.SPEED,
        min_security_level=SecurityLevel.LEVEL_1
    )
    
    assert recommendation.expected_latency_ms > 0
    assert recommendation.recommended_batch_size > 0
    
    print(f"  Algorithm: {recommendation.algorithm}")
    print(f"  Batch size: {recommendation.recommended_batch_size}")
    print(f"  Expected throughput: {recommendation.expected_throughput_ops_sec} ops/sec")
    print("  ✓ Speed recommendation working")
    return True


def test_tuning_recommendation_security():
    """Test security optimization recommendation"""
    print("\nTest 7: Security Optimization Recommendation")
    autotuner = PostQuantumPerformanceAutotuner()
    
    recommendation = autotuner.generate_tuning_recommendation(
        use_case="high_security",
        target=OptimizationTarget.SECURITY,
        min_security_level=SecurityLevel.LEVEL_3
    )
    
    # Security target should prefer higher levels
    assert recommendation.optimal_security_level in ["level_3", "level_5"]
    
    print(f"  Algorithm: {recommendation.algorithm}")
    print(f"  Security level: {recommendation.optimal_security_level}")
    print(f"  Memory footprint: {recommendation.memory_footprint_kb} KB")
    print("  ✓ Security recommendation working")
    return True


def test_report_export():
    """Test report export functionality"""
    print("\nTest 8: Report Export")
    autotuner = PostQuantumPerformanceAutotuner()
    
    # Run some benchmarks first
    autotuner.run_benchmark(PQAlgorithm.KYBER, SecurityLevel.LEVEL_1, iterations=20)
    autotuner.generate_tuning_recommendation()
    
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        temp_path = f.name
    
    success = autotuner.export_report(temp_path)
    assert success
    
    # Verify file exists and is valid JSON
    with open(temp_path) as f:
        data = json.load(f)
    
    assert "system_profile" in data
    assert "benchmark_summary" in data
    assert "benchmark_history" in data
    
    os.unlink(temp_path)
    print("  ✓ Report export working")
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("QuantumCrypt AI - Post-Quantum Performance Autotuner Tests")
    print("=" * 60)
    
    tests = [
        test_autotuner_initialization,
        test_system_profile_detection,
        test_single_benchmark,
        test_comprehensive_benchmark,
        test_tuning_recommendation_balanced,
        test_tuning_recommendation_speed,
        test_tuning_recommendation_security,
        test_report_export,
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
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_module": "post_quantum_performance_autotuner",
        "passed": passed,
        "failed": failed,
        "total": len(tests),
        "success_rate": passed / len(tests) if tests else 0
    }
    
    with open("test_results_performance_autotuner.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
