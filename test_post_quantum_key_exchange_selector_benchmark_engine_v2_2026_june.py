#!/usr/bin/env python3
"""
Test Suite for QuantumCrypt AI - Post-Quantum Key Exchange Selector & Benchmark Engine V2
Production-grade tests with real-world scenarios
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_exchange_selector_benchmark_engine_v2_2026_june import (
    PQAlgorithmRegistry,
    PQBenchmarkEngine,
    PQAlgorithmSelector,
    SecurityLevel,
    AlgorithmCategory,
    UseCaseType,
    PQAlgorithm
)


def test_algorithm_registry_initialization():
    """Test algorithm registry loads correctly"""
    print("Testing Algorithm Registry Initialization...")
    registry = PQAlgorithmRegistry()

    # Should have all major algorithms
    kyber = registry.get_algorithm("CRYSTALS-Kyber-768")
    assert kyber is not None, "Kyber-768 should exist"
    assert kyber.nist_standardized == True, "Kyber should be NIST standardized"
    assert kyber.security_level == SecurityLevel.LEVEL_3
    assert kyber.public_key_size == 1184

    dilithium = registry.get_algorithm("CRYSTALS-Dilithium-3")
    assert dilithium is not None, "Dilithium-3 should exist"
    assert dilithium.category == AlgorithmCategory.SIGNATURE

    hybrid = registry.get_algorithm("Hybrid-X25519-Kyber-768")
    assert hybrid is not None, "Hybrid mode should exist"
    assert hybrid.category == AlgorithmCategory.HYBRID

    all_algos = registry.list_algorithms()
    assert len(all_algos) >= 8, f"Should have at least 8 algorithms, got {len(all_algos)}"

    kem_algos = registry.list_algorithms(AlgorithmCategory.KEM)
    assert len(kem_algos) >= 4, f"Should have at least 4 KEM algorithms"

    print(f"  ✓ Registry loaded with {len(all_algos)} algorithms")
    return True


def test_security_level_filtering():
    """Test filtering by security level"""
    print("Testing Security Level Filtering...")
    registry = PQAlgorithmRegistry()

    level5 = registry.get_by_security_level(SecurityLevel.LEVEL_5)
    assert len(level5) >= 1, "Should have Level 5 algorithms"
    assert any("Kyber-1024" in a.name for a in level5), "Kyber-1024 should be Level 5"

    level3 = registry.get_by_security_level(SecurityLevel.LEVEL_3)
    assert len(level3) >= 2, "Should have Level 3 algorithms"

    print("  ✓ Security Level Filtering PASSED")
    return True


def test_use_case_filtering():
    """Test filtering by use case"""
    print("Testing Use Case Filtering...")
    registry = PQAlgorithmRegistry()

    tls_algos = registry.get_for_use_case(UseCaseType.TLS_HANDSHAKE)
    assert len(tls_algos) >= 3, "Should have TLS-compatible algorithms"

    iot_algos = registry.get_for_use_case(UseCaseType.IOT_DEVICE)
    assert len(iot_algos) >= 1, "Should have IoT-compatible algorithms"

    high_sec = registry.get_for_use_case(UseCaseType.HIGH_SECURITY)
    assert len(high_sec) >= 2, "Should have high-security algorithms"

    print(f"  ✓ Use Case Filtering PASSED: TLS={len(tls_algos)}, IoT={len(iot_algos)}, HighSec={len(high_sec)}")
    return True


def test_algorithm_to_dict():
    """Test algorithm serialization"""
    print("Testing Algorithm Serialization...")
    registry = PQAlgorithmRegistry()
    kyber = registry.get_algorithm("CRYSTALS-Kyber-768")

    data = kyber.to_dict()
    assert data["name"] == "CRYSTALS-Kyber-768"
    assert data["security_level"] == 3
    assert "public_key_size" in data
    assert "performance_score" in data
    assert isinstance(data["supported_use_cases"], list)

    print("  ✓ Algorithm Serialization PASSED")
    return True


def test_single_algorithm_benchmark():
    """Test benchmarking single algorithm"""
    print("Testing Single Algorithm Benchmark...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)

    results = benchmarker.benchmark_algorithm("CRYSTALS-Kyber-768", iterations=100)

    assert "key_generation" in results
    assert "encapsulation" in results
    assert "decapsulation" in results

    kg = results["key_generation"]
    assert kg.algorithm_name == "CRYSTALS-Kyber-768"
    assert kg.iterations == 100
    assert kg.total_time_ms > 0
    assert kg.avg_time_us > 0
    assert kg.ops_per_second > 0

    print(f"  ✓ Benchmark PASSED: {kg.ops_per_second:.0f} keygen ops/sec")
    return True


def test_algorithm_comparison():
    """Test comparing multiple algorithms"""
    print("Testing Algorithm Comparison...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)

    algos_to_compare = [
        "CRYSTALS-Kyber-512",
        "CRYSTALS-Kyber-768",
        "CRYSTALS-Kyber-1024"
    ]

    comparison = benchmarker.compare_algorithms(algos_to_compare, iterations=50)

    assert "performance_ranking" in comparison["summary"]
    ranking = comparison["summary"]["performance_ranking"]
    assert len(ranking) == 3

    # Kyber-512 should be fastest (smallest, Level 1)
    assert ranking[0]["algorithm"] == "CRYSTALS-Kyber-512", "Kyber-512 should be fastest"
    assert ranking[2]["algorithm"] == "CRYSTALS-Kyber-1024", "Kyber-1024 should be slowest"

    print(f"  ✓ Comparison PASSED: Ranking = {[r['algorithm'] for r in ranking]}")
    return True


def test_recommendation_tls_handshake():
    """Test recommendation for TLS Handshake use case"""
    print("Testing Recommendation - TLS Handshake...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)
    selector = PQAlgorithmSelector(registry, benchmarker)

    recommendation = selector.recommend_for_use_case(
        UseCaseType.TLS_HANDSHAKE,
        min_security_level=SecurityLevel.LEVEL_1
    )

    assert recommendation.primary_algorithm is not None
    assert len(recommendation.alternative_algorithms) > 0
    assert recommendation.match_score > 0
    assert recommendation.match_score <= 1.0

    print(f"  ✓ TLS Recommendation: Primary={recommendation.primary_algorithm}, Match={recommendation.match_score:.2f}")
    return True


def test_recommendation_high_security():
    """Test recommendation for High Security use case"""
    print("Testing Recommendation - High Security...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)
    selector = PQAlgorithmSelector(registry, benchmarker)

    recommendation = selector.recommend_for_use_case(
        UseCaseType.HIGH_SECURITY,
        min_security_level=SecurityLevel.LEVEL_3
    )

    primary = registry.get_algorithm(recommendation.primary_algorithm)
    assert primary.security_level.value >= 3, "Should recommend Level 3+ algorithm"

    print(f"  ✓ High Security Recommendation: {recommendation.primary_algorithm}")
    print(f"    Security: {recommendation.security_assessment}")
    return True


def test_recommendation_iot_constrained():
    """Test recommendation for IoT/constrained devices"""
    print("Testing Recommendation - IoT Constrained...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)
    selector = PQAlgorithmSelector(registry, benchmarker)

    recommendation = selector.recommend_for_use_case(
        UseCaseType.CONSTRAINED_DEVICE,
        min_security_level=SecurityLevel.LEVEL_1
    )

    primary = registry.get_algorithm(recommendation.primary_algorithm)
    assert primary.performance_score >= 7, "Should recommend high-performance algorithm"

    print(f"  ✓ IoT Recommendation: {recommendation.primary_algorithm}")
    print(f"    Performance: {recommendation.performance_assessment}")
    return True


def test_hybrid_preference():
    """Test hybrid mode preference"""
    print("Testing Hybrid Mode Preference...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)
    selector = PQAlgorithmSelector(registry, benchmarker)

    recommendation = selector.recommend_for_use_case(
        UseCaseType.TLS_HANDSHAKE,
        min_security_level=SecurityLevel.LEVEL_1,
        prefer_hybrid=True
    )

    primary = registry.get_algorithm(recommendation.primary_algorithm)
    assert primary.category == AlgorithmCategory.HYBRID, "Should recommend hybrid algorithm"

    print(f"  ✓ Hybrid Preference PASSED: {recommendation.primary_algorithm}")
    return True


def test_comparison_report_generation():
    """Test comprehensive comparison report generation"""
    print("Testing Comparison Report Generation...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)
    selector = PQAlgorithmSelector(registry, benchmarker)

    use_cases = [
        UseCaseType.TLS_HANDSHAKE,
        UseCaseType.HIGH_SECURITY,
        UseCaseType.IOT_DEVICE
    ]

    report_json = selector.generate_comparison_report(use_cases, output_format="json")
    report = json.loads(report_json)

    assert "use_cases_analyzed" in report
    assert "recommendations" in report
    assert len(report["recommendations"]) == 3

    print(f"  ✓ Report Generation PASSED: {len(report['recommendations'])} use cases analyzed")
    return True


def test_benchmark_history():
    """Test benchmark history tracking"""
    print("Testing Benchmark History...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)

    # Run some benchmarks
    benchmarker.benchmark_algorithm("CRYSTALS-Kyber-512", iterations=10)
    benchmarker.benchmark_algorithm("CRYSTALS-Kyber-768", iterations=10)

    history = benchmarker.get_benchmark_history()
    assert len(history) > 0, "Should have benchmark history"

    print(f"  ✓ Benchmark History PASSED: {len(history)} records")
    return True


def test_recommendation_to_dict():
    """Test recommendation serialization"""
    print("Testing Recommendation Serialization...")
    registry = PQAlgorithmRegistry()
    benchmarker = PQBenchmarkEngine(registry)
    selector = PQAlgorithmSelector(registry, benchmarker)

    recommendation = selector.recommend_for_use_case(UseCaseType.TLS_HANDSHAKE)
    data = recommendation.to_dict()

    assert "primary_algorithm" in data
    assert "alternative_algorithms" in data
    assert "match_score" in data
    assert "security_assessment" in data
    assert "migration_complexity" in data

    print("  ✓ Recommendation Serialization PASSED")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 70)
    print("QuantumCrypt AI - Post-Quantum Key Exchange Selector & Benchmark V2")
    print("PRODUCTION TEST SUITE")
    print("=" * 70)

    tests = [
        test_algorithm_registry_initialization,
        test_security_level_filtering,
        test_use_case_filtering,
        test_algorithm_to_dict,
        test_single_algorithm_benchmark,
        test_algorithm_comparison,
        test_recommendation_tls_handshake,
        test_recommendation_high_security,
        test_recommendation_iot_constrained,
        test_hybrid_preference,
        test_comparison_report_generation,
        test_benchmark_history,
        test_recommendation_to_dict,
    ]

    results = []
    start_time = time.time()

    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"  ✗ EXCEPTION in {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            results.append((test.__name__, False))

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  {status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed in {elapsed:.3f}s")

    # Save test results
    test_results = {
        "test_suite": "Post-Quantum Key Exchange Selector & Benchmark Engine V2",
        "tests_passed": passed,
        "tests_total": total,
        "pass_rate": passed / total,
        "execution_time_seconds": elapsed,
        "results": {name: result for name, result in results}
    }

    with open("test_results_post_quantum_key_exchange_selector_benchmark_v2.json", "w") as f:
        json.dump(test_results, f, indent=2)

    print(f"\nTest results saved to test_results_post_quantum_key_exchange_selector_benchmark_v2.json")

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
