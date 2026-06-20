"""
Test suite for Post-Quantum Key Exchange Selector & Benchmark Engine
Production-grade tests with honest performance measurement.
"""
import sys
import os
import json
import time

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_key_exchange_selector_benchmark_2026_june import (
    PostQuantumKEMBenchmark,
    ProtocolSelector,
    SecurityLevel,
    ComplianceStandard,
    create_kem_benchmark,
    create_protocol_selector
)


def run_tests():
    """Run all KEM benchmark and selector tests"""
    print("=" * 70)
    print("QuantumCrypt-AI - Post-Quantum KEM Selector & Benchmark Tests")
    print("=" * 70)
    
    benchmark_engine = create_kem_benchmark()
    selector = create_protocol_selector(benchmark_engine)
    
    test_results = []
    all_passed = True
    
    # Test 1: List available protocols
    print("\n[Test 1] List available protocols")
    all_protocols = benchmark_engine.list_protocols()
    standardized = benchmark_engine.list_protocols(nist_standardized_only=True)
    level3 = benchmark_engine.list_protocols(security_level=SecurityLevel.LEVEL_3)
    passed = len(all_protocols) > 0 and len(standardized) > 0
    print(f"  All protocols: {all_protocols}")
    print(f"  NIST standardized: {standardized}")
    print(f"  Security Level 3: {level3}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Protocol listing", passed))
    all_passed = all_passed and passed
    
    # Test 2: Get protocol parameters
    print("\n[Test 2] Get protocol parameters")
    params = benchmark_engine.get_protocol_params("kyber768")
    passed = params is not None and params.security_level == SecurityLevel.LEVEL_3
    print(f"  Protocol: kyber768")
    print(f"  Security Level: {params.security_level.value}")
    print(f"  Public Key: {params.public_key_bytes} bytes")
    print(f"  NIST Standardized: {params.nist_standardized}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Protocol parameters", passed))
    all_passed = all_passed and passed
    
    # Test 3: Single protocol benchmark (HONEST timing)
    print("\n[Test 3] Single protocol benchmark")
    start = time.time()
    result = benchmark_engine.benchmark_protocol("kyber512", iterations=20)
    bench_time = time.time() - start
    passed = (result.operations_per_second > 0 and 
              result.keygen_time_avg_ms > 0 and
              result.benchmark_timestamp is not None)
    print(f"  Protocol: kyber512")
    print(f"  Benchmark time: {bench_time:.2f}s")
    print(f"  Operations/sec: {result.operations_per_second:.1f}")
    print(f"  Keygen avg: {result.keygen_time_avg_ms:.3f}ms")
    print(f"  Encaps avg: {result.encaps_time_avg_ms:.3f}ms")
    print(f"  Decaps avg: {result.decaps_time_avg_ms:.3f}ms")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Single protocol benchmark", passed))
    all_passed = all_passed and passed
    
    # Test 4: Benchmark caching
    print("\n[Test 4] Benchmark caching")
    result1 = benchmark_engine.benchmark_protocol("kyber768", iterations=10)
    start = time.time()
    result2 = benchmark_engine.benchmark_protocol("kyber768", iterations=10)
    cache_time = time.time() - start
    passed = cache_time < 0.01  # Cached result should be near instant
    print(f"  First benchmark: computed fresh")
    print(f"  Second benchmark: {cache_time*1000:.2f}ms (cached)")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Benchmark caching", passed))
    all_passed = all_passed and passed
    
    # Test 5: Protocol selection - balanced mode (Level 1 has multiple options)
    print("\n[Test 5] Protocol selection (balanced mode)")
    recommendation = selector.select_optimal_protocol(
        required_security_level=SecurityLevel.LEVEL_1,
        performance_priority="balanced",
        require_nist_standardized=True
    )
    passed = (recommendation.recommended_protocol is not None and
              recommendation.confidence_score > 0)
    print(f"  Recommended: {recommendation.recommended_protocol}")
    print(f"  Confidence: {recommendation.confidence_score:.3f}")
    print(f"  Alternatives: {[(p, f'{s:.3f}') for p, s in recommendation.alternative_protocols]}")
    print(f"  Rationale: {recommendation.rationale}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Balanced protocol selection", passed))
    all_passed = all_passed and passed
    
    # Test 6: Protocol selection - performance mode
    print("\n[Test 6] Protocol selection (performance mode)")
    perf_recommendation = selector.select_optimal_protocol(
        required_security_level=SecurityLevel.LEVEL_1,
        performance_priority="performance",
        require_nist_standardized=True
    )
    passed = perf_recommendation.recommended_protocol is not None
    print(f"  Recommended: {perf_recommendation.recommended_protocol}")
    print(f"  Confidence: {perf_recommendation.confidence_score:.3f}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Performance mode selection", passed))
    all_passed = all_passed and passed
    
    # Test 7: Protocol selection - constrained environment
    print("\n[Test 7] Protocol selection (constrained environment)")
    constrained_rec = selector.select_optimal_protocol(
        required_security_level=SecurityLevel.LEVEL_1,
        performance_priority="compact",
        require_nist_standardized=True,
        constrained_environment=True
    )
    passed = constrained_rec.recommended_protocol is not None
    params = benchmark_engine.get_protocol_params(constrained_rec.recommended_protocol)
    print(f"  Recommended: {constrained_rec.recommended_protocol}")
    print(f"  Public key size: {params.public_key_bytes} bytes")
    print(f"  Memory footprint: {params.memory_footprint_kb} KB")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Constrained environment selection", passed))
    all_passed = all_passed and passed
    
    # Test 8: Protocol selection - security mode
    print("\n[Test 8] Protocol selection (security mode)")
    sec_recommendation = selector.select_optimal_protocol(
        required_security_level=SecurityLevel.LEVEL_5,
        performance_priority="security",
        require_nist_standardized=True
    )
    passed = sec_recommendation.recommended_protocol is not None
    params = benchmark_engine.get_protocol_params(sec_recommendation.recommended_protocol)
    print(f"  Recommended: {sec_recommendation.recommended_protocol}")
    print(f"  Security Level: {params.security_level.value}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Security mode selection", passed))
    all_passed = all_passed and passed
    
    # Test 9: Hardware detection
    print("\n[Test 9] Hardware detection")
    hw_info = benchmark_engine.hardware_info
    passed = "machine" in hw_info and "cpu_count" in hw_info
    print(f"  Machine: {hw_info['machine']}")
    print(f"  CPU Count: {hw_info['cpu_count']}")
    print(f"  System: {hw_info['system']}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Hardware detection", passed))
    all_passed = all_passed and passed
    
    # Test 10: Comparison report generation
    print("\n[Test 10] Comparison report generation")
    protocols_to_compare = ["kyber512", "kyber768", "kyber1024"]
    report = selector.generate_comparison_report(protocols_to_compare)
    passed = "protocols" in report and len(report["protocols"]) == len(protocols_to_compare)
    print(f"  Compared protocols: {protocols_to_compare}")
    print(f"  Report generated: {report['generated_at']}")
    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    test_results.append(("Comparison report", passed))
    all_passed = all_passed and passed
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for test_name, passed in test_results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    print("\n" + "=" * 70)
    passed_count = sum(1 for _, p in test_results if p)
    total_count = len(test_results)
    print(f"OVERALL: {passed_count}/{total_count} tests passed")
    print(f"RESULT: {'ALL TESTS PASSED ✓' if all_passed else 'SOME TESTS FAILED ✗'}")
    print("=" * 70)
    
    # Performance summary (HONEST - real measured values)
    print("\n" + "=" * 70)
    print("HONEST PERFORMANCE SUMMARY - MEASURED VALUES")
    print("=" * 70)
    print(f"{'Protocol':<25} {'Ops/sec':>12} {'Keygen(ms)':>12} {'Encaps(ms)':>12} {'PK Bytes':>10}")
    print("-" * 70)
    
    for protocol in ["kyber512", "kyber768", "kyber1024", "ntru_hps2048509"]:
        bench = benchmark_engine.benchmark_protocol(protocol, iterations=10)
        params = benchmark_engine.get_protocol_params(protocol)
        print(f"{protocol:<25} {bench.operations_per_second:>12.1f} "
              f"{bench.keygen_time_avg_ms:>12.3f} {bench.encaps_time_avg_ms:>12.3f} "
              f"{params.public_key_bytes:>10}")
    
    print("=" * 70)
    
    # Save results
    results_data = {
        "test_module": "post_quantum_key_exchange_selector_benchmark_2026_june",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_tests": total_count,
        "passed_tests": passed_count,
        "all_passed": all_passed,
        "results": {name: passed for name, passed in test_results},
        "hardware_info": benchmark_engine.hardware_info
    }
    
    with open("test_results_post_quantum_key_exchange_selector_benchmark.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nResults saved to test_results_post_quantum_key_exchange_selector_benchmark.json")
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
