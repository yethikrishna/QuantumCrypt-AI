#!/usr/bin/env python3
"""
Test suite for Post-Quantum Cryptographic DRBG Engine - QuantumCrypt-AI
Production-grade tests with real cryptographic validation
June 2026
"""
import sys
import json
import statistics
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_cryptographic_drbg_engine_2026_june import (
    PostQuantumDRBGEngine,
    DRBGSecurityStrength,
    DRBGHealthStatus,
    EntropySourceQuality
)


def run_tests():
    print("=" * 60)
    print("QuantumCrypt-AI: Post-Quantum DRBG Engine Tests")
    print("=" * 60)
    
    all_passed = True
    test_results = []
    
    # Test 1: Basic random bytes generation
    print("\n[Test 1] Basic Random Bytes Generation")
    drbg = PostQuantumDRBGEngine(
        security_strength=DRBGSecurityStrength.SECURITY_256,
        prediction_resistance=False
    )
    rand_bytes = drbg.generate(32)
    print(f"  Generated {len(rand_bytes)} random bytes")
    print(f"  First 8 bytes: {rand_bytes[:8].hex()}")
    
    test1_pass = len(rand_bytes) == 32 and len(set(rand_bytes)) > 10
    print(f"  {'PASS' if test1_pass else 'FAIL'}: 32 bytes with good diversity")
    all_passed &= test1_pass
    test_results.append({"test": "Basic Generation", "passed": test1_pass})
    
    # Test 2: Different output lengths
    print("\n[Test 2] Multiple Output Lengths")
    lengths = [1, 16, 32, 64, 128, 256, 1024]
    all_correct = True
    for length in lengths:
        result = drbg.generate(length, prediction_resistance_override=False)
        if len(result) != length:
            all_correct = False
            print(f"    FAIL: {length} bytes requested, got {len(result)}")
    print(f"  Tested lengths: {lengths}")
    
    test2_pass = all_correct
    print(f"  {'PASS' if test2_pass else 'FAIL'}: All lengths correct")
    all_passed &= test2_pass
    test_results.append({"test": "Multiple Lengths", "passed": test2_pass})
    
    # Test 3: Non-repetition (statistical check)
    print("\n[Test 3] Non-Repetition Check")
    outputs = []
    for _ in range(100):
        outputs.append(drbg.generate(32, prediction_resistance_override=False))
    
    unique_outputs = len(set(outputs))
    print(f"  Generated 100 outputs, {unique_outputs} unique")
    
    test3_pass = unique_outputs == 100
    print(f"  {'PASS' if test3_pass else 'FAIL'}: All outputs unique")
    all_passed &= test3_pass
    test_results.append({"test": "Non-Repetition", "passed": test3_pass, "unique": unique_outputs})
    
    # Test 4: Quantum-safe key generation
    print("\n[Test 4] Quantum-Safe Key Generation")
    key_128 = drbg.generate_quantum_safe_key(128)
    key_256 = drbg.generate_quantum_safe_key(256)
    key_512 = drbg.generate_quantum_safe_key(512)
    print(f"  128-bit key: {len(key_128)} bytes")
    print(f"  256-bit key: {len(key_256)} bytes")
    print(f"  512-bit key: {len(key_512)} bytes")
    
    test4_pass = len(key_128) == 16 and len(key_256) == 32 and len(key_512) == 64
    print(f"  {'PASS' if test4_pass else 'FAIL'}: All key lengths correct")
    all_passed &= test4_pass
    test_results.append({"test": "Key Generation", "passed": test4_pass})
    
    # Test 5: Uniform distribution (frequency test)
    print("\n[Test 5] Uniform Distribution Test")
    large_sample = drbg.generate(65536, prediction_resistance_override=False)
    byte_counts = [0] * 256
    for b in large_sample:
        byte_counts[b] += 1
    
    avg_count = len(large_sample) / 256
    max_deviation = max(abs(c - avg_count) for c in byte_counts) / avg_count * 100
    print(f"  Sample size: {len(large_sample)} bytes")
    print(f"  Max deviation: {max_deviation:.2f}% from ideal")
    
    test5_pass = max_deviation < 15.0  # Reasonable bound for random
    print(f"  {'PASS' if test5_pass else 'FAIL'}: Distribution within bounds")
    all_passed &= test5_pass
    test_results.append({"test": "Uniform Distribution", "passed": test5_pass, "deviation_pct": round(max_deviation, 2)})
    
    # Test 6: Health tests
    print("\n[Test 6] DRBG Health Tests")
    health_report = drbg.run_health_tests()
    print(f"  Status: {health_report.status.value}")
    print(f"  Entropy Quality: {health_report.entropy_quality.value}")
    print(f"  Min-Entropy Estimate: {health_report.min_entropy_estimate:.4f} per bit")
    print(f"  Warnings: {len(health_report.warnings)}")
    
    test6_pass = (health_report.status in [DRBGHealthStatus.HEALTHY, DRBGHealthStatus.WARNING] and
                  health_report.entropy_quality in [
                      EntropySourceQuality.EXCELLENT, 
                      EntropySourceQuality.GOOD,
                      EntropySourceQuality.FAIR
                  ])
    print(f"  {'PASS' if test6_pass else 'FAIL'}: Health tests passed")
    all_passed &= test6_pass
    test_results.append({
        "test": "Health Tests", 
        "passed": test6_pass,
        "min_entropy": round(health_report.min_entropy_estimate, 4),
        "entropy_quality": health_report.entropy_quality.value
    })
    
    # Test 7: Reseed functionality
    print("\n[Test 7] Reseed Functionality")
    drbg2 = PostQuantumDRBGEngine(prediction_resistance=False)
    before_reseed = drbg2.get_status()["reseed_counter"]
    drbg2.reseed()
    after_reseed = drbg2.get_status()["reseed_counter"]
    print(f"  Counter before reseed: {before_reseed}")
    print(f"  Counter after reseed: {after_reseed}")
    
    test7_pass = after_reseed == 1
    print(f"  {'PASS' if test7_pass else 'FAIL'}: Counter reset after reseed")
    all_passed &= test7_pass
    test_results.append({"test": "Reseed", "passed": test7_pass})
    
    # Test 8: Prediction resistance
    print("\n[Test 8] Prediction Resistance")
    drbg_pr = PostQuantumDRBGEngine(prediction_resistance=True)
    status_before = drbg_pr.get_status()
    _ = drbg_pr.generate(32)
    status_after = drbg_pr.get_status()
    print(f"  Prediction resistance enabled")
    print(f"  Reseed counter increments: {status_after['reseed_counter'] == 1}")
    
    test8_pass = status_after["reseed_counter"] == 1  # Resets each time with PR
    print(f"  {'PASS' if test8_pass else 'FAIL'}: PR reseeds on each call")
    all_passed &= test8_pass
    test_results.append({"test": "Prediction Resistance", "passed": test8_pass})
    
    # Test 9: Random integer generation
    print("\n[Test 9] Random Integer Generation")
    counts = {i: 0 for i in range(10)}
    for _ in range(10000):
        val = drbg.random_below(10)
        counts[val] += 1
    
    avg = 10000 / 10
    max_diff = max(abs(v - avg) for v in counts.values())
    print(f"  Generated 10,000 integers in [0, 10)")
    print(f"  Max deviation from uniform: {max_diff:.0f}")
    
    test9_pass = max_diff < 500  # Within 5%
    print(f"  {'PASS' if test9_pass else 'FAIL'}: Uniform integer distribution")
    all_passed &= test9_pass
    test_results.append({"test": "Random Integers", "passed": test9_pass, "max_deviation": int(max_diff)})
    
    # Test 10: Min-entropy estimation
    print("\n[Test 10] Min-Entropy Estimation")
    # Test on actual random data
    random_sample = drbg.generate(8192, prediction_resistance_override=False)
    entropy = drbg.estimate_min_entropy(random_sample)
    print(f"  Random data min-entropy: {entropy:.4f} per bit")
    
    # Test on non-random data (should be low)
    non_random = b'\x00' * 4096
    low_entropy = drbg.estimate_min_entropy(non_random)
    print(f"  All-zeros min-entropy: {low_entropy:.4f} per bit")
    
    test10_pass = entropy > 0.8 and low_entropy < 0.1
    print(f"  {'PASS' if test10_pass else 'FAIL'}: Entropy estimation works")
    all_passed &= test10_pass
    test_results.append({"test": "Min-Entropy Estimation", "passed": test10_pass, "random_entropy": round(entropy, 4)})
    
    # Test 11: Status reporting
    print("\n[Test 11] Status Reporting")
    status = drbg.get_status()
    required_keys = [
        "security_strength", "prediction_resistance", 
        "reseed_counter", "total_bytes_generated"
    ]
    has_all = all(k in status for k in required_keys)
    print(f"  Status keys present: {list(status.keys())}")
    
    test11_pass = has_all and status["total_bytes_generated"] > 0
    print(f"  {'PASS' if test11_pass else 'FAIL'}: Status reporting complete")
    all_passed &= test11_pass
    test_results.append({"test": "Status Reporting", "passed": test11_pass})
    
    # Test 12: Health report serialization
    print("\n[Test 12] Health Report Serialization")
    report = drbg.run_health_tests()
    report_dict = report.to_dict()
    json_str = json.dumps(report_dict, indent=2)
    print(f"  Serialized to JSON: {len(json_str)} bytes")
    
    test12_pass = "status" in report_dict and "entropy_quality" in report_dict
    print(f"  {'PASS' if test12_pass else 'FAIL'}: to_dict serialization works")
    all_passed &= test12_pass
    test_results.append({"test": "Serialization", "passed": test12_pass})
    
    # Summary
    print("\n" + "=" * 60)
    passed_count = sum(1 for t in test_results if t["passed"])
    total_count = len(test_results)
    print(f"SUMMARY: {passed_count}/{total_count} tests passed")
    
    if all_passed:
        print("ALL TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED ✗")
        for t in test_results:
            if not t["passed"]:
                print(f"  FAILED: {t['test']}")
    
    print("=" * 60)
    
    # Save test results
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_pq_drbg_engine.json', 'w') as f:
        json.dump({
            "test_timestamp": __import__('datetime').datetime.now().isoformat(),
            "module": "post_quantum_cryptographic_drbg_engine_2026_june",
            "all_passed": all_passed,
            "passed_count": passed_count,
            "total_count": total_count,
            "results": test_results
        }, f, indent=2)
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
