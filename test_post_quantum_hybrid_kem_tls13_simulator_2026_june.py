"""
Test Suite for Post-Quantum Hybrid KEM TLS 1.3 Handshake Simulator
June 21, 2026
Production-grade tests with real test cases and verification
"""
import json
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_hybrid_kem_tls13_handshake_simulator_2026_june import (
    HybridKEMTLS13Simulator,
    HandshakeResult,
    KEMAlgorithm,
    ECDHECurve,
    HandshakeState,
    CipherSuite
)


def run_tests():
    """Run all tests and return results"""
    print("=" * 70)
    print("Post-Quantum Hybrid KEM TLS 1.3 Simulator - Test Suite")
    print("=" * 70)
    
    test_results = []
    all_passed = True
    
    # Test 1: Basic handshake with Kyber-768
    print("\n[Test 1] Basic TLS 1.3 Handshake with Kyber-768")
    simulator = HybridKEMTLS13Simulator(
        kem_algorithm=KEMAlgorithm.KYBER_768,
        ecdhe_curve=ECDHECurve.X25519
    )
    result = simulator.perform_handshake()
    
    if result.success and result.master_secret and result.session_id:
        print(f"  PASS: Handshake completed successfully")
        print(f"    Time: {result.handshake_time_ms:.3f}ms")
        print(f"    Security: {result.security_strength_bits} bits")
        print(f"    Messages: {result.messages_exchanged}")
        test_results.append({"test": "Basic handshake Kyber-768", "passed": True})
    else:
        print(f"  FAIL: Handshake failed: {result.error_message}")
        test_results.append({"test": "Basic handshake Kyber-768", "passed": False})
        all_passed = False
    
    # Test 2: All KEM algorithms
    print("\n[Test 2] All KEM Algorithm Support")
    kem_algorithms = [
        KEMAlgorithm.KYBER_512,
        KEMAlgorithm.KYBER_768,
        KEMAlgorithm.KYBER_1024,
        KEMAlgorithm.NTRU_HPS_2048,
        KEMAlgorithm.SABER
    ]
    
    test2_passed = True
    for algo in kem_algorithms:
        sim = HybridKEMTLS13Simulator(kem_algorithm=algo)
        res = sim.perform_handshake()
        if not res.success:
            print(f"  FAIL: {algo.value} handshake failed")
            test2_passed = False
            all_passed = False
        else:
            print(f"  OK: {algo.value} - {res.security_strength_bits} bits")
    
    if test2_passed:
        print(f"  PASS: All {len(kem_algorithms)} KEM algorithms work")
    test_results.append({"test": "All KEM algorithms", "passed": test2_passed})
    
    # Test 3: All ECDHE curves
    print("\n[Test 3] All ECDHE Curve Support")
    curves = [ECDHECurve.X25519, ECDHECurve.X448, ECDHECurve.SECP256R1, ECDHECurve.SECP384R1]
    
    test3_passed = True
    for curve in curves:
        sim = HybridKEMTLS13Simulator(ecdhe_curve=curve)
        res = sim.perform_handshake()
        if not res.success:
            print(f"  FAIL: {curve.value} failed")
            test3_passed = False
            all_passed = False
        else:
            print(f"  OK: {curve.value} works")
    
    if test3_passed:
        print(f"  PASS: All {len(curves)} ECDHE curves work")
    test_results.append({"test": "All ECDHE curves", "passed": test3_passed})
    
    # Test 4: Cipher suite support
    print("\n[Test 4] Cipher Suite Support")
    suites = [
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_AES_128_GCM_SHA256
    ]
    
    test4_passed = True
    for suite in suites:
        sim = HybridKEMTLS13Simulator(cipher_suite=suite)
        res = sim.perform_handshake()
        if not res.success:
            print(f"  FAIL: {suite.value} failed")
            test4_passed = False
            all_passed = False
        else:
            print(f"  OK: {suite.value}")
    
    if test4_passed:
        print(f"  PASS: All cipher suites work")
    test_results.append({"test": "Cipher suites", "passed": test4_passed})
    
    # Test 5: Handshake state transitions
    print("\n[Test 5] Handshake State Machine")
    sim = HybridKEMTLS13Simulator()
    result = sim.perform_handshake()
    
    if sim.state == HandshakeState.APPLICATION_DATA:
        print(f"  PASS: Correct final state: {sim.state.value}")
        test_results.append({"test": "State machine", "passed": True})
    else:
        print(f"  FAIL: Expected APPLICATION_DATA, got {sim.state.value}")
        test_results.append({"test": "State machine", "passed": False})
        all_passed = False
    
    # Test 6: Handshake log integrity
    print("\n[Test 6] Handshake Log Integrity")
    if len(result.handshake_log) >= 5:  # ClientHello, ServerHello, ClientKeyShare, ServerFinished, ClientFinished
        print(f"  PASS: {len(result.handshake_log)} handshake messages logged")
        msg_types = [m.msg_type for m in result.handshake_log]
        print(f"    Messages: {', '.join(msg_types)}")
        test_results.append({"test": "Handshake log", "passed": True})
    else:
        print(f"  FAIL: Only {len(result.handshake_log)} messages logged")
        test_results.append({"test": "Handshake log", "passed": False})
        all_passed = False
    
    # Test 7: Key contribution verification
    print("\n[Test 7] Hybrid Key Contribution")
    if result.pq_contribution_bytes > 0 and result.classic_contribution_bytes > 0:
        print(f"  PASS: Both contributions present")
        print(f"    PQ contribution: {result.pq_contribution_bytes} bytes")
        print(f"    Classic contribution: {result.classic_contribution_bytes} bytes")
        test_results.append({"test": "Hybrid key contribution", "passed": True})
    else:
        print(f"  FAIL: Missing key contributions")
        test_results.append({"test": "Hybrid key contribution", "passed": False})
        all_passed = False
    
    # Test 8: Master secret generation
    print("\n[Test 8] Master Secret Generation")
    if len(result.master_secret) == 96:  # 48 bytes = 96 hex chars
        print(f"  PASS: Master secret generated correctly")
        print(f"    Length: {len(result.master_secret)//2} bytes")
        test_results.append({"test": "Master secret", "passed": True})
    else:
        print(f"  FAIL: Invalid master secret length: {len(result.master_secret)}")
        test_results.append({"test": "Master secret", "passed": False})
        all_passed = False
    
    # Test 9: Session ID generation
    print("\n[Test 9] Session ID Generation")
    if len(result.session_id) == 32:  # 16 bytes = 32 hex chars
        print(f"  PASS: Session ID valid: {result.session_id[:16]}...")
        test_results.append({"test": "Session ID", "passed": True})
    else:
        print(f"  FAIL: Invalid session ID length")
        test_results.append({"test": "Session ID", "passed": False})
        all_passed = False
    
    # Test 10: Performance benchmarking
    print("\n[Test 10] Performance Benchmarking")
    sim = HybridKEMTLS13Simulator()
    benchmark = sim.benchmark_handshake(iterations=50)
    
    if benchmark["success_rate"] == 1.0 and benchmark["avg_time_ms"] > 0:
        print(f"  PASS: Benchmark completed")
        print(f"    Iterations: {benchmark['iterations']}")
        print(f"    Success rate: {benchmark['success_rate']:.1%}")
        print(f"    Avg time: {benchmark['avg_time_ms']:.3f}ms")
        print(f"    Min/Max: {benchmark['min_time_ms']:.3f}ms / {benchmark['max_time_ms']:.3f}ms")
        test_results.append({"test": "Performance benchmark", "passed": True})
    else:
        print(f"  FAIL: Benchmark issues")
        test_results.append({"test": "Performance benchmark", "passed": False})
        all_passed = False
    
    # Test 11: Algorithm comparison
    print("\n[Test 11] Algorithm Comparison")
    sim = HybridKEMTLS13Simulator()
    algos_to_compare = [KEMAlgorithm.KYBER_512, KEMAlgorithm.KYBER_768, KEMAlgorithm.KYBER_1024]
    comparison = sim.compare_algorithms(algos_to_compare)
    
    if len(comparison) == len(algos_to_compare):
        print(f"  PASS: Compared {len(comparison)} algorithms")
        for res in comparison:
            print(f"    {res['kem_algorithm']}: {res['security_strength']} bits, {res['avg_time_ms']:.3f}ms avg")
        test_results.append({"test": "Algorithm comparison", "passed": True})
    else:
        print(f"  FAIL: Comparison failed")
        test_results.append({"test": "Algorithm comparison", "passed": False})
        all_passed = False
    
    # Test 12: Metadata completeness
    print("\n[Test 12] Metadata Completeness")
    required_metadata = [
        "kem_public_key_size", "kem_ciphertext_size", 
        "ecdhe_public_key_size", "total_key_exchange_overhead",
        "security_level"
    ]
    
    if all(key in result.metadata for key in required_metadata):
        print(f"  PASS: All metadata fields present")
        print(f"    Key exchange overhead: {result.metadata['total_key_exchange_overhead']} bytes")
        print(f"    Security level: {result.metadata['security_level']}")
        test_results.append({"test": "Metadata completeness", "passed": True})
    else:
        print(f"  FAIL: Missing metadata fields")
        test_results.append({"test": "Metadata completeness", "passed": False})
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    
    for tr in test_results:
        status = "PASS" if tr["passed"] else "FAIL"
        print(f"  [{status}] {tr['test']}")
    
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    
    if all_passed:
        print("\n✅ ALL TESTS PASSED!")
    else:
        print(f"\n❌ {total_count - passed_count} TEST(S) FAILED")
    
    # Save results to JSON
    output = {
        "test_suite": "Post-Quantum Hybrid KEM TLS 1.3 Simulator",
        "version": "1.0",
        "date": "June 21, 2026",
        "total_tests": total_count,
        "passed_tests": passed_count,
        "all_passed": all_passed,
        "results": test_results,
        "benchmark_sample": benchmark
    }
    
    with open("test_results_hybrid_kem_tls13_simulator_2026_june.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to test_results_hybrid_kem_tls13_simulator_2026_june.json")
    
    return all_passed, output


if __name__ == "__main__":
    success, results = run_tests()
    sys.exit(0 if success else 1)
