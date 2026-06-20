#!/usr/bin/env python3
"""
Test suite for Post-Quantum Key Exchange Protocol Simulator
June 2026 - Production Testing
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import directly without __init__.py
import importlib.util
spec = importlib.util.spec_from_file_location(
    'pq_kem_simulator',
    'quantum_crypt/post_quantum_key_exchange_protocol_simulator_2026_june.py'
)
pq_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pq_module)

PostQuantumKeyExchangeSimulator = pq_module.PostQuantumKeyExchangeSimulator
PQProtocol = pq_module.PQProtocol
ProtocolStatus = pq_module.ProtocolStatus
NISTSecurityLevel = pq_module.NISTSecurityLevel


def test_simulator_initialization():
    """Test simulator initialization and metrics"""
    print("=" * 60)
    print("TEST 1: Simulator Initialization")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    metrics = simulator.get_protocol_metrics()
    
    print(f"  ✓ Simulator initialized")
    print(f"    - Protocols supported: {metrics['protocols_supported']}")
    print(f"    - NIST standardized: {metrics['nist_standardized_count']}")
    print(f"    - Version: {metrics['simulator_version']}")
    
    assert metrics["protocols_supported"] == 9, "Should support 9 protocols"
    print("  ✓ Initialization PASSED\n")
    return True


def test_single_key_exchange():
    """Test basic key exchange simulation"""
    print("=" * 60)
    print("TEST 2: Single Key Exchange (KYBER-768)")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    result = simulator.simulate_key_exchange(PQProtocol.KYBER_768)
    
    print(f"  Protocol: {result.protocol.value}")
    print(f"  Status: {result.status.value}")
    print(f"  Keys match: {result.keys_match}")
    print(f"  Handshake time: {result.handshake_time_ms:.2f}ms")
    print(f"  Security validated: {result.security_validated}")
    
    assert result.keys_match, "Shared secrets must match"
    assert result.status == ProtocolStatus.COMPLETE, "Exchange should complete"
    assert result.handshake_time_ms > 0, "Should measure time"
    print("  ✓ Key exchange PASSED\n")
    return True


def test_all_protocols():
    """Test all supported protocols"""
    print("=" * 60)
    print("TEST 3: All Protocol Key Exchanges")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    passed = 0
    total = len(PQProtocol)
    
    for protocol in PQProtocol:
        result = simulator.simulate_key_exchange(protocol)
        status = "✓" if result.keys_match else "✗"
        print(f"  {status} {protocol.value}: keys_match={result.keys_match}, "
              f"time={result.handshake_time_ms:.2f}ms")
        if result.keys_match:
            passed += 1
    
    print(f"\n  {passed}/{total} protocols completed successfully")
    assert passed == total, "All protocols should work"
    print("  ✓ All protocol tests PASSED\n")
    return True


def test_security_validation():
    """Test security validation functionality"""
    print("=" * 60)
    print("TEST 4: Security Validation")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    
    test_cases = [
        (PQProtocol.KYBER_512, NISTSecurityLevel.LEVEL_1, True),
        (PQProtocol.KYBER_768, NISTSecurityLevel.LEVEL_3, True),
        (PQProtocol.KYBER_1024, NISTSecurityLevel.LEVEL_5, True),
        (PQProtocol.SABER, NISTSecurityLevel.LEVEL_3, False),
    ]
    
    for protocol, expected_level, expected_standardized in test_cases:
        result = simulator.simulate_key_exchange(protocol)
        validation = result.validation_report
        
        print(f"  {protocol.value}:")
        print(f"    Level: {validation['security_level']} (expected: {expected_level.value})")
        print(f"    Standardized: {validation['nist_standardized']} (expected: {expected_standardized})")
        print(f"    Score: {validation['overall_score']:.2f}")
        
        assert validation["security_level"] == expected_level.value
        assert validation["nist_standardized"] == expected_standardized
    
    print("  ✓ Security validation PASSED\n")
    return True


def test_mitm_simulation():
    """Test MITM attack simulation and detection"""
    print("=" * 60)
    print("TEST 5: MITM Attack Simulation")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    
    result = simulator.simulate_key_exchange(PQProtocol.KYBER_768, simulate_mitm=True)
    
    print(f"  MITM simulated: {result.mitm_attack_simulated}")
    print(f"  MITM detected: {result.mitm_detected}")
    print(f"  Keys still match: {result.keys_match}")
    print(f"  Final status: {result.status.value}")
    
    assert result.mitm_attack_simulated == True
    print("  ✓ MITM simulation PASSED\n")
    return True


def test_protocol_benchmarking():
    """Test protocol benchmarking feature"""
    print("=" * 60)
    print("TEST 6: Protocol Benchmarking")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    benchmarks = simulator.benchmark_all_protocols()
    
    print(f"  Benchmarked {len(benchmarks)} protocols")
    print(f"  {'Protocol':<25} {'Level':<15} {'Time(ms)':<10} {'Std':<5}")
    print("  " + "-" * 60)
    
    for bench in benchmarks:
        std = "✓" if bench["nist_standardized"] else " "
        print(f"  {bench['protocol']:<25} {bench['security_level']:<15} "
              f"{bench['total_handshake_ms']:<10.2f} {std:<5}")
    
    assert len(benchmarks) == len(PQProtocol), "Should benchmark all protocols"
    print("  ✓ Benchmarking PASSED\n")
    return True


def test_recommendations():
    """Test recommendation generation"""
    print("=" * 60)
    print("TEST 7: Recommendation Generation")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    
    protocols_to_test = [PQProtocol.KYBER_768, PQProtocol.SABER]
    
    for protocol in protocols_to_test:
        result = simulator.simulate_key_exchange(protocol)
        print(f"  {protocol.value}:")
        print(f"    Recommendations generated: {len(result.recommendations)}")
        for rec in result.recommendations[:3]:
            print(f"      - {rec}")
        print()
        
        assert len(result.recommendations) >= 1, "Should generate recommendations"
    
    print("  ✓ Recommendation generation PASSED\n")
    return True


def test_performance_timing():
    """Test performance timing measurements"""
    print("=" * 60)
    print("TEST 8: Performance Timing")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    result = simulator.simulate_key_exchange(PQProtocol.KYBER_768)
    
    print(f"  Key generation: {result.keygen_time_ms:.3f}ms")
    print(f"  Encapsulation: {result.encaps_time_ms:.3f}ms")
    print(f"  Decapsulation: {result.decaps_time_ms:.3f}ms")
    print(f"  Total handshake: {result.handshake_time_ms:.3f}ms")
    
    # All timings should be positive
    assert result.keygen_time_ms > 0
    assert result.encaps_time_ms > 0
    assert result.decaps_time_ms > 0
    assert result.handshake_time_ms > result.keygen_time_ms + result.encaps_time_ms
    
    print("  ✓ Performance timing PASSED\n")
    return True


def test_protocol_parameters():
    """Test protocol parameter correctness"""
    print("=" * 60)
    print("TEST 9: Protocol Parameter Validation")
    print("=" * 60)
    
    simulator = PostQuantumKeyExchangeSimulator()
    metrics = simulator.get_protocol_metrics()
    
    for proto_name, params in metrics["protocols"].items():
        print(f"  {proto_name}:")
        print(f"    PK size: {params['public_key_size']} bytes")
        print(f"    CT size: {params['ciphertext_size']} bytes")
        print(f"    Security: {params['security_bits']} bits")
        
        # Validate parameter ranges
        assert params["public_key_size"] > 0
        assert params["ciphertext_size"] > 0
        assert params["security_bits"] >= 128
    
    print("  ✓ Protocol parameters PASSED\n")
    return True


def run_all_tests():
    """Run all test cases"""
    print("\n" + "=" * 60)
    print("POST-QUANTUM KEY EXCHANGE SIMULATOR - TEST SUITE")
    print("=" * 60 + "\n")
    
    tests = [
        test_simulator_initialization,
        test_single_key_exchange,
        test_all_protocols,
        test_security_validation,
        test_mitm_simulation,
        test_protocol_benchmarking,
        test_recommendations,
        test_performance_timing,
        test_protocol_parameters
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
            print(f"  ✗ TEST FAILED: {test.__name__}")
            print(f"    Error: {str(e)}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - PQ Key Exchange Simulator working correctly!")
    else:
        print(f"\n✗ {failed} TESTS FAILED")
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
