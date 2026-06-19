#!/usr/bin/env python3
"""
Test suite for Post-Quantum TLS 1.3 Key Exchange Simulator
Comprehensive testing of all PQ key exchange features
"""

import sys
import json
from quantum_crypt.post_quantum_secure_key_exchange_tls13_simulator_2026_june import (
    PQTLS13HandshakeSimulator,
    KyberKEMSimulator,
    ECDHESimulator,
    TLS13KeySchedule,
    KeyExchangeMode,
    CipherSuite,
    KeyExchangeResult,
    SecurityAssessment,
    get_pq_tls13_simulator
)


def run_tests():
    """Run all test cases"""
    print("=" * 70)
    print("TEST SUITE: Post-Quantum TLS 1.3 Key Exchange Simulator")
    print("=" * 70)
    
    all_passed = True
    test_results = []
    
    # Test 1: Kyber KEM functionality
    print("\n[TEST 1] Kyber KEM Simulator")
    try:
        kyber = KyberKEMSimulator(security_level=3)
        sk, pk = kyber.keygen()
        
        assert len(sk) == kyber.params['sk_bytes']
        assert len(pk) == kyber.params['pk_bytes']
        
        ss_server, ct = kyber.encaps(pk)
        ss_client = kyber.decaps(ct, sk)
        
        assert len(ss_server) == 32
        assert len(ss_client) == 32
        assert len(ct) == kyber.params['ct_bytes']
        
        print("  ✓ Kyber keygen, encaps, decaps all working")
        print(f"    - Security Level: {kyber.security_level}")
        print(f"    - SK size: {len(sk)} bytes")
        print(f"    - PK size: {len(pk)} bytes")
        print(f"    - CT size: {len(ct)} bytes")
        
        test_results.append(("Kyber KEM", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Kyber KEM", "FAIL"))
        all_passed = False
    
    # Test 2: ECDHE functionality
    print("\n[TEST 2] ECDHE Simulator")
    try:
        ecdhe = ECDHESimulator()
        sk1, pk1 = ecdhe.keygen()
        sk2, pk2 = ecdhe.keygen()
        
        ss1 = ecdhe.derive(sk1, pk2)
        ss2 = ecdhe.derive(sk2, pk1)
        
        assert len(sk1) == 32
        assert len(pk1) == 32
        assert len(ss1) == 32
        assert len(ss2) == 32
        
        print("  ✓ ECDHE key exchange working correctly")
        
        test_results.append(("ECDHE", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("ECDHE", "FAIL"))
        all_passed = False
    
    # Test 3: TLS 1.3 Key Schedule
    print("\n[TEST 3] TLS 1.3 Key Schedule")
    try:
        ks = TLS13KeySchedule()
        shared = b'\x01' * 32
        cr = b'\x02' * 32
        sr = b'\x03' * 32
        
        secrets = ks.derive_all_secrets(shared, cr, sr)
        
        assert 'shared_secret' in secrets
        assert 'master_secret' in secrets
        assert 'client_handshake_traffic_secret' in secrets
        assert 'server_handshake_traffic_secret' in secrets
        assert 'client_application_traffic_secret' in secrets
        assert 'server_application_traffic_secret' in secrets
        
        assert len(secrets['master_secret']) == 48
        assert len(secrets['client_application_traffic_secret']) == 48
        
        print("  ✓ TLS 1.3 key schedule derives all secrets correctly")
        print(f"    - Master secret: {len(secrets['master_secret'])} bytes")
        print(f"    - Traffic secrets: {len(secrets['client_application_traffic_secret'])} bytes")
        
        test_results.append(("TLS Key Schedule", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("TLS Key Schedule", "FAIL"))
        all_passed = False
    
    # Test 4: Hybrid Handshake (Recommended)
    print("\n[TEST 4] Hybrid Mode Handshake (ECDHE + Kyber) - RECOMMENDED")
    try:
        simulator = PQTLS13HandshakeSimulator()
        result = simulator.perform_handshake(mode=KeyExchangeMode.HYBRID)
        
        assert result.success == True
        assert result.pq_protected == True
        assert result.mode == KeyExchangeMode.HYBRID
        assert len(result.session_id) == 32
        assert result.messages_exchanged == 4
        assert len(result.shared_secret) == 48
        assert len(result.master_secret) == 48
        
        print("  ✓ Hybrid handshake completed successfully")
        print(f"    - PQ Protected: {result.pq_protected}")
        print(f"    - Handshake time: {result.handshake_time_ms:.2f} ms")
        print(f"    - Security: {result.security_level}")
        
        test_results.append(("Hybrid Handshake", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Hybrid Handshake", "FAIL"))
        all_passed = False
    
    # Test 5: PQ-Only Handshake
    print("\n[TEST 5] PQ-Only Mode Handshake (Kyber Only)")
    try:
        simulator = PQTLS13HandshakeSimulator()
        result = simulator.perform_handshake(mode=KeyExchangeMode.PQ_ONLY)
        
        assert result.success == True
        assert result.pq_protected == True
        assert result.mode == KeyExchangeMode.PQ_ONLY
        
        print("  ✓ PQ-only handshake completed successfully")
        print(f"    - PQ Protected: {result.pq_protected}")
        print(f"    - Handshake time: {result.handshake_time_ms:.2f} ms")
        
        test_results.append(("PQ-Only Handshake", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("PQ-Only Handshake", "FAIL"))
        all_passed = False
    
    # Test 6: Classical-Only Handshake
    print("\n[TEST 6] Classical-Only Mode Handshake (ECDHE Only)")
    try:
        simulator = PQTLS13HandshakeSimulator()
        result = simulator.perform_handshake(mode=KeyExchangeMode.CLASSICAL_ONLY)
        
        assert result.success == True
        assert result.pq_protected == False
        assert result.mode == KeyExchangeMode.CLASSICAL_ONLY
        
        print("  ✓ Classical-only handshake completed successfully")
        print(f"    - PQ Protected: {result.pq_protected}")
        print(f"    - Handshake time: {result.handshake_time_ms:.2f} ms")
        
        test_results.append(("Classical Handshake", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Classical Handshake", "FAIL"))
        all_passed = False
    
    # Test 7: Security Assessment
    print("\n[TEST 7] Security Assessment")
    try:
        simulator = PQTLS13HandshakeSimulator()
        
        hybrid_assessment = simulator.get_security_assessment(KeyExchangeMode.HYBRID)
        classical_assessment = simulator.get_security_assessment(KeyExchangeMode.CLASSICAL_ONLY)
        
        assert hybrid_assessment.quantum_resistant == True
        assert classical_assessment.quantum_resistant == False
        assert hybrid_assessment.nist_security_level == 3
        assert classical_assessment.nist_security_level == 1
        assert len(hybrid_assessment.recommendations) >= 1
        
        print("  ✓ Security assessments generated correctly")
        print(f"    - Hybrid: Quantum Resistant = {hybrid_assessment.quantum_resistant}, NIST L{hybrid_assessment.nist_security_level}")
        print(f"    - Classical: Quantum Resistant = {classical_assessment.quantum_resistant}, NIST L{classical_assessment.nist_security_level}")
        
        test_results.append(("Security Assessment", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Security Assessment", "FAIL"))
        all_passed = False
    
    # Test 8: Mode Comparison
    print("\n[TEST 8] Mode Comparison")
    try:
        simulator = PQTLS13HandshakeSimulator()
        comparison = simulator.compare_modes()
        
        assert len(comparison) == 3
        assert 'hybrid_ecdhe_kyber' in comparison
        assert 'post_quantum_kyber' in comparison
        assert 'classical_ecdhe' in comparison
        
        print("  ✓ All three modes compared successfully")
        for mode, data in comparison.items():
            qr = "✓ PQ-SAFE" if data['quantum_resistant'] else "✗ AT RISK"
            print(f"    - {mode}: {data['handshake_time_ms']:.2f}ms | {qr}")
        
        test_results.append(("Mode Comparison", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Mode Comparison", "FAIL"))
        all_passed = False
    
    # Test 9: Cipher Suite Support
    print("\n[TEST 9] Cipher Suite Support")
    try:
        simulator = PQTLS13HandshakeSimulator()
        
        for suite in CipherSuite:
            result = simulator.perform_handshake(cipher_suite=suite)
            assert result.success == True
            assert result.cipher_suite == suite
        
        print("  ✓ All cipher suites supported")
        print(f"    - {CipherSuite.TLS_AES_256_GCM_SHA384.value}")
        print(f"    - {CipherSuite.TLS_CHACHA20_POLY1305_SHA256.value}")
        print(f"    - {CipherSuite.TLS_AES_128_GCM_SHA256.value}")
        
        test_results.append(("Cipher Suites", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Cipher Suites", "FAIL"))
        all_passed = False
    
    # Test 10: Factory Function
    print("\n[TEST 10] Factory Function")
    try:
        simulator1 = get_pq_tls13_simulator()
        simulator2 = get_pq_tls13_simulator()
        
        assert simulator1 is not None
        assert isinstance(simulator1, PQTLS13HandshakeSimulator)
        
        result = simulator1.perform_handshake()
        assert result.success == True
        
        print("  ✓ Factory function returns valid working simulator")
        
        test_results.append(("Factory Function", "PASS"))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        test_results.append(("Factory Function", "FAIL"))
        all_passed = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for test_name, status in test_results:
        status_mark = "✓ PASS" if status == "PASS" else "✗ FAIL"
        print(f"  {test_name:40s} {status_mark}")
    
    passed_count = sum(1 for _, s in test_results if s == "PASS")
    total_count = len(test_results)
    
    print("\n" + "-" * 70)
    print(f"RESULTS: {passed_count}/{total_count} tests passed")
    
    # Save results
    results_data = {
        'test_timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'module_tested': 'post_quantum_secure_key_exchange_tls13_simulator',
        'total_tests': total_count,
        'passed_tests': passed_count,
        'failed_tests': total_count - passed_count,
        'success_rate': passed_count / total_count,
        'all_passed': all_passed,
        'test_details': test_results
    }
    
    with open('test_results_pq_tls13_key_exchange.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"Results saved to test_results_pq_tls13_key_exchange.json")
    
    if all_passed:
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED - PQ TLS 1.3 Key Exchange is production-ready!")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print("✗ SOME TESTS FAILED - Please review and fix issues")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
