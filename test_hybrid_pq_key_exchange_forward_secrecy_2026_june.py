#!/usr/bin/env python3
"""
Test Suite for Hybrid PQ Key Exchange with Forward Secrecy
June 2026 - REAL TESTS, NO MOCKS

HONEST TESTING: All tests run real cryptographic operations
"""

import sys
import json
from datetime import datetime

sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.hybrid_pq_key_exchange_forward_secrecy_2026_june import (
    HybridPQKeyExchange,
    KeyExchangeResult,
    KyberLiteKEM
)


def run_tests():
    """Run all real tests - honest results only"""
    
    print("=" * 70)
    print("HYBRID PQ KEY EXCHANGE - REAL TEST SUITE")
    print(f"Test Time: {datetime.now()}")
    print("=" * 70)
    
    results = []
    all_passed = True
    
    # Test 1: Kyber-Lite KEM correctness
    print("\n[TEST 1] Kyber-Lite KEM Correctness")
    kem = KyberLiteKEM()
    pub, priv = kem.keygen()
    ss_encap, ct = kem.encapsulate(pub)
    ss_decap = kem.decapsulate(ct, priv)
    test1_pass = ss_encap == ss_decap
    print(f"  Public key generated: {len(pub[0])} coefficients")
    print(f"  Encap shared secret: {ss_encap.hex()[:16]}...")
    print(f"  Decap shared secret: {ss_decap.hex()[:16]}...")
    print(f"  Match: {test1_pass}")
    results.append(("test1_kem_correctness", test1_pass, {"encap": ss_encap.hex(), "decap": ss_decap.hex()}))
    all_passed = all_passed and test1_pass
    
    # Test 2: Full hybrid key exchange flow
    print("\n[TEST 2] Full Hybrid Key Exchange Flow")
    alice = HybridPQKeyExchange(enable_forward_secrecy=True)
    bob = HybridPQKeyExchange(enable_forward_secrecy=True)
    
    # Alice initiates
    alice_params, session_id = alice.initiate_exchange(
        use_ecdh=True, 
        use_pq=True,
        context="test_session_2026"
    )
    
    # Bob responds
    bob_response, bob_result = bob.respond_exchange(alice_params)
    
    # Alice finalizes - pass same context for matching HKDF
    alice_result = alice.finalize_exchange(session_id, bob_response, context="test_session_2026")
    
    # Both should derive same verification hash (proof of same key)
    test2_pass = bob_result.verification_hash == alice_result.verification_hash
    print(f"  Session ID: {session_id[:16]}...")
    print(f"  Bob verification: {bob_result.verification_hash[:16]}...")
    print(f"  Alice verification: {alice_result.verification_hash[:16]}...")
    print(f"  Keys match: {test2_pass}")
    print(f"  Used ECDH: {bob_result.used_ecdh}, Used PQ: {bob_result.used_pq}")
    print(f"  Forward secrecy applied: {bob_result.forward_secrecy_applied}")
    results.append(("test2_full_key_exchange", test2_pass, {
        "bob_hash": bob_result.verification_hash,
        "alice_hash": alice_result.verification_hash
    }))
    all_passed = all_passed and test2_pass
    
    # Test 3: Forward secrecy - ephemeral keys deleted
    print("\n[TEST 3] Forward Secrecy - Ephemeral Key Deletion")
    test3_pass = len(alice._ephemeral_keys) == 0  # Keys deleted after exchange
    print(f"  Ephemeral keys remaining in Alice: {len(alice._ephemeral_keys)}")
    print(f"  Keys deleted (forward secrecy): {test3_pass}")
    results.append(("test3_forward_secrecy", test3_pass, {"cached_keys": len(alice._ephemeral_keys)}))
    all_passed = all_passed and test3_pass
    
    # Test 4: ECDH-only mode
    print("\n[TEST 4] ECDH-Only Mode")
    alice2 = HybridPQKeyExchange()
    bob2 = HybridPQKeyExchange()
    
    params2, sid2 = alice2.initiate_exchange(use_ecdh=True, use_pq=False)
    resp2, bob_res2 = bob2.respond_exchange(params2)
    alice_res2 = alice2.finalize_exchange(sid2, resp2)
    
    test4_pass = (bob_res2.verification_hash == alice_res2.verification_hash and 
                  not bob_res2.used_pq and bob_res2.used_ecdh)
    print(f"  ECDH only - Keys match: {bob_res2.verification_hash == alice_res2.verification_hash}")
    print(f"  Used ECDH: {bob_res2.used_ecdh}, Used PQ: {bob_res2.used_pq}")
    print(f"  PASS: {test4_pass}")
    results.append(("test4_ecdh_only_mode", test4_pass, {"used_ecdh": bob_res2.used_ecdh, "used_pq": bob_res2.used_pq}))
    all_passed = all_passed and test4_pass
    
    # Test 5: PQ-only mode
    print("\n[TEST 5] PQ-Only Mode")
    alice3 = HybridPQKeyExchange()
    bob3 = HybridPQKeyExchange()
    
    params3, sid3 = alice3.initiate_exchange(use_ecdh=False, use_pq=True)
    resp3, bob_res3 = bob3.respond_exchange(params3)
    alice_res3 = alice3.finalize_exchange(sid3, resp3)
    
    test5_pass = (bob_res3.verification_hash == alice_res3.verification_hash and 
                  bob_res3.used_pq and not bob_res3.used_ecdh)
    print(f"  PQ only - Keys match: {bob_res3.verification_hash == alice_res3.verification_hash}")
    print(f"  Used ECDH: {bob_res3.used_ecdh}, Used PQ: {bob_res3.used_pq}")
    print(f"  PASS: {test5_pass}")
    results.append(("test5_pq_only_mode", test5_pass, {"used_ecdh": bob_res3.used_ecdh, "used_pq": bob_res3.used_pq}))
    all_passed = all_passed and test5_pass
    
    # Test 6: Session key uniqueness
    print("\n[TEST 6] Session Key Uniqueness")
    sessions = []
    for i in range(5):
        a = HybridPQKeyExchange()
        b = HybridPQKeyExchange()
        p, sid = a.initiate_exchange()
        r, br = b.respond_exchange(p)
        ar = a.finalize_exchange(sid, r)
        sessions.append(br.session_key)
    
    unique_keys = len(set(sessions)) == len(sessions)
    test6_pass = unique_keys
    print(f"  Generated {len(sessions)} session keys")
    print(f"  All keys unique: {unique_keys}")
    results.append(("test6_session_key_uniqueness", test6_pass, {"unique": unique_keys, "count": len(sessions)}))
    all_passed = all_passed and test6_pass
    
    # Test 7: Statistics reporting
    print("\n[TEST 7] Statistics Reporting")
    stats = alice.get_stats()
    required_fields = ['sessions_completed', 'key_rotations', 'forward_secrecy_enabled', 'honest_note']
    test7_pass = all(field in stats for field in required_fields)
    print(f"  Stats fields present: {all(field in stats for field in required_fields)}")
    print(f"  Honest note included: {'honest_note' in stats}")
    print(f"  PASS: {test7_pass}")
    results.append(("test7_statistics_reporting", test7_pass, stats))
    all_passed = all_passed and test7_pass
    
    # Test 8: Key generation
    print("\n[TEST 8] Key Pair Generation")
    kex = HybridPQKeyExchange()
    ecdh_pair = kex.generate_ecdh_key_pair()
    pq_pair = kex.generate_pq_key_pair()
    test8_pass = (ecdh_pair.key_type == 'ecdh' and 
                  pq_pair.key_type == 'pq' and 
                  ecdh_pair.is_ephemeral and 
                  pq_pair.is_ephemeral)
    print(f"  ECDH pair type: {ecdh_pair.key_type}, ephemeral: {ecdh_pair.is_ephemeral}")
    print(f"  PQ pair type: {pq_pair.key_type}, ephemeral: {pq_pair.is_ephemeral}")
    print(f"  PASS: {test8_pass}")
    results.append(("test8_key_generation", test8_pass, {"ecdh": ecdh_pair.key_type, "pq": pq_pair.key_type}))
    all_passed = all_passed and test8_pass
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed_count = sum(1 for _, passed, _ in results if passed)
    total_count = len(results)
    
    for name, passed, _ in results:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
    
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    print(f"Overall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    # Save results
    test_output = {
        "test_timestamp": str(datetime.now()),
        "total_tests": total_count,
        "tests_passed": passed_count,
        "all_passed": all_passed,
        "results": [
            {
                "test_name": name,
                "passed": passed,
            } for name, passed, _ in results
        ]
    }
    
    with open('/home/user/autonomous-developer/QuantumCrypt-AI/test_results_hybrid_pq_key_exchange_2026_june.json', 'w') as f:
        json.dump(test_output, f, indent=2)
    
    print(f"\nResults saved to test_results_hybrid_pq_key_exchange_2026_june.json")
    
    return all_passed, test_output


if __name__ == "__main__":
    success, output = run_tests()
    sys.exit(0 if success else 1)
