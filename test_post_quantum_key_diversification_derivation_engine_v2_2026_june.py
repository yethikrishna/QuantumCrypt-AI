"""
Test suite for Post-Quantum Key Diversification & Derivation Engine v2
Real production-grade tests for QuantumCrypt-AI
"""
import sys
import json
import time
import hmac
from pathlib import Path

# Add quantum_crypt to path
sys.path.insert(0, str(Path(__file__).parent / "quantum_crypt"))

from post_quantum_key_diversification_derivation_engine_v2_2026_june import (
    KeyDiversificationEngine,
    PostQuantumHKDF,
    DerivedKey,
    KeyRatchetingResult,
    DiversificationResult,
    KDFAlgorithm,
    KeyPurpose,
    DiversificationStrategy,
)


def run_tests():
    """Run all tests and return results"""
    print("=" * 70)
    print("Testing Post-Quantum Key Diversification & Derivation Engine v2")
    print("=" * 70)
    
    # Use fixed master seed for deterministic tests
    test_seed = b'\x00' * 32 + b'\xff' * 32
    engine = KeyDiversificationEngine(master_seed=test_seed)
    results = []
    all_passed = True
    
    # Test 1: HKDF basic derivation
    print("\n[Test 1] HKDF basic derivation functionality")
    hkdf = PostQuantumHKDF('sha256')
    ikm = b'test input key material'
    salt = b'test salt'
    info = b'test info'
    derived = hkdf.derive(ikm, 32, salt, info)
    test1_passed = len(derived) == 32 and derived != ikm
    print(f"  Derived length: {len(derived)} bytes")
    print(f"  Derived != input: {derived != ikm}")
    print(f"  PASSED: {test1_passed}")
    results.append({"test": "hkdf_basic", "passed": test1_passed, "length": len(derived)})
    all_passed = all_passed and test1_passed
    
    # Test 2: Key derivation for specific purpose
    print("\n[Test 2] Key derivation with specific purpose")
    enc_key = engine.derive_key(KeyPurpose.ENCRYPTION, key_length=32)
    sig_key = engine.derive_key(KeyPurpose.SIGNING, key_length=32)
    test2_passed = (len(enc_key.key_material) == 32 and 
                   len(sig_key.key_material) == 32 and 
                   enc_key.key_material != sig_key.key_material)
    print(f"  Enc key length: {len(enc_key.key_material)}")
    print(f"  Sig key length: {len(sig_key.key_material)}")
    print(f"  Keys are different (domain separation): {enc_key.key_material != sig_key.key_material}")
    print(f"  PASSED: {test2_passed}")
    results.append({"test": "purpose_derivation", "passed": test2_passed, "domain_separation": enc_key.key_material != sig_key.key_material})
    all_passed = all_passed and test2_passed
    
    # Test 3: User-based key diversification
    print("\n[Test 3] User-based key diversification")
    user1_key = engine.derive_key(KeyPurpose.ENCRYPTION, user_id="user_001")
    user2_key = engine.derive_key(KeyPurpose.ENCRYPTION, user_id="user_002")
    test3_passed = user1_key.key_material != user2_key.key_material
    print(f"  User 1 key != User 2 key: {user1_key.key_material != user2_key.key_material}")
    print(f"  User 1 tags: {user1_key.diversification_tags}")
    print(f"  User 2 tags: {user2_key.diversification_tags}")
    print(f"  PASSED: {test3_passed}")
    results.append({"test": "user_diversification", "passed": test3_passed, "keys_different": user1_key.key_material != user2_key.key_material})
    all_passed = all_passed and test3_passed
    
    # Test 4: Deterministic derivation (same params = same key)
    print("\n[Test 4] Deterministic derivation consistency")
    key1 = engine.derive_key(KeyPurpose.ENCRYPTION, context="test", salt=b'fixed_salt')
    key2 = engine.derive_key(KeyPurpose.ENCRYPTION, context="test", salt=b'fixed_salt')
    test4_passed = hmac.compare_digest(key1.key_material, key2.key_material)
    print(f"  Same params produce same key: {test4_passed}")
    print(f"  PASSED: {test4_passed}")
    results.append({"test": "deterministic", "passed": test4_passed})
    all_passed = all_passed and test4_passed
    
    # Test 5: Hierarchical key derivation
    print("\n[Test 5] Hierarchical key derivation")
    hier_key = engine.derive_hierarchical(
        derivation_path=['org', 'dept', 'user', 'enc'],
        purpose=KeyPurpose.ENCRYPTION,
        key_length=32
    )
    test5_passed = (len(hier_key.key_material) == 32 and 
                   len(hier_key.derivation_path) == 4)
    print(f"  Derivation path: {hier_key.derivation_path}")
    print(f"  Key length: {len(hier_key.key_material)}")
    print(f"  PASSED: {test5_passed}")
    results.append({"test": "hierarchical", "passed": test5_passed, "path_depth": len(hier_key.derivation_path)})
    all_passed = all_passed and test5_passed
    
    # Test 6: Key ratcheting with forward secrecy
    print("\n[Test 6] Key ratcheting with forward secrecy")
    ratchet1 = engine.ratchet_key("test_chain", KeyPurpose.ENCRYPTION)
    ratchet2 = engine.ratchet_key("test_chain", KeyPurpose.ENCRYPTION)
    test6_passed = (ratchet1.current_key.key_material != ratchet2.current_key.key_material and
                   ratchet2.ratchet_counter > ratchet1.ratchet_counter and
                   ratchet1.forward_secrecy_verified)
    print(f"  Ratchet 1 counter: {ratchet1.ratchet_counter}")
    print(f"  Ratchet 2 counter: {ratchet2.ratchet_counter}")
    print(f"  Ratchet keys different: {ratchet1.current_key.key_material != ratchet2.current_key.key_material}")
    print(f"  Forward secrecy verified: {ratchet1.forward_secrecy_verified}")
    print(f"  PASSED: {test6_passed}")
    results.append({"test": "key_ratcheting", "passed": test6_passed, "forward_secrecy": ratchet1.forward_secrecy_verified})
    all_passed = all_passed and test6_passed
    
    # Test 7: Multi-context diversification
    print("\n[Test 7] Multi-context key diversification")
    contexts = ['web', 'mobile', 'api', 'admin', 'backup']
    div_result = engine.diversify_for_multiple_contexts(
        contexts=contexts,
        purpose=KeyPurpose.ENCRYPTION
    )
    test7_passed = (div_result.total_derived_keys == 5 and
                   len(set(k.key_material for k in div_result.derived_keys.values())) == 5)
    print(f"  Total derived keys: {div_result.total_derived_keys}")
    print(f"  All keys unique: {len(set(k.key_material for k in div_result.derived_keys.values())) == 5}")
    print(f"  Contexts: {div_result.domain_tags}")
    print(f"  PASSED: {test7_passed}")
    results.append({"test": "multi_context", "passed": test7_passed, "num_keys": div_result.total_derived_keys})
    all_passed = all_passed and test7_passed
    
    # Test 8: Key derivation consistency verification
    print("\n[Test 8] Derivation consistency verification")
    original_params = {'purpose': KeyPurpose.AUTHENTICATION, 'context': 'verify_test'}
    derived = engine.derive_key(**original_params)
    is_consistent = engine.verify_key_derivation_consistency(derived, original_params)
    test8_passed = is_consistent
    print(f"  Derivation verified consistent: {is_consistent}")
    print(f"  PASSED: {test8_passed}")
    results.append({"test": "consistency_verify", "passed": test8_passed})
    all_passed = all_passed and test8_passed
    
    # Test 9: Multi-user key hierarchy generation
    print("\n[Test 9] Multi-user key hierarchy generation")
    hierarchy = engine.generate_key_hierarchy(num_users=5, keys_per_user=3)
    test9_passed = (len(hierarchy) == 5 and
                   all(len(keys) == 3 for keys in hierarchy.values()))
    print(f"  Number of users: {len(hierarchy)}")
    print(f"  Keys per user: {[len(keys) for keys in hierarchy.values()]}")
    print(f"  PASSED: {test9_passed}")
    results.append({"test": "multi_user_hierarchy", "passed": test9_passed, "num_users": len(hierarchy)})
    all_passed = all_passed and test9_passed
    
    # Test 10: Different key lengths
    print("\n[Test 10] Different key length support")
    key_16 = engine.derive_key(KeyPurpose.ENCRYPTION, key_length=16)
    key_24 = engine.derive_key(KeyPurpose.ENCRYPTION, key_length=24)
    key_32 = engine.derive_key(KeyPurpose.ENCRYPTION, key_length=32)
    key_64 = engine.derive_key(KeyPurpose.ENCRYPTION, key_length=64)
    test10_passed = (len(key_16.key_material) == 16 and
                    len(key_24.key_material) == 24 and
                    len(key_32.key_material) == 32 and
                    len(key_64.key_material) == 64)
    print(f"  16 bytes: {len(key_16.key_material)}")
    print(f"  24 bytes: {len(key_24.key_material)}")
    print(f"  32 bytes: {len(key_32.key_material)}")
    print(f"  64 bytes: {len(key_64.key_material)}")
    print(f"  PASSED: {test10_passed}")
    results.append({"test": "key_lengths", "passed": test10_passed})
    all_passed = all_passed and test10_passed
    
    # Test 11: Master key fingerprint (safe for logging)
    print("\n[Test 11] Master key fingerprint")
    fingerprint = engine.get_master_key_fingerprint()
    test11_passed = len(fingerprint) == 16 and fingerprint.isalnum()
    print(f"  Master fingerprint: {fingerprint}")
    print(f"  Length (16 hex chars): {len(fingerprint)}")
    print(f"  PASSED: {test11_passed}")
    results.append({"test": "fingerprint", "passed": test11_passed})
    all_passed = all_passed and test11_passed
    
    # Test 12: Safe serialization (no key material exposed)
    print("\n[Test 12] Safe serialization (no key material exposure)")
    test_key = engine.derive_key(KeyPurpose.ENCRYPTION)
    serialized = engine.to_dict(test_key)
    test12_passed = 'key_material' not in serialized and 'purpose' in serialized
    print(f"  Serialized keys: {list(serialized.keys())[:8]}")
    print(f"  No key material exposed: {'key_material' not in serialized}")
    print(f"  PASSED: {test12_passed}")
    results.append({"test": "safe_serialization", "passed": test12_passed})
    all_passed = all_passed and test12_passed
    
    # Test 13: Performance benchmark
    print("\n[Test 13] Performance benchmark")
    start_time = time.time()
    for i in range(100):
        engine.derive_key(KeyPurpose.ENCRYPTION, context=f'perf_test_{i}')
    elapsed = time.time() - start_time
    avg_time = elapsed / 100 * 1000  # ms
    test13_passed = avg_time < 2.0  # Under 2ms per derivation
    print(f"  100 derivations in {elapsed:.3f}s")
    print(f"  Average: {avg_time:.3f}ms per derivation")
    print(f"  PASSED: {test13_passed}")
    results.append({"test": "performance", "passed": test13_passed, "avg_ms": avg_time})
    all_passed = all_passed and test13_passed
    
    # Summary
    print("\n" + "=" * 70)
    print(f"ALL TESTS PASSED: {all_passed}")
    print(f"Passed: {sum(1 for r in results if r['passed'])}/{len(results)}")
    print("=" * 70)
    
    # Save test results
    test_output = {
        "module": "post_quantum_key_diversification_derivation_engine_v2_2026_june",
        "timestamp": time.time(),
        "all_passed": all_passed,
        "passed_count": sum(1 for r in results if r["passed"]),
        "total_tests": len(results),
        "test_results": results
    }
    
    with open("test_results_key_diversification_derivation_v2_2026_june.json", "w") as f:
        json.dump(test_output, f, indent=2)
    
    print(f"\nTest results saved to test_results_key_diversification_derivation_v2_2026_june.json")
    
    return all_passed, results


if __name__ == "__main__":
    success, results = run_tests()
    sys.exit(0 if success else 1)
