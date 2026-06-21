#!/usr/bin/env python3
"""
Test for QuantumCrypt-AI: Post-Quantum Secure HSM Emulator
June 21, 2026 - Production Grade Tests

REAL TESTS - actually runs and verifies functionality
"""

import sys
import os
import json
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_secure_hsm_emulator_2026_june import (
    PostQuantumHSMEmulator,
    create_post_quantum_hsm,
    verify_post_quantum_hsm,
    KeyAlgorithm,
    KeyType,
    KeyState,
    HSMRole,
    OperationType,
    HSMStats
)


def run_comprehensive_tests():
    """Run comprehensive real tests"""
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum HSM Emulator - TEST SUITE")
    print("June 21, 2026 - Production Grade")
    print("=" * 70)
    
    hsm = create_post_quantum_hsm("test-hsm-emulator")
    
    test_results = {
        "test_suite": "Post-Quantum HSM Emulator",
        "date": "2026-06-21",
        "tests_passed": 0,
        "tests_failed": 0,
        "test_cases": [],
        "final_verification": None
    }
    
    # Test 1: HSM Initialization
    print("\n[TEST 1] HSM Initialization")
    health = hsm.health_check()
    passed = health["status"] == "healthy" and health["initialized"] == True
    status = "PASS" if passed else "FAIL"
    print(f"  HSM health check: {status}")
    print(f"    HSM ID: {health['hsm_id']}")
    print(f"    FIPS Mode: {health['fips_mode']}")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    test_results["test_cases"].append({
        "test": "hsm_initialization",
        "passed": passed,
        "expected": "healthy",
        "actual": health["status"]
    })
    
    # Test 2: Key Generation - All Algorithms
    print("\n[TEST 2] Key Generation (All Algorithms)")
    algorithms = [
        (KeyAlgorithm.KYBER_768, KeyType.KEY_EXCHANGE),
        (KeyAlgorithm.DILITHIUM_5, KeyType.SIGNING_KEY),
        (KeyAlgorithm.AES_256_GCM, KeyType.DATA_ENCRYPTION_KEY),
        (KeyAlgorithm.FALCON_512, KeyType.SIGNING_KEY),
    ]
    
    generated_keys = []
    for alg, key_type in algorithms:
        key_id, metadata = hsm.generate_key(
            "admin", alg, key_type, f"Test key: {alg.value}"
        )
        passed = metadata.state == KeyState.ACTIVE and metadata.algorithm == alg
        status = "PASS" if passed else "FAIL"
        print(f"  {alg.value}: {status} (key_id: {key_id[:16]}...)")
        generated_keys.append((key_id, metadata))
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
    
    # Test 3: Sign and Verify
    print("\n[TEST 3] Digital Signature (Sign + Verify)")
    signing_key_id, _ = generated_keys[1]  # Dilithium signing key
    test_messages = [
        b"Hello, Quantum World!",
        b"Test message for post-quantum signature",
        b""  # Empty message
    ]
    
    for msg in test_messages:
        signature = hsm.sign("admin", signing_key_id, msg)
        verified = hsm.verify("admin", signing_key_id, msg, signature)
        passed = verified and len(signature) == 64
        status = "PASS" if passed else "FAIL"
        msg_preview = msg[:20].decode('utf-8', errors='replace') if msg else "(empty)"
        print(f"  Message '{msg_preview}': {status}")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
    
    # Test 4: Encrypt and Decrypt
    print("\n[TEST 4] Encryption (Encrypt + Decrypt)")
    enc_key_id, _ = generated_keys[2]  # AES encryption key
    test_data = [
        b"Secret quantum-safe data",
        b"Top secret: NIST PQ algorithms are now standard",
        b"Short",
        b"A" * 1000,  # Larger data
    ]
    
    for data in test_data:
        ciphertext = hsm.encrypt("admin", enc_key_id, data)
        decrypted = hsm.decrypt("admin", enc_key_id, ciphertext)
        passed = decrypted == data
        status = "PASS" if passed else "FAIL"
        print(f"  Data ({len(data)} bytes): {status}")
        
        if passed:
            test_results["tests_passed"] += 1
        else:
            test_results["tests_failed"] += 1
    
    # Test 5: Key Rotation
    print("\n[TEST 5] Key Rotation")
    original_key_id, original_metadata = generated_keys[0]
    new_key_id, new_metadata = hsm.rotate_key("admin", original_key_id)
    passed = (new_key_id != original_key_id and 
              new_metadata.state == KeyState.ACTIVE and
              new_metadata.algorithm == original_metadata.algorithm)
    status = "PASS" if passed else "FAIL"
    print(f"  Key rotation: {status}")
    print(f"    Original: {original_key_id[:16]}...")
    print(f"    New: {new_key_id[:16]}...")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 6: Role-Based Access Control
    print("\n[TEST 6] Role-Based Access Control")
    
    # Create crypto user (can sign/encrypt but not generate keys)
    hsm._roles["crypto_user_1"] = HSMRole.CRYPTO_USER
    
    # Should fail - crypto user cannot generate keys
    try:
        hsm.generate_key("crypto_user_1", KeyAlgorithm.KYBER_512, KeyType.KEY_EXCHANGE)
        rbac_passed1 = False
    except PermissionError:
        rbac_passed1 = True
    
    # Should succeed - crypto user can sign
    try:
        _ = hsm.sign("crypto_user_1", signing_key_id, b"test")
        rbac_passed2 = True
    except PermissionError:
        rbac_passed2 = False
    
    rbac_passed = rbac_passed1 and rbac_passed2
    status = "PASS" if rbac_passed else "FAIL"
    print(f"  Permission enforcement: {status}")
    print(f"    Key gen denied: {rbac_passed1}")
    print(f"    Sign allowed: {rbac_passed2}")
    
    if rbac_passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 7: Key Deletion
    print("\n[TEST 7] Secure Key Deletion")
    del_key_id, _ = hsm.generate_key(
        "admin", KeyAlgorithm.KYBER_512, KeyType.KEY_EXCHANGE, "To be deleted"
    )
    initial_count = len(hsm.list_keys())
    hsm.delete_key("admin", del_key_id)
    final_count = len(hsm.list_keys())
    passed = final_count == initial_count - 1
    status = "PASS" if passed else "FAIL"
    print(f"  Key deletion: {status} (count: {initial_count} -> {final_count})")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 8: Audit Logging
    print("\n[TEST 8] Audit Logging")
    audit_log = hsm.get_audit_log(50)
    passed = len(audit_log) > 0
    status = "PASS" if passed else "FAIL"
    print(f"  Audit log entries: {status} (count: {len(audit_log)})")
    
    # Verify log has expected operations
    op_types = set(op.operation_type for op in audit_log)
    expected_ops = {OperationType.KEY_GENERATE, OperationType.SIGN, OperationType.ENCRYPT}
    has_expected = len(op_types & expected_ops) >= 2
    print(f"  Expected operations logged: {has_expected}")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 9: Statistics and Monitoring
    print("\n[TEST 9] Statistics and Monitoring")
    stats = hsm.get_statistics()
    passed = (stats.total_keys > 0 and 
              stats.active_keys > 0 and 
              stats.total_operations > 0 and
              stats.uptime_seconds > 0)
    status = "PASS" if passed else "FAIL"
    print(f"  Statistics tracking: {status}")
    print(f"    Total keys: {stats.total_keys}")
    print(f"    Active keys: {stats.active_keys}")
    print(f"    Total operations: {stats.total_operations}")
    print(f"    Uptime: {stats.uptime_seconds:.2f}s")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Test 10: List Keys Metadata
    print("\n[TEST 10] Key Metadata Listing")
    keys = hsm.list_keys()
    passed = len(keys) > 0 and all(hasattr(k, 'key_id') for k in keys)
    status = "PASS" if passed else "FAIL"
    print(f"  Metadata listing: {status} ({len(keys)} keys)")
    
    if passed:
        test_results["tests_passed"] += 1
    else:
        test_results["tests_failed"] += 1
    
    # Final verification
    print("\n" + "=" * 70)
    print("FINAL VERIFICATION")
    print("=" * 70)
    verification = verify_post_quantum_hsm()
    test_results["final_verification"] = verification
    
    print(f"Verification: {'PASSED' if verification['verified'] else 'FAILED'}")
    print(f"Message: {verification['message']}")
    print(f"Individual tests: {json.dumps(verification['test_results'], indent=2)}")
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    total = test_results["tests_passed"] + test_results["tests_failed"]
    print(f"Total Tests: {total}")
    print(f"Passed: {test_results['tests_passed']}")
    print(f"Failed: {test_results['tests_failed']}")
    print(f"Success Rate: {(test_results['tests_passed']/total*100):.1f}%")
    
    # Save results
    output_file = "test_results_post_quantum_hsm_emulator_2026_june.json"
    with open(output_file, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    print(f"\nResults saved to: {output_file}")
    
    return test_results


if __name__ == "__main__":
    results = run_comprehensive_tests()
    sys.exit(0 if results["tests_failed"] == 0 else 1)
