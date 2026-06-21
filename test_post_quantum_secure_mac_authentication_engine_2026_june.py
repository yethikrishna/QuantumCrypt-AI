#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure MAC Authentication Engine
June 2026 - Production Grade Tests

Real, working tests - no mocks, no empty shells.
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
from quantum_crypt.post_quantum_secure_mac_authentication_engine_2026_june import (
    PostQuantumMACEngine,
    MACAlgorithm,
    SecurityLevel
)


def run_tests():
    """Run all tests and return results"""
    print("=" * 70)
    print("POST-QUANTUM MAC AUTHENTICATION ENGINE - PRODUCTION TEST SUITE")
    print("=" * 70)
    
    engine = PostQuantumMACEngine()
    results = {
        'passed': 0,
        'failed': 0,
        'tests': []
    }
    
    def test(name, condition):
        """Helper for test assertions"""
        if condition:
            results['passed'] += 1
            results['tests'].append({'name': name, 'status': 'PASSED'})
            print(f"✓ {name}")
        else:
            results['failed'] += 1
            results['tests'].append({'name': name, 'status': 'FAILED'})
            print(f"✗ {name}")
    
    print("\n--- Test 1: Key Generation ---")
    
    key = engine.generate_key(security_level=SecurityLevel.LEVEL_5)
    test("Key ID generated", len(key.key_id) > 0)
    test("Key has correct size (LEVEL_5 = 64 bytes)", len(key.key_bytes) == 64)
    test("Key has security level 5", key.security_level == SecurityLevel.LEVEL_5)
    test("Key creation timestamp set", len(key.created_at) > 0)
    
    print("\n--- Test 2: Key Security Levels ---")
    
    key_l1 = engine.generate_key(security_level=SecurityLevel.LEVEL_1)
    test("LEVEL_1 key has 32 bytes", len(key_l1.key_bytes) == 32)
    
    key_l3 = engine.generate_key(security_level=SecurityLevel.LEVEL_3)
    test("LEVEL_3 key has 48 bytes", len(key_l3.key_bytes) == 48)
    
    print("\n--- Test 3: HMAC-SHA2-256 Computation ---")
    
    message = b"Test message for MAC authentication"
    result = engine.compute_mac(message, key, MACAlgorithm.HMAC_SHA2_256)
    test("MAC computed successfully", result.mac_value is not None)
    test("MAC has correct size (32 bytes)", len(result.mac_value) == 32)
    test("Algorithm recorded correctly", result.algorithm == MACAlgorithm.HMAC_SHA2_256)
    test("Hex output works", len(result.hex()) == 64)
    
    print("\n--- Test 4: HMAC-SHA2-512 Computation ---")
    
    result_512 = engine.compute_mac(message, key, MACAlgorithm.HMAC_SHA2_512)
    test("HMAC-SHA2-512 has correct size (64 bytes)", len(result_512.mac_value) == 64)
    
    print("\n--- Test 5: HMAC-SHA3 Computation (Post-Quantum Hash) ---")
    
    result_sha3 = engine.compute_mac(message, key, MACAlgorithm.HMAC_SHA3_512)
    test("HMAC-SHA3-512 computed successfully", result_sha3.mac_value is not None)
    test("SHA3-512 has correct size", len(result_sha3.mac_value) == 64)
    
    print("\n--- Test 6: MAC Verification (Valid) ---")
    
    is_valid, verify_result = engine.verify_mac(
        message, result.mac_value, key, MACAlgorithm.HMAC_SHA2_256
    )
    test("Valid MAC verification passes", is_valid)
    test("Result marked as verified", verify_result.verified)
    
    print("\n--- Test 7: MAC Verification (Invalid) ---")
    
    wrong_mac = b"X" * 32
    is_valid_invalid, _ = engine.verify_mac(
        message, wrong_mac, key, MACAlgorithm.HMAC_SHA2_256
    )
    test("Invalid MAC verification fails", not is_valid_invalid)
    
    print("\n--- Test 8: Poly1305 MAC ---")
    
    poly_result = engine.compute_mac(message, key, MACAlgorithm.POLY1305)
    test("Poly1305 MAC computed", poly_result.mac_value is not None)
    test("Poly1305 has correct size (16 bytes)", len(poly_result.mac_value) == 16)
    
    print("\n--- Test 9: KMAC Algorithms ---")
    
    kmac128_result = engine.compute_mac(message, key, MACAlgorithm.KMAC_128)
    test("KMAC-128 computed", kmac128_result.mac_value is not None)
    
    kmac256_result = engine.compute_mac(message, key, MACAlgorithm.KMAC_256)
    test("KMAC-256 computed", kmac256_result.mac_value is not None)
    
    print("\n--- Test 10: BLAKE3 Keyed Hash ---")
    
    blake3_result = engine.compute_mac(message, key, MACAlgorithm.BLAKE3_KEYED)
    test("BLAKE3 keyed hash computed", blake3_result.mac_value is not None)
    
    print("\n--- Test 11: String Message Support ---")
    
    str_result = engine.compute_mac("String message", key)
    test("String messages supported", str_result.mac_value is not None)
    
    print("\n--- Test 12: Key Management ---")
    
    test("Key retrieval works", engine.get_key(key.key_id) is not None)
    test("Non-existent key returns None", engine.get_key("nonexistent") is None)
    
    print("\n--- Test 13: Key Revocation ---")
    
    revoke_result = engine.revoke_key(key.key_id)
    test("Key revocation successful", revoke_result)
    test("Revoked key not returned", engine.get_key(key.key_id) is None)
    
    print("\n--- Test 14: Key Import ---")
    
    import_key_bytes = b"A" * 64
    imported = engine.import_key(import_key_bytes, MACAlgorithm.HMAC_SHA2_512)
    test("Key import successful", imported is not None)
    test("Imported key stored", engine.get_key(imported.key_id) is not None)
    
    print("\n--- Test 15: Subkey Derivation (HKDF) ---")
    
    parent_key = engine.generate_key()
    subkey = engine.derive_subkey(parent_key, "encryption")
    test("Subkey derived successfully", subkey is not None)
    test("Subkey different from parent", subkey.key_bytes != parent_key.key_bytes)
    
    print("\n--- Test 16: Key Rotation ---")
    
    rotate_key = engine.generate_key()
    old_id = rotate_key.key_id
    new_key = engine.rotate_key(old_id)
    test("Key rotation generates new key", new_key is not None)
    test("Old key revoked", engine.get_key(old_id) is None)
    
    print("\n--- Test 17: Batch Verification ---")
    
    batch_key = engine.generate_key()
    batch_result = engine.compute_mac("msg1", batch_key)
    
    tasks = [
        ("msg1", batch_result.hex(), batch_key.key_id),
        ("msg2", "00" * 32, batch_key.key_id),
    ]
    batch_out = engine.batch_verify(tasks)
    test("Batch verification works", len(batch_out) == 2)
    
    print("\n--- Test 18: Streaming MAC ---")
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(b"Test file content for streaming MAC")
        temp_path = f.name
    
    try:
        stream_key = engine.generate_key()
        stream_result = engine.compute_streaming_mac(temp_path, stream_key)
        test("Streaming MAC computed", stream_result.mac_value is not None)
    finally:
        os.unlink(temp_path)
    
    print("\n--- Test 19: Statistics Tracking ---")
    
    stats = engine.get_statistics()
    test("MACs computed tracked", stats['macs_computed'] > 0)
    test("Verifications tracked", stats['verifications_attempted'] > 0)
    test("Success rate calculated", stats['verification_success_rate'] >= 0)
    
    print("\n--- Test 20: Determinism - Same Input = Same MAC ---")
    
    det_key = engine.generate_key()
    r1 = engine.compute_mac(message, det_key)
    r2 = engine.compute_mac(message, det_key)
    test("MAC is deterministic", r1.mac_value == r2.mac_value)
    
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {results['passed']} PASSED, {results['failed']} FAILED")
    print("=" * 70)
    
    # Save results
    with open('test_results_post_quantum_mac_2026_june.json', 'w') as f:
        json.dump({
            'test_timestamp': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
            'passed': results['passed'],
            'failed': results['failed'],
            'success_rate': round(results['passed'] / (results['passed'] + results['failed']) * 100, 2),
            'tests': results['tests']
        }, f, indent=2)
    
    print(f"\nResults saved to test_results_post_quantum_mac_2026_june.json")
    
    return results['failed'] == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
