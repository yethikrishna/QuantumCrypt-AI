#!/usr/bin/env python3
"""
Test Suite for Post-Quantum HSM Emulator - QuantumCrypt-AI
June 17, 2026 - Production Tests
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_hsm_emulator_2026_june import (
    PostQuantumHSMEmulator,
    KeyType,
    KeyUsage,
    HSMOperation,
    SecurityLevel,
    create_post_quantum_hsm
)


def test_hsm_initialization():
    """Test HSM initialization"""
    print("Test 1: HSM Initialization")
    hsm = PostQuantumHSMEmulator(security_level=SecurityLevel.LEVEL_3)
    
    result = hsm.initialize()
    print(f"  HSM ID: {hsm.hsm_id}")
    print(f"  Initialized: {result}")
    print(f"  Security Level: {hsm.security_level.value}")
    
    assert result == True, "HSM should initialize successfully"
    print("  ✓ PASSED\n")


def test_key_generation():
    """Test key generation inside HSM"""
    print("Test 2: Key Generation")
    hsm = create_post_quantum_hsm()
    
    result = hsm.generate_key(
        key_type=KeyType.HMAC_SECRET,
        key_size=256,
        label="test-signing-key",
        extractable=False
    )
    
    print(f"  Success: {result.success}")
    print(f"  Key ID: {result.key_id}")
    print(f"  Has checksum: {result.checksum is not None}")
    
    assert result.success == True, "Key generation should succeed"
    assert result.key_id is not None, "Should return key ID"
    assert result.checksum is not None, "Should return key checksum"
    print("  ✓ PASSED\n")


def test_sign_and_verify():
    """Test sign and verify operations"""
    print("Test 3: Sign and Verify Operations")
    hsm = create_post_quantum_hsm()
    
    gen_result = hsm.generate_key(
        key_type=KeyType.HMAC_SECRET,
        key_size=256,
        label="signing-key"
    )
    key_id = gen_result.key_id
    
    test_data = b"Hello, QuantumCrypt HSM!"
    sign_result = hsm.sign_data(key_id, test_data)
    
    print(f"  Sign success: {sign_result.success}")
    print(f"  Signature length: {len(sign_result.data) if sign_result.data else 0}")
    
    verify_result = hsm.verify_signature(key_id, test_data, sign_result.data)
    
    print(f"  Verify success: {verify_result.success}")
    
    # Test with wrong data
    bad_verify = hsm.verify_signature(key_id, b"Wrong data", sign_result.data)
    print(f"  Wrong data verify: {bad_verify.success}")
    
    assert sign_result.success == True, "Signing should succeed"
    assert verify_result.success == True, "Verification should pass"
    assert bad_verify.success == False, "Wrong data should fail verification"
    print("  ✓ PASSED\n")


def test_encrypt_and_decrypt():
    """Test encrypt and decrypt operations"""
    print("Test 4: Encrypt and Decrypt Operations")
    hsm = create_post_quantum_hsm()
    
    gen_result = hsm.generate_key(
        key_type=KeyType.SYMMETRIC_AES,
        key_size=256,
        label="encryption-key",
        allowed_usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT]
    )
    key_id = gen_result.key_id
    
    plaintext = b"Secret message that needs post-quantum protection!"
    encrypt_result = hsm.encrypt_data(key_id, plaintext)
    
    print(f"  Encrypt success: {encrypt_result.success}")
    print(f"  Ciphertext length: {len(encrypt_result.data) if encrypt_result.data else 0}")
    
    decrypt_result = hsm.decrypt_data(key_id, encrypt_result.data)
    
    print(f"  Decrypt success: {decrypt_result.success}")
    print(f"  Decrypted matches original: {decrypt_result.data == plaintext}")
    
    assert encrypt_result.success == True, "Encryption should succeed"
    assert decrypt_result.success == True, "Decryption should succeed"
    assert decrypt_result.data == plaintext, "Decrypted data should match original"
    print("  ✓ PASSED\n")


def test_key_info():
    """Test key metadata retrieval"""
    print("Test 5: Key Information Retrieval")
    hsm = create_post_quantum_hsm()
    
    gen_result = hsm.generate_key(
        key_type=KeyType.POST_QUANTUM_DILITHIUM,
        key_size=256,
        label="pq-signing-key"
    )
    key_id = gen_result.key_id
    
    info = hsm.get_key_info(key_id)
    
    print(f"  Key ID: {info['key_id']}")
    print(f"  Key Type: {info['key_type']}")
    print(f"  Key Size: {info['key_size']}")
    print(f"  Label: {info['label']}")
    print(f"  Usage Count: {info['usage_count']}")
    
    assert info is not None, "Should return key info"
    assert info['key_id'] == key_id, "Key ID should match"
    assert info['key_type'] == KeyType.POST_QUANTUM_DILITHIUM.value, "Key type should match"
    print("  ✓ PASSED\n")


def test_key_deletion():
    """Test secure key deletion"""
    print("Test 6: Key Deletion")
    hsm = create_post_quantum_hsm()
    
    gen_result = hsm.generate_key(
        key_type=KeyType.HMAC_SECRET,
        key_size=256,
        label="to-be-deleted"
    )
    key_id = gen_result.key_id
    
    # Verify key exists
    assert hsm.get_key_info(key_id) is not None, "Key should exist before deletion"
    
    delete_result = hsm.delete_key(key_id)
    
    print(f"  Delete success: {delete_result.success}")
    print(f"  Key exists after delete: {hsm.get_key_info(key_id) is not None}")
    
    assert delete_result.success == True, "Deletion should succeed"
    assert hsm.get_key_info(key_id) is None, "Key should not exist after deletion"
    print("  ✓ PASSED\n")


def test_audit_logging():
    """Test audit logging functionality"""
    print("Test 7: Audit Logging")
    hsm = create_post_quantum_hsm(enable_audit_logging=True)
    
    # Perform some operations
    gen_result = hsm.generate_key(KeyType.HMAC_SECRET, 256, "test-key")
    hsm.sign_data(gen_result.key_id, b"test data")
    hsm.delete_key(gen_result.key_id)
    
    audit_log = hsm.get_audit_log(limit=10)
    
    print(f"  Audit log entries: {len(audit_log)}")
    print(f"  Operations logged: {[e['operation'] for e in audit_log]}")
    
    assert len(audit_log) >= 3, "Should log all operations"
    print("  ✓ PASSED\n")


def test_usage_policy_enforcement():
    """Test key usage policy enforcement"""
    print("Test 8: Usage Policy Enforcement")
    hsm = create_post_quantum_hsm()
    
    # Create sign-only key
    gen_result = hsm.generate_key(
        key_type=KeyType.HMAC_SECRET,
        key_size=256,
        label="sign-only-key",
        allowed_usage=[KeyUsage.SIGN]  # No VERIFY
    )
    key_id = gen_result.key_id
    
    # Sign should work
    sign_result = hsm.sign_data(key_id, b"test")
    print(f"  Sign (allowed): {sign_result.success}")
    
    # Verify should fail - not in allowed usage
    verify_result = hsm.verify_signature(key_id, b"test", sign_result.data)
    print(f"  Verify (not allowed): {verify_result.success}")
    print(f"  Error: {verify_result.error_message}")
    
    assert sign_result.success == True, "Allowed operation should work"
    assert verify_result.success == False, "Disallowed operation should fail"
    print("  ✓ PASSED\n")


def test_zeroization():
    """Test emergency zeroization"""
    print("Test 9: Emergency Zeroization")
    hsm = create_post_quantum_hsm()
    
    # Generate multiple keys
    for i in range(3):
        hsm.generate_key(KeyType.HMAC_SECRET, 256, f"key-{i}")
    
    print(f"  Keys before zeroize: {len(hsm._key_store)}")
    
    hsm.zeroize()
    
    print(f"  Keys after zeroize: {len(hsm._key_store)}")
    print(f"  Zeroized: {hsm._zeroized}")
    print(f"  Master KEK destroyed: {hsm._master_kek is None}")
    
    assert len(hsm._key_store) == 0, "All keys should be destroyed"
    assert hsm._zeroized == True, "HSM should be marked zeroized"
    assert hsm._master_kek is None, "Master KEK should be destroyed"
    print("  ✓ PASSED\n")


def main():
    """Run all tests"""
    print("=" * 60)
    print("Post-Quantum HSM Emulator - Production Test Suite")
    print("QuantumCrypt-AI | June 17, 2026")
    print("=" * 60 + "\n")
    
    tests = [
        test_hsm_initialization,
        test_key_generation,
        test_sign_and_verify,
        test_encrypt_and_decrypt,
        test_key_info,
        test_key_deletion,
        test_audit_logging,
        test_usage_policy_enforcement,
        test_zeroization
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed > 0:
        sys.exit(1)
    else:
        print("\nAll tests passed successfully! ✓")
        return 0


if __name__ == "__main__":
    main()
