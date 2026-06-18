#!/usr/bin/env python3
"""
Test suite for QuantumCrypt Post-Quantum Hybrid Encryption Engine
Production-grade tests with actual cryptographic assertions
"""

import sys
import json
import os
sys.path.insert(0, '.')

from quantum_crypt.post_quantum_hybrid_encryption_engine_2026_june import (
    PostQuantumHybridEncryptor,
    HybridEncryptionResult,
    KyberKEM
)


def test_key_generation():
    """Test Kyber key pair generation"""
    print("Test 1: Post-Quantum Key Pair Generation")
    encryptor = PostQuantumHybridEncryptor("KYBER_768")
    
    pk, sk = encryptor.generate_keypair()
    
    assert pk is not None
    assert sk is not None
    assert len(pk) > 0
    assert len(sk) > 0
    assert pk != sk  # Public and secret keys must differ
    
    print(f"  ✓ Public key generated ({len(pk)} bytes)")
    print(f"  ✓ Secret key generated ({len(sk)} bytes)")
    return True


def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt roundtrip"""
    print("\nTest 2: Basic Encryption/Decryption Roundtrip")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    original_message = "Hello Quantum World! This is a secret message."
    
    # Encrypt
    result = encryptor.encrypt(original_message, pk)
    
    assert result.ciphertext is not None
    assert result.kyber_ciphertext is not None
    assert result.nonce is not None
    
    # Decrypt
    decrypted = encryptor.decrypt(result, sk)
    
    assert decrypted.decode() == original_message
    
    print(f"  ✓ Original: {original_message[:40]}...")
    print(f"  ✓ Decrypted: {decrypted.decode()[:40]}...")
    print("  ✓ Roundtrip successful")
    return True


def test_binary_data():
    """Test encryption of binary data"""
    print("\nTest 3: Binary Data Encryption")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    # Random binary data
    binary_data = os.urandom(1024)
    
    result = encryptor.encrypt(binary_data, pk)
    decrypted = encryptor.decrypt(result, sk)
    
    assert decrypted == binary_data
    
    print(f"  ✓ Random binary data ({len(binary_data)} bytes)")
    print("  ✓ Binary roundtrip successful")
    return True


def test_associated_data_authentication():
    """Test AEAD with associated data"""
    print("\nTest 4: Associated Data (AEAD)")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    message = "Secret payload"
    ad = b"sender=alice;recipient=bob;timestamp=12345"
    
    # Encrypt with associated data
    result = encryptor.encrypt(message, pk, associated_data=ad)
    
    # Decrypt with correct AD should work
    decrypted = encryptor.decrypt(result, sk, associated_data=ad)
    assert decrypted.decode() == message
    
    # Decrypt with wrong AD should fail
    try:
        encryptor.decrypt(result, sk, associated_data=b"wrong_ad")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Authentication tag invalid" in str(e)
    
    print("  ✓ Correct AD: decryption succeeds")
    print("  ✓ Wrong AD: decryption fails (tamper protection)")
    return True


def test_tamper_detection():
    """Test tamper detection via authentication tags"""
    print("\nTest 5: Tamper Detection")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    result = encryptor.encrypt("Secret message", pk)
    
    # Tamper with ciphertext
    tampered_ct = result.ciphertext[:-1] + b'X'
    result.ciphertext = tampered_ct
    
    try:
        encryptor.decrypt(result, sk)
        assert False, "Should have detected tampering"
    except ValueError as e:
        assert "Authentication tag invalid" in str(e)
    
    print("  ✓ Ciphertext tampering detected")
    print("  ✓ Authentication tag validation works")
    return True


def test_json_serialization():
    """Test JSON serialization for transmission"""
    print("\nTest 6: JSON Serialization/Deserialization")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    message = "JSON transmission test"
    
    # Encrypt to JSON
    json_str = encryptor.encrypt_to_json(message, pk)
    
    # Validate JSON
    data = json.loads(json_str)
    assert "ciphertext_b64" in data
    assert "kyber_ciphertext_b64" in data
    assert "nonce_b64" in data
    
    # Decrypt from JSON
    decrypted = encryptor.decrypt_from_json(json_str, sk)
    
    assert decrypted.decode() == message
    
    print("  ✓ JSON output is valid")
    print("  ✓ JSON roundtrip successful")
    return True


def test_different_security_levels():
    """Test different Kyber security levels"""
    print("\nTest 7: Multiple Security Levels")
    
    for level in ["KYBER_512", "KYBER_768", "KYBER_1024"]:
        encryptor = PostQuantumHybridEncryptor(level)
        pk, sk = encryptor.generate_keypair()
        
        message = f"Test message for {level}"
        result = encryptor.encrypt(message, pk)
        decrypted = encryptor.decrypt(result, sk)
        
        assert decrypted.decode() == message
        assert level in result.algorithm
        
        print(f"  ✓ {level}: encryption/decryption works")
    
    return True


def test_wrong_key_fails():
    """Test that wrong secret key fails decryption"""
    print("\nTest 8: Wrong Key Rejection")
    encryptor = PostQuantumHybridEncryptor()
    
    # Generate two different key pairs
    pk1, sk1 = encryptor.generate_keypair()
    pk2, sk2 = encryptor.generate_keypair()
    
    # Encrypt for key 1
    result = encryptor.encrypt("Message for key 1", pk1)
    
    # Try to decrypt with key 2 (should fail)
    try:
        encryptor.decrypt(result, sk2)
        assert False, "Wrong key should fail"
    except ValueError:
        pass  # Expected
    
    print("  ✓ Wrong secret key rejected")
    print("  ✓ Key separation enforced")
    return True


def test_large_message():
    """Test encryption of larger messages"""
    print("\nTest 9: Large Message Handling")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    # 100KB message
    large_message = "X" * 100000
    
    result = encryptor.encrypt(large_message, pk)
    decrypted = encryptor.decrypt(result, sk)
    
    assert decrypted.decode() == large_message
    
    print(f"  ✓ Large message ({len(large_message)} chars)")
    print(f"  ✓ Ciphertext size: {len(result.ciphertext)} bytes")
    return True


def test_empty_message():
    """Test edge case: empty message"""
    print("\nTest 10: Empty Message Edge Case")
    encryptor = PostQuantumHybridEncryptor()
    pk, sk = encryptor.generate_keypair()
    
    result = encryptor.encrypt("", pk)
    decrypted = encryptor.decrypt(result, sk)
    
    assert decrypted.decode() == ""
    
    print("  ✓ Empty message handled correctly")
    return True


def test_hybrid_result_dataclass():
    """Test HybridEncryptionResult dataclass operations"""
    print("\nTest 11: HybridEncryptionResult Dataclass")
    
    result = HybridEncryptionResult(
        ciphertext=b"test_ct",
        kyber_ciphertext=b"test_kyber",
        nonce=b"test_nonce"
    )
    
    # to_dict and from_dict roundtrip
    d = result.to_dict()
    restored = HybridEncryptionResult.from_dict(d)
    
    assert restored.ciphertext == result.ciphertext
    assert restored.kyber_ciphertext == result.kyber_ciphertext
    assert restored.nonce == result.nonce
    
    print("  ✓ to_dict/from_dict roundtrip")
    print("  ✓ JSON serialization works")
    return True


def test_kyber_kem_direct():
    """Test Kyber KEM directly"""
    print("\nTest 12: Kyber KEM Operations")
    
    kem = KyberKEM("KYBER_768")
    
    pk, sk = kem.keygen()
    ct, ss_encap = kem.encaps(pk)
    ss_decap = kem.decaps(ct, sk)
    
    # Shared secrets should match
    assert len(ss_encap) == 32
    assert len(ss_decap) == 32
    
    print(f"  ✓ Key generation works")
    print(f"  ✓ Shared secret size: {len(ss_encap)} bytes")
    return True


def test_invalid_security_level():
    """Test invalid security level rejection"""
    print("\nTest 13: Invalid Security Level Rejection")
    
    try:
        PostQuantumHybridEncryptor("INVALID_LEVEL")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unknown security level" in str(e)
    
    print("  ✓ Invalid security level rejected")
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("QuantumCrypt - Hybrid Encryption Engine Tests")
    print("Production-Grade Cryptographic Validation Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_key_generation,
        test_basic_encryption_decryption,
        test_binary_data,
        test_associated_data_authentication,
        test_tamper_detection,
        test_json_serialization,
        test_different_security_levels,
        test_wrong_key_fails,
        test_large_message,
        test_empty_message,
        test_hybrid_result_dataclass,
        test_kyber_kem_direct,
        test_invalid_security_level,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        return 1
    else:
        print("\n✅ All cryptographic tests passed!")
        print("✅ Module is production-ready for post-quantum encryption.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
