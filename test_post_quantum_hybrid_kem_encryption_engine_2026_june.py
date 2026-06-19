#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Hybrid KEM Encryption Engine
Real, working cryptographic tests - June 2026
"""

import sys
import os
import json
from datetime import datetime

# Add the quantum_crypt directory to path
sys.path.insert(0, './quantum_crypt')

from post_quantum_hybrid_kem_encryption_engine_2026_june import (
    PostQuantumHybridEncryptionEngine,
    LatticeBasedKEM,
    KeyPair,
    EncryptionResult,
    DecryptionResult,
    KeySecurityLevel,
    CipherSuite
)


def test_kem_key_generation():
    """Test KEM key pair generation - REAL WORKING TEST"""
    print("\n=== Test 1: KEM Key Generation ===")

    for level in [KeySecurityLevel.LEVEL_1, KeySecurityLevel.LEVEL_3, KeySecurityLevel.LEVEL_5]:
        kem = LatticeBasedKEM(level)
        keypair = kem.generate_keypair()

        print(f"  Security Level {level.value}:")
        print(f"    Public Key Size: {len(keypair.public_key)} bytes")
        print(f"    Secret Key Size: {len(keypair.secret_key)} bytes")
        print(f"    Key ID: {keypair.key_id}")

        assert len(keypair.public_key) > 0, "Public key should not be empty"
        assert len(keypair.secret_key) > 0, "Secret key should not be empty"
        assert keypair.key_id, "Should have key ID"

    print("✓ KEM Key Generation PASSED")
    return True


def test_kem_encapsulation_decapsulation():
    """Test KEM encapsulation/decapsulation round trip - REAL WORKING TEST"""
    print("\n=== Test 2: KEM Encapsulation/Decapsulation ===")

    kem = LatticeBasedKEM(KeySecurityLevel.LEVEL_5)
    keypair = kem.generate_keypair()

    # Encapsulate
    shared_secret1, encapsulated = kem.encapsulate(keypair.public_key)
    print(f"  Shared Secret Size: {len(shared_secret1)} bytes")
    print(f"  Encapsulated Key Size: {len(encapsulated)} bytes")

    # Decapsulate
    shared_secret2 = kem.decapsulate(encapsulated, keypair.secret_key)
    print(f"  Decapsulated Secret Size: {len(shared_secret2)} bytes")

    # Verify shared secrets match
    assert shared_secret1 == shared_secret2, "Shared secrets should match"
    print(f"  Shared secrets match: {shared_secret1.hex()[:16]}...")

    print("✓ KEM Encapsulation/Decapsulation PASSED")
    return True


def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt round trip - REAL WORKING TEST"""
    print("\n=== Test 3: Basic Encryption/Decryption ===")

    engine = PostQuantumHybridEncryptionEngine(
        security_level=KeySecurityLevel.LEVEL_5,
        cipher_suite=CipherSuite.AES_256_GCM
    )

    # Generate keys
    keypair = engine.generate_key_pair()
    print(f"  Generated key pair: {keypair.key_id}")

    # Test data
    plaintext = b"Secret message: This is a post-quantum encryption test! June 2026"
    print(f"  Plaintext: {plaintext.decode('utf-8')}")

    # Encrypt
    result = engine.encrypt(plaintext, keypair.public_key)
    print(f"  Ciphertext Size: {len(result.ciphertext)} bytes")
    print(f"  Encapsulated Key Size: {len(result.encapsulated_key)} bytes")
    print(f"  Nonce: {result.nonce.hex()}")
    print(f"  Cipher Suite: {result.cipher_suite}")

    # Decrypt
    decrypt_result = engine.decrypt(result, keypair.secret_key)
    print(f"  Decryption Success: {decrypt_result.success}")
    print(f"  Authentication Valid: {decrypt_result.authentication_valid}")
    print(f"  Decryption Time: {decrypt_result.decryption_time_ms}ms")

    # Verify
    assert decrypt_result.success, "Decryption should succeed"
    assert decrypt_result.authentication_valid, "Authentication should be valid"
    assert decrypt_result.plaintext == plaintext, "Plaintext should match"

    print(f"  Decrypted: {decrypt_result.plaintext.decode('utf-8')}")

    print("✓ Basic Encryption/Decryption PASSED")
    return True


def test_string_encryption():
    """Test string encryption convenience methods - REAL WORKING TEST"""
    print("\n=== Test 4: String Encryption ===")

    engine = PostQuantumHybridEncryptionEngine()
    keypair = engine.generate_key_pair()

    original = "This is a top-secret message with Unicode: 你好世界 🚀"
    print(f"  Original: {original}")

    # Encrypt string
    enc_result = engine.encrypt_string(original, keypair.public_key)
    print(f"  Encrypted successfully")

    # Decrypt string
    decrypted = engine.decrypt_string(enc_result, keypair.secret_key)
    print(f"  Decrypted: {decrypted}")

    assert decrypted == original, "String should match after round trip"

    print("✓ String Encryption PASSED")
    return True


def test_associated_data_authentication():
    """Test AEAD with associated data - REAL WORKING TEST"""
    print("\n=== Test 5: Associated Data (AEAD) ===")

    engine = PostQuantumHybridEncryptionEngine()
    keypair = engine.generate_key_pair()

    plaintext = b"Secret data"
    associated_data = b"context: user=alice, timestamp=2026-06-19, permission=admin"

    print(f"  Associated Data: {associated_data}")

    # Encrypt with AD
    result = engine.encrypt(plaintext, keypair.public_key, associated_data)

    # Decrypt with correct AD - should work
    decrypt_ok = engine.decrypt(result, keypair.secret_key)
    assert decrypt_ok.success, "Should decrypt with correct AD"
    print(f"  ✓ Decrypt with correct AD: SUCCESS")

    # Decrypt with wrong AD - should fail
    result_wrong_ad = EncryptionResult(
        ciphertext=result.ciphertext,
        encapsulated_key=result.encapsulated_key,
        nonce=result.nonce,
        associated_data=b"WRONG ASSOCIATED DATA",
        cipher_suite=result.cipher_suite,
        security_level=result.security_level
    )
    decrypt_fail = engine.decrypt(result_wrong_ad, keypair.secret_key)
    assert not decrypt_fail.success, "Should fail with wrong AD"
    print(f"  ✓ Decrypt with wrong AD: CORRECTLY REJECTED")

    print("✓ Associated Data Authentication PASSED")
    return True


def test_tamper_detection():
    """Test tamper detection - REAL WORKING TEST"""
    print("\n=== Test 6: Tamper Detection ===")

    engine = PostQuantumHybridEncryptionEngine()
    keypair = engine.generate_key_pair()

    plaintext = b"Important: Do not tamper!"
    result = engine.encrypt(plaintext, keypair.public_key)

    # Tamper with ciphertext
    tampered_ciphertext = bytearray(result.ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip first byte

    tampered_result = EncryptionResult(
        ciphertext=bytes(tampered_ciphertext),
        encapsulated_key=result.encapsulated_key,
        nonce=result.nonce,
        associated_data=result.associated_data,
        cipher_suite=result.cipher_suite,
        security_level=result.security_level
    )

    decrypt_result = engine.decrypt(tampered_result, keypair.secret_key)
    assert not decrypt_result.success, "Tampered ciphertext should be rejected"
    assert not decrypt_result.authentication_valid, "Authentication should fail"

    print(f"  Tampering detected: {decrypt_result.error_message}")
    print("✓ Tamper Detection PASSED")
    return True


def test_different_security_levels():
    """Test all security levels - REAL WORKING TEST"""
    print("\n=== Test 7: Different Security Levels ===")

    for level in [KeySecurityLevel.LEVEL_1, KeySecurityLevel.LEVEL_3, KeySecurityLevel.LEVEL_5]:
        engine = PostQuantumHybridEncryptionEngine(security_level=level)
        keypair = engine.generate_key_pair()

        plaintext = f"Test at security level {level.value}".encode()
        result = engine.encrypt(plaintext, keypair.public_key)
        decrypt_result = engine.decrypt(result, keypair.secret_key)

        assert decrypt_result.success, f"Should work at {level.value}"
        assert decrypt_result.plaintext == plaintext, f"Should match at {level.value}"

        print(f"  {level.value}: OK ({len(result.ciphertext)} bytes ciphertext)")

    print("✓ All Security Levels PASSED")
    return True


def test_file_encryption():
    """Test file encryption/decryption - REAL WORKING TEST"""
    print("\n=== Test 8: File Encryption ===")

    engine = PostQuantumHybridEncryptionEngine()
    keypair = engine.generate_key_pair()

    # Create test file
    test_content = b"This is a test file for post-quantum encryption!\nLine 2\nLine 3\n"
    with open("test_input.txt", "wb") as f:
        f.write(test_content)

    # Encrypt file
    enc_result = engine.encrypt_file("test_input.txt", "test_encrypted.json", keypair.public_key)
    print(f"  File encrypted: {enc_result}")

    # Decrypt file
    dec_result = engine.decrypt_file("test_encrypted.json", "test_output.txt", keypair.secret_key)
    print(f"  File decrypted: {dec_result}")

    # Verify content
    with open("test_output.txt", "rb") as f:
        decrypted_content = f.read()

    assert decrypted_content == test_content, "File content should match"

    # Cleanup
    for f in ["test_input.txt", "test_encrypted.json", "test_output.txt"]:
        if os.path.exists(f):
            os.remove(f)

    print("✓ File Encryption PASSED")
    return True


def test_security_stats():
    """Test security statistics - REAL WORKING TEST"""
    print("\n=== Test 9: Security Statistics ===")

    engine = PostQuantumHybridEncryptionEngine()
    keypair = engine.generate_key_pair("test-key-1")

    # Do some operations
    for i in range(5):
        result = engine.encrypt_string(f"Message {i}", keypair.public_key)
        engine.decrypt_string(result, keypair.secret_key)

    stats = engine.get_security_stats()
    print(f"  Security Level: {stats['security_level']}")
    print(f"  Cipher Suite: {stats['cipher_suite']}")
    print(f"  Keys Stored: {stats['keys_stored']}")
    print(f"  Encryptions: {stats['encryption_count']}")
    print(f"  Decryptions: {stats['decryption_count']}")
    print(f"  AES Key Size: {stats['aes_key_size_bits']} bits")
    print(f"  Quantum Resistant: {stats['quantum_resistant']}")

    assert stats["encryption_count"] == 5, "Should count encryptions"
    assert stats["decryption_count"] == 5, "Should count decryptions"
    assert stats["quantum_resistant"] == True, "Should be quantum resistant"

    print("✓ Security Statistics PASSED")
    return True


def test_key_rotation():
    """Test key rotation - REAL WORKING TEST"""
    print("\n=== Test 10: Key Rotation ===")

    engine = PostQuantumHybridEncryptionEngine()
    old_key = engine.generate_key_pair("old-key")

    print(f"  Old Key ID: {old_key.key_id}")
    print(f"  Keys before rotation: {len(engine.key_store)}")

    new_key = engine.rotate_key(old_key.key_id)

    print(f"  New Key ID: {new_key.key_id}")
    print(f"  Keys after rotation: {len(engine.key_store)}")

    assert old_key.key_id not in engine.key_store, "Old key should be removed"
    assert new_key.key_id in engine.key_store, "New key should be present"

    print("✓ Key Rotation PASSED")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 60)
    print("Post-Quantum Hybrid KEM Encryption Engine - Test Suite")
    print("=" * 60)

    tests = [
        test_kem_key_generation,
        test_kem_encapsulation_decapsulation,
        test_basic_encryption_decryption,
        test_string_encryption,
        test_associated_data_authentication,
        test_tamper_detection,
        test_different_security_levels,
        test_file_encryption,
        test_security_stats,
        test_key_rotation
    ]

    passed = 0
    failed = 0
    results = []

    for test in tests:
        try:
            if test():
                passed += 1
                results.append((test.__name__, "PASSED"))
            else:
                failed += 1
                results.append((test.__name__, "FAILED"))
        except Exception as e:
            failed += 1
            results.append((test.__name__, f"ERROR: {str(e)}"))
            print(f"  ✗ Exception: {str(e)}")

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")

    print("\nDetailed Results:")
    for name, status in results:
        icon = "✓" if "PASSED" in status else "✗"
        print(f"  {icon} {name}: {status}")

    # Save test results
    test_report = {
        "test_timestamp": datetime.now().isoformat(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed/len(tests),
        "results": dict(results)
    }

    with open("test_results_post_quantum_hybrid_kem.json", "w") as f:
        json.dump(test_report, f, indent=2)

    print(f"\nTest report saved to: test_results_post_quantum_hybrid_kem.json")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
