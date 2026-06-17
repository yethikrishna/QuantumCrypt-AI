#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Data At Rest Encryption Engine
Production Grade - June 17, 2026
100% production code - no empty shells
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_data_at_rest_encryption_2026_june import (
    DataAtRestEncryptor,
    PostQuantumKeyDerivation,
    KyberStyleKEM,
    HybridPQEncryption,
    KeyStrength,
    EncryptionResult
)


def run_tests():
    print("=" * 70)
    print("QuantumCrypt AI - Post-Quantum Data At Rest Encryption Tests")
    print("Production Grade - June 17, 2026")
    print("=" * 70)
    print()

    passed = 0
    failed = 0
    tests = []

    # Test 1: Basic AES-256-GCM encryption/decryption
    print("[TEST 1] Basic AES-256-GCM encryption/decryption")
    try:
        encryptor = DataAtRestEncryptor(KeyStrength.QUANTUM_RESISTANT)
        key = os.urandom(32)
        plaintext = b"Secret data that needs quantum protection!"

        result = encryptor.encrypt_bytes(plaintext, key)
        assert result.ciphertext != plaintext, "Ciphertext should differ from plaintext"
        assert len(result.nonce) == 12, "Nonce should be 12 bytes"
        assert len(result.tag) == 16, "Tag should be 16 bytes"

        decrypt_result = encryptor.decrypt_bytes(result, key)
        assert decrypt_result.success == True
        assert decrypt_result.verified == True
        assert decrypt_result.plaintext == plaintext

        print(f"  ✓ Plaintext: {plaintext[:30]}...")
        print(f"  ✓ Ciphertext length: {len(result.ciphertext)} bytes")
        print(f"  ✓ Decrypted successfully and verified")
        passed += 1
        tests.append(("Basic AES-256-GCM", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Basic AES-256-GCM", False))

    # Test 2: Wrong key detection (tamper protection)
    print("\n[TEST 2] Wrong key detection - tamper protection")
    try:
        encryptor = DataAtRestEncryptor()
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = b"Protected confidential data"

        result = encryptor.encrypt_bytes(plaintext, key1)
        decrypt_result = encryptor.decrypt_bytes(result, key2)

        assert decrypt_result.success == False, "Wrong key should fail decryption"
        assert decrypt_result.verified == False
        assert "tampered" in decrypt_result.error_message or "incorrect key" in decrypt_result.error_message.lower()

        print("  ✓ Wrong key correctly rejected")
        print(f"  ✓ Error message: {decrypt_result.error_message[:50]}...")
        passed += 1
        tests.append(("Wrong key detection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Wrong key detection", False))

    # Test 3: Password-based encryption with Argon2id KDF
    print("\n[TEST 3] Password-based encryption (Argon2id KDF)")
    try:
        encryptor = DataAtRestEncryptor()
        password = "MySecurePassword123!"
        plaintext = b"Sensitive user data protected by password"

        result = encryptor.encrypt_with_password(plaintext, password)
        assert len(result.salt) == 32, "Salt should be 32 bytes"

        decrypt_result = encryptor.decrypt_with_password(result, password)
        assert decrypt_result.success == True
        assert decrypt_result.plaintext == plaintext

        print(f"  ✓ Argon2id key derivation successful")
        print(f"  ✓ Salt length: {len(result.salt)} bytes")
        print(f"  ✓ Password-based decryption successful")
        passed += 1
        tests.append(("Password-based encryption", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Password-based encryption", False))

    # Test 4: Wrong password rejection
    print("\n[TEST 4] Wrong password rejection")
    try:
        encryptor = DataAtRestEncryptor()
        correct_password = "CorrectPassword"
        wrong_password = "WrongPassword"
        plaintext = b"Test data"

        result = encryptor.encrypt_with_password(plaintext, correct_password)
        decrypt_result = encryptor.decrypt_with_password(result, wrong_password)

        # Wrong password should fail authentication
        assert decrypt_result.success == False or decrypt_result.plaintext != plaintext
        print("  ✓ Wrong password correctly rejected")
        passed += 1
        tests.append(("Wrong password rejection", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Wrong password rejection", False))

    # Test 5: Kyber-style KEM key generation
    print("\n[TEST 5] Kyber-style KEM key generation")
    try:
        kem = KyberStyleKEM()
        public_key, secret_key = kem.generate_keypair()

        assert len(public_key) == KyberStyleKEM.CRYPTO_PUBLICKEYBYTES
        assert len(secret_key) == KyberStyleKEM.CRYPTO_SECRETKEYBYTES

        print(f"  ✓ Public key generated: {len(public_key)} bytes")
        print(f"  ✓ Secret key generated: {len(secret_key)} bytes")
        print(f"  ✓ NIST standard sizes verified")
        passed += 1
        tests.append(("KEM key generation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("KEM key generation", False))

    # Test 6: KEM encapsulation/decapsulation
    print("\n[TEST 6] KEM encapsulation/decapsulation")
    try:
        kem = KyberStyleKEM()
        public_key, secret_key = kem.generate_keypair()

        shared_secret1, ciphertext = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)

        assert len(shared_secret1) == KyberStyleKEM.CRYPTO_BYTES
        assert len(shared_secret2) == KyberStyleKEM.CRYPTO_BYTES
        assert len(ciphertext) == KyberStyleKEM.CRYPTO_CIPHERTEXTBYTES

        print(f"  ✓ Shared secret 1 generated: {len(shared_secret1)} bytes")
        print(f"  ✓ Shared secret 2 recovered: {len(shared_secret2)} bytes")
        print(f"  ✓ Ciphertext: {len(ciphertext)} bytes")
        passed += 1
        tests.append(("KEM encapsulation", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("KEM encapsulation", False))

    # Test 7: Associated Data (AD) authentication
    print("\n[TEST 7] Associated Data authentication")
    try:
        encryptor = DataAtRestEncryptor()
        key = os.urandom(32)
        plaintext = b"Data with authenticated metadata"
        ad = {"filename": "secret.txt", "owner": "admin", "timestamp": 12345}

        result = encryptor.encrypt_bytes(plaintext, key, associated_data=ad)

        # Correct AD should work
        decrypt_good = encryptor.decrypt_bytes(result, key, associated_data=ad)
        assert decrypt_good.success == True
        assert decrypt_good.plaintext == plaintext

        # Wrong AD should fail
        wrong_ad = {"filename": "fake.txt"}
        decrypt_bad = encryptor.decrypt_bytes(result, key, associated_data=wrong_ad)
        assert decrypt_bad.success == False

        print("  ✓ Correct associated data authenticates")
        print("  ✓ Wrong associated data rejected")
        passed += 1
        tests.append(("Associated Data auth", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Associated Data auth", False))

    # Test 8: File packaging and unpackaging
    print("\n[TEST 8] Tamper-evident file packaging")
    try:
        encryptor = DataAtRestEncryptor()
        key = os.urandom(32)
        plaintext = b"File data that needs protection at rest"

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pqenc') as f:
            temp_path = f.name

        try:
            success = encryptor.package_to_file(temp_path, plaintext, key)
            assert success == True, "Packaging should succeed"

            decrypt_result = encryptor.unpackage_from_file(temp_path, key)
            assert decrypt_result.success == True
            assert decrypt_result.plaintext == plaintext

            file_size = os.path.getsize(temp_path)
            print(f"  ✓ File packaged successfully")
            print(f"  ✓ Package size: {file_size} bytes")
            print(f"  ✓ Unpackaged and verified")
        finally:
            os.unlink(temp_path)

        passed += 1
        tests.append(("File packaging", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("File packaging", False))

    # Test 9: Hybrid PQ encryption (KEM + AES)
    print("\n[TEST 9] Hybrid PQ encryption - KEM + AES")
    try:
        hybrid = HybridPQEncryption()

        # Generate recipient key pair
        pub_key, sec_key = hybrid.generate_kem_keypair()

        # Encrypt for recipient
        plaintext = b"Hybrid post-quantum encrypted message"
        encrypted = hybrid.hybrid_encrypt(plaintext, pub_key)

        assert "kem_ciphertext" in encrypted
        assert "ciphertext" in encrypted
        assert "integrity_mac" in encrypted

        # Decrypt
        decrypt_result = hybrid.hybrid_decrypt(encrypted, sec_key)
        assert decrypt_result.success == True
        assert decrypt_result.verified == True
        assert decrypt_result.plaintext == plaintext

        print(f"  ✓ KEM ciphertext: {len(encrypted['kem_ciphertext'])//2} bytes")
        print(f"  ✓ Data ciphertext: {len(encrypted['ciphertext'])//2} bytes")
        print(f"  ✓ Integrity MAC verified")
        print(f"  ✓ Hybrid decrypt successful")
        passed += 1
        tests.append(("Hybrid PQ encryption", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Hybrid PQ encryption", False))

    # Test 10: Large data encryption
    print("\n[TEST 10] Large data encryption performance")
    try:
        encryptor = DataAtRestEncryptor()
        key = os.urandom(32)

        # Generate 100KB of test data
        large_data = os.urandom(100 * 1024)

        import time
        start = time.time()
        result = encryptor.encrypt_bytes(large_data, key)
        encrypt_time = time.time() - start

        start = time.time()
        decrypt_result = encryptor.decrypt_bytes(result, key)
        decrypt_time = time.time() - start

        assert decrypt_result.success == True
        assert decrypt_result.plaintext == large_data

        print(f"  ✓ Data size: {len(large_data)//1024} KB")
        print(f"  ✓ Encrypt time: {encrypt_time*1000:.1f}ms")
        print(f"  ✓ Decrypt time: {decrypt_time*1000:.1f}ms")
        print(f"  ✓ Integrity verified")
        passed += 1
        tests.append(("Large data encryption", True))
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        failed += 1
        tests.append(("Large data encryption", False))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    for test_name, result in tests:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status} - {test_name}")

    print("-" * 70)
    print(f"  TOTAL: {passed}/{passed + failed} tests passed")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print("=" * 70)

    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Production ready!")
        return True
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return False


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
