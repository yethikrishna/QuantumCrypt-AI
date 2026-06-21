#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure File Encryptor
June 21, 2026 - Production-grade testing
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_secure_file_encryptor_2026_june import (
    PostQuantumFileEncryptor,
    EncryptionKey,
    KeySecurityLevel,
    EncryptionMode,
    FileType,
    LatticeBasedKEM,
    create_file_encryptor,
    verify_file_encryptor
)


def run_file_encryption_decryption_test():
    """Test actual file encryption and decryption"""
    print("=" * 60)
    print("FILE ENCRYPTION/DECRYPTION TEST")
    print("=" * 60)

    encryptor = create_file_encryptor(KeySecurityLevel.LEVEL_5)

    # Create test files of different sizes
    test_cases = [
        ("small_file.txt", "Short secret message!" * 10),
        ("medium_file.txt", "Medium size test data for encryption. " * 1000),
        ("large_file.txt", "Large file content for chunked encryption. " * 10000),
    ]

    results = []

    for filename, content in test_cases:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=filename) as f:
            f.write(content)
            test_file = f.name

        encrypted_file = test_file + ".pqcrypt"
        decrypted_file = test_file + ".decrypted"

        key = encryptor.generate_encryption_key("secure_password_2026!")

        # Encrypt
        enc_result = encryptor.encrypt_file(test_file, encrypted_file, key)

        # Decrypt
        dec_result = encryptor.decrypt_file(encrypted_file, decrypted_file, key)

        # Verify
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()

        content_match = decrypted_content == content

        file_size = len(content.encode('utf-8'))

        print(f"✓ {filename}: {file_size} bytes")
        print(f"  Encrypted: {enc_result.success} in {enc_result.encryption_time_ms:.2f}ms")
        print(f"  Decrypted: {dec_result.success} in {dec_result.decryption_time_ms:.2f}ms")
        print(f"  Integrity: {dec_result.integrity_verified}")
        print(f"  Content match: {content_match}")
        print(f"  Overhead: {enc_result.compression_ratio:.2%}")

        results.append({
            "filename": filename,
            "original_size": file_size,
            "encrypted_size": enc_result.encrypted_size_bytes,
            "encryption_success": enc_result.success,
            "decryption_success": dec_result.success,
            "integrity_verified": dec_result.integrity_verified,
            "content_match": content_match,
            "encryption_time_ms": round(enc_result.encryption_time_ms, 2),
            "decryption_time_ms": round(dec_result.decryption_time_ms, 2),
            "overhead_ratio": round(enc_result.compression_ratio, 4)
        })

        # Cleanup
        os.unlink(test_file)
        os.unlink(encrypted_file)
        os.unlink(decrypted_file)

    all_passed = all(r["encryption_success"] and r["decryption_success"] and r["content_match"] for r in results)

    return {
        "test": "file_encryption_decryption",
        "passed": all_passed,
        "files_tested": len(results),
        "results": results
    }


def run_wrong_key_test():
    """Test that wrong keys fail to decrypt"""
    print("\n" + "=" * 60)
    print("WRONG KEY REJECTION TEST")
    print("=" * 60)

    encryptor = create_file_encryptor()

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Secret data that should be protected!")
        test_file = f.name

    encrypted_file = test_file + ".pqcrypt"
    decrypted_file = test_file + ".decrypted"

    # Encrypt with correct key
    correct_key = encryptor.generate_encryption_key("correct_password")
    enc_result = encryptor.encrypt_file(test_file, encrypted_file, correct_key)

    # Try to decrypt with wrong key
    wrong_key = encryptor.generate_encryption_key("wrong_password")
    dec_result = encryptor.decrypt_file(encrypted_file, decrypted_file, wrong_key)

    # Wrong key should FAIL to decrypt
    wrong_key_fails = not dec_result.success and "Authentication failed" in str(dec_result.error_message)

    print(f"✓ Encryption with correct key: {enc_result.success}")
    print(f"✓ Decryption with wrong key fails: {wrong_key_fails}")
    print(f"  Error message: {dec_result.error_message}")

    # Cleanup
    os.unlink(test_file)
    os.unlink(encrypted_file)
    if os.path.exists(decrypted_file):
        os.unlink(decrypted_file)

    return {
        "test": "wrong_key_rejection",
        "passed": wrong_key_fails,
        "encryption_success": enc_result.success,
        "wrong_key_decryption_fails": wrong_key_fails
    }


def run_tamper_detection_test():
    """Test that file tampering is detected"""
    print("\n" + "=" * 60)
    print("TAMPER DETECTION TEST")
    print("=" * 60)

    encryptor = create_file_encryptor()

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Important data that must not be tampered with!")
        test_file = f.name

    encrypted_file = test_file + ".pqcrypt"
    tampered_file = test_file + ".tampered"
    decrypted_file = test_file + ".decrypted"

    key = encryptor.generate_encryption_key("test_password")
    enc_result = encryptor.encrypt_file(test_file, encrypted_file, key)

    # Tamper with the encrypted file
    with open(encrypted_file, 'rb') as f:
        data = bytearray(f.read())
    # Modify some bytes in the middle
    if len(data) > 50:
        data[50] ^= 0xFF  # Flip bits
    with open(tampered_file, 'wb') as f:
        f.write(data)

    # Try to decrypt tampered file
    dec_result = encryptor.decrypt_file(tampered_file, decrypted_file, key)

    tamper_detected = not dec_result.success and not dec_result.integrity_verified

    print(f"✓ Encryption: {enc_result.success}")
    print(f"✓ Tampering detected: {tamper_detected}")
    print(f"  Error: {dec_result.error_message}")

    # Cleanup
    os.unlink(test_file)
    os.unlink(encrypted_file)
    os.unlink(tampered_file)
    if os.path.exists(decrypted_file):
        os.unlink(decrypted_file)

    return {
        "test": "tamper_detection",
        "passed": tamper_detected,
        "encryption_success": enc_result.success,
        "tamper_detected": tamper_detected
    }


def run_security_levels_test():
    """Test different security levels"""
    print("\n" + "=" * 60)
    print("SECURITY LEVELS TEST")
    print("=" * 60)

    levels = [KeySecurityLevel.LEVEL_1, KeySecurityLevel.LEVEL_3, KeySecurityLevel.LEVEL_5]
    results = {}

    for level in levels:
        encryptor = create_file_encryptor(level)
        key = encryptor.generate_encryption_key("test")

        kem = LatticeBasedKEM(level)
        pk, sk = kem.generate_keypair()

        print(f"✓ Level {level.value}: PK={len(pk)} bytes, SK={len(sk)} bytes, AES={len(key.aes_key)} bytes")

        results[f"LEVEL_{level.value}"] = {
            "pk_size": len(pk),
            "sk_size": len(sk),
            "aes_key_size": len(key.aes_key),
            "salt_size": len(key.salt)
        }

    return {
        "test": "security_levels",
        "passed": True,
        "levels_tested": len(levels),
        "results_by_level": results
    }


def run_kem_operations_test():
    """Test KEM key encapsulation/decapsulation"""
    print("\n" + "=" * 60)
    print("KEM OPERATIONS TEST")
    print("=" * 60)

    kem = LatticeBasedKEM(KeySecurityLevel.LEVEL_5)

    # Generate keypair
    pk, sk = kem.generate_keypair()
    print(f"✓ Generated keypair: PK={len(pk)} bytes, SK={len(sk)} bytes")

    # Encapsulate
    ss1, ct = kem.encapsulate(pk)
    print(f"✓ Encapsulated: shared_secret={len(ss1)} bytes, ciphertext={len(ct)} bytes")

    # Decapsulate
    ss2 = kem.decapsulate(ct, sk)
    print(f"✓ Decapsulated: shared_secret={len(ss2)} bytes")

    # Verify shared secrets match
    secrets_match = ss1 == ss2
    print(f"✓ Shared secrets match: {secrets_match}")

    return {
        "test": "kem_operations",
        "passed": secrets_match,
        "keypair_generated": True,
        "encapsulation_works": True,
        "decapsulation_works": True,
        "secrets_match": secrets_match
    }


def run_file_type_detection_test():
    """Test file type detection"""
    print("\n" + "=" * 60)
    print("FILE TYPE DETECTION TEST")
    print("=" * 60)

    encryptor = create_file_encryptor()

    test_files = [
        ("document.pdf", FileType.DOCUMENT),
        ("image.png", FileType.IMAGE),
        ("data.txt", FileType.TEXT),
        ("archive.zip", FileType.ARCHIVE),
        ("unknown.xyz", FileType.UNKNOWN),
    ]

    all_correct = True
    results = []

    for filename, expected_type in test_files:
        detected = encryptor._detect_file_type(filename)
        correct = detected == expected_type
        all_correct = all_correct and correct
        print(f"✓ {filename}: detected={detected.value}, expected={expected_type.value}, correct={correct}")
        results.append({"filename": filename, "detected": detected.value, "expected": expected_type.value, "correct": correct})

    return {
        "test": "file_type_detection",
        "passed": all_correct,
        "files_tested": len(test_files),
        "results": results
    }


def run_verification_test():
    """Run built-in verification test"""
    print("\n" + "=" * 60)
    print("VERIFICATION TEST")
    print("=" * 60)

    result = verify_file_encryptor()
    print(f"Verification: {'PASSED' if result['success'] else 'FAILED'}")
    print(f"Message: {result['message']}")

    if result['success']:
        for key, value in result.items():
            if key not in ['success', 'message', 'error']:
                print(f"  ✓ {key}: {value}")

    return result


def run_performance_benchmark():
    """Run performance benchmark"""
    print("\n" + "=" * 60)
    print("PERFORMANCE BENCHMARK")
    print("=" * 60)

    encryptor = create_file_encryptor()
    key = encryptor.generate_encryption_key("benchmark_password")

    sizes = [1024, 10*1024, 100*1024]  # 1KB, 10KB, 100KB
    results = []

    for size in sizes:
        content = "X" * size

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            test_file = f.name

        encrypted_file = test_file + ".pqcrypt"
        decrypted_file = test_file + ".decrypted"

        enc_result = encryptor.encrypt_file(test_file, encrypted_file, key)
        dec_result = encryptor.decrypt_file(encrypted_file, decrypted_file, key)

        enc_speed = size / enc_result.encryption_time_ms if enc_result.encryption_time_ms > 0 else 0
        dec_speed = size / dec_result.decryption_time_ms if dec_result.decryption_time_ms > 0 else 0

        print(f"✓ {size} bytes: encrypt={enc_result.encryption_time_ms:.2f}ms ({enc_speed:.0f} bytes/ms), decrypt={dec_result.decryption_time_ms:.2f}ms ({dec_speed:.0f} bytes/ms)")

        results.append({
            "size_bytes": size,
            "encryption_time_ms": round(enc_result.encryption_time_ms, 2),
            "decryption_time_ms": round(dec_result.decryption_time_ms, 2),
            "encryption_speed_bytes_per_ms": round(enc_speed, 1),
            "decryption_speed_bytes_per_ms": round(dec_speed, 1)
        })

        os.unlink(test_file)
        os.unlink(encrypted_file)
        os.unlink(decrypted_file)

    return {
        "test": "performance_benchmark",
        "passed": True,
        "benchmarks": results
    }


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("POST-QUANTUM SECURE FILE ENCRYPTOR - TEST SUITE")
    print("June 21, 2026 - Production Release")
    print("=" * 60 + "\n")

    all_test_results = []

    try:
        all_test_results.append(run_file_encryption_decryption_test())
        all_test_results.append(run_wrong_key_test())
        all_test_results.append(run_tamper_detection_test())
        all_test_results.append(run_security_levels_test())
        all_test_results.append(run_kem_operations_test())
        all_test_results.append(run_file_type_detection_test())
        all_test_results.append(run_verification_test())
        all_test_results.append(run_performance_benchmark())
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in all_test_results if r.get('passed', False))
    total = len(all_test_results)

    print(f"\nTotal Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total*100):.1f}%")

    # Save results
    output_file = "test_results_post_quantum_secure_file_encryptor.json"
    with open(output_file, 'w') as f:
        json.dump({
            "test_date": "2026-06-21",
            "encryptor_version": "v1.0",
            "total_tests": total,
            "tests_passed": passed,
            "tests_failed": total - passed,
            "success_rate": passed/total,
            "test_results": all_test_results
        }, f, indent=2)

    print(f"\n✓ Test results saved to {output_file}")

    if passed == total:
        print("\n✅ ALL TESTS PASSED - Production Ready!")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
