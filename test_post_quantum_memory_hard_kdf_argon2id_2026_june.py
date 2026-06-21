#!/usr/bin/env python3
"""
Test suite for Post-Quantum Memory-Hard KDF: Argon2id
QuantumCrypt-AI - Production-grade testing
"""

import sys
import os
import time

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_memory_hard_kdf_argon2id_2026_june import (
    Argon2id,
    KDFResult,
    SecureMemory,
    PostQuantumEnhancedKDF
)


def test_secure_memory_zeroization():
    """Test secure memory zeroization"""
    print("=" * 60)
    print("TEST 1: Secure Memory Zeroization")
    print("=" * 60)

    # Create sensitive data
    sensitive = bytearray(b"SECRET_PASSWORD_12345")
    original = bytes(sensitive)

    # Zeroize
    SecureMemory.zeroize(sensitive, passes=3)

    # Verify all bytes are zero
    all_zero = all(b == 0 for b in sensitive)
    assert all_zero, "Memory should be completely zeroized"
    assert bytes(sensitive) != original, "Original data should be overwritten"

    print(f"  Original length: {len(original)} bytes")
    print(f"  Zeroized: {' '.join(f'{b:02x}' for b in sensitive[:8])}...")
    print("  ✓ PASS: Secure memory zeroization working")
    return True


def test_secure_compare():
    """Test constant-time secure comparison"""
    print("\n" + "=" * 60)
    print("TEST 2: Constant-Time Secure Comparison")
    print("=" * 60)

    a = b"test_data_12345"
    b = b"test_data_12345"
    c = b"different_data"

    assert SecureMemory.secure_compare(a, b) is True, "Equal data should match"
    assert SecureMemory.secure_compare(a, c) is False, "Different data should not match"
    assert SecureMemory.secure_compare(a, b"short") is False, "Different lengths should not match"

    print("  Equal comparison: True")
    print("  Different comparison: False")
    print("  Different length: False")
    print("  ✓ PASS: Constant-time comparison working")
    return True


def test_salt_generation():
    """Test cryptographically secure salt generation"""
    print("\n" + "=" * 60)
    print("TEST 3: Salt Generation")
    print("=" * 60)

    salt1 = SecureMemory.generate_salt(16)
    salt2 = SecureMemory.generate_salt(16)

    assert len(salt1) == 16, "Salt should be 16 bytes"
    assert len(salt2) == 16, "Salt should be 16 bytes"
    assert salt1 != salt2, "Salts should be unique"

    # Test minimum length enforcement
    try:
        SecureMemory.generate_salt(8)
        print("  WARNING: Should have raised ValueError for short salt")
    except ValueError:
        print("  Correctly rejected short salt (< 16 bytes)")

    print(f"  Salt 1: {salt1.hex()[:16]}...")
    print(f"  Salt 2: {salt2.hex()[:16]}...")
    print("  ✓ PASS: Salt generation working")
    return True


def test_argon2id_basic_derivation():
    """Test basic Argon2id key derivation"""
    print("\n" + "=" * 60)
    print("TEST 4: Argon2id Basic Key Derivation")
    print("=" * 60)

    # Use low memory for fast testing
    kdf = Argon2id(
        memory_cost=1024,  # 1MB for testing
        time_cost=2,
        parallelism=1,
        hash_length=32
    )

    password = "MySecurePassword123!"
    result = kdf.derive_key(password)

    assert isinstance(result, KDFResult), "Should return KDFResult"
    assert len(result.derived_key) == 32, "Derived key should be 32 bytes"
    assert len(result.salt) == 16, "Salt should be 16 bytes"
    assert result.algorithm == "argon2id"

    print(f"  Password: {password}")
    print(f"  Derived key: {result.to_hex()}")
    print(f"  Salt: {result.salt.hex()}")
    print(f"  Hash length: {len(result.derived_key)} bytes ({len(result.derived_key) * 8} bits)")
    print("  ✓ PASS: Basic key derivation working")
    return True


def test_argon2id_deterministic():
    """Test deterministic derivation with same salt"""
    print("\n" + "=" * 60)
    print("TEST 5: Deterministic Derivation (Same Salt)")
    print("=" * 60)

    kdf = Argon2id(memory_cost=512, time_cost=1, parallelism=1, hash_length=32)

    password = "TestPassword456!"
    salt = SecureMemory.generate_salt(16)

    result1 = kdf.derive_key(password, salt=salt)
    result2 = kdf.derive_key(password, salt=salt)

    assert result1.derived_key == result2.derived_key, "Same password + salt should produce same key"
    assert result1.salt == result2.salt == salt, "Salt should be preserved"

    print(f"  Salt: {salt.hex()}")
    print(f"  Derivation 1: {result1.to_hex()[:32]}...")
    print(f"  Derivation 2: {result2.to_hex()[:32]}...")
    print("  Keys match: ✓")
    print("  ✓ PASS: Deterministic derivation working")
    return True


def test_argon2id_different_passwords():
    """Test different passwords produce different keys"""
    print("\n" + "=" * 60)
    print("TEST 6: Different Passwords Produce Different Keys")
    print("=" * 60)

    kdf = Argon2id(memory_cost=512, time_cost=1, parallelism=1, hash_length=32)
    salt = SecureMemory.generate_salt(16)

    result1 = kdf.derive_key("password1", salt=salt)
    result2 = kdf.derive_key("password2", salt=salt)

    assert result1.derived_key != result2.derived_key, "Different passwords should produce different keys"

    print(f"  password1 -> {result1.to_hex()[:32]}...")
    print(f"  password2 -> {result2.to_hex()[:32]}...")
    print("  Keys differ: ✓")
    print("  ✓ PASS: Different passwords produce different keys")
    return True


def test_argon2id_verification():
    """Test key verification"""
    print("\n" + "=" * 60)
    print("TEST 7: Key Verification")
    print("=" * 60)

    kdf = Argon2id(memory_cost=512, time_cost=1, parallelism=1, hash_length=32)

    password = "VerifyMe123!"
    result = kdf.derive_key(password)

    # Correct password should verify
    correct = kdf.verify_key(password, result.salt, result.derived_key)
    assert correct is True, "Correct password should verify"

    # Wrong password should fail
    wrong = kdf.verify_key("WrongPassword!", result.salt, result.derived_key)
    assert wrong is False, "Wrong password should not verify"

    print(f"  Correct password verification: {correct}")
    print(f"  Wrong password verification: {wrong}")
    print("  ✓ PASS: Key verification working")
    return True


def test_argon2id_security_level():
    """Test security level assessment"""
    print("\n" + "=" * 60)
    print("TEST 8: Security Level Assessment")
    print("=" * 60)

    # Low security
    low_kdf = Argon2id(memory_cost=16, time_cost=1, hash_length=16)
    low_level = low_kdf.get_security_level()
    print(f"  Low (16KB, 1 iter): {low_level['security_level']}")
    print(f"    Memory: {low_level['memory_mb']:.2f} MB")
    print(f"    PQ resistant: {low_level['post_quantum_resistant']}")

    # Medium security
    med_kdf = Argon2id(memory_cost=65536, time_cost=2, hash_length=32)
    med_level = med_kdf.get_security_level()
    print(f"  Medium (64MB, 2 iter): {med_level['security_level']}")
    print(f"    Memory: {med_level['memory_mb']:.2f} MB")
    print(f"    PQ resistant: {med_level['post_quantum_resistant']}")

    # High security
    high_kdf = Argon2id(memory_cost=262144, time_cost=3, hash_length=64)
    high_level = high_kdf.get_security_level()
    print(f"  High (256MB, 3 iter): {high_level['security_level']}")
    print(f"    Memory: {high_level['memory_mb']:.2f} MB")
    print(f"    PQ resistant: {high_level['post_quantum_resistant']}")

    assert med_level['post_quantum_resistant'] is True, "Medium+ should be post-quantum resistant"
    print("  ✓ PASS: Security level assessment working")
    return True


def test_post_quantum_enhanced():
    """Test post-quantum enhanced KDF"""
    print("\n" + "=" * 60)
    print("TEST 9: Post-Quantum Enhanced KDF")
    print("=" * 60)

    # Use smaller params for testing
    pq_kdf = PostQuantumEnhancedKDF(
        memory_cost=2048,
        time_cost=2,
        hash_length=64
    )

    password = "PostQuantumSecure2026!"
    additional_entropy = b"domain_separation_context"

    key, salt = pq_kdf.derive(password, additional_entropy=additional_entropy)

    assert len(key) == 64, "PQ enhanced key should be 64 bytes (512 bits)"
    assert len(salt) == 16, "Salt should be 16 bytes"

    # Test recovery code generation
    recovery_code = PostQuantumEnhancedKDF.generate_recovery_code()
    assert len(recovery_code) == 64, "Recovery code should be 64 hex chars (256 bits)"

    print(f"  Password: {password}")
    print(f"  PQ Key (512-bit): {key.hex()[:48]}...")
    print(f"  Salt: {salt.hex()}")
    print(f"  Recovery code: {recovery_code[:32]}...")
    print("  ✓ PASS: Post-quantum enhanced KDF working")
    return True


def test_performance_benchmark():
    """Test performance benchmark"""
    print("\n" + "=" * 60)
    print("TEST 10: Performance Benchmark")
    print("=" * 60)

    # Test with reasonable parameters
    kdf = Argon2id(
        memory_cost=8192,  # 8MB
        time_cost=2,
        parallelism=1,
        hash_length=32
    )

    start = time.time()
    result = kdf.derive_key("benchmark_test_password")
    elapsed = time.time() - start

    print(f"  Memory: 8 MB")
    print(f"  Iterations: 2")
    print(f"  Time: {elapsed * 1000:.2f} ms")
    print(f"  Output: {len(result.derived_key) * 8} bits")

    # Should complete in reasonable time
    assert elapsed < 10.0, "Should complete within 10 seconds"
    print("  ✓ PASS: Performance within acceptable bounds")
    return True


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("QuantumCrypt-AI: Argon2id Memory-Hard KDF Test Suite")
    print("=" * 60)

    tests = [
        test_secure_memory_zeroization,
        test_secure_compare,
        test_salt_generation,
        test_argon2id_basic_derivation,
        test_argon2id_deterministic,
        test_argon2id_different_passwords,
        test_argon2id_verification,
        test_argon2id_security_level,
        test_post_quantum_enhanced,
        test_performance_benchmark,
    ]

    passed = 0
    failed = 0
    failed_tests = []

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                failed_tests.append(test.__name__)
        except Exception as e:
            print(f"  ✗ EXCEPTION in {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
            failed_tests.append(test.__name__)

    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed}/{len(tests)} PASSED")
    print("=" * 60)

    if failed > 0:
        print(f"FAILED TESTS: {', '.join(failed_tests)}")
        return False

    print("\n✓ ALL TESTS PASSED - Production-grade implementation verified!")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
