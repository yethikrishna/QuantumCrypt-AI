#!/usr/bin/env python3
"""
Test suite for QuantumCrypt AI - Post-Quantum Secure Key Derivation Engine
REAL tests, not placeholder tests.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_key_derivation_engine_2026_june import (
    PostQuantumSecureKDF,
    KDFParameters,
    constant_time_compare,
    generate_salt,
    hkdf_extract,
    hkdf_expand,
    memory_hard_mix,
    post_quantum_key_mix,
    derive_post_quantum_key
)


def test_constant_time_compare():
    """Test constant-time comparison"""
    print("Testing constant_time_compare...")
    
    assert constant_time_compare(b"test", b"test") == True
    assert constant_time_compare(b"test", b"tes") == False
    assert constant_time_compare(b"test", b"Test") == False
    assert constant_time_compare(b"", b"") == True
    
    print("  ✓ constant_time_compare tests passed")


def test_generate_salt():
    """Test salt generation"""
    print("Testing generate_salt...")
    
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)
    
    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2  # Cryptographically random should differ
    
    print("  ✓ generate_salt tests passed")


def test_hkdf_basic():
    """Test basic HKDF functionality"""
    print("Testing HKDF extract and expand...")
    
    ikm = b"input_key_material_12345"
    salt = b"salt_123"
    info = b"context_info"
    
    # Test extract
    prk = hkdf_extract(salt, ikm)
    assert len(prk) == 32  # SHA256 output
    
    # Test expand
    derived = hkdf_expand(prk, info, 32)
    assert len(derived) == 32
    
    # Test determinism
    derived2 = hkdf_expand(prk, info, 32)
    assert derived == derived2
    
    print("  ✓ HKDF basic tests passed")


def test_memory_hard_mix():
    """Test memory-hard mixing function"""
    print("Testing memory_hard_mix...")
    
    input_data = b"test_input_data_12345"
    
    # Use small memory for testing
    result1 = memory_hard_mix(input_data, memory_kb=64, iterations=1)
    result2 = memory_hard_mix(input_data, memory_kb=64, iterations=1)
    
    assert len(result1) == 64  # SHA512 output
    assert result1 == result2  # Deterministic
    
    # Different input should give different output
    result3 = memory_hard_mix(b"different_input", memory_kb=64, iterations=1)
    assert result1 != result3
    
    print("  ✓ memory_hard_mix tests passed")


def test_post_quantum_key_mix():
    """Test post-quantum key mixing"""
    print("Testing post_quantum_key_mix...")
    
    key_material = b"key_material_test_12345"
    
    result1 = post_quantum_key_mix(key_material)
    result2 = post_quantum_key_mix(key_material)
    
    assert len(result1) == 64  # SHA512 output
    assert result1 == result2  # Deterministic
    
    # Avalanche effect - small input change = big output change
    result3 = post_quantum_key_mix(b"key_material_test_12346")
    diff = sum(a != b for a, b in zip(result1, result3))
    assert diff > 32  # At least half the bytes differ
    
    print("  ✓ post_quantum_key_mix tests passed")


def test_kdf_parameters():
    """Test KDF parameter validation"""
    print("Testing KDFParameters...")
    
    # Valid parameters
    valid = KDFParameters()
    assert valid.validate() == True
    
    # Invalid - too little memory
    invalid_mem = KDFParameters(memory_cost_kb=32)
    assert invalid_mem.validate() == False
    
    # Invalid - zero iterations
    invalid_iter = KDFParameters(iterations=0)
    assert invalid_iter.validate() == False
    
    # Invalid - too short output
    invalid_out = KDFParameters(output_length=8)
    assert invalid_out.validate() == False
    
    print("  ✓ KDFParameters tests passed")


def test_post_quantum_secure_kdf_basic():
    """Test basic KDF functionality"""
    print("Testing PostQuantumSecureKDF basic...")
    
    # Use minimal parameters for fast testing
    params = KDFParameters(
        memory_cost_kb=64,
        iterations=1,
        output_length=32
    )
    kdf = PostQuantumSecureKDF(params)
    
    ikm = b"my_secret_input_key_material"
    result = kdf.derive_key(ikm)
    
    assert "derived_key" in result
    assert "salt" in result
    assert "params" in result
    assert "intermediate" in result
    
    assert len(result["derived_key"]) == 32
    assert len(result["salt"]) == 16
    
    print("  ✓ PostQuantumSecureKDF basic tests passed")


def test_kdf_determinism():
    """Test KDF is deterministic with same salt"""
    print("Testing KDF determinism...")
    
    params = KDFParameters(memory_cost_kb=64, iterations=1, output_length=32)
    kdf = PostQuantumSecureKDF(params)
    
    ikm = b"test_ikm_deterministic"
    salt = b"fixed_salt_12345678"
    
    result1 = kdf.derive_key(ikm, salt=salt)
    result2 = kdf.derive_key(ikm, salt=salt)
    
    # Same IKM + same salt = same key
    assert result1["derived_key"] == result2["derived_key"]
    
    print("  ✓ KDF determinism tests passed")


def test_kdf_different_salt():
    """Test different salt produces different keys"""
    print("Testing KDF different salt...")
    
    params = KDFParameters(memory_cost_kb=64, iterations=1, output_length=32)
    kdf = PostQuantumSecureKDF(params)
    
    ikm = b"test_ikm_salt_test"
    
    result1 = kdf.derive_key(ikm, salt=b"salt_one________")
    result2 = kdf.derive_key(ikm, salt=b"salt_two________")
    
    # Same IKM + different salt = different key
    assert result1["derived_key"] != result2["derived_key"]
    
    print("  ✓ KDF different salt tests passed")


def test_kdf_different_ikm():
    """Test different IKM produces different keys"""
    print("Testing KDF different IKM...")
    
    params = KDFParameters(memory_cost_kb=64, iterations=1, output_length=32)
    kdf = PostQuantumSecureKDF(params)
    
    salt = b"fixed_salt_12345678"
    
    result1 = kdf.derive_key(b"ikm_one", salt=salt)
    result2 = kdf.derive_key(b"ikm_two", salt=salt)
    
    # Different IKM + same salt = different key
    assert result1["derived_key"] != result2["derived_key"]
    
    print("  ✓ KDF different IKM tests passed")


def test_kdf_verify():
    """Test key verification"""
    print("Testing KDF verify...")
    
    params = KDFParameters(memory_cost_kb=64, iterations=1, output_length=32)
    kdf = PostQuantumSecureKDF(params)
    
    ikm = b"verify_test_ikm"
    salt = b"verify_salt_12345"
    
    result = kdf.derive_key(ikm, salt=salt)
    key = result["derived_key"]
    
    # Correct verification
    assert kdf.verify_derivation(ikm, key, salt) == True
    
    # Wrong IKM
    assert kdf.verify_derivation(b"wrong_ikm", key, salt) == False
    
    # Wrong key
    assert kdf.verify_derivation(ikm, b"wrong_key________", salt) == False
    
    print("  ✓ KDF verify tests passed")


def test_convenience_function():
    """Test convenience derive_post_quantum_key function"""
    print("Testing derive_post_quantum_key convenience...")
    
    ikm = b"convenience_test_ikm"
    
    result = derive_post_quantum_key(ikm, output_length=32, memory_cost_kb=64)
    
    assert "derived_key" in result
    assert len(result["derived_key"]) == 32
    assert "salt" in result
    
    print("  ✓ convenience function tests passed")


def test_variable_output_length():
    """Test variable output lengths"""
    print("Testing variable output lengths...")
    
    for length in [16, 24, 32, 48, 64]:
        params = KDFParameters(
            memory_cost_kb=64,
            iterations=1,
            output_length=length
        )
        kdf = PostQuantumSecureKDF(params)
        result = kdf.derive_key(b"test_ikm")
        assert len(result["derived_key"]) == length
    
    print("  ✓ variable output length tests passed")


def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("QuantumCrypt AI - Post-Quantum KDF Tests")
    print("=" * 60)
    
    try:
        test_constant_time_compare()
        test_generate_salt()
        test_hkdf_basic()
        test_memory_hard_mix()
        test_post_quantum_key_mix()
        test_kdf_parameters()
        test_post_quantum_secure_kdf_basic()
        test_kdf_determinism()
        test_kdf_different_salt()
        test_kdf_different_ikm()
        test_kdf_verify()
        test_convenience_function()
        test_variable_output_length()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return True
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
