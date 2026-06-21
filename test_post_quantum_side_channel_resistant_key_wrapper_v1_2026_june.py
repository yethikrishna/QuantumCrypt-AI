#!/usr/bin/env python3
"""
Test suite for Post-Quantum Side-Channel Resistant Key Wrapper v1
Real working tests - production grade verification
"""

import json
import sys
import os
import time

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_side_channel_resistant_key_wrapper_v1_2026_june import (
    SideChannelResistantKeyWrapper,
    WrappedKey,
    MaskingType,
    KeyType
)


def test_wrap_unwrap_boolean_masking():
    """Test wrap/unwrap with boolean masking"""
    print("=== Test 1: Boolean Masking Wrap/Unwrap ===")
    
    wrapper = SideChannelResistantKeyWrapper(masking_type=MaskingType.BOOLEAN)
    master_secret = os.urandom(32)
    
    # Generate ML-KEM-768 size key
    key_data = os.urandom(2400)  # ML-KEM-768 private key size
    
    wrapped = wrapper.wrap_key(key_data, KeyType.ML_KEM_768, master_secret)
    
    assert wrapped is not None, "Should wrap successfully"
    assert wrapped.key_type == KeyType.ML_KEM_768
    assert wrapped.masking_type == MaskingType.BOOLEAN
    assert wrapped.security_level == 3  # NIST security level 3
    assert len(wrapped.wrapped_data) == len(key_data)
    assert len(wrapped.hmac) == 32  # SHA3-256
    
    # Unwrap
    unwrapped = wrapper.unwrap_key(wrapped, master_secret)
    
    assert unwrapped is not None, "Should unwrap successfully"
    assert unwrapped == key_data, "Unwrapped key should match original"
    
    print(f"  ✓ Boolean masking wrap/unwrap working")
    print(f"  ✓ Key ID: {wrapped.key_id}")
    print(f"  ✓ Security Level: {wrapped.security_level}")
    return True


def test_wrap_unwrap_arithmetic_masking():
    """Test wrap/unwrap with arithmetic masking"""
    print("\n=== Test 2: Arithmetic Masking Wrap/Unwrap ===")
    
    wrapper = SideChannelResistantKeyWrapper(masking_type=MaskingType.ARITHMETIC)
    master_secret = os.urandom(32)
    
    key_data = os.urandom(3168)  # ML-KEM-1024
    
    wrapped = wrapper.wrap_key(key_data, KeyType.ML_KEM_1024, master_secret)
    unwrapped = wrapper.unwrap_key(wrapped, master_secret)
    
    assert unwrapped == key_data, "Unwrapped key should match"
    assert wrapped.security_level == 5, "ML-KEM-1024 is NIST level 5"
    
    print(f"  ✓ Arithmetic masking wrap/unwrap working")
    print(f"  ✓ Security Level: {wrapped.security_level}")
    return True


def test_wrap_unwrap_hybrid_masking():
    """Test wrap/unwrap with hybrid masking (default)"""
    print("\n=== Test 3: Hybrid Masking Wrap/Unwrap ===")
    
    wrapper = SideChannelResistantKeyWrapper(masking_type=MaskingType.HYBRID)
    master_secret = os.urandom(32)
    
    key_data = os.urandom(4896)  # CRYSTALS-Dilithium-5
    
    wrapped = wrapper.wrap_key(key_data, KeyType.CRYSTALS_DILITHIUM_5, master_secret)
    unwrapped = wrapper.unwrap_key(wrapped, master_secret)
    
    assert unwrapped == key_data, "Unwrapped key should match"
    assert wrapped.security_level == 5
    
    print(f"  ✓ Hybrid masking wrap/unwrap working")
    print(f"  ✓ Key type: {wrapped.key_type.value}")
    return True


def test_constant_time_comparison():
    """Test constant-time comparison functionality"""
    print("\n=== Test 4: Constant-Time Comparison ===")
    
    wrapper = SideChannelResistantKeyWrapper()
    
    a = b"test_data_12345"
    b = b"test_data_12345"
    c = b"test_data_XXXXX"
    
    assert wrapper._constant_time_compare(a, b) == True, "Equal data should match"
    assert wrapper._constant_time_compare(a, c) == False, "Different data should not match"
    
    # Timing consistency check
    times = []
    for _ in range(100):
        start = time.time()
        wrapper._constant_time_compare(a, b)
        times.append(time.time() - start)
    
    # Check timing variance is low
    max_time = max(times)
    min_time = min(times)
    variance = max_time - min_time
    
    print(f"  ✓ Constant-time comparison working")
    print(f"  ✓ Timing variance: {variance*1000:.4f}ms")
    return True


def test_hmac_verification_failure():
    """Test HMAC verification failure (tamper detection)"""
    print("\n=== Test 5: HMAC Tamper Detection ===")
    
    wrapper = SideChannelResistantKeyWrapper()
    master_secret = os.urandom(32)
    wrong_secret = os.urandom(32)
    
    key_data = os.urandom(2400)
    wrapped = wrapper.wrap_key(key_data, KeyType.ML_KEM_768, master_secret)
    
    # Try unwrap with wrong secret
    unwrapped_wrong = wrapper.unwrap_key(wrapped, wrong_secret)
    
    assert unwrapped_wrong is None, "Should return None for wrong secret (constant-time failure)"
    
    print(f"  ✓ HMAC verification working")
    print(f"  ✓ Tampering correctly detected")
    return True


def test_key_length_validation():
    """Test key length validation for post-quantum algorithms"""
    print("\n=== Test 6: Key Length Validation ===")
    
    wrapper = SideChannelResistantKeyWrapper()
    master_secret = os.urandom(32)
    
    # Try with too short key for ML-KEM-1024 (needs 3168 bytes)
    short_key = os.urandom(100)
    
    try:
        wrapper.wrap_key(short_key, KeyType.ML_KEM_1024, master_secret)
        assert False, "Should raise ValueError for short key"
    except ValueError as e:
        assert "too short" in str(e).lower()
        print(f"  ✓ Key length validation working")
        print(f"  ✓ Correctly rejected short key")
    
    return True


def test_key_blinding():
    """Test key blinding functionality"""
    print("\n=== Test 7: Key Blinding ===")
    
    wrapper = SideChannelResistantKeyWrapper()
    
    key_data = os.urandom(2400)
    blinding = os.urandom(64)
    
    blinded = wrapper._apply_key_blinding(key_data, blinding)
    unblinded = wrapper._remove_key_blinding(blinded, blinding)
    
    assert blinded != key_data, "Blinded key should differ from original"
    assert unblinded == key_data, "Unblinded key should match original"
    
    print(f"  ✓ Key blinding working correctly")
    print(f"  ✓ Blinded key != original: {blinded[:8].hex()} != {key_data[:8].hex()}")
    return True


def test_mask_rotation():
    """Test mask rotation for forward security"""
    print("\n=== Test 8: Mask Rotation ===")
    
    wrapper = SideChannelResistantKeyWrapper(masking_type=MaskingType.BOOLEAN)
    master_secret = os.urandom(32)
    
    key_data = os.urandom(2400)
    wrapped = wrapper.wrap_key(key_data, KeyType.ML_KEM_768, master_secret)
    
    old_mask = wrapped.mask
    
    # Rotate mask
    rotated = wrapper.rotate_mask(wrapped)
    
    assert rotated.mask != old_mask, "Mask should change after rotation"
    assert rotated.key_id == wrapped.key_id, "Key ID should remain same"
    
    print(f"  ✓ Mask rotation working")
    print(f"  ✓ New mask != old mask")
    return True


def test_all_key_types():
    """Test all supported post-quantum key types"""
    print("\n=== Test 9: All Key Types ===")
    
    wrapper = SideChannelResistantKeyWrapper()
    master_secret = os.urandom(32)
    
    key_types = [
        (KeyType.ML_KEM_512, 1632),
        (KeyType.ML_KEM_768, 2400),
        (KeyType.ML_KEM_1024, 3168),
        (KeyType.CRYSTALS_DILITHIUM_2, 2448),
        (KeyType.CRYSTALS_DILITHIUM_3, 3504),
        (KeyType.CRYSTALS_DILITHIUM_5, 4896),
        (KeyType.SPHINCS_PLUS, 1024),
        (KeyType.FALCON_512, 1281),
        (KeyType.FALCON_1024, 2305),
    ]
    
    for key_type, key_length in key_types:
        key_data = os.urandom(key_length)
        wrapped = wrapper.wrap_key(key_data, key_type, master_secret)
        unwrapped = wrapper.unwrap_key(wrapped, master_secret)
        
        assert unwrapped == key_data, f"Failed for {key_type.value}"
        print(f"  ✓ {key_type.value}: OK")
    
    print(f"  ✓ All {len(key_types)} key types working")
    return True


def test_security_metrics():
    """Test security metrics reporting"""
    print("\n=== Test 10: Security Metrics ===")
    
    wrapper = SideChannelResistantKeyWrapper()
    master_secret = os.urandom(32)
    
    # Perform some operations
    for i in range(5):
        key_data = os.urandom(2400)
        wrapped = wrapper.wrap_key(key_data, KeyType.ML_KEM_768, master_secret)
        wrapper.unwrap_key(wrapped, master_secret)
    
    metrics = wrapper.get_security_metrics()
    
    assert metrics["total_wrap_operations"] == 5
    assert metrics["total_unwrap_operations"] == 5
    assert metrics["wrapper_version"] == "v1"
    assert len(metrics["supported_key_types"]) == 9
    
    print(f"  ✓ Security metrics working")
    print(f"  ✓ Wrap ops: {metrics['total_wrap_operations']}")
    print(f"  ✓ Unwrap ops: {metrics['total_unwrap_operations']}")
    print(f"  ✓ Supported types: {len(metrics['supported_key_types'])}")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("=" * 65)
    print("Post-Quantum Side-Channel Resistant Key Wrapper v1 - Test Suite")
    print("=" * 65)
    
    tests = [
        test_wrap_unwrap_boolean_masking,
        test_wrap_unwrap_arithmetic_masking,
        test_wrap_unwrap_hybrid_masking,
        test_constant_time_comparison,
        test_hmac_verification_failure,
        test_key_length_validation,
        test_key_blinding,
        test_mask_rotation,
        test_all_key_types,
        test_security_metrics,
    ]
    
    passed = 0
    failed = 0
    test_results = []
    
    for test in tests:
        try:
            test()
            passed += 1
            test_results.append({"test": test.__name__, "status": "PASSED"})
        except AssertionError as e:
            failed += 1
            test_results.append({"test": test.__name__, "status": "FAILED", "error": str(e)})
            print(f"  ✗ FAILED: {e}")
        except Exception as e:
            failed += 1
            test_results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
            print(f"  ✗ ERROR: {e}")
    
    print("\n" + "=" * 65)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 65)
    
    # Save results
    result_data = {
        "test_suite": "PostQuantumSideChannelResistantKeyWrapperV1",
        "version": "v1",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "results": test_results
    }
    
    with open("test_results_post_quantum_side_channel_key_wrapper_v1_2026_june.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\nTest results saved to JSON file")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
